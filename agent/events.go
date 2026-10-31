package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

var (
	// ErrEventContextNotFound reports an event with no retained Agent context.
	ErrEventContextNotFound = errors.New("aauth agent: event context not found")
	// ErrEventContextConflict reports changed context under one Resource/eid pair.
	ErrEventContextConflict = errors.New("aauth agent: event context conflicts with retained state")
	// ErrEventReplayConflict reports changed exact delivery state under one fingerprint.
	ErrEventReplayConflict = errors.New("aauth agent: event replay conflicts with retained state")
)

// EventsConfig enables Agent-side event context and replay state.
type EventsConfig struct {
	Store                EventStore
	MaxEventPayloadBytes int64
}

type eventsClientConfig struct {
	store           EventStore
	maxPayloadBytes int64
}

// EventContext is the caller-owned meaning bound to a public subscription
// before that registration becomes visible to a Resource.
type EventContext struct {
	EventID              string
	Resource             string
	Context              []byte
	SubscribeTokenSHA256 [sha256.Size]byte
}

// AcceptedEvent is one independently verified token and AP-forwarded payload
// candidate. The payload is authenticated to the Agent Provider by the
// Resource request proof; the AP-to-Agent transport remains host-defined.
type AcceptedEvent struct {
	Fingerprint events.DeliveryFingerprint
	EventID     string
	Resource    string
	EventToken  string
	Payload     []byte
	ContentType string
	ReceivedAt  time.Time
	ExpiresAt   time.Time
}

// EventAcceptance is the Agent store's atomic correlation and replay result.
type EventAcceptance struct {
	Context   EventContext
	Duplicate bool
}

// EventStore owns Agent-local subscription context and exact-delivery replay
// state. BindContext must copy the complete record, accept an exact repeat,
// and return ErrEventContextConflict for changed state under one
// (Resource, EventID) pair. AcceptEvent must atomically locate that context,
// check and retain the delivery fingerprint, and return Duplicate for an
// exact repeat. It must copy all byte slices and return
// ErrEventContextNotFound or ErrEventReplayConflict for the named failures.
// A non-sentinel error has uncertain commit state, so the Agent must not act
// on the candidate.
type EventStore interface {
	BindContext(context.Context, EventContext) error
	AcceptEvent(context.Context, AcceptedEvent) (EventAcceptance, error)
}

// PublicSubscriptionInput contains one already-obtained AP subscribe token,
// the selected public Resource endpoint, opaque registration parameters, and
// the caller's durable local context.
type PublicSubscriptionInput struct {
	Endpoint       string
	SubscribeToken string
	Parameters     []byte
	ContentType    string
	Context        []byte
}

// ProtectedSubscriptionInput contains an already-obtained AP subscribe token,
// a Resource-issued opaque ticket URL, registration parameters, and durable
// local context.
type ProtectedSubscriptionInput struct {
	TicketURL      string
	SubscribeToken string
	Parameters     []byte
	ContentType    string
	Context        []byte
}

// EventSubscription is the verified public or protected registration identity.
type EventSubscription struct {
	EventID  string
	Resource string
}

// EventDeliveryInput is one token and opaque payload forwarded through the
// Agent Provider's host-defined local delivery mechanism.
type EventDeliveryInput struct {
	EventToken  string
	Payload     []byte
	ContentType string
}

// ReceivedEvent is the Agent-correlated result. Duplicate true means the
// caller must not act on the event again.
type ReceivedEvent struct {
	Resource    string
	EventID     string
	Context     []byte
	Payload     []byte
	ContentType string
	ExpiresAt   time.Time
	Duplicate   bool
}

// RegisterPublicSubscription verifies the AP token, commits local context,
// and performs one signed registration POST. It never retries. When the
// Resource defers the registration, the error is a
// *PendingError[EventSubscription] that carries the pending registration;
// BeginPublicSubscription returns it as a Result.
func (client *Client) RegisterPublicSubscription(
	ctx context.Context,
	input PublicSubscriptionInput,
) (EventSubscription, error) {
	const operation = "register public event subscription"
	result, err := client.registerEventSubscription(ctx, operation, input)
	if err != nil {
		return EventSubscription{}, err
	}
	return completed(operation, result)
}

// BeginPublicSubscription performs the same single registration as
// RegisterPublicSubscription and returns the registration, or the pending
// registration when the Resource answers 202. Polls are signed with the same
// subscribe token.
func (client *Client) BeginPublicSubscription(
	ctx context.Context,
	input PublicSubscriptionInput,
) (Result[EventSubscription], error) {
	return client.registerEventSubscription(ctx, "begin public event subscription", input)
}

// RegisterProtectedSubscription binds context and performs one signed POST to
// a Resource-issued ticket URL. It never retries. A deferred registration is
// a *PendingError[EventSubscription], as for RegisterPublicSubscription.
func (client *Client) RegisterProtectedSubscription(
	ctx context.Context,
	input ProtectedSubscriptionInput,
) (EventSubscription, error) {
	const operation = "register protected event subscription"
	result, err := client.registerEventSubscription(ctx, operation, input.public())
	if err != nil {
		return EventSubscription{}, err
	}
	return completed(operation, result)
}

// BeginProtectedSubscription performs the same single POST as
// RegisterProtectedSubscription and returns the registration, or the pending
// registration when the Resource answers 202.
func (client *Client) BeginProtectedSubscription(
	ctx context.Context,
	input ProtectedSubscriptionInput,
) (Result[EventSubscription], error) {
	return client.registerEventSubscription(ctx, "begin protected event subscription", input.public())
}

func (input ProtectedSubscriptionInput) public() PublicSubscriptionInput {
	return PublicSubscriptionInput{
		Endpoint:       input.TicketURL,
		SubscribeToken: input.SubscribeToken,
		Parameters:     input.Parameters,
		ContentType:    input.ContentType,
		Context:        input.Context,
	}
}

func (client *Client) registerEventSubscription(
	ctx context.Context,
	operation string,
	input PublicSubscriptionInput,
) (Result[EventSubscription], error) {
	if client == nil || client.events == nil {
		return Result[EventSubscription]{}, fail(operation, errors.New("Events is not configured"))
	}
	if ctx == nil {
		return Result[EventSubscription]{}, fail(operation, errors.New("context is required"))
	}
	if input.SubscribeToken == "" {
		return Result[EventSubscription]{}, fail(operation, errors.New("subscribe token is required"))
	}
	if len(input.Context) == 0 {
		return Result[EventSubscription]{}, fail(operation, errors.New("event context is required"))
	}
	if len(input.Parameters) > 0 && input.ContentType == "" {
		return Result[EventSubscription]{}, fail(operation, errors.New("nonempty subscription parameters require a content type"))
	}
	if input.ContentType != "" {
		if _, _, err := mime.ParseMediaType(input.ContentType); err != nil {
			return Result[EventSubscription]{}, fail(operation, fmt.Errorf("content type: %w", err))
		}
	}
	if err := validateEventEndpoint(input.Endpoint); err != nil {
		return Result[EventSubscription]{}, fail(operation, err)
	}
	claims, err := events.VerifySubscribeToken(ctx, input.SubscribeToken, client.keyResolver, client.clock)
	if err != nil {
		return Result[EventSubscription]{}, fail(operation, err)
	}
	if claims.Subject != client.identifier {
		return Result[EventSubscription]{}, fail(operation, errors.New("subscribe-token subject does not match Agent"))
	}
	if !claims.Confirmation.JWK.Equal(client.signingKey.PublicJWK()) {
		return Result[EventSubscription]{}, fail(operation, errors.New("subscribe-token confirmation key does not match Agent key"))
	}
	endpoint, _ := url.Parse(input.Endpoint)
	resource := endpoint.Scheme + "://" + endpoint.Host
	if err := events.ValidateSubscribeRegistration(claims, resource, client.signingKey.PublicJWK()); err != nil {
		return Result[EventSubscription]{}, fail(operation, err)
	}
	contextRecord := EventContext{
		EventID: claims.EventID, Resource: claims.Audience,
		Context:              append([]byte(nil), input.Context...),
		SubscribeTokenSHA256: sha256.Sum256([]byte(input.SubscribeToken)),
	}
	if err := client.events.store.BindContext(ctx, contextRecord); err != nil {
		return Result[EventSubscription]{}, fail(operation, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, input.Endpoint, bytes.NewReader(input.Parameters))
	if err != nil {
		return Result[EventSubscription]{}, fail(operation, err)
	}
	// SignJWTRequestWithOptions covers content-digest for nonempty parameters.
	var components []string
	if input.ContentType != "" {
		request.Header.Set("Content-Type", input.ContentType)
		components = []string{"content-type"}
	}
	if err := signaturekey.SignJWTRequestWithOptions(
		request,
		client.signingKey,
		input.SubscribeToken,
		client.clock,
		signaturekey.SignOptions{
			AdditionalComponents: components,
			MaxBodyBytes:         client.maxSignedBodyBytes,
		},
	); err != nil {
		return Result[EventSubscription]{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Result[EventSubscription]{}, fail(operation, err)
	}
	subscription := EventSubscription{EventID: claims.EventID, Resource: claims.Audience}
	flow := newPendingFlow(client, "event subscription", input.SubscribeToken,
		func(_ context.Context, response *http.Response) (EventSubscription, error) {
			if response.StatusCode != http.StatusOK {
				return EventSubscription{}, responseFailure(response)
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes+1))
			return subscription, nil
		})
	result, err := flow.begin(ctx, response)
	if err != nil {
		return Result[EventSubscription]{}, fail(operation, err)
	}
	return result, nil
}

// AcceptEvent verifies and correlates one AP-forwarded event, as Events Agent
// Verification requires: the token's type, discovery document, signature and
// expiry; its aud against this Agent's identifier, exactly and
// case-sensitively; and the delivered payload against body_s256, so that a
// body altered, added, or dropped on the way through the Agent Provider is
// refused. Store success is required before the caller may act on a new
// event.
func (client *Client) AcceptEvent(ctx context.Context, input EventDeliveryInput) (ReceivedEvent, error) {
	const operation = "accept event"
	var received ReceivedEvent
	if client == nil || client.events == nil {
		return received, fail(operation, errors.New("Events is not configured"))
	}
	if ctx == nil {
		return received, fail(operation, errors.New("context is required"))
	}
	if int64(len(input.Payload)) > client.events.maxPayloadBytes {
		return received, fail(operation, errors.New("event payload is too large"))
	}
	if len(input.Payload) > 0 && input.ContentType == "" {
		return received, fail(operation, errors.New("nonempty event payload requires a content type"))
	}
	if input.ContentType != "" {
		if _, _, err := mime.ParseMediaType(input.ContentType); err != nil {
			return received, fail(operation, fmt.Errorf("content type: %w", err))
		}
	}
	claims, err := events.VerifyEventToken(ctx, input.EventToken, client.keyResolver, client.clock)
	if err != nil {
		return received, fail(operation, err)
	}
	if claims.Audience != client.identifier {
		return received, fail(operation, errors.New("event-token audience does not match Agent"))
	}
	if err := events.VerifyEventBody(claims, input.Payload); err != nil {
		return received, fail(operation, err)
	}
	candidate := AcceptedEvent{
		Fingerprint: events.Fingerprint(input.EventToken, input.ContentType, input.Payload),
		EventID:     claims.EventID, Resource: claims.Issuer, EventToken: input.EventToken,
		Payload: append([]byte(nil), input.Payload...), ContentType: input.ContentType,
		ReceivedAt: client.clock.Now().UTC(), ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	}
	accepted, err := client.events.store.AcceptEvent(ctx, candidate)
	if err != nil {
		return received, fail(operation, err)
	}
	if accepted.Context.EventID != claims.EventID || accepted.Context.Resource != claims.Issuer {
		return received, fail(operation, errors.New("event store returned mismatched context"))
	}
	return ReceivedEvent{
		Resource: claims.Issuer, EventID: claims.EventID,
		Context: append([]byte(nil), accepted.Context.Context...),
		Payload: append([]byte(nil), input.Payload...), ContentType: input.ContentType,
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(), Duplicate: accepted.Duplicate,
	}, nil
}

func normalizeAgentEventsConfig(config *EventsConfig) (*eventsClientConfig, error) {
	if config == nil {
		return nil, nil
	}
	if config.Store == nil {
		return nil, errors.New("aauth agent: Events store is required")
	}
	if config.MaxEventPayloadBytes < 0 {
		return nil, errors.New("aauth agent: maximum event payload size must not be negative")
	}
	limit := config.MaxEventPayloadBytes
	if limit == 0 {
		limit = maxResponseBytes
	}
	return &eventsClientConfig{store: config.Store, maxPayloadBytes: limit}, nil
}

func validateEventEndpoint(value string) error {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return errors.New("event endpoint must be an absolute HTTPS URL with no user information, query, or fragment")
	}
	return nil
}
