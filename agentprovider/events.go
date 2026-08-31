package agentprovider

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

var (
	// ErrEventSubscriptionNotFound reports an unknown or inactive event ID.
	ErrEventSubscriptionNotFound = errors.New("aauth: event subscription not found")
	// ErrEventSubscriptionInactive reports a host-disabled or completed subscription.
	ErrEventSubscriptionInactive = errors.New("aauth: event subscription is inactive")
	// ErrEventResourceMismatch reports delivery by a Resource other than the subscribed Resource.
	ErrEventResourceMismatch = errors.New("aauth: event resource does not match subscription")
	// ErrEventAgentMismatch reports an event audience other than the subscribed Agent.
	ErrEventAgentMismatch = errors.New("aauth: event agent does not match subscription")
	// ErrEventUsesExceeded reports delivery after a bounded subscription is exhausted.
	ErrEventUsesExceeded = errors.New("aauth: event subscription use limit exceeded")
	// ErrEventDeliveryConflict reports a retained delivery whose bytes do not
	// match the supplied delivery fingerprint.
	ErrEventDeliveryConflict = errors.New("aauth: event delivery conflicts with retained state")
)

// EventsConfig enables AP subscribe-token issuance and the Resource-to-AP
// event inbox. EventEndpoint may be any host-mounted absolute HTTPS URL.
type EventsConfig struct {
	EventEndpoint string
	// NewEventID returns an opaque identifier unique within this Agent
	// Provider. The store remains the durable collision boundary.
	NewEventID         func() string
	KeyResolver        signaturekey.KeyResolver
	Store              EventInboxStore
	MaxSignedBodyBytes int64
}

type eventsServerConfig struct {
	endpoint           string
	authority          string
	path               string
	newEventID         func() string
	keyResolver        signaturekey.KeyResolver
	store              EventInboxStore
	maxSignedBodyBytes int64
}

// SubscribeRequest asks the AP for a Resource-directed subscribe token. The
// AP supplies the opaque event ID. Lifetime controls only the token's
// registration deadline; it never expires an already-active subscription.
// Zero MaxUses means unlimited delivery.
type SubscribeRequest struct {
	Agent           string
	Resource        string
	ConfirmationKey jose.JWK
	Lifetime        time.Duration
	MaxUses         int64
}

// IssuedSubscribeToken is the exact token plus the context values an Agent
// must bind before presenting it to a Resource. ExpiresAt is the token's
// registration deadline, not the retained subscription's lifetime.
type IssuedSubscribeToken struct {
	Compact   string
	EventID   string
	ExpiresAt time.Time
	MaxUses   int64
}

// EventSubscription is the AP's durable routing and use-limit record. The
// compact token is retained so a host can audit the exact AP assertion from
// which the record was created. TokenExpiresAt is only the registration
// credential deadline; the store owns active state and any subscription
// lifetime independently.
type EventSubscription struct {
	EventID         string
	Agent           string
	Resource        string
	ConfirmationKey jose.JWK
	TokenExpiresAt  time.Time
	MaxUses         int64
	CompactToken    string
	TokenSHA256     [sha256.Size]byte
}

// EventDelivery is one fully verified Resource delivery candidate. The store
// uses Fingerprint as the exact token, signed-content-type, and payload
// delivery identity.
type EventDelivery struct {
	Fingerprint   events.DeliveryFingerprint
	EventID       string
	Agent         string
	Resource      string
	Token         string
	TokenSHA256   [sha256.Size]byte
	Payload       []byte
	PayloadSHA256 [sha256.Size]byte
	ContentType   string
	ReceivedAt    time.Time
}

// EventAcceptance is the retained result of one atomic inbox transition.
// MaximumUses is zero for an unlimited subscription.
type EventAcceptance struct {
	MaximumUses   int64
	RemainingUses int64
	Duplicate     bool
}

// EventInboxStore owns AP subscription and accepted-delivery state.
//
// CommitSubscription must copy and durably retain the complete record before
// returning. It must accept an exact repeat and reject a different record for
// the same EventID.
//
// AcceptEvent must atomically load the subscription, compare EventID,
// Resource and Agent, enforce active state and atomically increment the use
// count, and retain an independent copy of the exact token, content type, and
// payload before returning. An exact Fingerprint replay returns the first
// EventAcceptance without incrementing use count and with the first retained
// RemainingUses.
// Another fingerprint, including the same token with another content type or
// payload, is a distinct delivery. The method returns the typed sentinel above
// for every named refusal. A non-sentinel error has uncertain commit state;
// repeating the exact delivery must converge on the retained result or a
// stable refusal and must never double-consume a use.
type EventInboxStore interface {
	CommitSubscription(context.Context, EventSubscription) error
	AcceptEvent(context.Context, EventDelivery) (EventAcceptance, error)
}

func normalizeEventsConfig(_ string, config *EventsConfig) (*eventsServerConfig, error) {
	if config == nil {
		return nil, nil
	}
	if config.NewEventID == nil || config.KeyResolver == nil || config.Store == nil {
		return nil, errors.New("aauth: Agent Provider Events requires event ID source, key resolver, and store")
	}
	if config.MaxSignedBodyBytes < 0 {
		return nil, errors.New("aauth: Agent Provider Events maximum signed body size must not be negative")
	}
	endpoint, err := url.Parse(config.EventEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return nil, errors.New("aauth: Agent Provider event endpoint must be an HTTPS URL without user information, query, or fragment")
	}
	if endpoint.Path == "" {
		endpoint.Path = "/"
	}
	return &eventsServerConfig{
		endpoint:           endpoint.String(),
		authority:          endpoint.Host,
		path:               endpoint.EscapedPath(),
		newEventID:         config.NewEventID,
		keyResolver:        config.KeyResolver,
		store:              config.Store,
		maxSignedBodyBytes: config.MaxSignedBodyBytes,
	}, nil
}

// IssueSubscribeToken creates an opaque event ID and durably retains its AP
// subscription before returning the signed token.
func (server *Server) IssueSubscribeToken(ctx context.Context, request SubscribeRequest) (IssuedSubscribeToken, error) {
	var issued IssuedSubscribeToken
	if server == nil || server.events == nil {
		return issued, errors.New("aauth: Agent Provider Events is not configured")
	}
	if ctx == nil {
		return issued, errors.New("aauth: subscribe-token context is required")
	}
	eventID := server.events.newEventID()
	if eventID == "" {
		return issued, errors.New("aauth: Agent Provider event ID source returned an empty value")
	}
	now := server.clock.Now().UTC().Truncate(time.Second)
	compact, err := events.MintSubscribeToken(server.issuer, server.signingKey, events.SubscribeTokenRequest{
		Agent:           request.Agent,
		Resource:        request.Resource,
		ConfirmationKey: request.ConfirmationKey,
		EventID:         eventID,
		Lifetime:        request.Lifetime,
		MaxUses:         request.MaxUses,
	}, now)
	if err != nil {
		return issued, err
	}
	expiresAt := now.Add(request.Lifetime).UTC().Truncate(time.Second)
	record := EventSubscription{
		EventID: eventID, Agent: request.Agent, Resource: request.Resource,
		ConfirmationKey: request.ConfirmationKey, TokenExpiresAt: expiresAt, MaxUses: request.MaxUses,
		CompactToken: compact, TokenSHA256: sha256.Sum256([]byte(compact)),
	}
	if err := server.events.store.CommitSubscription(ctx, record); err != nil {
		return IssuedSubscribeToken{}, err
	}
	return IssuedSubscribeToken{
		Compact: compact, EventID: eventID, ExpiresAt: expiresAt, MaxUses: request.MaxUses,
	}, nil
}

func (server *Server) handleEvent(response http.ResponseWriter, request *http.Request) {
	if !strings.EqualFold(request.Host, server.events.authority) || request.URL.EscapedPath() != server.events.path || request.URL.RawQuery != "" {
		httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", errors.New("aauth: event delivery target is invalid"))
		return
	}
	requiredComponents := []string{"content-digest"}
	if request.Header.Get("Content-Type") != "" {
		requiredComponents = append([]string{"content-type"}, requiredComponents...)
	}
	prepared, err := signaturekey.PrepareRequest(request, server.clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeSelfJWT},
		RequiredComponents: requiredComponents,
		MaxBodyBytes:       server.events.maxSignedBodyBytes,
	})
	if err != nil {
		httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	compact, ok := prepared.Credential().SelfJWT()
	if !ok {
		httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", errors.New("aauth: event delivery requires self-jwt"))
		return
	}
	if err := events.ValidateEventTokenProfile(compact, prepared.VerifiedAt()); err != nil {
		httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_event_token", err)
		return
	}
	proof, assertion, err := prepared.VerifySelfJWT(request.Context(), server.events.keyResolver, events.EventTokenType)
	if err != nil {
		writeSignatureProblem(response, err)
		return
	}
	if request.Header.Get("Content-Type") == "" && len(proof.ExactBody()) > 0 {
		httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", errors.New("aauth: nonempty event payload requires content-type"))
		return
	}
	claims, err := events.EventTokenFromAssertion(assertion, proof.VerifiedAt())
	if err != nil {
		httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_event_token", err)
		return
	}
	delivery := EventDelivery{
		Fingerprint: events.Fingerprint(assertion.Compact(), request.Header.Get("Content-Type"), proof.ExactBody()),
		EventID:     claims.EventID, Agent: claims.Audience, Resource: claims.Issuer,
		Token: assertion.Compact(), TokenSHA256: sha256.Sum256([]byte(assertion.Compact())),
		Payload: proof.ExactBody(), PayloadSHA256: sha256.Sum256(proof.ExactBody()),
		ContentType: request.Header.Get("Content-Type"), ReceivedAt: proof.VerifiedAt(),
	}
	accepted, err := server.events.store.AcceptEvent(request.Context(), delivery)
	if err != nil {
		switch {
		case errors.Is(err, ErrEventSubscriptionNotFound), errors.Is(err, ErrEventSubscriptionInactive):
			httpapi.WriteProblem(response, http.StatusNotFound, "event_subscription_not_found", err)
		case errors.Is(err, ErrEventResourceMismatch), errors.Is(err, ErrEventAgentMismatch):
			httpapi.WriteProblem(response, http.StatusForbidden, "event_delivery_denied", err)
		case errors.Is(err, ErrEventUsesExceeded):
			httpapi.WriteProblem(response, http.StatusTooManyRequests, "event_uses_exceeded", err)
		case errors.Is(err, ErrEventDeliveryConflict):
			httpapi.WriteProblem(response, http.StatusBadRequest, "event_delivery_conflict", err)
		default:
			httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	if accepted.MaximumUses < 0 || accepted.RemainingUses < 0 ||
		accepted.MaximumUses == 0 && accepted.RemainingUses != 0 ||
		accepted.MaximumUses > 0 && accepted.RemainingUses >= accepted.MaximumUses {
		httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", errors.New("aauth: event store returned invalid use-limit state"))
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	if accepted.MaximumUses > 0 {
		httpapi.WriteJSON(response, http.StatusAccepted, struct {
			RemainingUses int64 `json:"remaining_uses"`
		}{RemainingUses: accepted.RemainingUses})
		return
	}
	response.WriteHeader(http.StatusAccepted)
}

func eventEndpoint(server *Server) string {
	if server == nil || server.events == nil {
		return ""
	}
	return server.events.endpoint
}

func (config eventsServerConfig) validate() error {
	if config.endpoint == "" || config.authority == "" || config.path == "" || config.newEventID == nil || config.keyResolver == nil || config.store == nil {
		return fmt.Errorf("aauth: invalid Agent Provider Events configuration")
	}
	return nil
}
