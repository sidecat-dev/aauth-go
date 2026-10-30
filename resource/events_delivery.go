package resource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// PrepareEvent creates one exact event token and owns copies of its payload.
// The token's aud and eid come from the retained subscription, so eid is the
// one the subscribe token carried, and a nonempty Payload sets body_s256 to
// its digest. It performs no network consequence.
func (service *EventService) PrepareEvent(ctx context.Context, input EventInput) (PreparedEvent, error) {
	var prepared PreparedEvent
	if service == nil {
		return prepared, errors.New("resource: Events service is required")
	}
	if ctx == nil {
		return prepared, errors.New("resource: event context is required")
	}
	if len(input.Payload) > 0 && strings.TrimSpace(input.ContentType) == "" {
		return prepared, errors.New("resource: nonempty event payload requires a content type")
	}
	if input.ContentType != "" {
		if _, _, err := mime.ParseMediaType(input.ContentType); err != nil {
			return prepared, fmt.Errorf("resource: event content type: %w", err)
		}
	}
	if input.Lifetime <= 0 {
		return prepared, errors.New("resource: event lifetime must be positive")
	}
	if err := aauth.ValidateServerIdentifier(input.AgentProvider); err != nil {
		return prepared, fmt.Errorf("resource: event Agent Provider: %w", err)
	}
	if input.EventID == "" {
		return prepared, errors.New("resource: event ID is required")
	}
	if int64(len(input.Payload)) > service.maxEventPayloadBytes {
		return prepared, errors.New("resource: event payload is too large")
	}
	ref := EventSubscriptionRef{AgentProvider: input.AgentProvider, EventID: input.EventID}
	subscription, err := service.store.Load(ctx, ref)
	if err != nil {
		return prepared, err
	}
	if subscription.AgentProvider != ref.AgentProvider || subscription.EventID != ref.EventID {
		return prepared, errors.New("resource: event store returned a mismatched subscription")
	}
	now := service.clock.Now().UTC().Truncate(time.Second)
	if !subscription.ExpiresAt.IsZero() && !subscription.ExpiresAt.After(now) {
		return prepared, ErrEventSubscriptionExpired
	}
	compact, err := events.MintEventToken(service.issuer, service.signingKey, events.EventTokenRequest{
		Agent: subscription.Agent, EventID: subscription.EventID, Payload: input.Payload, Lifetime: input.Lifetime,
	}, now)
	if err != nil {
		return prepared, err
	}
	return PreparedEvent{
		eventID: subscription.EventID, agentProvider: subscription.AgentProvider,
		agent: subscription.Agent, compact: compact, contentType: input.ContentType,
		payload: append([]byte(nil), input.Payload...), maxUses: subscription.MaxUses,
	}, nil
}

// DeliverEvent performs one explicit delivery attempt. It never retries. The
// signature covers the base components and, when the event carries a body,
// content-type and content-digest.
func (service *EventService) DeliverEvent(ctx context.Context, event PreparedEvent) (EventDeliveryResult, error) {
	var result EventDeliveryResult
	if service == nil {
		return result, errors.New("resource: Events service is required")
	}
	if ctx == nil {
		return result, errors.New("resource: event context is required")
	}
	if event.eventID == "" || event.agentProvider == "" || event.agent == "" || event.compact == "" ||
		len(event.payload) > 0 && event.contentType == "" {
		return result, errors.New("resource: prepared event is invalid")
	}
	subscription, err := service.store.Load(ctx, EventSubscriptionRef{
		AgentProvider: event.agentProvider,
		EventID:       event.eventID,
	})
	if err != nil {
		return result, err
	}
	if subscription.AgentProvider != event.agentProvider || subscription.EventID != event.eventID ||
		subscription.Agent != event.agent || subscription.MaxUses != event.maxUses {
		return result, ErrEventSubscriptionConflict
	}
	now := service.clock.Now().UTC()
	if !subscription.ExpiresAt.IsZero() && !subscription.ExpiresAt.After(now) {
		return result, ErrEventSubscriptionExpired
	}
	endpointValue, err := service.resolveEndpoint.ResolveEventEndpoint(ctx, event.agentProvider)
	if err != nil {
		return result, err
	}
	endpoint, err := parseExactHTTPSEndpoint(endpointValue)
	if err != nil {
		return result, fmt.Errorf("resource: AP event endpoint: %w", err)
	}
	if err := service.admitEndpoint(ctx, endpoint.String()); err != nil {
		return result, fmt.Errorf("resource: event endpoint egress denied: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(event.payload))
	if err != nil {
		return result, err
	}
	// SignSelfJWTRequestWithOptions covers content-digest for a nonempty body.
	var components []string
	if event.contentType != "" {
		request.Header.Set("Content-Type", event.contentType)
		components = []string{"content-type"}
	}
	if err := signaturekey.SignSelfJWTRequestWithOptions(request, service.signingKey, event.compact, service.clock, signaturekey.SignOptions{
		AdditionalComponents: components,
		MaxBodyBytes:         service.maxEventPayloadBytes,
	}); err != nil {
		return result, err
	}
	response, err := service.httpClient.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, defaultEventBodyBytes+1))
	if readErr != nil {
		return result, readErr
	}
	if int64(len(body)) > defaultEventBodyBytes {
		return result, &EventDeliveryError{StatusCode: response.StatusCode, Accepted: response.StatusCode == http.StatusAccepted, Cause: errors.New("response body is too large")}
	}
	if response.StatusCode != http.StatusAccepted {
		return result, &EventDeliveryError{StatusCode: response.StatusCode, Body: append([]byte(nil), body...)}
	}
	result.Limited = event.maxUses > 0
	if event.maxUses == 0 {
		return result, nil
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		return EventDeliveryResult{}, &EventDeliveryError{
			StatusCode: http.StatusAccepted, Accepted: true, Body: append([]byte(nil), body...),
			Cause: errors.New("bounded event feedback must use application/json"),
		}
	}
	var feedback struct {
		RemainingUses *int64 `json:"remaining_uses"`
	}
	if err := jsonstrict.RejectAmbiguousNames(body); err != nil {
		return EventDeliveryResult{}, &EventDeliveryError{
			StatusCode: http.StatusAccepted, Accepted: true, Body: append([]byte(nil), body...), Cause: err,
		}
	}
	if err := jsonstrict.RejectCaseVariants(body, &feedback); err != nil {
		return EventDeliveryResult{}, &EventDeliveryError{
			StatusCode: http.StatusAccepted, Accepted: true, Body: append([]byte(nil), body...), Cause: err,
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	err = decoder.Decode(&feedback)
	var trailing any
	if err == nil {
		if trailingErr := decoder.Decode(&trailing); !errors.Is(trailingErr, io.EOF) {
			err = errors.New("bounded event feedback must contain one JSON value")
		}
	}
	if err != nil || feedback.RemainingUses == nil ||
		*feedback.RemainingUses < 0 || *feedback.RemainingUses >= event.maxUses {
		if err == nil {
			err = errors.New("remaining_uses is required and must be nonnegative and less than the subscription maximum")
		}
		return EventDeliveryResult{}, &EventDeliveryError{
			StatusCode: http.StatusAccepted, Accepted: true, Body: append([]byte(nil), body...), Cause: err,
		}
	}
	result.RemainingUses = *feedback.RemainingUses
	return result, nil
}
