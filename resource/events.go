package resource

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const defaultEventBodyBytes int64 = 1 << 20

var (
	// ErrEventSubscriptionNotFound reports an unknown event ID.
	ErrEventSubscriptionNotFound = errors.New("resource: event subscription not found")
	// ErrEventSubscriptionExpired reports a Resource-expired subscription.
	ErrEventSubscriptionExpired = errors.New("resource: event subscription expired")
	// ErrEventSubscriptionConflict reports changed registration facts under
	// one Agent-Provider/event-ID pair.
	ErrEventSubscriptionConflict = errors.New("resource: event subscription conflicts with retained state")
	// ErrEventSubscriptionDenied reports local public-registration policy refusal.
	ErrEventSubscriptionDenied = errors.New("resource: event subscription denied")
)

// EventEndpointResolver resolves the AP's current event_endpoint from current
// AP metadata at delivery time.
type EventEndpointResolver interface {
	ResolveEventEndpoint(context.Context, string) (string, error)
}

// EventEndpointResolverFunc adapts a function to EventEndpointResolver.
type EventEndpointResolverFunc func(context.Context, string) (string, error)

// ResolveEventEndpoint calls function.
func (function EventEndpointResolverFunc) ResolveEventEndpoint(ctx context.Context, provider string) (string, error) {
	return function(ctx, provider)
}

// EventServiceConfig composes one Resource's public Events registration and
// explicit outbound-delivery steps. AP metadata acquisition remains behind a
// bounded host-supplied resolver.
type EventServiceConfig struct {
	Issuer               string
	SigningKey           jose.SigningKey
	KeyResolver          signaturekey.KeyResolver
	Clock                aauth.Clock
	SubscriptionEndpoint string
	Store                EventSubscriptionStore
	RegisterPublic       func(context.Context, PublicSubscriptionRequest) (PublicSubscriptionDecision, error)
	Protected            *ProtectedSubscriptionConfig
	ResolveEventEndpoint EventEndpointResolver
	AdmitEventEndpoint   signaturekey.EgressAdmitter
	HTTPClient           *http.Client
	MaxRegistrationBytes int64
	MaxEventPayloadBytes int64
}

// PublicSubscriptionRequest contains the fully verified registration inputs
// available to Resource policy.
type PublicSubscriptionRequest struct {
	Token       events.SubscribeTokenClaims
	Parameters  []byte
	ContentType string
	VerifiedAt  time.Time
}

// PublicSubscriptionDecision supplies the Resource-owned subscription
// lifetime. Zero ExpiresAt means the Resource imposes no time limit.
type PublicSubscriptionDecision struct {
	ExpiresAt time.Time
}

// EventSubscription is one Resource-retained public subscription. ExpiresAt
// is Resource policy, not the subscribe token's registration deadline.
type EventSubscription struct {
	EventID              string
	AgentProvider        string
	Agent                string
	MaxUses              int64
	SubscribeTokenSHA256 [sha256.Size]byte
	RegistrationSHA256   [sha256.Size]byte
	Parameters           []byte
	ContentType          string
	RegisteredAt         time.Time
	ExpiresAt            time.Time
}

// EventSubscriptionRef identifies one subscription at a Resource. Event IDs
// are unique only within their issuing Agent Provider.
type EventSubscriptionRef struct {
	AgentProvider string
	EventID       string
}

// EventSubscriptionStore owns Resource subscription state. Commit must copy
// and atomically retain one first record. RegistrationSHA256 is the stable
// request identity. A repeat with that same digest must return the first
// retained record without replacing its RegisteredAt or Resource-selected
// ExpiresAt; changed registration bytes under one subscription reference return
// ErrEventSubscriptionConflict. Both methods key records by
// (AgentProvider, EventID). Load must return an independent copy or
// ErrEventSubscriptionNotFound.
type EventSubscriptionStore interface {
	Commit(context.Context, EventSubscription) (EventSubscription, error)
	Load(context.Context, EventSubscriptionRef) (EventSubscription, error)
}

// EventInput selects one exact outbound event by its AP-scoped subscription
// reference. Payload is the complete AsyncAPI-defined HTTP body; it is not
// wrapped by this package.
type EventInput struct {
	AgentProvider string
	EventID       string
	ContentType   string
	Payload       []byte
	Lifetime      time.Duration
}

// PreparedEvent is one immutable token, content type, and payload consequence.
// Repeating DeliverEvent with the same value reuses those exact values and
// performs one fresh signed HTTP attempt.
type PreparedEvent struct {
	eventID       string
	agentProvider string
	agent         string
	compact       string
	contentType   string
	payload       []byte
	maxUses       int64
}

// EventDeliveryResult is the AP's accepted delivery feedback.
type EventDeliveryResult struct {
	Limited       bool
	RemainingUses int64
}

// EventDeliveryError preserves one failed HTTP outcome. Accepted is true when
// the AP returned 202 but its required feedback was invalid, so a caller knows
// that repeating the same PreparedEvent is consequence-safe but may be only a
// result-recovery attempt.
type EventDeliveryError struct {
	StatusCode int
	Accepted   bool
	Body       []byte
	Cause      error
}

func (failure *EventDeliveryError) Error() string {
	if failure == nil {
		return "resource: event delivery failed"
	}
	if failure.Cause != nil {
		return fmt.Sprintf("resource: event delivery status %d: %v", failure.StatusCode, failure.Cause)
	}
	return fmt.Sprintf("resource: event delivery status %d", failure.StatusCode)
}

func (failure *EventDeliveryError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

// EventService implements the Events-specific Resource surface without
// changing Core Resource access-mode constructors.
type EventService struct {
	issuer               string
	signingKey           jose.SigningKey
	keyResolver          signaturekey.KeyResolver
	clock                aauth.Clock
	subscriptionEndpoint *url.URL
	store                EventSubscriptionStore
	registerPublic       func(context.Context, PublicSubscriptionRequest) (PublicSubscriptionDecision, error)
	resolveEndpoint      EventEndpointResolver
	admitEndpoint        signaturekey.EgressAdmitter
	httpClient           *http.Client
	maxRegistrationBytes int64
	maxEventPayloadBytes int64
	registrationHandler  http.Handler
	protected            *protectedSubscriptionConfig
	protectedHandler     http.Handler
}

// NewEventService constructs the configured public and optional protected
// Events Resource surfaces.
func NewEventService(config EventServiceConfig) (*EventService, error) {
	if err := aauth.ValidateServerIdentifier(config.Issuer); err != nil {
		return nil, fmt.Errorf("resource: Events issuer: %w", err)
	}
	if config.SigningKey.ID() == "" {
		return nil, errors.New("resource: Events signing key is required")
	}
	if _, err := config.SigningKey.PublicJWK().PublicKey(); err != nil {
		return nil, fmt.Errorf("resource: Events signing key: %w", err)
	}
	if config.KeyResolver == nil || config.Clock == nil || config.Store == nil ||
		config.RegisterPublic == nil || config.ResolveEventEndpoint == nil || config.AdmitEventEndpoint == nil || config.HTTPClient == nil {
		return nil, errors.New("resource: complete Events resolver, clock, store, policy, endpoint resolver, and HTTP client are required")
	}
	endpoint, err := parseExactHTTPSEndpoint(config.SubscriptionEndpoint)
	if err != nil {
		return nil, fmt.Errorf("resource: subscription endpoint: %w", err)
	}
	issuer, _ := url.Parse(config.Issuer)
	if !sameOrigin(endpoint, issuer) {
		return nil, errors.New("resource: subscription endpoint must use the Resource issuer origin")
	}
	if config.MaxRegistrationBytes < 0 || config.MaxEventPayloadBytes < 0 {
		return nil, errors.New("resource: Events body limits must not be negative")
	}
	maxRegistration := config.MaxRegistrationBytes
	if maxRegistration == 0 {
		maxRegistration = defaultEventBodyBytes
	}
	maxPayload := config.MaxEventPayloadBytes
	if maxPayload == 0 {
		maxPayload = defaultEventBodyBytes
	}
	client := *config.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("resource: event delivery redirects are not permitted")
	}
	service := &EventService{
		issuer: config.Issuer, signingKey: config.SigningKey, keyResolver: config.KeyResolver,
		clock: config.Clock, subscriptionEndpoint: endpoint, store: config.Store,
		registerPublic: config.RegisterPublic, resolveEndpoint: config.ResolveEventEndpoint,
		admitEndpoint: config.AdmitEventEndpoint,
		httpClient:    &client, maxRegistrationBytes: maxRegistration, maxEventPayloadBytes: maxPayload,
	}
	service.registrationHandler = http.HandlerFunc(service.handlePublicSubscription)
	if err := service.configureProtectedSubscriptions(config.Protected); err != nil {
		return nil, err
	}
	return service, nil
}

func cloneEventSubscription(record EventSubscription) EventSubscription {
	record.Parameters = append([]byte(nil), record.Parameters...)
	return record
}

func parseExactHTTPSEndpoint(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return nil, errors.New("endpoint must be an absolute HTTPS URL with no user information, query, or fragment")
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed, nil
}

func sameOrigin(left, right *url.URL) bool {
	return left != nil && right != nil && strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}
