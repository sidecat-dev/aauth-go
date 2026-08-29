package reference

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"net/http"
	"net/url"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

var ErrUnknownEnrollment = errors.New("reference: unknown enrollment")

const bootstrapNonceBytes = 16

// AgentEnrollment is the provider-owned binding from one durable installation
// key to the stable agent identity and person server it may request.
type AgentEnrollment struct {
	Agent        string
	PersonServer string
}

// EnrollmentStore resolves a durable installation key thumbprint without
// imposing a database or account model on the AAuth implementation.
type EnrollmentStore interface {
	LookupEnrollment(ctx context.Context, durableThumbprint string) (AgentEnrollment, error)
}

// StaticEnrollmentStore is an explicit read-only enrollment source for
// embedded deployments and deterministic qualification.
type StaticEnrollmentStore map[string]AgentEnrollment

func (store StaticEnrollmentStore) LookupEnrollment(
	_ context.Context,
	durableThumbprint string,
) (AgentEnrollment, error) {
	enrollment, ok := store[durableThumbprint]
	if !ok {
		return AgentEnrollment{}, ErrUnknownEnrollment
	}
	return enrollment, nil
}

// AgentRefreshEvaluation is the provider policy input after both the durable
// identity proof and delegated HTTP request proof have been verified.
type AgentRefreshEvaluation struct {
	Enrollment      AgentEnrollment
	DurableIdentity string
	DurableKey      jose.JWK
	RequestKey      jose.JWK
	SignatureScheme string
	PersonServer    string
}

type AgentRefreshPolicy func(context.Context, AgentRefreshEvaluation) error

var ErrRefreshProofReplayed = errors.New("reference: refresh request proof was replayed")

// RefreshReplayStore atomically admits a verified request proof until its
// expiry. Deployments may back this with durable or distributed custody.
type RefreshReplayStore interface {
	AdmitRefreshProof(
		ctx context.Context,
		replayKey string,
		expiresAt time.Time,
		now time.Time,
	) error
}

// MemoryRefreshReplayStore is the process-local reference implementation.
type MemoryRefreshReplayStore struct {
	mu      sync.Mutex
	replays map[string]time.Time
}

func NewMemoryRefreshReplayStore() *MemoryRefreshReplayStore {
	return &MemoryRefreshReplayStore{replays: make(map[string]time.Time)}
}

func (store *MemoryRefreshReplayStore) AdmitRefreshProof(
	_ context.Context,
	replayKey string,
	expiresAt time.Time,
	now time.Time,
) error {
	if store == nil {
		return errors.New("reference: refresh replay store is required")
	}
	if replayKey == "" || !expiresAt.After(now) {
		return errors.New("reference: refresh replay proof is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.replays == nil {
		store.replays = make(map[string]time.Time)
	}
	for existing, expiry := range store.replays {
		if !expiry.After(now) {
			delete(store.replays, existing)
		}
	}
	if _, exists := store.replays[replayKey]; exists {
		return ErrRefreshProofReplayed
	}
	store.replays[replayKey] = expiresAt
	return nil
}

type AgentProviderConfig struct {
	Identifier            string
	SigningKey            jose.SigningKey
	Clock                 aauth.Clock
	NewID                 func() string
	Events                *AgentProviderEventsConfig
	Enrollments           EnrollmentStore
	RefreshPolicy         AgentRefreshPolicy
	RefreshReplays        RefreshReplayStore
	AgentTokenLifetime    time.Duration
	MaxDelegationLifetime time.Duration
}

// AgentProviderEventsConfig enables the public Events subscription profile.
// The store and lifetime policy remain deployment-owned authority boundaries.
type AgentProviderEventsConfig struct {
	EventEndpoint           string
	Store                   APEventStore
	KeyResolver             aauth.KeyResolver
	SubscriptionActiveUntil func(context.Context, string, string) (time.Time, error)
	TokenLifetime           time.Duration
}

// EventSubscriptionRequest binds a resource and agent confirmation key to one
// provider-generated event identifier.
type EventSubscriptionRequest struct {
	Resource       string
	Agent          string
	AgentKey       jose.JWK
	ContractDigest string
	OperationID    string
	MessageID      string
}

// AgentProvider publishes issuer discovery, supports direct issuance for
// embedded callers, and serves the informational enrolled-install refresh
// profile when an EnrollmentStore is configured.
type AgentProvider struct {
	identifier            string
	signingKey            jose.SigningKey
	clock                 aauth.Clock
	newID                 func() string
	eventEndpoint         string
	eventEndpointPath     string
	eventStore            APEventStore
	eventKeyResolver      aauth.KeyResolver
	eventActiveUntil      func(context.Context, string, string) (time.Time, error)
	eventTokenLifetime    time.Duration
	enrollments           EnrollmentStore
	refreshPolicy         AgentRefreshPolicy
	refreshReplays        RefreshReplayStore
	agentTokenLifetime    time.Duration
	maxDelegationLifetime time.Duration
}

func NewAgentProvider(config AgentProviderConfig) (*AgentProvider, error) {
	if err := aauth.ValidateServerIdentifier(config.Identifier); err != nil {
		return nil, err
	}
	if config.SigningKey.ID() == "" {
		return nil, errors.New("reference: agent provider signing key is required")
	}
	if config.Clock == nil {
		return nil, errors.New("reference: agent provider clock is required")
	}
	if config.NewID == nil {
		return nil, errors.New("reference: agent provider identifier source is required")
	}
	var eventEndpoint string
	var eventEndpointPath string
	var eventStore APEventStore
	var eventKeyResolver aauth.KeyResolver
	var eventActiveUntil func(context.Context, string, string) (time.Time, error)
	var eventTokenLifetime time.Duration
	if config.Events != nil {
		if err := aauth.ValidateEndpoint(config.Events.EventEndpoint); err != nil {
			return nil, fmt.Errorf("reference: agent provider event endpoint: %w", err)
		}
		if config.Events.Store == nil {
			return nil, errors.New("reference: agent provider event store is required")
		}
		if config.Events.KeyResolver == nil {
			return nil, errors.New("reference: agent provider event key resolver is required")
		}
		if config.Events.SubscriptionActiveUntil == nil {
			return nil, errors.New("reference: agent provider event active-until policy is required")
		}
		if config.Events.TokenLifetime <= 0 {
			return nil, errors.New("reference: agent provider event token lifetime must be positive")
		}
		eventEndpoint = config.Events.EventEndpoint
		parsedEventEndpoint, err := url.Parse(eventEndpoint)
		if err != nil || parsedEventEndpoint.Path == "" || parsedEventEndpoint.Path == "/" {
			return nil, errors.New("reference: agent provider event endpoint requires a non-root path")
		}
		eventEndpointPath = parsedEventEndpoint.Path
		eventStore = config.Events.Store
		eventKeyResolver = config.Events.KeyResolver
		eventActiveUntil = config.Events.SubscriptionActiveUntil
		eventTokenLifetime = config.Events.TokenLifetime
	}
	lifetime := config.AgentTokenLifetime
	if lifetime == 0 {
		lifetime = time.Hour
	}
	if lifetime <= 0 || lifetime > 24*time.Hour {
		return nil, errors.New("reference: agent-token lifetime must be between zero and 24 hours")
	}
	maxDelegationLifetime := config.MaxDelegationLifetime
	if maxDelegationLifetime == 0 {
		maxDelegationLifetime = 5 * time.Minute
	}
	if maxDelegationLifetime <= 0 {
		return nil, errors.New("reference: maximum bootstrap delegation lifetime must be positive")
	}
	refreshReplays := config.RefreshReplays
	if refreshReplays == nil {
		refreshReplays = NewMemoryRefreshReplayStore()
	}
	return &AgentProvider{
		identifier:            config.Identifier,
		signingKey:            config.SigningKey,
		clock:                 config.Clock,
		newID:                 config.NewID,
		eventEndpoint:         eventEndpoint,
		eventEndpointPath:     eventEndpointPath,
		eventStore:            eventStore,
		eventKeyResolver:      eventKeyResolver,
		eventActiveUntil:      eventActiveUntil,
		eventTokenLifetime:    eventTokenLifetime,
		enrollments:           config.Enrollments,
		refreshPolicy:         config.RefreshPolicy,
		refreshReplays:        refreshReplays,
		agentTokenLifetime:    lifetime,
		maxDelegationLifetime: maxDelegationLifetime,
	}, nil
}

// IssueEventSubscription commits the AP authority before returning the exact
// single-shot public registration credential to its caller.
func (provider *AgentProvider) IssueEventSubscription(
	ctx context.Context,
	request EventSubscriptionRequest,
) (string, error) {
	if provider == nil || provider.eventStore == nil {
		return "", errors.New("reference: agent provider Events is not configured")
	}
	if err := aauth.ValidateServerIdentifier(request.Resource); err != nil {
		return "", fmt.Errorf("reference: event subscription resource: %w", err)
	}
	if err := aauth.ValidateAgentIdentifier(request.Agent); err != nil {
		return "", fmt.Errorf("reference: event subscription agent: %w", err)
	}
	if _, err := request.AgentKey.PublicKey(); err != nil {
		return "", fmt.Errorf("reference: event subscription agent key: %w", err)
	}
	if err := validateEventContractBinding(request.ContractDigest, request.OperationID, request.MessageID); err != nil {
		return "", err
	}
	eventID := provider.newID()
	if eventID == "" {
		return "", errors.New("reference: event subscription identifier source returned an empty value")
	}
	now := provider.clock.Now()
	activeUntil, err := provider.eventActiveUntil(ctx, request.Resource, request.Agent)
	if err != nil {
		return "", fmt.Errorf("reference: event subscription active-until policy: %w", err)
	}
	if !activeUntil.After(now) {
		return "", errors.New("reference: event subscription active-until must be in the future")
	}
	maxUses := 1
	compact, err := aauth.MintSubscribeToken(provider.signingKey, aauth.SubscribeTokenClaims{
		Issuer:       provider.identifier,
		DWK:          aauth.AgentDiscoveryDocument,
		Subject:      request.Agent,
		Audience:     request.Resource,
		Confirmation: aauth.Confirmation{JWK: request.AgentKey},
		EventID:      eventID,
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(provider.eventTokenLifetime).Unix(),
		MaxUses:      &maxUses,
	})
	if err != nil {
		return "", err
	}
	if err := provider.eventStore.CreateSubscription(ctx, APEventSubscription{
		APIssuer:       provider.identifier,
		EventID:        eventID,
		Resource:       request.Resource,
		Agent:          request.Agent,
		ActiveUntil:    activeUntil,
		MaxUses:        maxUses,
		ContractDigest: request.ContractDigest,
		OperationID:    request.OperationID,
		MessageID:      request.MessageID,
	}); err != nil {
		return "", err
	}
	return compact, nil
}

func (provider *AgentProvider) IssueAgentToken(request aauth.AgentTokenRequest) (string, error) {
	return aauth.MintAgentToken(
		provider.identifier,
		provider.signingKey,
		request,
		provider.clock.Now(),
		provider.newID(),
	)
}

func (provider *AgentProvider) Handler() http.Handler {
	mux := http.NewServeMux()
	if provider.eventEndpointPath != "" {
		mux.HandleFunc("POST "+provider.eventEndpointPath, provider.acceptEvent)
	}
	if provider.enrollments != nil {
		mux.HandleFunc("POST /refresh", provider.refresh)
	}
	mux.HandleFunc("GET /.well-known/aauth-agent.json", func(response http.ResponseWriter, _ *http.Request) {
		metadata := map[string]any{
			"issuer":   provider.identifier,
			"jwks_uri": provider.identifier + "/jwks",
		}
		if provider.eventEndpoint != "" {
			metadata["event_endpoint"] = provider.eventEndpoint
		}
		writeJSON(response, http.StatusOK, metadata)
	})
	mux.HandleFunc("GET /jwks", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]any{
			"keys": []jose.JWK{provider.signingKey.PublicJWK()},
		})
	})
	return mux
}

const referenceEventTokenLifetime = 5 * time.Minute

func (provider *AgentProvider) acceptEvent(response http.ResponseWriter, request *http.Request) {
	hasBody := request.ContentLength != 0 || len(request.TransferEncoding) != 0 ||
		(request.Body != nil && request.Body != http.NoBody)
	var exactPayload []byte
	var payloadDigest string
	var err error
	var requiredComponents []string
	if hasBody {
		exactPayload, err = readBoundedRequestBody(request)
		if err != nil {
			writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", err)
			return
		}
		if len(exactPayload) > maxEventPayloadBody {
			writeProblem(response, http.StatusRequestEntityTooLarge, "request_too_large", errors.New("reference: event payload exceeds the supported bound"))
			return
		}
		requiredComponents = []string{"content-type", "content-digest"}
		payloadDigest = eventPayloadDigest(exactPayload)
	}
	var claims aauth.EventTokenClaims
	verified, err := aauth.VerifyRequest(
		request.Context(),
		request,
		provider.eventKeyResolver,
		provider.clock,
		aauth.VerifyRequestOptions{
			RequiredComponents:       requiredComponents,
			AllowedCredentialTypes:   []string{aauth.EventTokenType},
			AllowedSignatureKeyTypes: []string{aauth.SignatureKeySelfJWT},
			SelfJWTMaximumLifetime:   referenceEventTokenLifetime,
			SelfJWTClaimPolicy: func(verified aauth.VerifiedSelfJWT) error {
				decoded, decodeErr := aauth.DecodeVerifiedEventToken(verified, provider.clock)
				if decodeErr == nil {
					claims = decoded
				}
				return decodeErr
			},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	if verified.SelfJWT == nil || verified.RawCredential == "" || verified.Signer != claims.Issuer {
		writeSignatureFailure(response, errors.New("reference: verified event proof is incomplete"))
		return
	}
	if hasBody && (len(exactPayload) == 0 || request.Header.Get("Content-Type") != "application/json" || validateEventJSON(exactPayload) != nil) {
		writeProblem(response, http.StatusBadRequest, "invalid_payload", errors.New("reference: event payload must be one application/json value"))
		return
	}
	_, remaining, err := provider.eventStore.AcceptEvent(request.Context(), AcceptedEventInput{
		Resource: claims.Issuer, Agent: claims.Audience, EventID: claims.EventID,
		Token: verified.RawCredential, ContentType: request.Header.Get("Content-Type"),
		Payload: exactPayload, PayloadDigest: payloadDigest,
		AcceptedAt: provider.clock.Now(),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrEventPayloadNotAllowed):
			writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("event payload is not allowed"))
		case errors.Is(err, ErrEventSubscriptionMismatch):
			writeProblem(response, http.StatusForbidden, "subscription_mismatch", errors.New("event subscription does not match the request"))
		case errors.Is(err, ErrEventSubscriptionNotFound):
			writeProblem(response, http.StatusNotFound, "subscription_not_found", errors.New("event subscription was not found"))
		case errors.Is(err, ErrEventSubscriptionExhausted):
			writeProblem(response, http.StatusTooManyRequests, "subscription_exhausted", errors.New("event subscription has no remaining uses"))
		default:
			writeProblem(response, http.StatusInternalServerError, "server_error", nil)
		}
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]int{"remaining_uses": remaining})
}

// BootstrapRefreshRequest selects the person server for the new agent token.
// This AP endpoint is an informational bootstrap profile, not a core AAuth
// protocol message.
type BootstrapRefreshRequest struct {
	PersonServer string `json:"person_server"`
	Nonce        string `json:"nonce"`
}

type bootstrapRefreshResponse struct {
	Agent      string `json:"agent"`
	AgentToken string `json:"agent_token"`
}

func (provider *AgentProvider) refresh(response http.ResponseWriter, request *http.Request) {
	verified, err := aauth.VerifyRequest(
		request.Context(),
		request,
		nil,
		provider.clock,
		aauth.VerifyRequestOptions{
			RequiredComponents: []string{"content-digest"},
			AllowedSignatureKeyTypes: []string{
				aauth.SignatureKeyHWK,
				aauth.SignatureKeyJKTJWT,
			},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	if verified.JKTJWT != nil &&
		verified.JKTJWT.ExpiresAt.Sub(verified.JKTJWT.IssuedAt) >
			provider.maxDelegationLifetime {
		writeProblem(
			response,
			http.StatusForbidden,
			"delegation_too_long",
			errors.New("reference: jkt-jwt delegation lifetime exceeds provider policy"),
		)
		return
	}
	var refresh BootstrapRefreshRequest
	if err := decodeJSON(response, request, &refresh); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := aauth.ValidateServerIdentifier(refresh.PersonServer); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	nonce, err := base64.RawURLEncoding.DecodeString(refresh.Nonce)
	if err != nil || len(nonce) != bootstrapNonceBytes ||
		base64.RawURLEncoding.EncodeToString(nonce) != refresh.Nonce {
		writeProblem(
			response,
			http.StatusBadRequest,
			"invalid_request",
			errors.New("reference: bootstrap request nonce is invalid"),
		)
		return
	}
	durableThumbprint, err := verified.IdentityKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", nil)
		return
	}
	enrollment, err := provider.enrollments.LookupEnrollment(request.Context(), durableThumbprint)
	if err != nil {
		if errors.Is(err, ErrUnknownEnrollment) {
			writeProblem(response, http.StatusForbidden, "unknown_enrollment", errors.New("the durable identity is not enrolled"))
			return
		}
		writeProblem(response, http.StatusInternalServerError, "enrollment_lookup_failed", err)
		return
	}
	if err := aauth.ValidateAgentIdentifier(enrollment.Agent); err != nil {
		writeProblem(response, http.StatusInternalServerError, "invalid_enrollment", err)
		return
	}
	if err := aauth.ValidateServerIdentifier(enrollment.PersonServer); err != nil {
		writeProblem(response, http.StatusInternalServerError, "invalid_enrollment", err)
		return
	}
	if refresh.PersonServer != enrollment.PersonServer {
		writeProblem(
			response,
			http.StatusForbidden,
			"person_server_not_allowed",
			errors.New("reference: requested person server is not enrolled"),
		)
		return
	}
	evaluation := AgentRefreshEvaluation{
		Enrollment:      enrollment,
		DurableIdentity: verified.Signer,
		DurableKey:      verified.IdentityKey,
		RequestKey:      verified.PublicKey,
		SignatureScheme: verified.SignatureKeyType,
		PersonServer:    refresh.PersonServer,
	}
	if provider.refreshPolicy != nil {
		if err := provider.refreshPolicy(request.Context(), evaluation); err != nil {
			writeHostPolicyRefusal(response, "refresh_denied", "agent refresh policy denied the request")
			return
		}
	}
	replayExpiresAt := verified.Created.Add(aauth.DefaultSignatureWindow + time.Nanosecond)
	if verified.JKTJWT != nil && verified.JKTJWT.ExpiresAt.Before(replayExpiresAt) {
		replayExpiresAt = verified.JKTJWT.ExpiresAt
	}
	if err := provider.refreshReplays.AdmitRefreshProof(
		request.Context(),
		verified.ReplayKey,
		replayExpiresAt,
		provider.clock.Now(),
	); err != nil {
		if errors.Is(err, ErrRefreshProofReplayed) {
			writeSignatureFailure(response, err)
			return
		}
		writeProblem(response, http.StatusInternalServerError, "replay_custody_failed", err)
		return
	}
	token, err := provider.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        enrollment.Agent,
		PersonServer: refresh.PersonServer,
		PublicKey:    verified.PublicKey,
		Lifetime:     provider.agentTokenLifetime,
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "token_issuance_failed", err)
		return
	}
	writeJSON(response, http.StatusOK, bootstrapRefreshResponse{
		Agent:      enrollment.Agent,
		AgentToken: token,
	})
}
