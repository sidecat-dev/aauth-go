package reference

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

var ErrUnknownEnrollment = errors.New("reference: unknown enrollment")

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
	DurableKey      aauth.JWK
	RequestKey      aauth.JWK
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
	SigningKey            aauth.SigningKey
	Clock                 aauth.Clock
	NewID                 func() string
	Enrollments           EnrollmentStore
	RefreshPolicy         AgentRefreshPolicy
	RefreshReplays        RefreshReplayStore
	AgentTokenLifetime    time.Duration
	MaxDelegationLifetime time.Duration
}

// AgentProvider publishes issuer discovery, supports direct issuance for
// embedded callers, and serves the informational enrolled-install refresh
// profile when an EnrollmentStore is configured.
type AgentProvider struct {
	identifier            string
	signingKey            aauth.SigningKey
	clock                 aauth.Clock
	newID                 func() string
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
		enrollments:           config.Enrollments,
		refreshPolicy:         config.RefreshPolicy,
		refreshReplays:        refreshReplays,
		agentTokenLifetime:    lifetime,
		maxDelegationLifetime: maxDelegationLifetime,
	}, nil
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
	if provider.enrollments != nil {
		mux.HandleFunc("POST /refresh", provider.refresh)
	}
	mux.HandleFunc("GET /.well-known/aauth-agent.json", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]any{
			"issuer":   provider.identifier,
			"jwks_uri": provider.identifier + "/jwks",
		})
	})
	mux.HandleFunc("GET /jwks", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]any{
			"keys": []aauth.JWK{provider.signingKey.PublicJWK()},
		})
	})
	return mux
}

// BootstrapRefreshRequest selects the person server for the new agent token.
// This AP endpoint is an informational bootstrap profile, not a core AAuth
// protocol message.
type BootstrapRefreshRequest struct {
	PersonServer string `json:"person_server"`
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
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", err)
		return
	}
	if verified.JKTJWT != nil &&
		verified.JKTJWT.ExpiresAt.Sub(verified.JKTJWT.IssuedAt) >
			provider.maxDelegationLifetime {
		writeProblem(
			response,
			http.StatusUnauthorized,
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
	durableThumbprint, err := verified.IdentityKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_key", err)
		return
	}
	enrollment, err := provider.enrollments.LookupEnrollment(request.Context(), durableThumbprint)
	if err != nil {
		if errors.Is(err, ErrUnknownEnrollment) {
			writeProblem(response, http.StatusUnauthorized, "unknown_enrollment", err)
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
			writeProblem(response, http.StatusForbidden, "refresh_denied", err)
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
			writeProblem(response, http.StatusUnauthorized, "invalid_signature", err)
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
