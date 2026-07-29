package reference

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type AccessServerConfig struct {
	Identifier          string
	SigningKey          aauth.SigningKey
	KeyResolver         aauth.KeyResolver
	Clock               aauth.Clock
	NewID               func() string
	TrustedPersonServer func(context.Context, string) error
	// TrustedUpstreamIssuer admits auth-token issuers whose established
	// authorization the access server may extend through call chaining.
	TrustedUpstreamIssuer func(context.Context, string) error
	AuthorizationPolicy   aauth.AuthorizationPolicy
	InteractionRequired   func(context.Context, aauth.AuthorizationRequest) (bool, error)
	Random                io.Reader
	PendingLifetime       time.Duration
}

type AccessServer struct {
	identifier            string
	signingKey            aauth.SigningKey
	keyResolver           aauth.KeyResolver
	clock                 aauth.Clock
	newID                 func() string
	trustedPersonServer   func(context.Context, string) error
	trustedUpstreamIssuer func(context.Context, string) error
	authorizationPolicy   aauth.AuthorizationPolicy
	interactionRequired   func(context.Context, aauth.AuthorizationRequest) (bool, error)
	random                io.Reader
	pendingLifetime       time.Duration

	replayMu      sync.Mutex
	replayedProof map[string]time.Time
	randomMu      sync.Mutex
	pendingMu     sync.Mutex
	pending       map[string]*pendingAccessServerAuthorization
}

type accessServerAuthorizationContext struct {
	request              aauth.AuthorizationRequest
	resourceToken        aauth.ResourceTokenClaims
	targetAgent          string
	targetKey            aauth.JWK
	parentAgent          string
	targetTokenExpiresAt int64
	pollingServer        string
	pollingKeyThumbprint string
}

type pendingAccessServerAuthorization struct {
	pendingInteraction
	context  accessServerAuthorizationContext
	decision aauth.AuthorizationDecision
}

func NewAccessServer(config AccessServerConfig) (*AccessServer, error) {
	if err := aauth.ValidateServerIdentifier(config.Identifier); err != nil {
		return nil, err
	}
	if config.SigningKey.ID() == "" || config.KeyResolver == nil || config.Clock == nil ||
		config.NewID == nil || config.TrustedPersonServer == nil || config.AuthorizationPolicy == nil {
		return nil, errors.New("reference: access server requires key, resolver, clock, id source, trust, and policy")
	}
	pendingLifetime := config.PendingLifetime
	if pendingLifetime == 0 {
		pendingLifetime = 5 * time.Minute
	}
	if pendingLifetime < 0 {
		return nil, errors.New("reference: pending lifetime must not be negative")
	}
	random := config.Random
	if random == nil {
		random = rand.Reader
	}
	return &AccessServer{
		identifier:            config.Identifier,
		signingKey:            config.SigningKey,
		keyResolver:           config.KeyResolver,
		clock:                 config.Clock,
		newID:                 config.NewID,
		trustedPersonServer:   config.TrustedPersonServer,
		trustedUpstreamIssuer: config.TrustedUpstreamIssuer,
		authorizationPolicy:   config.AuthorizationPolicy,
		interactionRequired:   config.InteractionRequired,
		random:                random,
		pendingLifetime:       pendingLifetime,
		replayedProof:         make(map[string]time.Time),
		pending:               make(map[string]*pendingAccessServerAuthorization),
	}, nil
}

func (server *AccessServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", server.handleToken)
	mux.HandleFunc("GET /pending/{id}", server.handlePendingAuthorization)
	mux.HandleFunc("GET /interaction/{id}", server.handleInteraction)
	mux.HandleFunc("GET /.well-known/aauth-access.json", server.handleMetadata)
	mux.HandleFunc("GET /jwks", server.handleJWKS)
	return mux
}

func (server *AccessServer) handleToken(response http.ResponseWriter, request *http.Request) {
	verified, err := aauth.VerifyRequest(request.Context(), request, server.keyResolver, server.clock, aauth.VerifyRequestOptions{
		RequiredComponents:       []string{"content-digest"},
		AllowedSignatureKeyTypes: []string{aauth.SignatureKeyJWKSURI},
	})
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", err)
		return
	}
	if err := server.trustedPersonServer(request.Context(), verified.Signer); err != nil {
		writeProblem(response, http.StatusForbidden, "untrusted_person_server", err)
		return
	}
	if server.seenReplay(verified.ReplayKey, verified.Created.Add(aauth.DefaultSignatureWindow)) {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", errors.New("request proof was replayed"))
		return
	}

	var input struct {
		ResourceToken string `json:"resource_token"`
		AgentToken    string `json:"agent_token"`
		SubagentToken string `json:"subagent_token,omitempty"`
		UpstreamToken string `json:"upstream_token,omitempty"`
	}
	if err := decodeJSON(response, request, &input); err != nil ||
		input.ResourceToken == "" || input.AgentToken == "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	agentToken, err := aauth.VerifyAgentToken(request.Context(), input.AgentToken, server.keyResolver, server.clock)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_agent_token", err)
		return
	}
	if agentToken.ParentAgent != "" {
		writeProblem(response, http.StatusForbidden, "invalid_agent_token", errors.New("sub-agent cannot act as a parent"))
		return
	}
	if agentToken.PersonServer != "" && agentToken.PersonServer != verified.Signer {
		writeProblem(response, http.StatusForbidden, "invalid_agent_token", errors.New("agent token names a different person server"))
		return
	}

	targetAgent := agentToken.Subject
	targetKey := agentToken.Confirmation.JWK
	parentAgent := ""
	targetExpiry := agentToken.ExpiresAt
	if input.SubagentToken != "" {
		subagent, err := aauth.VerifyAgentToken(request.Context(), input.SubagentToken, server.keyResolver, server.clock)
		if err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_subagent_token", err)
			return
		}
		if subagent.ParentAgent != agentToken.Subject {
			writeProblem(response, http.StatusForbidden, "invalid_subagent_token", errors.New("sub-agent token does not name the parent agent"))
			return
		}
		targetAgent = subagent.Subject
		targetKey = subagent.Confirmation.JWK
		parentAgent = agentToken.Subject
		if subagent.ExpiresAt < targetExpiry {
			targetExpiry = subagent.ExpiresAt
		}
	}
	var upstream *aauth.AuthTokenClaims
	if input.UpstreamToken != "" {
		if server.trustedUpstreamIssuer == nil {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("call chaining is not configured"))
			return
		}
		claims, err := aauth.VerifyAuthToken(request.Context(), input.UpstreamToken, server.keyResolver, server.clock)
		if err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_upstream_token", err)
			return
		}
		if err := server.trustedUpstreamIssuer(request.Context(), claims.Issuer); err != nil {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", err)
			return
		}
		// The upstream token's agent and confirmation key identify the
		// upstream caller. The intermediary resource is bound by the
		// token audience and its agent-token issuer.
		if claims.Audience != agentToken.Issuer {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("upstream auth-token audience does not match intermediary issuer"))
			return
		}
		if claims.Mission != nil && claims.Mission.Approver != verified.Signer {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("upstream mission names a different person server"))
			return
		}
		if claims.ExpiresAt < targetExpiry {
			targetExpiry = claims.ExpiresAt
		}
		upstream = &claims
	}

	resourceToken, err := aauth.VerifyResourceToken(request.Context(), input.ResourceToken, server.keyResolver, server.clock)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
		return
	}
	if resourceToken.Audience != server.identifier {
		writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("resource-token audience does not match access server"))
		return
	}
	if resourceToken.Agent != targetAgent {
		writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("resource-token agent does not match authorized agent"))
		return
	}
	thumbprint, err := targetKey.Thumbprint()
	if err != nil || thumbprint != resourceToken.AgentJKT {
		writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("resource-token agent_jkt does not match authorized agent key"))
		return
	}
	if resourceToken.Mission != nil && resourceToken.Mission.Approver != verified.Signer {
		writeProblem(response, http.StatusForbidden, "invalid_mission", errors.New("mission approver does not match person server"))
		return
	}
	if upstream != nil {
		if (upstream.Mission == nil) != (resourceToken.Mission == nil) {
			writeProblem(response, http.StatusForbidden, "invalid_mission", errors.New("downstream and upstream mission presence differs"))
			return
		}
		if upstream.Mission != nil && *upstream.Mission != *resourceToken.Mission {
			writeProblem(response, http.StatusForbidden, "invalid_mission", errors.New("downstream mission does not match upstream authorization"))
			return
		}
	}
	scopes, err := parseScopes(resourceToken.Scope)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
		return
	}
	pollingKeyThumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_key", err)
		return
	}
	authorizationContext := accessServerAuthorizationContext{
		request: aauth.AuthorizationRequest{
			Agent:       targetAgent,
			ParentAgent: parentAgent,
			Resource:    resourceToken.Issuer,
			Scope:       append([]string(nil), scopes...),
			Mission:     resourceToken.Mission,
			Upstream:    upstream,
		},
		resourceToken:        resourceToken,
		targetAgent:          targetAgent,
		targetKey:            targetKey,
		parentAgent:          parentAgent,
		targetTokenExpiresAt: targetExpiry,
		pollingServer:        verified.Signer,
		pollingKeyThumbprint: pollingKeyThumbprint,
	}
	if server.interactionRequired != nil {
		required, err := server.interactionRequired(
			request.Context(),
			copyAuthorizationRequest(authorizationContext.request),
		)
		if err != nil {
			writeProblem(response, http.StatusForbidden, "access_denied", err)
			return
		}
		if required {
			if err := server.beginPendingAuthorization(response, authorizationContext); err != nil {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
			}
			return
		}
	}
	decision, err := server.authorizationPolicy(
		request.Context(),
		copyAuthorizationRequest(authorizationContext.request),
	)
	if err != nil {
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	if err := validateAuthorizationDecision(decision, scopes); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("authorization policy returned an invalid grant"))
		return
	}
	server.completeAuthorization(response, authorizationContext, decision)
}

func (server *AccessServer) completeAuthorization(
	response http.ResponseWriter,
	authorizationContext accessServerAuthorizationContext,
	decision aauth.AuthorizationDecision,
) {
	actor := authorizationActor(
		authorizationContext.request.Upstream,
		authorizationContext.parentAgent,
	)
	now := server.clock.Now()
	expiresAt := now.Add(time.Hour).Unix()
	if authorizationContext.targetTokenExpiresAt < expiresAt {
		expiresAt = authorizationContext.targetTokenExpiresAt
	}
	authToken, err := aauth.MintAuthToken(server.signingKey, aauth.AuthTokenClaims{
		Issuer:       server.identifier,
		DWK:          aauth.AccessDiscoveryDocument,
		Audience:     authorizationContext.resourceToken.Issuer,
		JTI:          server.newID(),
		Agent:        authorizationContext.targetAgent,
		Confirmation: aauth.Confirmation{JWK: authorizationContext.targetKey},
		Actor:        actor,
		IssuedAt:     now.Unix(),
		ExpiresAt:    expiresAt,
		Subject:      decision.Subject,
		Scope:        strings.Join(decision.Scope, " "),
		Mission:      authorizationContext.resourceToken.Mission,
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"auth_token": authToken,
		"expires_in": expiresAt - now.Unix(),
	})
}

func (server *AccessServer) beginPendingAuthorization(
	response http.ResponseWriter,
	authorizationContext accessServerAuthorizationContext,
) error {
	now := server.clock.Now()
	expiresAt := now.Add(server.pendingLifetime)
	for _, tokenExpiry := range []int64{
		authorizationContext.targetTokenExpiresAt,
		authorizationContext.resourceToken.ExpiresAt,
	} {
		candidate := time.Unix(tokenExpiry, 0)
		if candidate.Before(expiresAt) {
			expiresAt = candidate
		}
	}
	if !expiresAt.After(now) {
		return errors.New("reference: authorization credentials expire before interaction can begin")
	}
	server.randomMu.Lock()
	interaction, err := newPendingInteraction(server.random, expiresAt)
	server.randomMu.Unlock()
	if err != nil {
		return err
	}
	pending := &pendingAccessServerAuthorization{
		pendingInteraction: interaction,
		context:            copyAccessServerAuthorizationContext(authorizationContext),
	}
	server.pendingMu.Lock()
	if _, exists := server.pending[interaction.id]; exists {
		server.pendingMu.Unlock()
		return errors.New("reference: pending identifier source returned a duplicate value")
	}
	server.pending[interaction.id] = pending
	server.pendingMu.Unlock()
	return server.writePendingAuthorization(
		response,
		interaction.id,
		pendingAuthorizationWaiting,
		interaction.code,
	)
}

func copyAccessServerAuthorizationContext(
	authorizationContext accessServerAuthorizationContext,
) accessServerAuthorizationContext {
	copied := authorizationContext
	copied.request = copyAuthorizationRequest(authorizationContext.request)
	return copied
}

func (server *AccessServer) writePendingAuthorization(
	response http.ResponseWriter,
	pendingID string,
	state pendingAuthorizationState,
	code string,
) error {
	requirement, err := aauth.FormatRequirementHeader(aauth.Requirement{
		Type:            aauth.RequirementInteraction,
		InteractionURL:  server.identifier + "/interaction/" + pendingID,
		InteractionCode: code,
	})
	if err != nil {
		return err
	}
	response.Header().Set("Location", "/pending/"+pendingID)
	response.Header().Set("Retry-After", "0")
	response.Header().Set("AAuth-Requirement", requirement)
	writeJSON(response, http.StatusAccepted, map[string]string{"status": string(state)})
	return nil
}

// ApproveAuthorization records the access authority's trusted approval after
// code correlation and reevaluates resource policy.
func (server *AccessServer) ApproveAuthorization(ctx context.Context, pendingID string) error {
	server.pendingMu.Lock()
	pending, exists := server.pending[pendingID]
	if !exists {
		server.pendingMu.Unlock()
		return errors.New("reference: pending authorization does not exist")
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		server.pendingMu.Unlock()
		return errors.New("reference: pending authorization expired")
	}
	if pending.state != pendingAuthorizationInteracting {
		server.pendingMu.Unlock()
		return errors.New("reference: pending authorization is not awaiting a trusted decision")
	}
	authorizationRequest := copyAuthorizationRequest(pending.context.request)
	server.pendingMu.Unlock()

	decision, err := server.authorizationPolicy(ctx, authorizationRequest)
	if err != nil {
		return err
	}
	if err := validateAuthorizationDecision(decision, authorizationRequest.Scope); err != nil {
		return err
	}

	server.pendingMu.Lock()
	defer server.pendingMu.Unlock()
	if pending.state != pendingAuthorizationInteracting {
		return errors.New("reference: pending authorization changed while approval was evaluated")
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		return errors.New("reference: pending authorization expired")
	}
	pending.decision = aauth.AuthorizationDecision{
		Subject: decision.Subject,
		Scope:   append([]string(nil), decision.Scope...),
	}
	pending.state = pendingAuthorizationApproved
	return nil
}

// RejectAuthorization records a trusted terminal AS decision.
func (server *AccessServer) RejectAuthorization(
	pendingID string,
	code aauth.PollingErrorCode,
) error {
	if code != aauth.PollingDenied &&
		code != aauth.PollingAbandoned &&
		code != aauth.PollingServerError {
		return errors.New("reference: unsupported authorization rejection code")
	}
	server.pendingMu.Lock()
	defer server.pendingMu.Unlock()
	pending, exists := server.pending[pendingID]
	if !exists {
		return errors.New("reference: pending authorization does not exist")
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		return errors.New("reference: pending authorization expired")
	}
	if pending.state != pendingAuthorizationInteracting {
		return errors.New("reference: pending authorization is not awaiting a trusted decision")
	}
	pending.pollingError = code
	pending.state = pendingAuthorizationRejected
	return nil
}

func (server *AccessServer) handlePendingAuthorization(
	response http.ResponseWriter,
	request *http.Request,
) {
	verified, err := aauth.VerifyRequest(
		request.Context(),
		request,
		server.keyResolver,
		server.clock,
		aauth.VerifyRequestOptions{
			AllowedSignatureKeyTypes: []string{aauth.SignatureKeyJWKSURI},
		},
	)
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", err)
		return
	}
	if err := server.trustedPersonServer(request.Context(), verified.Signer); err != nil {
		writeProblem(response, http.StatusForbidden, "untrusted_person_server", err)
		return
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_key", err)
		return
	}

	server.pendingMu.Lock()
	pending, exists := server.pending[request.PathValue("id")]
	if !exists {
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "gone", errors.New("pending authorization is unknown"))
		return
	}
	if pending.context.pollingServer != verified.Signer ||
		pending.context.pollingKeyThumbprint != thumbprint {
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusForbidden, "invalid_pending", errors.New("pending authorization belongs to a different person-server key"))
		return
	}
	if (pending.state == pendingAuthorizationWaiting ||
		pending.state == pendingAuthorizationInteracting) &&
		!pending.expiresAt.After(server.clock.Now()) {
		pending.state = pendingAuthorizationExpired
	}

	switch pending.state {
	case pendingAuthorizationWaiting, pendingAuthorizationInteracting:
		id := pending.id
		state := pending.state
		code := pending.code
		server.pendingMu.Unlock()
		if err := server.writePendingAuthorization(response, id, state, code); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
	case pendingAuthorizationApproved:
		authorizationContext := copyAccessServerAuthorizationContext(pending.context)
		decision := aauth.AuthorizationDecision{
			Subject: pending.decision.Subject,
			Scope:   append([]string(nil), pending.decision.Scope...),
		}
		pending.state = pendingAuthorizationServed
		server.pendingMu.Unlock()
		server.completeAuthorization(response, authorizationContext, decision)
	case pendingAuthorizationExpired:
		pending.state = pendingAuthorizationServed
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusRequestTimeout, "expired", errors.New("pending authorization expired"))
	case pendingAuthorizationRejected:
		code := pending.pollingError
		pending.state = pendingAuthorizationServed
		server.pendingMu.Unlock()
		status := http.StatusForbidden
		if code == aauth.PollingServerError {
			status = http.StatusInternalServerError
		}
		writeProblem(response, status, string(code), errors.New("pending authorization was not approved"))
	case pendingAuthorizationInvalidCode:
		pending.state = pendingAuthorizationServed
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "invalid_code", errors.New("interaction code validation failed"))
	default:
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "gone", errors.New("pending authorization already returned a terminal response"))
	}
}

func (server *AccessServer) handleInteraction(
	response http.ResponseWriter,
	request *http.Request,
) {
	server.pendingMu.Lock()
	pending, exists := server.pending[request.PathValue("id")]
	if !exists {
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "invalid_code", errors.New("pending interaction is unknown"))
		return
	}
	status, code, err := pending.correlate(
		request.URL.Query()["code"],
		server.clock.Now(),
	)
	if err != nil {
		server.pendingMu.Unlock()
		writeProblem(response, status, code, err)
		return
	}
	authorizationRequest := copyAuthorizationRequest(pending.context.request)
	server.pendingMu.Unlock()

	writeJSON(response, http.StatusOK, map[string]any{
		"status":   "interacting",
		"agent":    authorizationRequest.Agent,
		"resource": authorizationRequest.Resource,
		"scope":    strings.Join(authorizationRequest.Scope, " "),
	})
}

func (server *AccessServer) seenReplay(key string, expiresAt time.Time) bool {
	server.replayMu.Lock()
	defer server.replayMu.Unlock()
	now := server.clock.Now()
	for existing, expiry := range server.replayedProof {
		if !expiry.After(now) {
			delete(server.replayedProof, existing)
		}
	}
	if _, exists := server.replayedProof[key]; exists {
		return true
	}
	server.replayedProof[key] = expiresAt
	return false
}

func (server *AccessServer) handleMetadata(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{
		"issuer":         server.identifier,
		"jwks_uri":       server.identifier + "/jwks",
		"token_endpoint": server.identifier + "/token",
	})
}

func (server *AccessServer) handleJWKS(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{
		"keys": []aauth.JWK{server.signingKey.PublicJWK()},
	})
}
