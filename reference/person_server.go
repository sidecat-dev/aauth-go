package reference

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type PersonServerConfig struct {
	Identifier            string
	SigningKey            aauth.SigningKey
	KeyResolver           aauth.KeyResolver
	Clock                 aauth.Clock
	NewID                 func() string
	MissionPolicy         aauth.MissionPolicy
	AuthorizationPolicy   aauth.AuthorizationPolicy
	InteractionRequired   func(context.Context, aauth.AuthorizationRequest) (bool, error)
	Random                io.Reader
	PendingLifetime       time.Duration
	FederationClient      *http.Client
	AccessServerEndpoint  func(context.Context, string) (string, error)
	TrustedUpstreamIssuer func(context.Context, string) error
}

type PersonServer struct {
	identifier            string
	signingKey            aauth.SigningKey
	keyResolver           aauth.KeyResolver
	clock                 aauth.Clock
	newID                 func() string
	missionPolicy         aauth.MissionPolicy
	authorizationPolicy   aauth.AuthorizationPolicy
	interactionRequired   func(context.Context, aauth.AuthorizationRequest) (bool, error)
	random                io.Reader
	pendingLifetime       time.Duration
	federationClient      *http.Client
	accessServerEndpoint  func(context.Context, string) (string, error)
	trustedUpstreamIssuer func(context.Context, string) error

	mu            sync.RWMutex
	missions      map[string]storedMission
	randomMu      sync.Mutex
	pendingMu     sync.Mutex
	pending       map[string]*pendingPersonAuthorization
	replayMu      sync.Mutex
	replayedProof map[string]time.Time
}

type storedMission struct {
	agent  string
	bytes  []byte
	active bool
}

type missionBlob struct {
	Approver      string       `json:"approver"`
	Agent         string       `json:"agent"`
	ApprovedAt    string       `json:"approved_at"`
	Description   string       `json:"description"`
	ApprovedTools []aauth.Tool `json:"approved_tools,omitempty"`
	Capabilities  []string     `json:"capabilities,omitempty"`
}

type personAuthorizationContext struct {
	request                aauth.AuthorizationRequest
	resourceTokenCompact   string
	agentTokenCompact      string
	subagentTokenCompact   string
	targetAgent            string
	targetKey              aauth.JWK
	parentAgent            string
	pollingAgent           string
	pollingAgentThumbprint string
	targetTokenExpiresAt   int64
	resourceToken          aauth.ResourceTokenClaims
}

type pendingPersonAuthorization struct {
	pendingInteraction
	context           personAuthorizationContext
	decision          aauth.AuthorizationDecision
	federated         *pendingFederatedAuthorization
	pollingFederation bool
}

type pendingFederatedAuthorization struct {
	accessServer string
	location     string
	retryAfter   time.Duration
	notBefore    time.Time
	status       string
	requirement  *aauth.Requirement
}

type accessServerExchange struct {
	authToken string
	claims    aauth.AuthTokenClaims
	deferred  *aauth.DeferredResponse
}

func NewPersonServer(config PersonServerConfig) (*PersonServer, error) {
	if err := aauth.ValidateServerIdentifier(config.Identifier); err != nil {
		return nil, err
	}
	if config.SigningKey.ID() == "" || config.KeyResolver == nil || config.Clock == nil ||
		config.NewID == nil || config.MissionPolicy == nil || config.AuthorizationPolicy == nil {
		return nil, errors.New("reference: person server requires key, resolver, clock, id source, and policies")
	}
	if (config.FederationClient == nil) != (config.AccessServerEndpoint == nil) {
		return nil, errors.New("reference: federation client and access-server endpoint resolver must be configured together")
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
	return &PersonServer{
		identifier:            config.Identifier,
		signingKey:            config.SigningKey,
		keyResolver:           config.KeyResolver,
		clock:                 config.Clock,
		newID:                 config.NewID,
		missionPolicy:         config.MissionPolicy,
		authorizationPolicy:   config.AuthorizationPolicy,
		interactionRequired:   config.InteractionRequired,
		random:                random,
		pendingLifetime:       pendingLifetime,
		federationClient:      config.FederationClient,
		accessServerEndpoint:  config.AccessServerEndpoint,
		trustedUpstreamIssuer: config.TrustedUpstreamIssuer,
		missions:              make(map[string]storedMission),
		pending:               make(map[string]*pendingPersonAuthorization),
		replayedProof:         make(map[string]time.Time),
	}, nil
}

func (server *PersonServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mission", server.handleMission)
	mux.HandleFunc("POST /token", server.handleToken)
	mux.HandleFunc("GET /pending/{id}", server.handlePendingAuthorization)
	mux.HandleFunc("GET /interaction/{id}", server.handleInteraction)
	mux.HandleFunc("GET /.well-known/aauth-person.json", server.handleMetadata)
	mux.HandleFunc("GET /jwks", server.handleJWKS)
	return mux
}

func (server *PersonServer) handleMission(response http.ResponseWriter, request *http.Request) {
	verified, err := aauth.VerifyRequest(request.Context(), request, server.keyResolver, server.clock, aauth.VerifyRequestOptions{
		RequiredComponents:     []string{"content-digest"},
		AllowedCredentialTypes: []string{aauth.AgentTokenType},
	})
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", err)
		return
	}
	var proposal aauth.MissionProposal
	if err := decodeJSON(response, request, &proposal); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if strings.TrimSpace(proposal.Description) == "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("mission description is required"))
		return
	}
	decision, err := server.missionPolicy(request.Context(), proposal)
	if err != nil {
		writeProblem(response, http.StatusForbidden, "mission_denied", err)
		return
	}
	if strings.TrimSpace(decision.Description) == "" {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("mission policy returned an empty description"))
		return
	}
	blob, err := json.Marshal(missionBlob{
		Approver:      server.identifier,
		Agent:         verified.Agent,
		ApprovedAt:    server.clock.Now().UTC().Format(time.RFC3339Nano),
		Description:   decision.Description,
		ApprovedTools: append([]aauth.Tool(nil), decision.Tools...),
		Capabilities:  append([]string(nil), decision.Capabilities...),
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	reference := aauth.MissionReference{
		Approver: server.identifier,
		S256:     aauth.S256(blob),
	}
	header, err := reference.Header()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	server.mu.Lock()
	server.missions[reference.S256] = storedMission{
		agent:  verified.Agent,
		bytes:  append([]byte(nil), blob...),
		active: true,
	}
	server.mu.Unlock()

	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("AAuth-Mission", header)
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(blob)
}

func (server *PersonServer) handleToken(response http.ResponseWriter, request *http.Request) {
	verified, err := aauth.VerifyRequest(request.Context(), request, server.keyResolver, server.clock, aauth.VerifyRequestOptions{
		RequiredComponents:     []string{"content-digest"},
		AllowedCredentialTypes: []string{aauth.AgentTokenType},
	})
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", err)
		return
	}
	if server.seenReplay(verified.ReplayKey, verified.Created.Add(aauth.DefaultSignatureWindow)) {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", errors.New("request proof was replayed"))
		return
	}
	var input struct {
		ResourceToken string `json:"resource_token"`
		SubagentToken string `json:"subagent_token,omitempty"`
		UpstreamToken string `json:"upstream_token,omitempty"`
		Justification string `json:"justification,omitempty"`
	}
	if err := decodeJSON(response, request, &input); err != nil || input.ResourceToken == "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if verified.AgentToken.ParentAgent != "" {
		writeProblem(response, http.StatusForbidden, "invalid_agent", errors.New("sub-agent cannot request authorization directly"))
		return
	}
	if input.SubagentToken != "" && input.UpstreamToken != "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("subagent_token and upstream_token cannot be combined"))
		return
	}

	targetAgent := verified.Agent
	targetKey := verified.PublicKey
	parentAgent := ""
	targetTokenExpiry := verified.AgentToken.ExpiresAt
	if input.SubagentToken != "" {
		subagent, err := aauth.VerifyAgentToken(request.Context(), input.SubagentToken, server.keyResolver, server.clock)
		if err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_subagent_token", err)
			return
		}
		if subagent.ParentAgent == "" || subagent.ParentAgent != verified.Agent {
			writeProblem(response, http.StatusForbidden, "invalid_subagent_token", errors.New("sub-agent token does not name the signing parent"))
			return
		}
		if subagent.PersonServer != "" && subagent.PersonServer != server.identifier {
			writeProblem(response, http.StatusForbidden, "invalid_subagent_token", errors.New("sub-agent token names a different person server"))
			return
		}
		targetAgent = subagent.Subject
		targetKey = subagent.Confirmation.JWK
		parentAgent = verified.Agent
		if subagent.ExpiresAt < targetTokenExpiry {
			targetTokenExpiry = subagent.ExpiresAt
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
		if claims.Audience != verified.AgentToken.Issuer {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("upstream auth-token audience does not match intermediary issuer"))
			return
		}
		if claims.Mission != nil {
			if claims.Mission.Approver != server.identifier {
				writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("upstream mission names a different person server"))
				return
			}
		} else if claims.Issuer != server.identifier {
			writeProblem(response, http.StatusForbidden, "invalid_upstream_token", errors.New("missionless upstream token must route to its issuer"))
			return
		}
		upstream = &claims
	}

	resourceToken, err := aauth.VerifyResourceToken(request.Context(), input.ResourceToken, server.keyResolver, server.clock)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
		return
	}
	if resourceToken.Audience != server.identifier {
		if server.federationClient == nil || server.accessServerEndpoint == nil {
			writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("resource-token audience requires an unconfigured access server"))
			return
		}
		if err := aauth.ValidateServerIdentifier(resourceToken.Audience); err != nil {
			writeProblem(response, http.StatusForbidden, "invalid_resource_token", err)
			return
		}
	}
	if resourceToken.Agent != targetAgent {
		writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("resource-token agent does not match requester"))
		return
	}
	thumbprint, err := targetKey.Thumbprint()
	if err != nil || thumbprint != resourceToken.AgentJKT {
		writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("resource-token agent_jkt does not match authorized agent key"))
		return
	}

	scopes, err := parseScopes(resourceToken.Scope)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
		return
	}
	if upstream != nil {
		if (upstream.Mission == nil) != (resourceToken.Mission == nil) {
			writeProblem(response, http.StatusForbidden, "invalid_mission", errors.New("downstream and upstream mission presence differs"))
			return
		}
	}
	if resourceToken.Mission != nil {
		if resourceToken.Mission.Approver != server.identifier {
			writeProblem(response, http.StatusForbidden, "invalid_mission", errors.New("mission approver does not match person server"))
			return
		}
		server.mu.RLock()
		mission, exists := server.missions[resourceToken.Mission.S256]
		server.mu.RUnlock()
		missionOwner := verified.Agent
		if upstream != nil {
			missionOwner = upstream.Agent
			if upstream.Mission == nil || *upstream.Mission != *resourceToken.Mission {
				writeProblem(response, http.StatusForbidden, "invalid_mission", errors.New("downstream mission does not match upstream authorization"))
				return
			}
		}
		if !exists || !mission.active || mission.agent != missionOwner ||
			aauth.S256(mission.bytes) != resourceToken.Mission.S256 {
			writeProblem(response, http.StatusForbidden, "invalid_mission", errors.New("mission is absent, inactive, or bound to a different agent"))
			return
		}
	}

	pollingAgentThumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_key", err)
		return
	}
	authorizationContext := personAuthorizationContext{
		request: aauth.AuthorizationRequest{
			Agent:         targetAgent,
			ParentAgent:   parentAgent,
			Resource:      resourceToken.Issuer,
			Scope:         append([]string(nil), scopes...),
			Mission:       resourceToken.Mission,
			Justification: input.Justification,
			Upstream:      upstream,
		},
		resourceTokenCompact:   input.ResourceToken,
		agentTokenCompact:      verified.RawCredential,
		subagentTokenCompact:   input.SubagentToken,
		targetAgent:            targetAgent,
		targetKey:              targetKey,
		parentAgent:            parentAgent,
		pollingAgent:           verified.Agent,
		pollingAgentThumbprint: pollingAgentThumbprint,
		targetTokenExpiresAt:   targetTokenExpiry,
		resourceToken:          resourceToken,
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

	decision, err := server.authorizationPolicy(request.Context(), authorizationContext.request)
	if err != nil {
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	if err := validatePersonAuthorizationDecision(decision, scopes); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("authorization policy returned an invalid grant"))
		return
	}
	server.completeAuthorization(response, request.Context(), authorizationContext, decision)
}

func (server *PersonServer) completeAuthorization(
	response http.ResponseWriter,
	ctx context.Context,
	authorizationContext personAuthorizationContext,
	decision aauth.AuthorizationDecision,
) {
	resourceToken := authorizationContext.resourceToken
	now := server.clock.Now()
	if resourceToken.Audience != server.identifier {
		if authorizationContext.request.Upstream != nil {
			writeProblem(response, http.StatusNotImplemented, "federation_failed", errors.New("four-party call chaining is not yet implemented"))
			return
		}
		exchange, err := server.exchangeWithAccessServer(
			ctx,
			resourceToken.Audience,
			authorizationContext.resourceTokenCompact,
			authorizationContext.agentTokenCompact,
			authorizationContext.subagentTokenCompact,
			authorizationContext.targetAgent,
			authorizationContext.targetKey,
			authorizationContext.parentAgent,
			resourceToken,
			decision,
		)
		if err != nil {
			writeProblem(response, http.StatusBadGateway, "federation_failed", err)
			return
		}
		if exchange.deferred != nil {
			if err := server.beginFederatedAuthorization(
				response,
				authorizationContext,
				decision,
				resourceToken.Audience,
				*exchange.deferred,
			); err != nil {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
			}
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{
			"auth_token": exchange.authToken,
			"expires_in": exchange.claims.ExpiresAt - now.Unix(),
		})
		return
	}

	expiresAt := now.Add(time.Hour).Unix()
	if authorizationContext.targetTokenExpiresAt < expiresAt {
		expiresAt = authorizationContext.targetTokenExpiresAt
	}
	var actor *aauth.Actor
	if authorizationContext.request.Upstream != nil {
		actor = &aauth.Actor{
			Agent: authorizationContext.pollingAgent,
			Actor: authorizationContext.request.Upstream.Actor,
		}
	} else if authorizationContext.parentAgent != "" {
		actor = &aauth.Actor{Agent: authorizationContext.parentAgent}
	}
	authToken, err := aauth.MintAuthToken(server.signingKey, aauth.AuthTokenClaims{
		Issuer:       server.identifier,
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     resourceToken.Issuer,
		JTI:          server.newID(),
		Agent:        authorizationContext.targetAgent,
		Confirmation: aauth.Confirmation{JWK: authorizationContext.targetKey},
		Actor:        actor,
		IssuedAt:     now.Unix(),
		ExpiresAt:    expiresAt,
		Subject:      decision.Subject,
		Scope:        strings.Join(decision.Scope, " "),
		Mission:      resourceToken.Mission,
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

func (server *PersonServer) beginPendingAuthorization(
	response http.ResponseWriter,
	authorizationContext personAuthorizationContext,
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
	pending := &pendingPersonAuthorization{
		pendingInteraction: interaction,
		context:            copyPersonAuthorizationContext(authorizationContext),
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

func (server *PersonServer) beginFederatedAuthorization(
	response http.ResponseWriter,
	authorizationContext personAuthorizationContext,
	decision aauth.AuthorizationDecision,
	accessServer string,
	deferred aauth.DeferredResponse,
) error {
	server.randomMu.Lock()
	pendingID, err := aauth.GeneratePendingID(server.random)
	server.randomMu.Unlock()
	if err != nil {
		return err
	}
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
		return errors.New("reference: authorization credentials expire before federation can complete")
	}
	state := pendingAuthorizationWaiting
	if deferred.Status == "interacting" {
		state = pendingAuthorizationInteracting
	}
	federated := &pendingFederatedAuthorization{
		accessServer: accessServer,
		location:     deferred.Location,
		retryAfter:   deferred.RetryAfter,
		notBefore:    now.Add(deferred.RetryAfter),
		status:       deferred.Status,
		requirement:  copyRequirement(deferred.Requirement),
	}
	pending := &pendingPersonAuthorization{
		pendingInteraction: pendingInteraction{
			id:        pendingID,
			state:     state,
			expiresAt: expiresAt,
		},
		context: copyPersonAuthorizationContext(authorizationContext),
		decision: aauth.AuthorizationDecision{
			Subject: decision.Subject,
			Scope:   append([]string(nil), decision.Scope...),
		},
		federated: federated,
	}
	server.pendingMu.Lock()
	if _, exists := server.pending[pendingID]; exists {
		server.pendingMu.Unlock()
		return errors.New("reference: pending identifier source returned a duplicate value")
	}
	server.pending[pendingID] = pending
	server.pendingMu.Unlock()
	return server.writeFederatedPendingAuthorization(response, pendingID, federated, now)
}

func copyRequirement(requirement *aauth.Requirement) *aauth.Requirement {
	if requirement == nil {
		return nil
	}
	copied := *requirement
	return &copied
}

func (server *PersonServer) writeFederatedPendingAuthorization(
	response http.ResponseWriter,
	pendingID string,
	federated *pendingFederatedAuthorization,
	now time.Time,
) error {
	if federated == nil {
		return errors.New("reference: federated pending authorization is required")
	}
	delay := federated.retryAfter
	if federated.notBefore.After(now) {
		delay = federated.notBefore.Sub(now)
	}
	response.Header().Set("Location", "/pending/"+pendingID)
	response.Header().Set("Retry-After", fmt.Sprintf("%d", durationSecondsCeil(delay)))
	if federated.requirement != nil {
		requirement, err := aauth.FormatRequirementHeader(*federated.requirement)
		if err != nil {
			return err
		}
		response.Header().Set("AAuth-Requirement", requirement)
	}
	writeJSON(response, http.StatusAccepted, map[string]string{"status": federated.status})
	return nil
}

func durationSecondsCeil(duration time.Duration) int64 {
	if duration <= 0 {
		return 0
	}
	seconds := int64(duration / time.Second)
	if duration%time.Second != 0 {
		seconds++
	}
	return seconds
}

func copyPersonAuthorizationContext(
	authorizationContext personAuthorizationContext,
) personAuthorizationContext {
	copied := authorizationContext
	copied.request = copyAuthorizationRequest(authorizationContext.request)
	return copied
}

func (server *PersonServer) writePendingAuthorization(
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

// ApproveAuthorization records a trusted user approval after the interaction
// code has correlated a browser session. The code itself cannot call this
// method or choose the resulting subject or scope.
func (server *PersonServer) ApproveAuthorization(ctx context.Context, pendingID string) error {
	server.pendingMu.Lock()
	pending, exists := server.pending[pendingID]
	if !exists {
		server.pendingMu.Unlock()
		return errors.New("reference: pending authorization does not exist")
	}
	now := server.clock.Now()
	if !pending.expiresAt.After(now) {
		pending.state = pendingAuthorizationExpired
		server.pendingMu.Unlock()
		return errors.New("reference: pending authorization expired")
	}
	if pending.federated != nil {
		server.pendingMu.Unlock()
		return errors.New("reference: access-server authorization requires an access-server decision")
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
	if err := validatePersonAuthorizationDecision(decision, authorizationRequest.Scope); err != nil {
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

// RejectAuthorization records a trusted terminal denial or abandonment.
func (server *PersonServer) RejectAuthorization(
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
	if pending.federated != nil {
		return errors.New("reference: access-server authorization requires an access-server decision")
	}
	if pending.state != pendingAuthorizationInteracting {
		return errors.New("reference: pending authorization is not awaiting a trusted decision")
	}
	pending.pollingError = code
	pending.state = pendingAuthorizationRejected
	return nil
}

func (server *PersonServer) handlePendingAuthorization(
	response http.ResponseWriter,
	request *http.Request,
) {
	verified, err := aauth.VerifyRequest(
		request.Context(),
		request,
		server.keyResolver,
		server.clock,
		aauth.VerifyRequestOptions{
			AllowedCredentialTypes: []string{aauth.AgentTokenType},
		},
	)
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", err)
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
	if pending.context.pollingAgent != verified.Agent ||
		pending.context.pollingAgentThumbprint != thumbprint {
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusForbidden, "invalid_pending", errors.New("pending authorization belongs to a different agent key"))
		return
	}
	if (pending.state == pendingAuthorizationWaiting ||
		pending.state == pendingAuthorizationInteracting) &&
		!pending.expiresAt.After(server.clock.Now()) {
		pending.state = pendingAuthorizationExpired
	}

	switch pending.state {
	case pendingAuthorizationWaiting, pendingAuthorizationInteracting:
		if pending.federated != nil {
			if pending.pollingFederation ||
				server.clock.Now().Before(pending.federated.notBefore) {
				id := pending.id
				federated := copyPendingFederation(pending.federated)
				server.pendingMu.Unlock()
				if err := server.writeFederatedPendingAuthorization(
					response,
					id,
					federated,
					server.clock.Now(),
				); err != nil {
					writeProblem(response, http.StatusInternalServerError, "server_error", err)
				}
				return
			}
			pending.pollingFederation = true
			id := pending.id
			federated := copyPendingFederation(pending.federated)
			authorizationContext := copyPersonAuthorizationContext(pending.context)
			decision := aauth.AuthorizationDecision{
				Subject: pending.decision.Subject,
				Scope:   append([]string(nil), pending.decision.Scope...),
			}
			server.pendingMu.Unlock()
			server.pollFederatedAuthorization(
				response,
				request.Context(),
				id,
				federated,
				authorizationContext,
				decision,
			)
			return
		}
		id := pending.id
		state := pending.state
		code := pending.code
		server.pendingMu.Unlock()
		if err := server.writePendingAuthorization(response, id, state, code); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
	case pendingAuthorizationApproved:
		authorizationContext := copyPersonAuthorizationContext(pending.context)
		decision := aauth.AuthorizationDecision{
			Subject: pending.decision.Subject,
			Scope:   append([]string(nil), pending.decision.Scope...),
		}
		pending.state = pendingAuthorizationServed
		server.pendingMu.Unlock()
		server.completeAuthorization(response, request.Context(), authorizationContext, decision)
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

func copyPendingFederation(
	federated *pendingFederatedAuthorization,
) *pendingFederatedAuthorization {
	if federated == nil {
		return nil
	}
	copied := *federated
	copied.requirement = copyRequirement(federated.requirement)
	return &copied
}

func (server *PersonServer) handleInteraction(
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
	if !pending.expiresAt.After(server.clock.Now()) {
		pending.state = pendingAuthorizationExpired
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusRequestTimeout, "expired", errors.New("pending interaction expired"))
		return
	}
	if pending.federated != nil {
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusGone, "invalid_code", errors.New("interaction is hosted by the access server"))
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

func (server *PersonServer) seenReplay(key string, expiresAt time.Time) bool {
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

func validatePersonAuthorizationDecision(
	decision aauth.AuthorizationDecision,
	requestedScope []string,
) error {
	if decision.Subject == "" {
		return errors.New("authorization decision requires a subject")
	}
	return validateAuthorizationDecision(decision, requestedScope)
}

func (server *PersonServer) pollFederatedAuthorization(
	responseWriter http.ResponseWriter,
	ctx context.Context,
	pendingID string,
	federated *pendingFederatedAuthorization,
	authorizationContext personAuthorizationContext,
	personDecision aauth.AuthorizationDecision,
) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, federated.location, nil)
	if err != nil {
		server.retryFederatedAuthorization(responseWriter, pendingID, federated, 5*time.Second)
		return
	}
	request.Header.Set("Prefer", "wait=0")
	if err := aauth.SignRequestWithJWKSURI(
		request,
		server.signingKey,
		server.identifier,
		aauth.PersonDiscoveryDocument,
		server.clock,
	); err != nil {
		server.failFederatedAuthorization(responseWriter, pendingID, http.StatusInternalServerError, "server_error", err)
		return
	}
	response, err := server.federationClient.Do(request)
	if err != nil {
		server.retryFederatedAuthorization(responseWriter, pendingID, federated, 5*time.Second)
		return
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
		exchange, err := server.parseAccessServerGrant(
			ctx,
			response,
			federated.accessServer,
			authorizationContext.targetAgent,
			authorizationContext.targetKey,
			authorizationContext.parentAgent,
			authorizationContext.resourceToken,
			personDecision,
		)
		if err != nil {
			server.failFederatedAuthorization(responseWriter, pendingID, http.StatusBadGateway, "federation_failed", err)
			return
		}
		if !server.serveFederatedAuthorization(pendingID) {
			server.writeFederatedTransitionFailure(responseWriter, pendingID)
			return
		}
		writeJSON(responseWriter, http.StatusOK, map[string]any{
			"auth_token": exchange.authToken,
			"expires_in": exchange.claims.ExpiresAt - server.clock.Now().Unix(),
		})
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			server.failFederatedAuthorization(responseWriter, pendingID, http.StatusBadGateway, "federation_failed", err)
			return
		}
		if endpoint, endpointErr := endpointIdentifier(deferred.Location); endpointErr != nil ||
			endpoint != federated.accessServer {
			server.failFederatedAuthorization(
				responseWriter,
				pendingID,
				http.StatusBadGateway,
				"federation_failed",
				errors.New("access-server pending continuation moved to another origin"),
			)
			return
		}
		next := &pendingFederatedAuthorization{
			accessServer: federated.accessServer,
			location:     deferred.Location,
			retryAfter:   deferred.RetryAfter,
			notBefore:    server.clock.Now().Add(deferred.RetryAfter),
			status:       deferred.Status,
			requirement:  copyRequirement(deferred.Requirement),
		}
		if !server.updateFederatedAuthorization(pendingID, next) {
			server.writeFederatedTransitionFailure(responseWriter, pendingID)
			return
		}
		if err := server.writeFederatedPendingAuthorization(
			responseWriter,
			pendingID,
			next,
			server.clock.Now(),
		); err != nil {
			server.failFederatedAuthorization(responseWriter, pendingID, http.StatusInternalServerError, "server_error", err)
		}
	case http.StatusTooManyRequests:
		delay := federated.retryAfter + 5*time.Second
		server.retryFederatedAuthorization(responseWriter, pendingID, federated, delay)
	case http.StatusServiceUnavailable:
		delay, err := responseRetryAfter(response.Header.Values("Retry-After"), server.clock.Now())
		if err != nil {
			delay = 5 * time.Second
		}
		server.retryFederatedAuthorization(responseWriter, pendingID, federated, delay)
	default:
		status := response.StatusCode
		code := "federation_failed"
		detail := errors.New("access server returned a terminal response")
		if strings.HasPrefix(
			strings.ToLower(response.Header.Get("Content-Type")),
			"application/problem+json",
		) {
			problem, decodeErr := aauth.DecodeProblemResponse(response)
			if decodeErr == nil {
				code = string(problem.Code)
				detail = errors.New(problem.Detail)
			} else {
				detail = decodeErr
			}
		}
		server.failFederatedAuthorization(responseWriter, pendingID, status, code, detail)
	}
}

func (server *PersonServer) retryFederatedAuthorization(
	response http.ResponseWriter,
	pendingID string,
	federated *pendingFederatedAuthorization,
	delay time.Duration,
) {
	next := copyPendingFederation(federated)
	next.retryAfter = delay
	next.notBefore = server.clock.Now().Add(delay)
	if !server.updateFederatedAuthorization(pendingID, next) {
		server.writeFederatedTransitionFailure(response, pendingID)
		return
	}
	if err := server.writeFederatedPendingAuthorization(
		response,
		pendingID,
		next,
		server.clock.Now(),
	); err != nil {
		server.failFederatedAuthorization(response, pendingID, http.StatusInternalServerError, "server_error", err)
	}
}

func (server *PersonServer) updateFederatedAuthorization(
	pendingID string,
	federated *pendingFederatedAuthorization,
) bool {
	server.pendingMu.Lock()
	defer server.pendingMu.Unlock()
	pending, exists := server.pending[pendingID]
	if !exists || !pending.pollingFederation || pending.federated == nil ||
		(pending.state != pendingAuthorizationWaiting && pending.state != pendingAuthorizationInteracting) {
		return false
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		pending.pollingFederation = false
		pending.state = pendingAuthorizationExpired
		return false
	}
	pending.federated = copyPendingFederation(federated)
	pending.pollingFederation = false
	if federated.status == "interacting" {
		pending.state = pendingAuthorizationInteracting
	} else {
		pending.state = pendingAuthorizationWaiting
	}
	return true
}

func (server *PersonServer) serveFederatedAuthorization(pendingID string) bool {
	server.pendingMu.Lock()
	defer server.pendingMu.Unlock()
	pending, exists := server.pending[pendingID]
	if !exists || !pending.pollingFederation || pending.federated == nil ||
		(pending.state != pendingAuthorizationWaiting && pending.state != pendingAuthorizationInteracting) {
		return false
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		pending.pollingFederation = false
		pending.state = pendingAuthorizationExpired
		return false
	}
	pending.pollingFederation = false
	pending.state = pendingAuthorizationServed
	return true
}

func (server *PersonServer) writeFederatedTransitionFailure(
	response http.ResponseWriter,
	pendingID string,
) {
	server.pendingMu.Lock()
	pending, exists := server.pending[pendingID]
	if exists && pending.state == pendingAuthorizationExpired {
		pending.state = pendingAuthorizationServed
		server.pendingMu.Unlock()
		writeProblem(response, http.StatusRequestTimeout, "expired", errors.New("pending authorization expired"))
		return
	}
	server.pendingMu.Unlock()
	writeProblem(response, http.StatusGone, "gone", errors.New("pending authorization changed during federation"))
}

func (server *PersonServer) failFederatedAuthorization(
	response http.ResponseWriter,
	pendingID string,
	status int,
	code string,
	err error,
) {
	server.pendingMu.Lock()
	if pending, exists := server.pending[pendingID]; exists {
		pending.pollingFederation = false
		pending.state = pendingAuthorizationServed
	}
	server.pendingMu.Unlock()
	writeProblem(response, status, code, err)
}

func (server *PersonServer) exchangeWithAccessServer(
	ctx context.Context,
	accessServerIdentifier string,
	resourceTokenCompact string,
	agentTokenCompact string,
	subagentTokenCompact string,
	targetAgent string,
	targetKey aauth.JWK,
	parentAgent string,
	resourceToken aauth.ResourceTokenClaims,
	personDecision aauth.AuthorizationDecision,
) (accessServerExchange, error) {
	var exchange accessServerExchange
	endpoint, err := server.accessServerEndpoint(ctx, accessServerIdentifier)
	if err != nil {
		return exchange, fmt.Errorf("resolve access-server endpoint: %w", err)
	}
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return exchange, err
	}
	endpointIssuer, err := endpointIdentifier(endpoint)
	if err != nil {
		return exchange, err
	}
	if endpointIssuer != accessServerIdentifier {
		return exchange, errors.New("access-server endpoint origin does not match resource-token audience")
	}
	input := map[string]string{
		"resource_token": resourceTokenCompact,
		"agent_token":    agentTokenCompact,
	}
	if subagentTokenCompact != "" {
		input["subagent_token"] = subagentTokenCompact
	}
	body, err := json.Marshal(input)
	if err != nil {
		return exchange, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return exchange, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Prefer", "wait=0")
	if err := aauth.SignRequestWithJWKSURI(
		request,
		server.signingKey,
		server.identifier,
		aauth.PersonDiscoveryDocument,
		server.clock,
	); err != nil {
		return exchange, err
	}
	response, err := server.federationClient.Do(request)
	if err != nil {
		return exchange, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			return exchange, err
		}
		exchange.deferred = &deferred
		return exchange, nil
	case http.StatusOK:
		return server.parseAccessServerGrant(
			ctx,
			response,
			accessServerIdentifier,
			targetAgent,
			targetKey,
			parentAgent,
			resourceToken,
			personDecision,
		)
	default:
		body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		return exchange, fmt.Errorf("access server returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
}

func (server *PersonServer) parseAccessServerGrant(
	ctx context.Context,
	response *http.Response,
	accessServerIdentifier string,
	targetAgent string,
	targetKey aauth.JWK,
	parentAgent string,
	resourceToken aauth.ResourceTokenClaims,
	personDecision aauth.AuthorizationDecision,
) (accessServerExchange, error) {
	var exchange accessServerExchange
	var result struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxJSONBody)).Decode(&result); err != nil {
		return exchange, err
	}
	claims, err := aauth.VerifyAuthToken(ctx, result.AuthToken, server.keyResolver, server.clock)
	if err != nil {
		return exchange, err
	}
	if claims.Issuer != accessServerIdentifier || claims.DWK != aauth.AccessDiscoveryDocument {
		return exchange, errors.New("access-server auth token has the wrong issuer or discovery document")
	}
	if err := aauth.ValidateAuthTokenContext(
		claims,
		resourceToken.Issuer,
		targetAgent,
		targetKey,
		nil,
	); err != nil {
		return exchange, err
	}
	grantedScopes, err := parseScopes(claims.Scope)
	if err != nil {
		return exchange, err
	}
	if !scopesContained(grantedScopes, personDecision.Scope) {
		return exchange, errors.New("access-server auth token exceeds the person-server grant")
	}
	if resourceToken.Mission != nil {
		if claims.Mission == nil || *claims.Mission != *resourceToken.Mission {
			return exchange, errors.New("access-server auth token changed the mission reference")
		}
	}
	if parentAgent == "" {
		if claims.Actor != nil {
			return exchange, errors.New("access-server auth token unexpectedly contains an act chain")
		}
	} else if claims.Actor == nil || claims.Actor.Agent != parentAgent {
		return exchange, errors.New("access-server auth token does not name the parent agent")
	}
	exchange.authToken = result.AuthToken
	exchange.claims = claims
	return exchange, nil
}

func (server *PersonServer) handleMetadata(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{
		"issuer":   server.identifier,
		"jwks_uri": server.identifier + "/jwks",
	})
}

func (server *PersonServer) handleJWKS(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{
		"keys": []aauth.JWK{server.signingKey.PublicJWK()},
	})
}
