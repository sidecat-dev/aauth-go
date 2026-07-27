package reference

import (
	"context"
	"errors"
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
	AuthorizationPolicy aauth.AuthorizationPolicy
}

type AccessServer struct {
	identifier          string
	signingKey          aauth.SigningKey
	keyResolver         aauth.KeyResolver
	clock               aauth.Clock
	newID               func() string
	trustedPersonServer func(context.Context, string) error
	authorizationPolicy aauth.AuthorizationPolicy

	replayMu      sync.Mutex
	replayedProof map[string]time.Time
}

func NewAccessServer(config AccessServerConfig) (*AccessServer, error) {
	if err := aauth.ValidateServerIdentifier(config.Identifier); err != nil {
		return nil, err
	}
	if config.SigningKey.ID() == "" || config.KeyResolver == nil || config.Clock == nil ||
		config.NewID == nil || config.TrustedPersonServer == nil || config.AuthorizationPolicy == nil {
		return nil, errors.New("reference: access server requires key, resolver, clock, id source, trust, and policy")
	}
	return &AccessServer{
		identifier:          config.Identifier,
		signingKey:          config.SigningKey,
		keyResolver:         config.KeyResolver,
		clock:               config.Clock,
		newID:               config.NewID,
		trustedPersonServer: config.TrustedPersonServer,
		authorizationPolicy: config.AuthorizationPolicy,
		replayedProof:       make(map[string]time.Time),
	}, nil
}

func (server *AccessServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", server.handleToken)
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
	scopes, err := parseScopes(resourceToken.Scope)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
		return
	}
	decision, err := server.authorizationPolicy(request.Context(), aauth.AuthorizationRequest{
		Agent:       targetAgent,
		ParentAgent: parentAgent,
		Resource:    resourceToken.Issuer,
		Scope:       append([]string(nil), scopes...),
		Mission:     resourceToken.Mission,
	})
	if err != nil {
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	if len(decision.Scope) == 0 || !scopesContained(decision.Scope, scopes) {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("authorization policy returned an invalid grant"))
		return
	}
	var actor *aauth.Actor
	if parentAgent != "" {
		actor = &aauth.Actor{Agent: parentAgent}
	}
	now := server.clock.Now()
	expiresAt := now.Add(time.Hour).Unix()
	if targetExpiry < expiresAt {
		expiresAt = targetExpiry
	}
	authToken, err := aauth.MintAuthToken(server.signingKey, aauth.AuthTokenClaims{
		Issuer:       server.identifier,
		DWK:          aauth.AccessDiscoveryDocument,
		Audience:     resourceToken.Issuer,
		JTI:          server.newID(),
		Agent:        targetAgent,
		Confirmation: aauth.Confirmation{JWK: targetKey},
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
