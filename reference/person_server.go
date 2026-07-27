package reference

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type PersonServerConfig struct {
	Identifier          string
	SigningKey          aauth.SigningKey
	KeyResolver         aauth.KeyResolver
	Clock               aauth.Clock
	NewID               func() string
	MissionPolicy       aauth.MissionPolicy
	AuthorizationPolicy aauth.AuthorizationPolicy
}

type PersonServer struct {
	identifier          string
	signingKey          aauth.SigningKey
	keyResolver         aauth.KeyResolver
	clock               aauth.Clock
	newID               func() string
	missionPolicy       aauth.MissionPolicy
	authorizationPolicy aauth.AuthorizationPolicy

	mu       sync.RWMutex
	missions map[string]storedMission
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

func NewPersonServer(config PersonServerConfig) (*PersonServer, error) {
	if err := aauth.ValidateServerIdentifier(config.Identifier); err != nil {
		return nil, err
	}
	if config.SigningKey.ID() == "" || config.KeyResolver == nil || config.Clock == nil ||
		config.NewID == nil || config.MissionPolicy == nil || config.AuthorizationPolicy == nil {
		return nil, errors.New("reference: person server requires key, resolver, clock, id source, and policies")
	}
	return &PersonServer{
		identifier:          config.Identifier,
		signingKey:          config.SigningKey,
		keyResolver:         config.KeyResolver,
		clock:               config.Clock,
		newID:               config.NewID,
		missionPolicy:       config.MissionPolicy,
		authorizationPolicy: config.AuthorizationPolicy,
		missions:            make(map[string]storedMission),
	}, nil
}

func (server *PersonServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mission", server.handleMission)
	mux.HandleFunc("POST /token", server.handleToken)
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
	var input struct {
		ResourceToken string `json:"resource_token"`
		SubagentToken string `json:"subagent_token,omitempty"`
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

	resourceToken, err := aauth.VerifyResourceToken(request.Context(), input.ResourceToken, server.keyResolver, server.clock)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
		return
	}
	if resourceToken.Audience != server.identifier {
		writeProblem(response, http.StatusForbidden, "invalid_resource_token", errors.New("resource-token audience does not match person server"))
		return
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
	if resourceToken.Mission != nil {
		if resourceToken.Mission.Approver != server.identifier {
			writeProblem(response, http.StatusForbidden, "invalid_mission", errors.New("mission approver does not match person server"))
			return
		}
		server.mu.RLock()
		mission, exists := server.missions[resourceToken.Mission.S256]
		server.mu.RUnlock()
		if !exists || !mission.active || mission.agent != verified.Agent ||
			aauth.S256(mission.bytes) != resourceToken.Mission.S256 {
			writeProblem(response, http.StatusForbidden, "invalid_mission", errors.New("mission is absent, inactive, or bound to a different agent"))
			return
		}
	}

	decision, err := server.authorizationPolicy(request.Context(), aauth.AuthorizationRequest{
		Agent:         targetAgent,
		ParentAgent:   parentAgent,
		Resource:      resourceToken.Issuer,
		Scope:         append([]string(nil), scopes...),
		Mission:       resourceToken.Mission,
		Justification: input.Justification,
	})
	if err != nil {
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	if decision.Subject == "" || len(decision.Scope) == 0 || !scopesContained(decision.Scope, scopes) {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("authorization policy returned an invalid grant"))
		return
	}

	now := server.clock.Now()
	expiresAt := now.Add(time.Hour).Unix()
	if targetTokenExpiry < expiresAt {
		expiresAt = targetTokenExpiry
	}
	var actor *aauth.Actor
	if parentAgent != "" {
		actor = &aauth.Actor{Agent: parentAgent}
	}
	authToken, err := aauth.MintAuthToken(server.signingKey, aauth.AuthTokenClaims{
		Issuer:       server.identifier,
		DWK:          aauth.PersonDiscoveryDocument,
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
