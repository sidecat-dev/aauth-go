package reference

import (
	"bytes"
	"context"
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
	federationClient      *http.Client
	accessServerEndpoint  func(context.Context, string) (string, error)
	trustedUpstreamIssuer func(context.Context, string) error

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
	if (config.FederationClient == nil) != (config.AccessServerEndpoint == nil) {
		return nil, errors.New("reference: federation client and access-server endpoint resolver must be configured together")
	}
	return &PersonServer{
		identifier:            config.Identifier,
		signingKey:            config.SigningKey,
		keyResolver:           config.KeyResolver,
		clock:                 config.Clock,
		newID:                 config.NewID,
		missionPolicy:         config.MissionPolicy,
		authorizationPolicy:   config.AuthorizationPolicy,
		federationClient:      config.FederationClient,
		accessServerEndpoint:  config.AccessServerEndpoint,
		trustedUpstreamIssuer: config.TrustedUpstreamIssuer,
		missions:              make(map[string]storedMission),
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

	decision, err := server.authorizationPolicy(request.Context(), aauth.AuthorizationRequest{
		Agent:         targetAgent,
		ParentAgent:   parentAgent,
		Resource:      resourceToken.Issuer,
		Scope:         append([]string(nil), scopes...),
		Mission:       resourceToken.Mission,
		Justification: input.Justification,
		Upstream:      upstream,
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
	if resourceToken.Audience != server.identifier {
		if upstream != nil {
			writeProblem(response, http.StatusNotImplemented, "federation_failed", errors.New("four-party call chaining is not yet implemented"))
			return
		}
		federatedToken, federatedClaims, err := server.exchangeWithAccessServer(
			request.Context(),
			resourceToken.Audience,
			input.ResourceToken,
			verified.RawCredential,
			input.SubagentToken,
			targetAgent,
			targetKey,
			parentAgent,
			resourceToken,
			decision,
		)
		if err != nil {
			writeProblem(response, http.StatusBadGateway, "federation_failed", err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{
			"auth_token": federatedToken,
			"expires_in": federatedClaims.ExpiresAt - now.Unix(),
		})
		return
	}

	expiresAt := now.Add(time.Hour).Unix()
	if targetTokenExpiry < expiresAt {
		expiresAt = targetTokenExpiry
	}
	var actor *aauth.Actor
	if upstream != nil {
		actor = &aauth.Actor{Agent: verified.Agent, Actor: upstream.Actor}
	} else if parentAgent != "" {
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
) (string, aauth.AuthTokenClaims, error) {
	var claims aauth.AuthTokenClaims
	endpoint, err := server.accessServerEndpoint(ctx, accessServerIdentifier)
	if err != nil {
		return "", claims, fmt.Errorf("resolve access-server endpoint: %w", err)
	}
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return "", claims, err
	}
	endpointIssuer, err := endpointIdentifier(endpoint)
	if err != nil {
		return "", claims, err
	}
	if endpointIssuer != accessServerIdentifier {
		return "", claims, errors.New("access-server endpoint origin does not match resource-token audience")
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
		return "", claims, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", claims, err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequestWithJWKSURI(
		request,
		server.signingKey,
		server.identifier,
		aauth.PersonDiscoveryDocument,
		server.clock,
	); err != nil {
		return "", claims, err
	}
	response, err := server.federationClient.Do(request)
	if err != nil {
		return "", claims, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		return "", claims, fmt.Errorf("access server returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	var result struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxJSONBody)).Decode(&result); err != nil {
		return "", claims, err
	}
	claims, err = aauth.VerifyAuthToken(ctx, result.AuthToken, server.keyResolver, server.clock)
	if err != nil {
		return "", claims, err
	}
	if claims.Issuer != accessServerIdentifier || claims.DWK != aauth.AccessDiscoveryDocument {
		return "", claims, errors.New("access-server auth token has the wrong issuer or discovery document")
	}
	if err := aauth.ValidateAuthTokenContext(
		claims,
		resourceToken.Issuer,
		targetAgent,
		targetKey,
		nil,
	); err != nil {
		return "", claims, err
	}
	grantedScopes, err := parseScopes(claims.Scope)
	if err != nil {
		return "", claims, err
	}
	if !scopesContained(grantedScopes, personDecision.Scope) {
		return "", claims, errors.New("access-server auth token exceeds the person-server grant")
	}
	if resourceToken.Mission != nil {
		if claims.Mission == nil || *claims.Mission != *resourceToken.Mission {
			return "", claims, errors.New("access-server auth token changed the mission reference")
		}
	}
	if parentAgent == "" {
		if claims.Actor != nil {
			return "", claims, errors.New("access-server auth token unexpectedly contains an act chain")
		}
	} else if claims.Actor == nil || claims.Actor.Agent != parentAgent {
		return "", claims, errors.New("access-server auth token does not name the parent agent")
	}
	return result.AuthToken, claims, nil
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
