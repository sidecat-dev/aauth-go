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

type ResourceConfig struct {
	Identifier          string
	PersonServer        string
	AccessServer        string
	SigningKey          aauth.SigningKey
	KeyResolver         aauth.KeyResolver
	Clock               aauth.Clock
	NewID               func() string
	Scopes              []string
	AuthorizationPolicy aauth.AuthorizationPolicy
	Operation           func(context.Context, aauth.AuthorizedRequest) (any, error)
}

type Resource struct {
	identifier          string
	tokenAudience       string
	signingKey          aauth.SigningKey
	hasSigningKey       bool
	keyResolver         aauth.KeyResolver
	clock               aauth.Clock
	newID               func() string
	scopes              []string
	authorizationPolicy aauth.AuthorizationPolicy
	operation           func(context.Context, aauth.AuthorizedRequest) (any, error)
	accessMu            sync.Mutex
	access              map[string]localAccessGrant
	replayMu            sync.Mutex
	replayedProof       map[string]time.Time
}

type localAccessGrant struct {
	agent      string
	subject    string
	thumbprint string
	scope      []string
	mission    *aauth.MissionReference
	expiresAt  time.Time
}

func NewResource(config ResourceConfig) (*Resource, error) {
	if err := aauth.ValidateServerIdentifier(config.Identifier); err != nil {
		return nil, err
	}
	modeCount := 0
	if config.PersonServer != "" {
		modeCount++
	}
	if config.AccessServer != "" {
		modeCount++
	}
	if config.AuthorizationPolicy != nil {
		modeCount++
	}
	if modeCount != 1 {
		return nil, errors.New("reference: resource requires exactly one person server, access server, or local authorization policy")
	}
	tokenAudience := config.PersonServer
	if tokenAudience == "" {
		tokenAudience = config.AccessServer
	}
	if tokenAudience != "" {
		if err := aauth.ValidateServerIdentifier(tokenAudience); err != nil {
			return nil, err
		}
	}
	if tokenAudience != "" && config.SigningKey.ID() == "" {
		return nil, errors.New("reference: a resource that issues resource tokens requires a signing key")
	}
	if config.KeyResolver == nil || config.Clock == nil || config.NewID == nil ||
		len(config.Scopes) == 0 || config.Operation == nil {
		return nil, errors.New("reference: resource requires resolver, clock, id source, scopes, and operation")
	}
	if _, err := parseScopes(strings.Join(config.Scopes, " ")); err != nil {
		return nil, err
	}
	return &Resource{
		identifier:          config.Identifier,
		tokenAudience:       tokenAudience,
		signingKey:          config.SigningKey,
		hasSigningKey:       config.SigningKey.ID() != "",
		keyResolver:         config.KeyResolver,
		clock:               config.Clock,
		newID:               config.NewID,
		scopes:              append([]string(nil), config.Scopes...),
		authorizationPolicy: config.AuthorizationPolicy,
		operation:           config.Operation,
		access:              make(map[string]localAccessGrant),
		replayedProof:       make(map[string]time.Time),
	}, nil
}

func (resource *Resource) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /authorize", resource.handleAuthorize)
	mux.HandleFunc("GET /.well-known/aauth-resource.json", resource.handleMetadata)
	mux.HandleFunc("GET /jwks", resource.handleJWKS)
	mux.HandleFunc("/", resource.handleProtected)
	return mux
}

func (resource *Resource) handleAuthorize(response http.ResponseWriter, request *http.Request) {
	required := []string{"content-digest"}
	if request.Header.Get("AAuth-Mission") != "" {
		required = append(required, "aauth-mission")
	}
	verified, err := aauth.VerifyRequest(request.Context(), request, resource.keyResolver, resource.clock, aauth.VerifyRequestOptions{
		RequiredComponents:     required,
		AllowedCredentialTypes: []string{aauth.AgentTokenType},
	})
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", err)
		return
	}
	var input struct {
		Scope string `json:"scope"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	scopes, err := parseScopes(input.Scope)
	if err != nil || !scopesContained(scopes, resource.scopes) {
		writeProblem(response, http.StatusBadRequest, "invalid_scope", err)
		return
	}
	var mission *aauth.MissionReference
	if header := request.Header.Get("AAuth-Mission"); header != "" {
		parsed, err := aauth.ParseMissionHeader(header)
		if err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_mission", err)
			return
		}
		mission = &parsed
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_key", err)
		return
	}
	now := resource.clock.Now()
	if resource.authorizationPolicy != nil {
		decision, err := resource.authorizationPolicy(request.Context(), aauth.AuthorizationRequest{
			Agent:    verified.Agent,
			Resource: resource.identifier,
			Scope:    append([]string(nil), scopes...),
			Mission:  mission,
		})
		if err != nil {
			writeProblem(response, http.StatusForbidden, "access_denied", err)
			return
		}
		if len(decision.Scope) == 0 || !scopesContained(decision.Scope, scopes) {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("local authorization policy returned an invalid grant"))
			return
		}
		accessToken := resource.newID()
		if err := aauth.ValidateAccessToken(accessToken); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		expiresAt := now.Add(time.Hour)
		if agentExpiry := time.Unix(verified.AgentToken.ExpiresAt, 0); agentExpiry.Before(expiresAt) {
			expiresAt = agentExpiry
		}
		resource.accessMu.Lock()
		if _, exists := resource.access[accessToken]; exists {
			resource.accessMu.Unlock()
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("access token source returned a duplicate value"))
			return
		}
		resource.access[accessToken] = localAccessGrant{
			agent:      verified.Agent,
			subject:    decision.Subject,
			thumbprint: thumbprint,
			scope:      append([]string(nil), decision.Scope...),
			mission:    mission,
			expiresAt:  expiresAt,
		}
		resource.accessMu.Unlock()
		response.Header().Set("AAuth-Access", accessToken)
		writeJSON(response, http.StatusOK, map[string]any{
			"status": "authorized",
			"scope":  strings.Join(decision.Scope, " "),
		})
		return
	}

	token, err := aauth.MintResourceToken(resource.signingKey, aauth.ResourceTokenClaims{
		Issuer:    resource.identifier,
		DWK:       aauth.ResourceDiscoveryDocument,
		Audience:  resource.tokenAudience,
		JTI:       resource.newID(),
		Agent:     verified.Agent,
		AgentJKT:  thumbprint,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Scope:     strings.Join(scopes, " "),
		Mission:   mission,
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"resource_token": token})
}

func (resource *Resource) handleProtected(response http.ResponseWriter, request *http.Request) {
	if usesAAuthScheme(request.Header.Get("Authorization")) {
		resource.handleAccessProtected(response, request)
		return
	}
	verified, err := aauth.VerifyRequest(request.Context(), request, resource.keyResolver, resource.clock, aauth.VerifyRequestOptions{
		AllowedCredentialTypes: []string{aauth.AuthTokenType},
	})
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", err)
		return
	}
	claims := verified.AuthToken
	if err := aauth.ValidateAuthTokenContext(*claims, resource.identifier, verified.Agent, verified.PublicKey, resource.scopes); err != nil {
		writeProblem(response, http.StatusForbidden, "invalid_token", err)
		return
	}
	granted, err := parseScopes(claims.Scope)
	if err != nil {
		writeProblem(response, http.StatusForbidden, "insufficient_scope", err)
		return
	}
	if resource.seenReplay(verified.ReplayKey, verified.Created.Add(aauth.DefaultSignatureWindow)) {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", errors.New("request proof was replayed"))
		return
	}

	result, err := resource.operation(request.Context(), aauth.AuthorizedRequest{
		Agent:     claims.Agent,
		Subject:   claims.Subject,
		Scope:     granted,
		Mission:   claims.Mission,
		Actor:     claims.Actor,
		AuthToken: verified.RawCredential,
		Method:    request.Method,
		Path:      request.URL.Path,
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "operation_failed", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func usesAAuthScheme(header string) bool {
	separator := strings.IndexByte(header, ' ')
	return separator > 0 && strings.EqualFold(header[:separator], "AAuth")
}

func (resource *Resource) handleAccessProtected(response http.ResponseWriter, request *http.Request) {
	verified, err := aauth.VerifyRequest(request.Context(), request, resource.keyResolver, resource.clock, aauth.VerifyRequestOptions{
		RequiredComponents:     []string{"authorization"},
		AllowedCredentialTypes: []string{aauth.AgentTokenType},
	})
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", err)
		return
	}
	accessToken, err := aauth.ParseAccessAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_access", err)
		return
	}
	resource.accessMu.Lock()
	grant, exists := resource.access[accessToken]
	if exists && !grant.expiresAt.After(resource.clock.Now()) {
		delete(resource.access, accessToken)
		exists = false
	}
	resource.accessMu.Unlock()
	if !exists {
		writeProblem(response, http.StatusForbidden, "invalid_access", errors.New("access token is unknown or expired"))
		return
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil || grant.agent != verified.Agent || grant.thumbprint != thumbprint {
		writeProblem(response, http.StatusForbidden, "invalid_access", errors.New("access token is bound to a different agent key"))
		return
	}
	if !scopesContained(resource.scopes, grant.scope) {
		writeProblem(response, http.StatusForbidden, "insufficient_scope", errors.New("access token does not grant the operation scope"))
		return
	}
	if resource.seenReplay(verified.ReplayKey, verified.Created.Add(aauth.DefaultSignatureWindow)) {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", errors.New("request proof was replayed"))
		return
	}
	result, err := resource.operation(request.Context(), aauth.AuthorizedRequest{
		Agent:   grant.agent,
		Subject: grant.subject,
		Scope:   append([]string(nil), grant.scope...),
		Mission: grant.mission,
		Method:  request.Method,
		Path:    request.URL.Path,
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "operation_failed", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (resource *Resource) seenReplay(key string, expiresAt time.Time) bool {
	resource.replayMu.Lock()
	defer resource.replayMu.Unlock()
	now := resource.clock.Now()
	for existing, expiry := range resource.replayedProof {
		if !expiry.After(now) {
			delete(resource.replayedProof, existing)
		}
	}
	if _, exists := resource.replayedProof[key]; exists {
		return true
	}
	resource.replayedProof[key] = expiresAt
	return false
}

func (resource *Resource) handleMetadata(response http.ResponseWriter, _ *http.Request) {
	metadata := map[string]any{
		"issuer":                 resource.identifier,
		"authorization_endpoint": resource.identifier + "/authorize",
	}
	if resource.authorizationPolicy != nil {
		metadata["access_mode"] = "aauth-access-token"
	} else {
		metadata["access_mode"] = "auth-token"
	}
	if resource.hasSigningKey {
		metadata["jwks_uri"] = resource.identifier + "/jwks"
	}
	writeJSON(response, http.StatusOK, metadata)
}

func (resource *Resource) handleJWKS(response http.ResponseWriter, _ *http.Request) {
	if !resource.hasSigningKey {
		writeProblem(response, http.StatusNotFound, "not_found", errors.New("resource has no signing keys"))
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"keys": []aauth.JWK{resource.signingKey.PublicJWK()},
	})
}
