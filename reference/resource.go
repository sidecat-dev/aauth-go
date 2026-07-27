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
	Identifier   string
	PersonServer string
	AccessServer string
	SigningKey   aauth.SigningKey
	KeyResolver  aauth.KeyResolver
	Clock        aauth.Clock
	NewID        func() string
	Scopes       []string
	Operation    func(context.Context, aauth.AuthorizedRequest) (any, error)
}

type Resource struct {
	identifier    string
	tokenAudience string
	signingKey    aauth.SigningKey
	keyResolver   aauth.KeyResolver
	clock         aauth.Clock
	newID         func() string
	scopes        []string
	operation     func(context.Context, aauth.AuthorizedRequest) (any, error)
	replayMu      sync.Mutex
	replayedProof map[string]time.Time
}

func NewResource(config ResourceConfig) (*Resource, error) {
	if err := aauth.ValidateServerIdentifier(config.Identifier); err != nil {
		return nil, err
	}
	if (config.PersonServer == "") == (config.AccessServer == "") {
		return nil, errors.New("reference: resource requires exactly one person-server or access-server audience")
	}
	tokenAudience := config.PersonServer
	if tokenAudience == "" {
		tokenAudience = config.AccessServer
	}
	if err := aauth.ValidateServerIdentifier(tokenAudience); err != nil {
		return nil, err
	}
	if config.SigningKey.ID() == "" || config.KeyResolver == nil || config.Clock == nil ||
		config.NewID == nil || len(config.Scopes) == 0 || config.Operation == nil {
		return nil, errors.New("reference: resource requires key, resolver, clock, id source, scopes, and operation")
	}
	if _, err := parseScopes(strings.Join(config.Scopes, " ")); err != nil {
		return nil, err
	}
	return &Resource{
		identifier:    config.Identifier,
		tokenAudience: tokenAudience,
		signingKey:    config.SigningKey,
		keyResolver:   config.KeyResolver,
		clock:         config.Clock,
		newID:         config.NewID,
		scopes:        append([]string(nil), config.Scopes...),
		operation:     config.Operation,
		replayedProof: make(map[string]time.Time),
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
		Agent:   claims.Agent,
		Subject: claims.Subject,
		Scope:   granted,
		Mission: claims.Mission,
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
	writeJSON(response, http.StatusOK, map[string]any{
		"issuer":                 resource.identifier,
		"jwks_uri":               resource.identifier + "/jwks",
		"authorization_endpoint": resource.identifier + "/authorize",
	})
}

func (resource *Resource) handleJWKS(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{
		"keys": []aauth.JWK{resource.signingKey.PublicJWK()},
	})
}
