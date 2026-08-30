// Package personserver implements explicit immediate three-party and
// federated four-party Person Server compositions. Either composition can also
// host the bounded person-token interaction.
package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/aauth-dev/auth-go/internal/httpapi"
	"github.com/aauth-dev/auth-go/jose"
	"github.com/aauth-dev/auth-go/signaturekey"
)

const (
	maxRequestBytes       = 1 << 20
	maximumPersonLifetime = time.Hour
)

// DefaultMaximumResourceTokenLifetime is the retention and acceptance bound
// used when either public config leaves MaximumResourceTokenLifetime zero.
const DefaultMaximumResourceTokenLifetime = 5 * time.Minute

// ErrPersonTokenNotFound reports that no retained person-token record matches
// an issuer and token identifier.
var ErrPersonTokenNotFound = errors.New("personserver: person token not found")

// FederatedAuthorizationConfig supplies a four-party Person Server. It issues
// person tokens, retains their lineage, and federates auth-token requests to an
// Access Server.
type FederatedAuthorizationConfig struct {
	Issuer      string
	SigningKey  jose.SigningKey
	KeyResolver signaturekey.KeyResolver
	Clock       aauth.Clock
	NewID       func() string
	HTTPClient  *http.Client
	// MaximumResourceTokenLifetime bounds resource tokens derived from a
	// retained person token. Zero selects DefaultMaximumResourceTokenLifetime.
	MaximumResourceTokenLifetime time.Duration
	AccessServerEndpoint         func(context.Context, string) (string, error)
	Tokens                       TokenStore
	BindPerson                   func(context.Context, PersonTokenRequest) (Person, error)
	// RequirePersonTokenInteraction optionally selects a host-authenticated
	// interaction before BindPerson. A required interaction uses the deferred
	// extension implemented by Tokens.
	RequirePersonTokenInteraction func(context.Context, PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error)
	Consent                       func(context.Context, AuthorizationRequest) error
}

// PSAuthorizationConfig supplies a three-party Person Server. It issues auth
// tokens itself, immediately or after host-authenticated consent, and therefore
// has no Access Server HTTP dependency.
type PSAuthorizationConfig struct {
	Issuer                        string
	SigningKey                    jose.SigningKey
	KeyResolver                   signaturekey.KeyResolver
	Clock                         aauth.Clock
	NewID                         func() string
	MaximumResourceTokenLifetime  time.Duration
	Tokens                        TokenStore
	BindPerson                    func(context.Context, PersonTokenRequest) (Person, error)
	RequirePersonTokenInteraction func(context.Context, PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error)
	Authorize                     func(context.Context, AuthorizationRequest) (AuthorizationDecision, error)
	// RequireAuthorizationInteraction optionally selects host-authenticated
	// consent after the complete three-party request has been verified.
	RequireAuthorizationInteraction func(context.Context, AuthorizationRequest) (AuthorizationInteractionPolicy, bool, error)
	// AuthorizationInteractions durably retains the authorization-specific
	// pending request and its exact terminal result.
	AuthorizationInteractions DeferredAuthorizationStore
}

// AuthorizationDecision is the scope and lifetime granted by one
// PS-authorization policy decision.
type AuthorizationDecision struct {
	Scopes   []string
	Lifetime time.Duration
}

// PersonTokenRequest is the verified agent and requested resource presented to
// person-binding policy.
type PersonTokenRequest struct {
	Agent                 string
	Resource              string
	AgentAdditionalClaims map[string]json.RawMessage
}

// Person is the directed identity and lifetime selected by person-binding
// policy.
type Person struct {
	Subject  string
	Tenant   string
	Lifetime time.Duration
}

// AuthorizationRequest is the verified Core context presented to policy before
// direct auth-token issuance or an Access Server exchange.
type AuthorizationRequest struct {
	Agent                 string
	Resource              string
	Subject               string
	Tenant                string
	Scopes                []string
	Capabilities          []string
	AgentAdditionalClaims map[string]json.RawMessage
}

// PersonTokenRecord is the retained binding used to validate a later resource
// token's presented_jti.
type PersonTokenRecord struct {
	JTI          string
	PersonServer string
	Resource     string
	Subject      string
	MissionS256  string
	Tenant       string
	ExpiresAt    time.Time
	RetainUntil  time.Time
}

// TokenStore retains and resolves person-token bindings. Implementations must
// commit one issuer/JTI record atomically.
type TokenStore interface {
	Commit(context.Context, PersonTokenRecord) error
	Load(context.Context, string, string) (PersonTokenRecord, error)
}

// Server is an AAuth Person Server.
type Server struct {
	issuer                          string
	signingKey                      jose.SigningKey
	keyResolver                     signaturekey.KeyResolver
	clock                           aauth.Clock
	newID                           func() string
	httpClient                      *http.Client
	maximumResourceTokenLifetime    time.Duration
	accessServerEndpoint            func(context.Context, string) (string, error)
	tokens                          TokenStore
	deferredTokens                  DeferredTokenStore
	bindPerson                      func(context.Context, PersonTokenRequest) (Person, error)
	requirePersonTokenInteraction   func(context.Context, PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error)
	consent                         func(context.Context, AuthorizationRequest) error
	authorizationMode               authorizationMode
	authorize                       func(context.Context, AuthorizationRequest) (AuthorizationDecision, error)
	requireAuthorizationInteraction func(context.Context, AuthorizationRequest) (AuthorizationInteractionPolicy, bool, error)
	authorizationInteractions       DeferredAuthorizationStore
}

type authorizationMode uint8

const (
	authorizationModeFederated authorizationMode = iota + 1
	authorizationModePersonServer
)

type serverConfig struct {
	issuer                        string
	signingKey                    jose.SigningKey
	keyResolver                   signaturekey.KeyResolver
	clock                         aauth.Clock
	newID                         func() string
	maximumResourceTokenLifetime  time.Duration
	tokens                        TokenStore
	bindPerson                    func(context.Context, PersonTokenRequest) (Person, error)
	requirePersonTokenInteraction func(context.Context, PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error)
}

// NewFederatedAuthorization constructs a four-party Person Server.
func NewFederatedAuthorization(config FederatedAuthorizationConfig) (*Server, error) {
	if config.HTTPClient == nil {
		return nil, errors.New("personserver: HTTP client is required")
	}
	if config.AccessServerEndpoint == nil {
		return nil, errors.New("personserver: Access Server endpoint resolver is required")
	}
	if config.Consent == nil {
		return nil, errors.New("personserver: consent policy is required")
	}
	server, err := newServer(serverConfig{
		issuer: config.Issuer, signingKey: config.SigningKey,
		keyResolver: config.KeyResolver, clock: config.Clock, newID: config.NewID,
		maximumResourceTokenLifetime: config.MaximumResourceTokenLifetime,
		tokens:                       config.Tokens, bindPerson: config.BindPerson,
		requirePersonTokenInteraction: config.RequirePersonTokenInteraction,
	})
	if err != nil {
		return nil, err
	}
	httpClient := *config.HTTPClient
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	server.httpClient = &httpClient
	server.accessServerEndpoint = config.AccessServerEndpoint
	server.consent = config.Consent
	server.authorizationMode = authorizationModeFederated
	return server, nil
}

// NewPSAuthorization constructs a three-party Person Server. Authorize supplies
// the immediate path. A paired interaction policy and store may supply the
// deferred path instead or act as a fallback before immediate authorization.
func NewPSAuthorization(config PSAuthorizationConfig) (*Server, error) {
	if (config.RequireAuthorizationInteraction == nil) != (config.AuthorizationInteractions == nil) {
		return nil, errors.New("personserver: authorization interaction policy and store must be configured together")
	}
	if config.Authorize == nil && config.RequireAuthorizationInteraction == nil {
		return nil, errors.New("personserver: immediate or deferred authorization policy is required")
	}
	server, err := newServer(serverConfig{
		issuer: config.Issuer, signingKey: config.SigningKey,
		keyResolver: config.KeyResolver, clock: config.Clock, newID: config.NewID,
		maximumResourceTokenLifetime: config.MaximumResourceTokenLifetime,
		tokens:                       config.Tokens, bindPerson: config.BindPerson,
		requirePersonTokenInteraction: config.RequirePersonTokenInteraction,
	})
	if err != nil {
		return nil, err
	}
	server.authorizationMode = authorizationModePersonServer
	server.authorize = config.Authorize
	server.requireAuthorizationInteraction = config.RequireAuthorizationInteraction
	server.authorizationInteractions = config.AuthorizationInteractions
	return server, nil
}

func newServer(config serverConfig) (*Server, error) {
	if err := aauth.ValidateServerIdentifier(config.issuer); err != nil {
		return nil, fmt.Errorf("personserver: issuer: %w", err)
	}
	if _, err := config.signingKey.PublicJWK().PublicKey(); err != nil {
		return nil, fmt.Errorf("personserver: signing key: %w", err)
	}
	if config.keyResolver == nil {
		return nil, errors.New("personserver: key resolver is required")
	}
	if config.clock == nil {
		return nil, errors.New("personserver: clock is required")
	}
	if config.newID == nil {
		return nil, errors.New("personserver: token ID source is required")
	}
	if config.tokens == nil {
		return nil, errors.New("personserver: token store is required")
	}
	if config.bindPerson == nil {
		return nil, errors.New("personserver: person-binding policy is required")
	}
	var deferredTokens DeferredTokenStore
	if config.requirePersonTokenInteraction != nil {
		var ok bool
		deferredTokens, ok = config.tokens.(DeferredTokenStore)
		if !ok {
			return nil, errors.New("personserver: person-token interaction requires a deferred token store")
		}
	}
	maximumResourceTokenLifetime := config.maximumResourceTokenLifetime
	if maximumResourceTokenLifetime == 0 {
		maximumResourceTokenLifetime = DefaultMaximumResourceTokenLifetime
	}
	if maximumResourceTokenLifetime < 0 {
		return nil, errors.New("personserver: maximum resource-token lifetime must be positive")
	}
	return &Server{
		issuer: config.issuer, signingKey: config.signingKey,
		keyResolver: config.keyResolver, clock: config.clock, newID: config.newID,
		maximumResourceTokenLifetime: maximumResourceTokenLifetime,
		tokens:                       config.tokens, deferredTokens: deferredTokens, bindPerson: config.bindPerson,
		requirePersonTokenInteraction: config.requirePersonTokenInteraction,
	}, nil
}

// Handler serves immediate and interactive person-token issuance plus the
// Person Server auth-token exchange.
func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /person", server.handlePerson)
	mux.HandleFunc("GET /person/pending/{id}", server.handlePendingPersonToken)
	mux.HandleFunc("POST /token", server.handleToken)
	mux.HandleFunc("GET /token/pending/{id}", server.handlePendingAuthorization)
	mux.HandleFunc("GET /.well-known/aauth-person.json", server.handleMetadata)
	mux.HandleFunc("GET /.well-known/jwks.json", server.handleJWKS)
	return mux
}

func (server *Server) handlePerson(response http.ResponseWriter, request *http.Request) {
	agentToken, agent, proof, err := server.verifyAgentRequest(request, []string{"content-type", "content-digest"})
	_ = agentToken
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	var input struct {
		Resource      string          `json:"resource"`
		MissionS256   json.RawMessage `json:"mission_s256"`
		SubagentToken json.RawMessage `json:"subagent_token"`
		UpstreamToken json.RawMessage `json:"upstream_token"`
		Justification json.RawMessage `json:"justification"`
		LoginHint     json.RawMessage `json:"login_hint"`
		Tenant        json.RawMessage `json:"tenant"`
		DomainHint    json.RawMessage `json:"domain_hint"`
		Prompt        json.RawMessage `json:"prompt"`
		Platform      json.RawMessage `json:"platform"`
		Device        json.RawMessage `json:"device"`
		Capabilities  json.RawMessage `json:"capabilities"`
	}
	if err := decodeJSON(request.Body, &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := rejectUnsupportedRequestMembers(map[string]json.RawMessage{
		"mission_s256": input.MissionS256, "subagent_token": input.SubagentToken,
		"upstream_token": input.UpstreamToken,
		"justification":  input.Justification, "login_hint": input.LoginHint,
		"tenant": input.Tenant, "domain_hint": input.DomainHint, "prompt": input.Prompt,
		"platform": input.Platform, "device": input.Device, "capabilities": input.Capabilities,
	}); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := aauth.ValidateServerIdentifier(input.Resource); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	personRequest := PersonTokenRequest{
		Agent: agent.Subject, Resource: input.Resource,
		AgentAdditionalClaims: cloneClaims(agent.AdditionalClaims),
	}
	if server.requirePersonTokenInteraction != nil {
		policy, required, err := server.requirePersonTokenInteraction(request.Context(), personRequest)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if required {
			if err := server.beginPersonTokenInteraction(response, request, personRequest, agent, policy); err != nil {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
			}
			return
		}
	}
	person, err := server.bindPerson(request.Context(), personRequest)
	if err != nil {
		writeProblem(response, http.StatusForbidden, "person_token_denied", err)
		return
	}
	if person.Subject == "" || person.Lifetime <= 0 || person.Lifetime > maximumPersonLifetime {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("person binding returned an invalid person"))
		return
	}
	expiresAt := proof.VerifiedAt().Add(person.Lifetime)
	if agentExpiry := time.Unix(agent.ExpiresAt, 0); agentExpiry.Before(expiresAt) {
		expiresAt = agentExpiry
	}
	claims := aauth.PersonTokenClaims{
		Issuer: server.issuer, DWK: aauth.PersonDiscoveryDocument,
		Audience: input.Resource, Subject: person.Subject,
		Confirmation: aauth.Confirmation{JWK: agent.Confirmation.JWK},
		JTI:          server.newID(), IssuedAt: proof.VerifiedAt().Unix(), ExpiresAt: expiresAt.Unix(),
		Tenant: person.Tenant,
	}
	compact, err := aauth.MintPersonToken(server.signingKey, claims)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	canonicalExpiry := time.Unix(claims.ExpiresAt, 0).UTC()
	if err := server.tokens.Commit(request.Context(), PersonTokenRecord{
		JTI: claims.JTI, PersonServer: claims.Issuer, Resource: claims.Audience,
		Subject: claims.Subject, MissionS256: claims.MissionS256, Tenant: claims.Tenant,
		ExpiresAt: canonicalExpiry, RetainUntil: canonicalExpiry.Add(server.maximumResourceTokenLifetime),
	}); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writePrivateJSON(response, http.StatusOK, struct {
		PersonToken string `json:"person_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}{PersonToken: compact, ExpiresIn: claims.ExpiresAt - proof.VerifiedAt().Unix()})
}

func (server *Server) handleToken(response http.ResponseWriter, request *http.Request) {
	agentToken, agent, proof, err := server.verifyAgentRequest(request, []string{"content-type", "content-digest"})
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	var input struct {
		ResourceToken string          `json:"resource_token"`
		UpstreamToken json.RawMessage `json:"upstream_token"`
		SubagentToken json.RawMessage `json:"subagent_token"`
		Justification json.RawMessage `json:"justification"`
		LoginHint     json.RawMessage `json:"login_hint"`
		Tenant        json.RawMessage `json:"tenant"`
		DomainHint    json.RawMessage `json:"domain_hint"`
		Prompt        json.RawMessage `json:"prompt"`
		Platform      json.RawMessage `json:"platform"`
		Device        json.RawMessage `json:"device"`
		Capabilities  json.RawMessage `json:"capabilities"`
	}
	if err := decodeJSON(request.Body, &input); err != nil || input.ResourceToken == "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	unsupportedCapabilities := input.Capabilities
	if server.authorizationMode == authorizationModePersonServer {
		unsupportedCapabilities = nil
	}
	if err := rejectUnsupportedRequestMembers(map[string]json.RawMessage{
		"upstream_token": input.UpstreamToken, "subagent_token": input.SubagentToken,
		"justification": input.Justification, "login_hint": input.LoginHint,
		"tenant": input.Tenant, "domain_hint": input.DomainHint, "prompt": input.Prompt,
		"platform": input.Platform, "device": input.Device, "capabilities": unsupportedCapabilities,
	}); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	var capabilities []string
	if server.authorizationMode == authorizationModePersonServer {
		capabilities, err = parseAuthorizationCapabilities(input.Capabilities)
		if err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_request", err)
			return
		}
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return proof.VerifiedAt() })
	resourceToken, err := aauth.VerifyResourceToken(
		request.Context(), input.ResourceToken, server.keyResolver, verificationClock,
	)
	if err != nil {
		writeEndpointTokenProblem(response, err, "invalid_resource_token", "expired_resource_token")
		return
	}
	if err := server.validateResourceTokenTopology(resourceToken); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
		return
	}
	if resourceToken.Interaction != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource-token interaction requires the deferred flow"))
		return
	}
	if resourceToken.MissionS256 != "" {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("mission-bound resource tokens require mission verification"))
		return
	}
	if resourceToken.Account != "" {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource-token account is not supported by the immediate flow"))
		return
	}
	resourceTokenExpiresAt := time.Unix(resourceToken.ExpiresAt, 0).UTC()
	resourceTokenIssuedAt := time.Unix(resourceToken.IssuedAt, 0).UTC()
	if resourceTokenExpiresAt.Sub(resourceTokenIssuedAt) > server.maximumResourceTokenLifetime {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token exceeds the configured maximum lifetime"))
		return
	}
	if err := aauth.ValidateServerIdentifier(resourceToken.Audience); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
		return
	}
	agentJKT, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil || resourceToken.AgentJKT != agentJKT {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token does not name the signing agent key"))
		return
	}
	scopes, err := parseScopes(resourceToken.Scope)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
		return
	}
	record, err := server.tokens.Load(request.Context(), server.issuer, resourceToken.PresentedJTI)
	if errors.Is(err, ErrPersonTokenNotFound) {
		writeProblem(response, http.StatusBadRequest, "unknown_person_token", err)
		return
	}
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := validatePersonTokenRecord(record); err != nil ||
		record.JTI != resourceToken.PresentedJTI ||
		record.PersonServer != resourceToken.PersonServer ||
		record.Resource != resourceToken.Issuer ||
		record.Subject != resourceToken.Subject ||
		record.MissionS256 != resourceToken.MissionS256 ||
		record.Tenant != resourceToken.Tenant ||
		resourceToken.IssuedAt >= record.ExpiresAt.Unix() ||
		resourceTokenExpiresAt.After(record.RetainUntil) ||
		!record.RetainUntil.After(proof.VerifiedAt()) {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token does not match the retained person token"))
		return
	}
	authorizationRequest := AuthorizationRequest{
		Agent: agent.Subject, Resource: resourceToken.Issuer,
		Subject: resourceToken.Subject, Tenant: resourceToken.Tenant,
		Scopes:                append([]string(nil), scopes...),
		Capabilities:          append([]string(nil), capabilities...),
		AgentAdditionalClaims: cloneClaims(agent.AdditionalClaims),
	}
	if server.authorizationMode == authorizationModePersonServer {
		if server.requireAuthorizationInteraction != nil {
			policyRequest := cloneAuthorizationRequest(authorizationRequest)
			policy, required, err := server.requireAuthorizationInteraction(request.Context(), policyRequest)
			if err != nil {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
				return
			}
			if required {
				if !slices.Contains(capabilities, "interaction") {
					writeProblem(response, http.StatusForbidden, "user_unreachable", errors.New("Agent did not declare interaction capability"))
					return
				}
				if err := server.beginAuthorizationInteraction(response, request, authorizationRequest, agent, resourceToken, policy); err != nil {
					writeProblem(response, http.StatusInternalServerError, "server_error", err)
				}
				return
			}
		}
		if server.authorize == nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("deferred authorization policy did not select interaction and no immediate authorization policy is configured"))
			return
		}
		server.issuePSAuthorizationToken(response, request, proof, agent, resourceToken, authorizationRequest)
		return
	}
	if err := server.consent(request.Context(), authorizationRequest); err != nil {
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	endpoint, err := server.accessServerEndpoint(request.Context(), resourceToken.Audience)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := validateAccessServerEndpoint(endpoint); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	accessInput, err := json.Marshal(struct {
		ResourceToken string `json:"resource_token"`
		AgentToken    string `json:"agent_token"`
	}{ResourceToken: input.ResourceToken, AgentToken: agentToken})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	accessRequest, err := http.NewRequestWithContext(request.Context(), http.MethodPost, endpoint, bytes.NewReader(accessInput))
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	accessRequest.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		accessRequest, server.signingKey, server.issuer, aauth.PersonDiscoveryDocument, server.clock,
		signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
			MaxBodyBytes:         maxRequestBytes,
		},
	); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	accessResponse, err := server.httpClient.Do(accessRequest)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	defer accessResponse.Body.Close()
	if accessResponse.StatusCode != http.StatusOK {
		if relayAccessServerProblem(response, accessResponse) {
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(accessResponse.Body, maxRequestBytes))
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("access server refused the token exchange"))
		return
	}
	accessBody, err := io.ReadAll(io.LimitReader(accessResponse.Body, maxRequestBytes+1))
	if err != nil || len(accessBody) > maxRequestBytes {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("access-server response is unavailable"))
		return
	}
	var accessOutput struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := decodeJSON(bytes.NewReader(accessBody), &accessOutput); err != nil || accessOutput.AuthToken == "" {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("access-server response is invalid"))
		return
	}
	authToken, err := aauth.VerifyAuthToken(
		request.Context(), accessOutput.AuthToken, server.keyResolver, server.clock,
	)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if authToken.Issuer != resourceToken.Audience ||
		authToken.DWK != aauth.AccessDiscoveryDocument ||
		authToken.ExpiresAt > agent.ExpiresAt ||
		authToken.MissionS256 != resourceToken.MissionS256 ||
		authToken.Tenant != resourceToken.Tenant || authToken.Account != resourceToken.Account {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("access-server auth token changed the authorized context"))
		return
	}
	if err := aauth.ValidateCurrentAuthTokenContext(
		authToken,
		aauth.AuthTokenContext{
			Issuer: resourceToken.Audience, DiscoveryDocument: aauth.AccessDiscoveryDocument,
			Resource: resourceToken.Issuer, PersonServer: server.issuer, Subject: resourceToken.Subject,
			RequestKey: agent.Confirmation.JWK,
		},
	); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	grantedScopes, err := parseScopes(authToken.Scope)
	if err != nil || !scopeSubset(grantedScopes, scopes) {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("access-server auth token grants an unrequested scope"))
		return
	}
	writePrivateJSON(response, http.StatusOK, struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}{
		AuthToken: accessOutput.AuthToken,
		ExpiresIn: authToken.ExpiresAt - server.clock.Now().Unix(),
	})
}

func (server *Server) validateResourceTokenTopology(resourceToken aauth.ResourceTokenClaims) error {
	if resourceToken.PersonServer != server.issuer {
		return errors.New("resource token does not name this person server")
	}
	switch server.authorizationMode {
	case authorizationModePersonServer:
		if resourceToken.Audience != server.issuer {
			return errors.New("resource token requires Access Server federation")
		}
	case authorizationModeFederated:
		// The explicit constructor selects federation even when the Access
		// Server is collocated at the Person Server's origin.
	default:
		return errors.New("person server authorization mode is invalid")
	}
	return nil
}

func (server *Server) issuePSAuthorizationToken(
	response http.ResponseWriter,
	request *http.Request,
	proof signaturekey.VerifiedRequest,
	agent aauth.AgentTokenClaims,
	resourceToken aauth.ResourceTokenClaims,
	authorizationRequest AuthorizationRequest,
) {
	policyRequest := authorizationRequest
	policyRequest.Scopes = append([]string(nil), authorizationRequest.Scopes...)
	policyRequest.Capabilities = append([]string(nil), authorizationRequest.Capabilities...)
	policyRequest.AgentAdditionalClaims = cloneClaims(authorizationRequest.AgentAdditionalClaims)
	decision, err := server.authorize(request.Context(), policyRequest)
	if err != nil {
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	grantedScopes, err := validateAuthorizationDecision(decision, authorizationRequest.Scopes)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	expiresAt := proof.VerifiedAt().Add(decision.Lifetime)
	agentExpiresAt := time.Unix(agent.ExpiresAt, 0)
	if agentExpiresAt.Before(expiresAt) {
		expiresAt = agentExpiresAt
	}
	if !expiresAt.After(proof.VerifiedAt()) {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("authorization decision has no usable lifetime"))
		return
	}
	claims := aauth.AuthTokenClaims{
		Issuer: server.issuer, DWK: aauth.PersonDiscoveryDocument,
		Audience: resourceToken.Issuer, JTI: server.newID(), PersonServer: server.issuer,
		Subject: resourceToken.Subject, Confirmation: aauth.Confirmation{JWK: agent.Confirmation.JWK},
		IssuedAt: proof.VerifiedAt().Unix(), ExpiresAt: expiresAt.Unix(),
		Scope: strings.Join(grantedScopes, " "), Tenant: resourceToken.Tenant,
	}
	compact, err := aauth.MintAuthToken(server.signingKey, claims)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writePrivateJSON(response, http.StatusOK, struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}{
		AuthToken: compact,
		ExpiresIn: claims.ExpiresAt - proof.VerifiedAt().Unix(),
	})
}

func validateAuthorizationDecision(decision AuthorizationDecision, requested []string) ([]string, error) {
	if decision.Lifetime <= 0 || decision.Lifetime > time.Hour {
		return nil, errors.New("authorization decision lifetime must be positive and at most one hour")
	}
	granted, err := parseScopes(strings.Join(decision.Scopes, " "))
	if err != nil {
		return nil, fmt.Errorf("authorization decision scope: %w", err)
	}
	if !scopeSubset(granted, requested) {
		return nil, errors.New("authorization decision grants an unrequested scope")
	}
	return granted, nil
}

func relayAccessServerProblem(response http.ResponseWriter, accessResponse *http.Response) bool {
	if accessResponse.StatusCode < http.StatusBadRequest || accessResponse.StatusCode >= http.StatusInternalServerError ||
		accessResponse.StatusCode == http.StatusUnauthorized {
		return false
	}
	problem, err := aauth.DecodeProblemResponse(accessResponse)
	if err != nil {
		return false
	}
	writeProblem(response, accessResponse.StatusCode, string(problem.Code), errors.New("access server refused the token exchange"))
	return true
}

func (server *Server) verifyAgentRequest(request *http.Request, requiredComponents []string) (string, aauth.AgentTokenClaims, signaturekey.VerifiedRequest, error) {
	var agent aauth.AgentTokenClaims
	prepared, err := signaturekey.PrepareRequest(request, server.clock, signaturekey.VerifyOptions{
		RequiredComponents: requiredComponents,
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJWT},
		MaxBodyBytes:       maxRequestBytes,
	})
	if err != nil {
		return "", agent, signaturekey.VerifiedRequest{}, err
	}
	compact, ok := prepared.Credential().JWT()
	if !ok {
		return "", agent, signaturekey.VerifiedRequest{}, errors.New("personserver: agent-token credential is required")
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return prepared.VerifiedAt() })
	agent, err = aauth.VerifyAgentToken(request.Context(), compact, server.keyResolver, verificationClock)
	if err != nil {
		return "", agent, signaturekey.VerifiedRequest{}, &requestTokenError{cause: err}
	}
	if agent.PersonServer != server.issuer || agent.ParentAgent != "" {
		return "", agent, signaturekey.VerifiedRequest{}, errors.New("personserver: agent token does not name this person server")
	}
	proof, err := prepared.Verify(agent.Confirmation.JWK)
	if err != nil {
		return "", agent, signaturekey.VerifiedRequest{}, err
	}
	return compact, agent, proof, nil
}

type requestTokenError struct{ cause error }

func (failure *requestTokenError) Error() string { return failure.cause.Error() }
func (failure *requestTokenError) Unwrap() error { return failure.cause }

func writeAgentTokenProblem(response http.ResponseWriter, err error) {
	var tokenFailure *requestTokenError
	if errors.As(err, &tokenFailure) {
		writeEndpointTokenProblem(response, tokenFailure.cause, "invalid_agent_token", "expired_agent_token")
		return
	}
	writeProblem(response, http.StatusUnauthorized, "invalid_agent_token", err)
}

func writeEndpointTokenProblem(response http.ResponseWriter, err error, invalidCode, expiredCode string) {
	var tokenFailure *aauth.TokenValidationError
	if errors.As(err, &tokenFailure) && tokenFailure.Code == aauth.TokenValidationExpired {
		writeProblem(response, http.StatusBadRequest, expiredCode, err)
		return
	}
	writeProblem(response, http.StatusBadRequest, invalidCode, err)
}

func (server *Server) handleMetadata(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{
		"issuer":                server.issuer,
		"person_token_endpoint": server.issuer + "/person",
		"auth_token_endpoint":   server.issuer + "/token",
		"jwks_uri":              server.issuer + "/.well-known/jwks.json",
	})
}

func (server *Server) handleJWKS(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{
		"keys": []jose.JWK{server.signingKey.PublicJWK()},
	})
}

func validatePersonTokenRecord(record PersonTokenRecord) error {
	if record.JTI == "" || record.PersonServer == "" || record.Resource == "" || record.Subject == "" ||
		record.ExpiresAt.IsZero() || !record.RetainUntil.After(record.ExpiresAt) {
		return errors.New("personserver: retained person token is invalid")
	}
	return nil
}

func parseScopes(value string) ([]string, error) {
	scopes, err := aauth.ParseScope(value)
	if err != nil {
		return nil, fmt.Errorf("personserver: token scope: %w", err)
	}
	return scopes, nil
}

func scopeSubset(granted, requested []string) bool {
	if len(granted) == 0 {
		return false
	}
	available := make(map[string]struct{}, len(requested))
	for _, scope := range requested {
		available[scope] = struct{}{}
	}
	for _, scope := range granted {
		if _, ok := available[scope]; !ok {
			return false
		}
	}
	return true
}

func validateAccessServerEndpoint(endpoint string) error {
	return aauth.ValidateEndpoint(endpoint)
}

func decodeJSON(reader io.Reader, destination any) error {
	return httpapi.DecodeJSON(reader, maxRequestBytes, destination)
}

func rejectUnsupportedRequestMembers(members map[string]json.RawMessage) error {
	for name, value := range members {
		if value != nil {
			return fmt.Errorf("personserver: request member %q is not supported by the immediate flow", name)
		}
	}
	return nil
}

func parseAuthorizationCapabilities(raw json.RawMessage) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("personserver: capabilities must be a JSON array")
	}
	var capabilities []string
	if err := json.Unmarshal(raw, &capabilities); err != nil {
		return nil, fmt.Errorf("personserver: capabilities: %w", err)
	}
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if _, duplicate := seen[capability]; duplicate {
			return nil, fmt.Errorf("personserver: capabilities repeats %q", capability)
		}
		if _, err := aauth.FormatCapabilities([]string{capability}); err != nil {
			return nil, fmt.Errorf("personserver: capability %q: %w", capability, err)
		}
		seen[capability] = struct{}{}
	}
	return append([]string(nil), capabilities...), nil
}

func cloneAuthorizationRequest(request AuthorizationRequest) AuthorizationRequest {
	request.Scopes = append([]string(nil), request.Scopes...)
	request.Capabilities = append([]string(nil), request.Capabilities...)
	request.AgentAdditionalClaims = cloneClaims(request.AgentAdditionalClaims)
	return request
}

func cloneClaims(claims map[string]json.RawMessage) map[string]json.RawMessage {
	if len(claims) == 0 {
		return nil
	}
	cloned := make(map[string]json.RawMessage, len(claims))
	for name, value := range claims {
		cloned[name] = append(json.RawMessage(nil), value...)
	}
	return cloned
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	httpapi.WriteJSON(response, status, value)
}

func writePrivateJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(response, status, value)
}

func writeProblem(response http.ResponseWriter, status int, code string, cause error) {
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteProblem(response, status, code, cause)
}
