// Package resource implements direct Agent and Person identity access,
// Resource-managed opaque sessions, and explicit PS-authorized or federated
// auth-token access. It also implements direct Agent-token revocation,
// immediate R3 class and per-call
// documents and enforcement, exposes a verified auth token to a call-chain
// intermediary, retains observed three-party revocation state, and supports
// Resource-held delivery in the federated composition. A separate EventService
// owns public Events registration and outbound delivery.
package resource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// FederatedAuthorizationConfig supplies a federated auth-token Resource's
// identity, policy, storage, and application dependencies. Its resource tokens
// name the configured Access Server. A mission-bound Person token requires no
// extra Resource configuration: only its signed digest is copied into the
// Resource token and later principal context.
type FederatedAuthorizationConfig struct {
	Issuer       string
	AccessServer string
	SigningKey   jose.SigningKey
	// KeyResolver must retain the Resource's own historical verification keys
	// for the lifetime of every R3 class authorization.
	KeyResolver signaturekey.KeyResolver
	Clock       aauth.Clock
	// NewID must be concurrency-safe and return a nonempty identifier that is
	// never reused while any token derived from it can remain valid.
	NewID                         func() string
	ScopeDescriptions             map[string]string
	AdditionalSignatureComponents []string
	MaxSignedBodyBytes            int64
	RequiredScopes                func(*http.Request) []string
	ResolvePerson                 func(context.Context, PersonIdentity, PersonContext) error
	// ValidateAccount confirms an optional Resource-owned account belongs to
	// the verified person before the account enters a Resource token.
	ValidateAccount func(context.Context, PersonIdentity, string) error
	Protected       http.Handler
	// R3 optionally enables registered R3 authorization on this HTTP Resource.
	R3 *R3Config
	// HeldInvocations enables Resource-held auth-token delivery. The host store
	// is a trusted persistence and authorization boundary; see
	// HeldInvocationStore.
	HeldInvocations HeldInvocationStore
	// HoldAuthTokenRequest selects held delivery per verified person-token
	// request. A nil function selects held delivery for every request when
	// HeldInvocations is configured.
	HoldAuthTokenRequest func(*http.Request) bool
	// MaxRetainedRequestBodyBytes bounds the retained application request body.
	MaxRetainedRequestBodyBytes int64
	// MaxRetainedResponseBodyBytes bounds the retained application response body.
	MaxRetainedResponseBodyBytes int64
	// MaxRetainedHeaderBytes bounds retained request headers and response headers
	// plus trailers. All three retained-application limits must be positive when
	// held delivery or R3 per-call retry is configured, and zero otherwise.
	MaxRetainedHeaderBytes int64
}

// PSAuthorizationConfig supplies a PS-authorization Resource's identity,
// policy, and application dependencies. Its resource tokens name the Person
// Server that issued the presented person token. This immediate composition
// does not include Resource-held delivery.
type PSAuthorizationConfig struct {
	Issuer                        string
	SigningKey                    jose.SigningKey
	KeyResolver                   signaturekey.KeyResolver
	Clock                         aauth.Clock
	NewID                         func() string
	ScopeDescriptions             map[string]string
	AdditionalSignatureComponents []string
	MaxSignedBodyBytes            int64
	RequiredScopes                func(*http.Request) []string
	ResolvePerson                 func(context.Context, PersonIdentity, PersonContext) error
	Protected                     http.Handler
	// R3 optionally enables registered class authorization on this HTTP
	// Resource. Per-call authorization remains a federated-only composition.
	R3 *R3Config
	// Budget optionally enables proactive Budget offers and fixed-price
	// enforcement for metered protected routes.
	Budget *BudgetConfig
	// AuthTokenStatuses enables observation and revocation of accepted auth
	// tokens. A nil store omits the revocation endpoint.
	AuthTokenStatuses AuthTokenStatusStore
}

// AgentIdentityConfig constructs a Resource that authorizes application
// requests from the verified Agent identity. It issues no Resource token and
// needs no Resource signing key, Access Server, scope catalog, or person
// resolver.
type AgentIdentityConfig struct {
	Issuer                        string
	KeyResolver                   signaturekey.KeyResolver
	Clock                         aauth.Clock
	AdditionalSignatureComponents []string
	MaxSignedBodyBytes            int64
	Protected                     http.Handler
	// AgentTokenRevocations enables the issuing Agent Provider's signed
	// revocation endpoint and checks retained markers before application use.
	AgentTokenRevocations AgentTokenRevocationStore
}

// PersonIdentityConfig constructs a Resource that authorizes application
// requests from the verified Person identity. It issues no Resource token and
// needs no Resource signing key, Access Server, or scope catalog.
type PersonIdentityConfig struct {
	Issuer                        string
	KeyResolver                   signaturekey.KeyResolver
	Clock                         aauth.Clock
	AdditionalSignatureComponents []string
	MaxSignedBodyBytes            int64
	ResolvePerson                 func(context.Context, PersonIdentity, PersonContext) error
	Protected                     http.Handler
}

// PersonIdentity is the stable person reference asserted to this Resource.
// ResolvePerson matches it to an existing Resource record or establishes that
// record on first use.
type PersonIdentity struct {
	Issuer  string
	Subject string
}

// PersonContext contains current signed assertions that may inform local
// policy or profile data. It is not part of the stable person identifier.
type PersonContext struct {
	MissionS256      string
	Tenant           string
	AdditionalClaims map[string]json.RawMessage
}

// AuthPrincipal is the person and scoped grant established by one current
// auth token.
type AuthPrincipal struct {
	PersonServer     string
	Subject          string
	MissionS256      string
	Tenant           string
	Account          *string
	Scope            []string
	Confirmation     jose.JWK
	AdditionalClaims map[string]json.RawMessage
}

// PersonPrincipal is the identity established by one verified person token.
// It carries no authorization scope.
type PersonPrincipal struct {
	PersonServer string
	Subject      string
	Tenant       string
	Confirmation jose.JWK
}

// AgentPrincipal is the Agent identity established by one verified agent
// token and its matching request proof. ParentAgent is nonempty for a
// one-level sub-agent. The principal carries identity, not a person or an
// authorization scope.
type AgentPrincipal struct {
	AgentProvider    string
	Agent            string
	ParentAgent      string
	PersonServer     string
	Confirmation     jose.JWK
	AdditionalClaims map[string]json.RawMessage
}

type authPrincipalContextKey struct{}
type authTokenContextKey struct{}
type agentPrincipalContextKey struct{}
type personPrincipalContextKey struct{}

// AuthPrincipalFromContext returns the scoped auth-token principal established
// for a protected request.
func AuthPrincipalFromContext(ctx context.Context) (AuthPrincipal, bool) {
	if ctx == nil {
		return AuthPrincipal{}, false
	}
	principal, ok := ctx.Value(authPrincipalContextKey{}).(AuthPrincipal)
	if !ok {
		return AuthPrincipal{}, false
	}
	if principal.Scope != nil {
		principal.Scope = append(make([]string, 0, len(principal.Scope)), principal.Scope...)
	}
	principal.AdditionalClaims = cloneAdditionalClaims(principal.AdditionalClaims)
	principal.Account = cloneAuthorizationAccount(principal.Account)
	return principal, true
}

// AuthTokenFromContext returns the exact compact auth token verified for the
// current protected request. It is absent from unverified and non-auth-token
// contexts. Call-chaining intermediaries can pass this value to their Person
// Server as upstream_token; callers must not log it.
func AuthTokenFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	compact, ok := ctx.Value(authTokenContextKey{}).(string)
	if !ok || compact == "" {
		return "", false
	}
	return compact, true
}

// AgentPrincipalFromContext returns the Agent identity established for an
// agent-identity protected request.
func AgentPrincipalFromContext(ctx context.Context) (AgentPrincipal, bool) {
	if ctx == nil {
		return AgentPrincipal{}, false
	}
	principal, ok := ctx.Value(agentPrincipalContextKey{}).(AgentPrincipal)
	if !ok {
		return AgentPrincipal{}, false
	}
	principal.AdditionalClaims = cloneAdditionalClaims(principal.AdditionalClaims)
	return principal, true
}

// PersonPrincipalFromContext returns the Person identity established for a
// person-identity protected request.
func PersonPrincipalFromContext(ctx context.Context) (PersonPrincipal, bool) {
	if ctx == nil {
		return PersonPrincipal{}, false
	}
	principal, ok := ctx.Value(personPrincipalContextKey{}).(PersonPrincipal)
	return principal, ok
}

// Server protects one ordinary HTTP handler under one explicit access mode.
type Server struct {
	issuer                        string
	accessMode                    aauth.AccessMode
	authorizationTopology         authorizationTopology
	accessServer                  string
	signingKey                    jose.SigningKey
	keyResolver                   signaturekey.KeyResolver
	clock                         aauth.Clock
	newID                         func() string
	scopeDescriptions             map[string]string
	additionalSignatureComponents []string
	maxSignedBodyBytes            int64
	requiredScopes                func(*http.Request) []string
	resolvePerson                 func(context.Context, PersonIdentity, PersonContext) error
	validateAccount               func(context.Context, PersonIdentity, string) error
	protected                     http.Handler
	authTokenStatuses             AuthTokenStatusStore
	agentTokenRevocations         AgentTokenRevocationStore
	heldInvocations               HeldInvocationStore
	holdAuthTokenRequest          func(*http.Request) bool
	maxRetainedRequestBodyBytes   int64
	maxRetainedResponseBodyBytes  int64
	maxRetainedHeaderBytes        int64
	r3                            *r3Config
	budget                        *budgetConfig
	handler                       http.Handler
}

type authorizationTopology uint8

const (
	authorizationTopologyFederated authorizationTopology = iota + 1
	authorizationTopologyPersonServer
)

type directIdentityConfig struct {
	issuer                        string
	accessMode                    aauth.AccessMode
	keyResolver                   signaturekey.KeyResolver
	clock                         aauth.Clock
	additionalSignatureComponents []string
	maxSignedBodyBytes            int64
	resolvePerson                 func(context.Context, PersonIdentity, PersonContext) error
	protected                     http.Handler
	agentTokenRevocations         AgentTokenRevocationStore
}

// NewAgentIdentity constructs an identity-only Resource that accepts verified
// agent-token requests.
func NewAgentIdentity(config AgentIdentityConfig) (*Server, error) {
	return newDirectIdentityServer(directIdentityConfig{
		issuer: config.Issuer, accessMode: aauth.AccessModeAgentToken,
		keyResolver: config.KeyResolver, clock: config.Clock,
		additionalSignatureComponents: config.AdditionalSignatureComponents,
		maxSignedBodyBytes:            config.MaxSignedBodyBytes, protected: config.Protected,
		agentTokenRevocations: config.AgentTokenRevocations,
	})
}

// NewPersonIdentity constructs an identity-only Resource that accepts
// verified person-token requests.
func NewPersonIdentity(config PersonIdentityConfig) (*Server, error) {
	if config.ResolvePerson == nil {
		return nil, errors.New("aauth: person-identity Resource requires a person resolver")
	}
	return newDirectIdentityServer(directIdentityConfig{
		issuer: config.Issuer, accessMode: aauth.AccessModePersonToken,
		keyResolver: config.KeyResolver, clock: config.Clock,
		additionalSignatureComponents: config.AdditionalSignatureComponents,
		maxSignedBodyBytes:            config.MaxSignedBodyBytes,
		resolvePerson:                 config.ResolvePerson, protected: config.Protected,
	})
}

func newDirectIdentityServer(config directIdentityConfig) (*Server, error) {
	if err := aauth.ValidateServerIdentifier(config.issuer); err != nil {
		return nil, fmt.Errorf("aauth: resource issuer: %w", err)
	}
	if config.keyResolver == nil {
		return nil, errors.New("aauth: resource key resolver is required")
	}
	if config.clock == nil {
		return nil, errors.New("aauth: resource clock is required")
	}
	if config.protected == nil {
		return nil, errors.New("aauth: protected handler is required")
	}
	if config.maxSignedBodyBytes < 0 {
		return nil, errors.New("aauth: resource maximum signed body size must not be negative")
	}
	additionalComponents, err := validateAdditionalSignatureComponents(config.additionalSignatureComponents)
	if err != nil {
		return nil, err
	}
	server := &Server{
		issuer: config.issuer, accessMode: config.accessMode,
		keyResolver: config.keyResolver, clock: config.clock,
		additionalSignatureComponents: additionalComponents,
		maxSignedBodyBytes:            config.maxSignedBodyBytes,
		resolvePerson:                 config.resolvePerson, protected: config.protected,
		agentTokenRevocations: config.agentTokenRevocations,
	}
	server.handler = server.newHandler()
	return server, nil
}

// NewFederatedAuthorization constructs a federated Resource that challenges person-token
// requests, issues resource tokens to one Access Server, and accepts scoped
// auth-token requests from that Access Server.
func NewFederatedAuthorization(config FederatedAuthorizationConfig) (*Server, error) {
	if err := aauth.ValidateServerIdentifier(config.AccessServer); err != nil {
		return nil, fmt.Errorf("aauth: resource access server: %w", err)
	}
	return newAuthorizationServer(config, authorizationTopologyFederated, nil, nil)
}

// NewPSAuthorization constructs a Resource that challenges person-token
// requests, issues each resource token to the Person Server that issued the
// presented person token, and accepts scoped or class-R3 auth tokens from that
// PS.
func NewPSAuthorization(config PSAuthorizationConfig) (*Server, error) {
	return newAuthorizationServer(FederatedAuthorizationConfig{
		Issuer: config.Issuer, SigningKey: config.SigningKey,
		KeyResolver: config.KeyResolver, Clock: config.Clock, NewID: config.NewID,
		ScopeDescriptions:             config.ScopeDescriptions,
		AdditionalSignatureComponents: config.AdditionalSignatureComponents,
		MaxSignedBodyBytes:            config.MaxSignedBodyBytes,
		RequiredScopes:                config.RequiredScopes, ResolvePerson: config.ResolvePerson,
		Protected: config.Protected,
		R3:        config.R3,
	}, authorizationTopologyPersonServer, config.AuthTokenStatuses, config.Budget)
}

func newAuthorizationServer(
	config FederatedAuthorizationConfig,
	topology authorizationTopology,
	authTokenStatuses AuthTokenStatusStore,
	budget *BudgetConfig,
) (*Server, error) {
	if err := aauth.ValidateServerIdentifier(config.Issuer); err != nil {
		return nil, fmt.Errorf("aauth: resource issuer: %w", err)
	}
	if config.SigningKey.ID() == "" {
		return nil, errors.New("aauth: resource signing key is required")
	}
	if _, err := config.SigningKey.PublicJWK().PublicKey(); err != nil {
		return nil, errors.New("aauth: resource signing key is invalid")
	}
	if config.KeyResolver == nil {
		return nil, errors.New("aauth: resource key resolver is required")
	}
	if config.Clock == nil {
		return nil, errors.New("aauth: resource clock is required")
	}
	if config.NewID == nil {
		return nil, errors.New("aauth: resource token ID source is required")
	}
	if config.Protected == nil {
		return nil, errors.New("aauth: protected handler is required")
	}
	if config.MaxSignedBodyBytes < 0 {
		return nil, errors.New("aauth: resource maximum signed body size must not be negative")
	}
	if config.RequiredScopes == nil && config.R3 == nil {
		return nil, errors.New("aauth: resource required-scope policy is required")
	}
	if config.ResolvePerson == nil {
		return nil, errors.New("aauth: resource person resolver is required")
	}
	if config.HoldAuthTokenRequest != nil && config.HeldInvocations == nil {
		return nil, errors.New("aauth: resource held-request selector requires held invocations")
	}
	validatedR3, err := validateR3Config(config.R3)
	if err != nil {
		return nil, err
	}
	if validatedR3 != nil && topology == authorizationTopologyPersonServer && validatedR3.perCall != nil {
		return nil, errors.New("aauth: Resource R3 per-call authorization requires federated authorization")
	}
	validatedBudget, err := validateBudgetConfig(budget, topology)
	if err != nil {
		return nil, err
	}
	retainsApplication := config.HeldInvocations != nil || validatedR3 != nil && validatedR3.perCall != nil
	for _, bound := range []struct {
		name  string
		limit int64
	}{
		{name: "retained request body", limit: config.MaxRetainedRequestBodyBytes},
		{name: "retained response body", limit: config.MaxRetainedResponseBodyBytes},
		{name: "retained header", limit: config.MaxRetainedHeaderBytes},
	} {
		name, limit := bound.name, bound.limit
		if limit < 0 {
			return nil, fmt.Errorf("aauth: resource maximum %s size must not be negative", name)
		}
		if retainsApplication && limit == 0 {
			return nil, fmt.Errorf("aauth: resource maximum %s size is required with retained application state", name)
		}
		if !retainsApplication && limit != 0 {
			return nil, fmt.Errorf("aauth: resource maximum %s size requires retained application state", name)
		}
	}
	scopeDescriptions := make(map[string]string, len(config.ScopeDescriptions))
	for scope, description := range config.ScopeDescriptions {
		if err := aauth.ValidateScopeValue(scope); err != nil {
			return nil, fmt.Errorf("aauth: resource scope: %w", err)
		}
		if strings.TrimSpace(description) == "" {
			return nil, fmt.Errorf("aauth: resource scope %q requires a nonblank description", scope)
		}
		scopeDescriptions[scope] = description
	}
	if len(scopeDescriptions) == 0 && validatedR3 == nil {
		return nil, errors.New("aauth: resource requires at least one scope")
	}
	requiredScopes := config.RequiredScopes
	if requiredScopes == nil {
		requiredScopes = func(*http.Request) []string { return nil }
	}
	additionalComponents, err := validateAdditionalSignatureComponents(config.AdditionalSignatureComponents)
	if err != nil {
		return nil, err
	}
	server := &Server{
		issuer:                        config.Issuer,
		accessMode:                    aauth.AccessModeAuthToken,
		authorizationTopology:         topology,
		accessServer:                  config.AccessServer,
		signingKey:                    config.SigningKey,
		keyResolver:                   config.KeyResolver,
		clock:                         config.Clock,
		newID:                         config.NewID,
		scopeDescriptions:             scopeDescriptions,
		additionalSignatureComponents: additionalComponents,
		maxSignedBodyBytes:            config.MaxSignedBodyBytes,
		requiredScopes:                requiredScopes,
		resolvePerson:                 config.ResolvePerson,
		validateAccount:               config.ValidateAccount,
		protected:                     config.Protected,
		authTokenStatuses:             authTokenStatuses,
		heldInvocations:               config.HeldInvocations,
		holdAuthTokenRequest:          config.HoldAuthTokenRequest,
		maxRetainedRequestBodyBytes:   config.MaxRetainedRequestBodyBytes,
		maxRetainedResponseBodyBytes:  config.MaxRetainedResponseBodyBytes,
		maxRetainedHeaderBytes:        config.MaxRetainedHeaderBytes,
		r3:                            validatedR3,
		budget:                        validatedBudget,
	}
	server.handler = server.newHandler()
	return server, nil
}

func validateAdditionalSignatureComponents(components []string) ([]string, error) {
	validated := make([]string, len(components))
	seen := make(map[string]struct{}, len(components))
	for index, component := range components {
		if err := signaturekey.ValidateAdditionalComponent(component); err != nil {
			return nil, fmt.Errorf("aauth: resource: %w", err)
		}
		if _, duplicate := seen[component]; duplicate {
			return nil, fmt.Errorf("aauth: resource additional signature component %q is duplicated", component)
		}
		seen[component] = struct{}{}
		validated[index] = component
	}
	return validated, nil
}

// Handler returns the Resource's discovery, authorization, optional revocation,
// and protected request surface.
func (server *Server) Handler() http.Handler {
	if server == nil || server.handler == nil {
		return http.NotFoundHandler()
	}
	return server.handler
}

func (server *Server) newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/aauth-resource.json", server.serveMetadata)
	if server.signingKey.ID() != "" {
		mux.HandleFunc("GET /.well-known/jwks.json", server.serveJWKS)
	}
	if server.accessMode == aauth.AccessModeAuthToken {
		mux.HandleFunc("POST /authorize", server.serveAuthorization)
	}
	if server.authTokenStatuses != nil || server.agentTokenRevocations != nil {
		mux.HandleFunc("POST /revoke", server.serveRevocation)
	}
	if server.r3 != nil {
		mux.HandleFunc("/r3/{document}", server.serveR3Document)
	}
	if server.heldInvocations != nil {
		mux.HandleFunc("GET /pending/{id}", server.serveHeldPoll)
		mux.HandleFunc("/pending/", server.serveHeldNamespace)
	}
	mux.Handle("/", http.HandlerFunc(server.serveProtected))
	return mux
}

func (server *Server) serveMetadata(response http.ResponseWriter, _ *http.Request) {
	// The metadata field applies to protected application routes. The
	// authorization endpoint also requires its JSON content-type and digest,
	// plus these advertised components.
	writeJSON(response, http.StatusOK, struct {
		Issuer                        string                    `json:"issuer"`
		JWKSURI                       string                    `json:"jwks_uri,omitempty"`
		AccessMode                    string                    `json:"access_mode"`
		AuthorizationEndpoint         string                    `json:"authorization_endpoint,omitempty"`
		RevocationEndpoint            string                    `json:"revocation_endpoint,omitempty"`
		ScopeDescriptions             map[string]string         `json:"scope_descriptions,omitempty"`
		AdditionalSignatureComponents []string                  `json:"additional_signature_components,omitempty"`
		R3Vocabularies                map[string]string         `json:"r3_vocabularies,omitempty"`
		BudgetUnits                   []budgets.UnitDeclaration `json:"budget_units,omitempty"`
	}{
		Issuer:                        server.issuer,
		JWKSURI:                       resourceJWKSURI(server),
		AccessMode:                    string(server.accessMode),
		AuthorizationEndpoint:         resourceAuthorizationEndpoint(server),
		RevocationEndpoint:            resourceRevocationEndpoint(server),
		ScopeDescriptions:             cloneScopeDescriptions(server.scopeDescriptions),
		AdditionalSignatureComponents: append([]string(nil), server.additionalSignatureComponents...),
		R3Vocabularies:                resourceR3Vocabularies(server),
		BudgetUnits:                   resourceBudgetUnits(server),
	})
}

func resourceBudgetUnits(server *Server) []budgets.UnitDeclaration {
	if server == nil || server.budget == nil {
		return nil
	}
	return append([]budgets.UnitDeclaration(nil), server.budget.units...)
}

func resourceR3Vocabularies(server *Server) map[string]string {
	if server == nil || server.r3 == nil {
		return nil
	}
	vocabularies := make(map[string]string, len(server.r3.vocabularyOrder))
	for _, uri := range server.r3.vocabularyOrder {
		vocabularies[string(uri)] = server.r3.vocabularies[uri].definition.Receipt().DiscoveryEndpoint()
	}
	return vocabularies
}

func resourceJWKSURI(server *Server) string {
	if server.signingKey.ID() == "" {
		return ""
	}
	return server.issuer + "/.well-known/jwks.json"
}

func resourceAuthorizationEndpoint(server *Server) string {
	if server.accessMode != aauth.AccessModeAuthToken {
		return ""
	}
	return server.issuer + "/authorize"
}

func resourceRevocationEndpoint(server *Server) string {
	if server.authTokenStatuses == nil && server.agentTokenRevocations == nil {
		return ""
	}
	return server.issuer + "/revoke"
}

func (server *Server) serveJWKS(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, struct {
		Keys []jose.JWK `json:"keys"`
	}{Keys: []jose.JWK{server.signingKey.PublicJWK()}})
}

func cloneScopeDescriptions(descriptions map[string]string) map[string]string {
	cloned := make(map[string]string, len(descriptions))
	for scope, description := range descriptions {
		cloned[scope] = description
	}
	return cloned
}
