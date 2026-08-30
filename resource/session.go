package resource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	aauth "aauth-go"
	"aauth-go/jose"
	"aauth-go/signaturekey"
)

// SessionInteractionPolicy configures the Resource's authenticated user
// interface and the pending authorization it correlates.
type SessionInteractionPolicy struct {
	URL                 string
	Lifetime            time.Duration
	RetryAfter          time.Duration
	MaximumCodeAttempts int
}

// SessionGrant is one Resource-local person and scope decision. Lifetime is a
// Resource policy choice because Core does not define session-token expiry.
type SessionGrant struct {
	Subject  string
	Scope    []string
	Lifetime time.Duration
}

// SessionAuthorizationRequest is the verified context available to optional
// immediate Resource policy. A false result asks for the configured
// interaction, or refuses when interaction is disabled.
type SessionAuthorizationRequest struct {
	AgentPrincipal AgentPrincipal
	Method         string
	Path           string
	RequiredScopes []string
}

// ResourceManagedConfig supplies the distinct two-party Resource composition.
// It issues no JWT and has no Person Server or Access Server dependency.
type ResourceManagedConfig struct {
	Issuer                        string
	KeyResolver                   signaturekey.KeyResolver
	Clock                         aauth.Clock
	Random                        io.Reader
	ScopeDescriptions             map[string]string
	AdditionalSignatureComponents []string
	MaxSignedBodyBytes            int64
	RequiredScopes                func(*http.Request) []string
	AuthorizeImmediately          func(context.Context, SessionAuthorizationRequest) (SessionGrant, bool, error)
	// Interaction is optional. Its zero value selects immediate-only policy.
	Interaction SessionInteractionPolicy
	// Sessions needs only SessionStore for immediate-only policy. Enabling
	// Interaction requires the supplied value to implement DeferredSessionStore.
	Sessions  SessionStore
	Protected http.Handler
}

// SessionPrincipal is the Resource-local person, stable Agent identity, and
// scope established by an opaque session plus the current verified proof.
type SessionPrincipal struct {
	Resource         string
	AgentProvider    string
	Agent            string
	ParentAgent      string
	Subject          string
	Scope            []string
	Confirmation     jose.JWK
	AdditionalClaims map[string]json.RawMessage
}

type sessionPrincipalContextKey struct{}

// SessionPrincipalFromContext returns an independent projection of the
// Resource-managed principal established for one protected request.
func SessionPrincipalFromContext(ctx context.Context) (SessionPrincipal, bool) {
	if ctx == nil {
		return SessionPrincipal{}, false
	}
	principal, ok := ctx.Value(sessionPrincipalContextKey{}).(SessionPrincipal)
	if !ok {
		return SessionPrincipal{}, false
	}
	principal.Scope = append([]string(nil), principal.Scope...)
	principal.AdditionalClaims = cloneSessionClaims(principal.AdditionalClaims)
	return principal, true
}

// ResourceManagedServer protects one handler with immediate Resource policy,
// optional Resource-owned interaction, and opaque session authorization. It
// is separate from Server because its dependencies and state model are not an
// auth-token topology.
type ResourceManagedServer struct {
	issuer                        string
	keyResolver                   signaturekey.KeyResolver
	clock                         aauth.Clock
	random                        io.Reader
	randomMu                      sync.Mutex
	scopeDescriptions             map[string]string
	additionalSignatureComponents []string
	maxSignedBodyBytes            int64
	requiredScopes                func(*http.Request) []string
	authorizeImmediately          func(context.Context, SessionAuthorizationRequest) (SessionGrant, bool, error)
	interaction                   SessionInteractionPolicy
	sessions                      SessionStore
	deferredSessions              DeferredSessionStore
	protected                     http.Handler
	handler                       http.Handler
}

// NewResourceManaged constructs a Resource that authorizes directly from a
// verified Agent, either through immediate policy alone or with Resource-owned
// interaction as a fallback, then accepts an opaque proof-bound session token.
func NewResourceManaged(config ResourceManagedConfig) (*ResourceManagedServer, error) {
	if err := aauth.ValidateServerIdentifier(config.Issuer); err != nil {
		return nil, fmt.Errorf("aauth: resource-managed issuer: %w", err)
	}
	if config.KeyResolver == nil {
		return nil, errors.New("aauth: resource-managed key resolver is required")
	}
	if config.Clock == nil {
		return nil, errors.New("aauth: resource-managed clock is required")
	}
	if config.MaxSignedBodyBytes < 0 {
		return nil, errors.New("aauth: resource-managed maximum signed body size must not be negative")
	}
	if config.RequiredScopes == nil {
		return nil, errors.New("aauth: resource-managed required-scope policy is required")
	}
	if config.Sessions == nil {
		return nil, errors.New("aauth: resource-managed session store is required")
	}
	if config.Protected == nil {
		return nil, errors.New("aauth: resource-managed protected handler is required")
	}
	scopes, err := validateManagedScopeDescriptions(config.ScopeDescriptions)
	if err != nil {
		return nil, err
	}
	components, err := validateAdditionalSignatureComponents(config.AdditionalSignatureComponents)
	if err != nil {
		return nil, err
	}
	var deferredSessions DeferredSessionStore
	if sessionInteractionPolicyEnabled(config.Interaction) {
		if err := validateSessionInteractionPolicy(config.Interaction); err != nil {
			return nil, err
		}
		var ok bool
		deferredSessions, ok = config.Sessions.(DeferredSessionStore)
		if !ok {
			return nil, errors.New("aauth: resource-managed interaction requires a deferred session store")
		}
	} else if config.AuthorizeImmediately == nil {
		return nil, errors.New("aauth: resource-managed immediate authorization policy is required when interaction is disabled")
	}
	server := &ResourceManagedServer{
		issuer: config.Issuer, keyResolver: config.KeyResolver, clock: config.Clock,
		random: config.Random, scopeDescriptions: scopes,
		additionalSignatureComponents: components, maxSignedBodyBytes: config.MaxSignedBodyBytes,
		requiredScopes: config.RequiredScopes, authorizeImmediately: config.AuthorizeImmediately,
		interaction: config.Interaction, sessions: config.Sessions, deferredSessions: deferredSessions,
		protected: config.Protected,
	}
	server.handler = server.newHandler()
	return server, nil
}

// Handler returns the Resource metadata, pending interaction, and protected
// application surface.
func (server *ResourceManagedServer) Handler() http.Handler {
	if server == nil || server.handler == nil {
		return http.NotFoundHandler()
	}
	return server.handler
}

func (server *ResourceManagedServer) newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/aauth-resource.json", server.serveMetadata)
	mux.HandleFunc("/session/pending/{id}", server.serveSessionPoll)
	mux.HandleFunc("/session/pending/", server.serveSessionPendingNamespace)
	mux.Handle("/", http.HandlerFunc(server.serveResourceManaged))
	return mux
}

func (server *ResourceManagedServer) serveMetadata(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, struct {
		Issuer                        string            `json:"issuer"`
		AccessMode                    string            `json:"access_mode"`
		ScopeDescriptions             map[string]string `json:"scope_descriptions"`
		AdditionalSignatureComponents []string          `json:"additional_signature_components,omitempty"`
	}{
		Issuer: server.issuer, AccessMode: string(aauth.AccessModeSessionToken),
		ScopeDescriptions:             cloneScopeDescriptions(server.scopeDescriptions),
		AdditionalSignatureComponents: append([]string(nil), server.additionalSignatureComponents...),
	})
}

func validateManagedScopeDescriptions(descriptions map[string]string) (map[string]string, error) {
	if len(descriptions) == 0 {
		return nil, errors.New("aauth: resource-managed requires at least one scope description")
	}
	validated := make(map[string]string, len(descriptions))
	for scope, description := range descriptions {
		if err := aauth.ValidateScopeValue(scope); err != nil {
			return nil, fmt.Errorf("aauth: resource-managed scope: %w", err)
		}
		if strings.TrimSpace(description) == "" {
			return nil, fmt.Errorf("aauth: resource-managed scope %q requires a nonblank description", scope)
		}
		validated[scope] = description
	}
	return validated, nil
}

func validateSessionInteractionPolicy(policy SessionInteractionPolicy) error {
	if _, err := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{
		URL: policy.URL, Code: "0000-0000",
	}); err != nil {
		return fmt.Errorf("aauth: resource-managed interaction: %w", err)
	}
	if policy.Lifetime <= 0 {
		return errors.New("aauth: resource-managed interaction lifetime must be positive")
	}
	if policy.RetryAfter < 0 || policy.RetryAfter%time.Second != 0 {
		return errors.New("aauth: resource-managed interaction retry interval must be nonnegative whole seconds")
	}
	if policy.MaximumCodeAttempts <= 0 {
		return errors.New("aauth: resource-managed interaction attempt bound must be positive")
	}
	return nil
}

func sessionInteractionPolicyEnabled(policy SessionInteractionPolicy) bool {
	return policy != (SessionInteractionPolicy{})
}

func cloneSessionClaims(values map[string]json.RawMessage) map[string]json.RawMessage {
	if values == nil {
		return nil
	}
	cloned := make(map[string]json.RawMessage, len(values))
	for name, value := range values {
		cloned[name] = append(json.RawMessage(nil), value...)
	}
	return cloned
}
