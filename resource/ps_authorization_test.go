package resource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "aauth-go"
	"aauth-go/jose"
	"aauth-go/signaturekey"
)

func TestNewPSAuthorizationRequiresOnlyThreePartyDependencies(t *testing.T) {
	t.Parallel()

	valid := PSAuthorizationConfig{
		Issuer: resourceIssuer, SigningKey: testSigningKey(t, "three-party-config", 50),
		KeyResolver: signaturekey.StaticKeyResolver{}, Clock: aauth.SystemClock{},
		NewID:             func() string { return "resource-token" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected:         http.NotFoundHandler(),
	}
	if _, err := NewPSAuthorization(valid); err != nil {
		t.Fatalf("complete three-party configuration: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*PSAuthorizationConfig)
	}{
		{name: "issuer", change: func(config *PSAuthorizationConfig) { config.Issuer = "" }},
		{name: "signing key", change: func(config *PSAuthorizationConfig) { config.SigningKey = jose.SigningKey{} }},
		{name: "key resolver", change: func(config *PSAuthorizationConfig) { config.KeyResolver = nil }},
		{name: "clock", change: func(config *PSAuthorizationConfig) { config.Clock = nil }},
		{name: "id source", change: func(config *PSAuthorizationConfig) { config.NewID = nil }},
		{name: "scope catalog", change: func(config *PSAuthorizationConfig) { config.ScopeDescriptions = nil }},
		{name: "required scopes", change: func(config *PSAuthorizationConfig) { config.RequiredScopes = nil }},
		{name: "person resolver", change: func(config *PSAuthorizationConfig) { config.ResolvePerson = nil }},
		{name: "handler", change: func(config *PSAuthorizationConfig) { config.Protected = nil }},
		{name: "body limit", change: func(config *PSAuthorizationConfig) { config.MaxSignedBodyBytes = -1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			if _, err := NewPSAuthorization(config); err == nil {
				t.Fatal("incomplete three-party configuration was accepted")
			}
		})
	}
}

func TestPSAuthorizationResourceIssuesToPersonServerAndAcceptsOnlyPSAuthTokens(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "three-party-person", 51)
	resourceKey := testSigningKey(t, "three-party-resource", 52)
	agentKey := testSigningKey(t, "three-party-agent", 53)
	accessKey := testSigningKey(t, "three-party-access", 54)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	var principals []AuthPrincipal
	var presentedAuthTokens []string
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "three-party-resource-token" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			compact, ok := AuthTokenFromContext(request.Context())
			if !ok || compact == "" {
				t.Error("protected request did not carry its verified auth token")
				return
			}
			principal, ok := AuthPrincipalFromContext(request.Context())
			if !ok {
				t.Error("protected request did not carry AuthPrincipal")
				return
			}
			presentedAuthTokens = append(presentedAuthTokens, compact)
			principals = append(principals, principal)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "three-party-person-token")
	authorize := signedRequest(
		t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", `{"scope":"records.read"}`,
	)
	authorizeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(authorizeResponse, authorize)
	if authorizeResponse.Code != http.StatusOK {
		t.Fatalf("authorize = %d %s", authorizeResponse.Code, authorizeResponse.Body.String())
	}
	var authorization struct {
		ResourceToken string `json:"resource_token"`
	}
	if err := json.Unmarshal(authorizeResponse.Body.Bytes(), &authorization); err != nil {
		t.Fatal(err)
	}
	resourceClaims, err := aauth.VerifyResourceToken(context.Background(), authorization.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if resourceClaims.Audience != personIssuer || resourceClaims.PersonServer != personIssuer {
		t.Fatalf("three-party resource token = %#v", resourceClaims)
	}

	psAuthToken := mintAuthToken(t, personKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		JTI: "three-party-auth-token", PersonServer: personIssuer, Subject: "person-1",
		Scope: "records.read", Tenant: "tenant-1",
	})
	protected := signedRequest(t, clock, agentKey, psAuthToken, http.MethodGet, resourceIssuer+"/records", "")
	protectedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(protectedResponse, protected)
	if protectedResponse.Code != http.StatusOK || len(principals) != 1 || len(presentedAuthTokens) != 1 || presentedAuthTokens[0] != psAuthToken {
		t.Fatalf("PS auth = %d %s principals=%d auth_tokens=%q", protectedResponse.Code, protectedResponse.Body.String(), len(principals), presentedAuthTokens)
	}
	if principal := principals[0]; principal.PersonServer != personIssuer || principal.Subject != "person-1" ||
		principal.Tenant != "tenant-1" || len(principal.Scope) != 1 || principal.Scope[0] != "records.read" {
		t.Fatalf("PS principal = %#v", principal)
	}

	asAuthToken := mintAuthToken(t, accessKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: resourceIssuer,
		JTI: "wrong-topology-auth-token", PersonServer: personIssuer, Subject: "person-1",
		Scope: "records.read", Tenant: "tenant-1",
	})
	wrongTopology := signedRequest(t, clock, agentKey, asAuthToken, http.MethodGet, resourceIssuer+"/records", "")
	wrongTopologyResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(wrongTopologyResponse, wrongTopology)
	if wrongTopologyResponse.Code == http.StatusOK || len(principals) != 1 {
		t.Fatalf("AS auth = %d %s principals=%d", wrongTopologyResponse.Code, wrongTopologyResponse.Body.String(), len(principals))
	}

	wrongProof := signedRequest(t, clock, accessKey, psAuthToken, http.MethodGet, resourceIssuer+"/records", "")
	wrongProofResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(wrongProofResponse, wrongProof)
	if wrongProofResponse.Code == http.StatusOK || len(presentedAuthTokens) != 1 {
		t.Fatalf("wrong proof = %d %s auth_tokens=%q", wrongProofResponse.Code, wrongProofResponse.Body.String(), presentedAuthTokens)
	}

	wrongAudienceToken := mintAuthToken(t, personKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: "https://other-resource.example",
		JTI: "wrong-audience-auth-token", PersonServer: personIssuer, Subject: "person-1", Scope: "records.read",
	})
	wrongAudience := signedRequest(t, clock, agentKey, wrongAudienceToken, http.MethodGet, resourceIssuer+"/records", "")
	wrongAudienceResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(wrongAudienceResponse, wrongAudience)
	if wrongAudienceResponse.Code == http.StatusOK || len(presentedAuthTokens) != 1 {
		t.Fatalf("wrong audience = %d %s auth_tokens=%q", wrongAudienceResponse.Code, wrongAudienceResponse.Body.String(), presentedAuthTokens)
	}

	wrongScopeToken := mintAuthToken(t, personKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		JTI: "wrong-scope-auth-token", PersonServer: personIssuer, Subject: "person-1", Scope: "records.admin",
	})
	wrongScope := signedRequest(t, clock, agentKey, wrongScopeToken, http.MethodGet, resourceIssuer+"/records", "")
	wrongScopeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(wrongScopeResponse, wrongScope)
	if wrongScopeResponse.Code == http.StatusOK || len(presentedAuthTokens) != 1 {
		t.Fatalf("wrong scope = %d %s auth_tokens=%q", wrongScopeResponse.Code, wrongScopeResponse.Body.String(), presentedAuthTokens)
	}

	malformedToken := signedRequest(t, clock, agentKey, "not-a-compact-token", http.MethodGet, resourceIssuer+"/records", "")
	malformedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(malformedResponse, malformedToken)
	if malformedResponse.Code == http.StatusOK || len(presentedAuthTokens) != 1 {
		t.Fatalf("malformed token = %d %s auth_tokens=%q", malformedResponse.Code, malformedResponse.Body.String(), presentedAuthTokens)
	}

	challenge := signedRequest(t, clock, agentKey, personToken, http.MethodGet, resourceIssuer+"/records", "")
	challengeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(challengeResponse, challenge)
	requirement := parseAuthTokenRequirement(t, challengeResponse)
	challengeClaims, err := aauth.VerifyResourceToken(context.Background(), requirement.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if challengeClaims.Audience != personIssuer || len(principals) != 1 {
		t.Fatalf("challenge resource token = %#v; principals=%d", challengeClaims, len(principals))
	}
}

func TestAuthTokenFromContextRequiresVerifiedResourceContext(t *testing.T) {
	t.Parallel()

	if compact, ok := AuthTokenFromContext(nil); ok || compact != "" {
		t.Fatalf("nil context token = %q, present=%t", compact, ok)
	}
	if compact, ok := AuthTokenFromContext(context.Background()); ok || compact != "" {
		t.Fatalf("ordinary context token = %q, present=%t", compact, ok)
	}
}

func TestFederatedAuthorizationUsesAccessRoleWhenPSAndASAreCollocated(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "collapsed-person", 55)
	resourceKey := testSigningKey(t, "collapsed-resource", 56)
	agentKey := testSigningKey(t, "collapsed-agent", 57)
	accessKey := testSigningKey(t, "collapsed-access", 58)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: personIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	protectedCalls := 0
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: resourceIssuer, AccessServer: personIssuer,
		SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "collapsed-resource-token" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			protectedCalls++
			response.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "collapsed-person-token")
	request := signedRequest(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", `{"scope":"records.read"}`)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("collocated PS/AS authorize = %d %s", response.Code, response.Body.String())
	}
	var output struct {
		ResourceToken string `json:"resource_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	resourceClaims, err := aauth.VerifyResourceToken(context.Background(), output.ResourceToken, resolver, clock)
	if err != nil || resourceClaims.Audience != personIssuer {
		t.Fatalf("collocated resource token = %#v, %v", resourceClaims, err)
	}
	accessToken := mintAuthToken(t, accessKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: resourceIssuer,
		JTI: "collapsed-access-token", PersonServer: personIssuer, Subject: "person-1",
		Scope: "records.read", Tenant: "tenant-1",
	})
	accessRequest := signedRequest(t, clock, agentKey, accessToken, http.MethodGet, resourceIssuer+"/records", "")
	accessResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(accessResponse, accessRequest)
	if accessResponse.Code != http.StatusNoContent || protectedCalls != 1 {
		t.Fatalf("collocated AS auth = %d %s; protected=%d", accessResponse.Code, accessResponse.Body.String(), protectedCalls)
	}
	personAuthToken := mintAuthToken(t, personKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		JTI: "wrong-collapsed-person-token", PersonServer: personIssuer, Subject: "person-1",
		Scope: "records.read", Tenant: "tenant-1",
	})
	personRequest := signedRequest(t, clock, agentKey, personAuthToken, http.MethodGet, resourceIssuer+"/records", "")
	personResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(personResponse, personRequest)
	if personResponse.Code == http.StatusNoContent || protectedCalls != 1 {
		t.Fatalf("collocated PS auth = %d %s; protected=%d", personResponse.Code, personResponse.Body.String(), protectedCalls)
	}
}
