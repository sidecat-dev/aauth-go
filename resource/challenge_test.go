package resource

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestAuthTokenRequirementChallengesValidPersonTokenWithoutApplicationConsequence(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 14, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "person-key", 31)
	resourceKey := testSigningKey(t, "resource-key", 32)
	agentKey := testSigningKey(t, "agent-key", 33)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
	}
	resolved := 0
	protected := 0
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer:                        resourceIssuer,
		AccessServer:                  accessIssuer,
		SigningKey:                    resourceKey,
		KeyResolver:                   resolver,
		Clock:                         clock,
		NewID:                         func() string { return "challenge-resource-token-1" },
		ScopeDescriptions:             map[string]string{"records.read": "Read records"},
		AdditionalSignatureComponents: []string{"x-route-proof"},
		RequiredScopes:                func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson: func(context.Context, PersonIdentity, PersonContext) error {
			resolved++
			return nil
		},
		Protected: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			protected++
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "person-token-1")
	request := httptest.NewRequest(http.MethodGet, resourceIssuer+"/records", nil)
	request.Header.Set("X-Route-Proof", "records-read")
	if err := signaturekey.SignJWTRequestWithOptions(request, agentKey, personToken, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"x-route-proof"},
	}); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusUnauthorized, response.Body.String())
	}
	requirement, err := aauth.ParseAuthTokenRequirement(response.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatalf("parse AAuth-Requirement: %v; header = %q", err, response.Header().Values("AAuth-Requirement"))
	}
	if requirement.ResourceToken == "" {
		t.Fatal("AAuth-Requirement resource token is empty")
	}
	if header := response.Header().Get("Signature-Error"); header != "" {
		t.Fatalf("Signature-Error = %q on a valid person-token proof", header)
	}
	if resolved != 0 || protected != 0 {
		t.Fatalf("challenge caused application consequences: ResolvePerson=%d Protected=%d", resolved, protected)
	}
}

func TestAuthTokenRequirementCarriesRouteBoundResourceToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 14, 15, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "person-key", 34)
	resourceKey := testSigningKey(t, "resource-key", 35)
	agentKey := testSigningKey(t, "agent-key", 36)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer:            resourceIssuer,
		AccessServer:      accessIssuer,
		SigningKey:        resourceKey,
		KeyResolver:       resolver,
		Clock:             clock,
		NewID:             func() string { return "challenge-resource-token-exact" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected:         http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "person-token-exact")
	request := signedRequest(t, clock, agentKey, personToken, http.MethodGet, resourceIssuer+"/records/42", "")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	requirement := parseAuthTokenRequirement(t, response)
	claims, err := aauth.VerifyResourceToken(context.Background(), requirement.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	wantJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != resourceIssuer ||
		claims.DWK != aauth.ResourceDiscoveryDocument ||
		claims.Audience != accessIssuer ||
		claims.JTI != "challenge-resource-token-exact" ||
		claims.AgentJKT != wantJKT ||
		claims.IssuedAt != now.Unix() ||
		claims.ExpiresAt != now.Add(5*time.Minute).Unix() ||
		claims.Scope != "records.read" ||
		claims.PersonServer != personIssuer ||
		claims.Subject != "person-1" ||
		claims.PresentedJTI != "person-token-exact" ||
		claims.MissionS256 != "" ||
		claims.Tenant != "tenant-1" ||
		claims.Account != nil ||
		claims.Interaction != nil {
		t.Fatalf("resource-token claims = %#v", claims)
	}
}

func TestAuthTokenRequirementUsesActualRouteScopes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 14, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "person-key", 37)
	resourceKey := testSigningKey(t, "resource-key", 38)
	agentKey := testSigningKey(t, "agent-key", 39)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	issued := 0
	ids := []string{"route-resource-token-get", "route-resource-token-post"}
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer:       resourceIssuer,
		AccessServer: accessIssuer,
		SigningKey:   resourceKey,
		KeyResolver:  resolver,
		Clock:        clock,
		NewID: func() string {
			id := ids[issued]
			issued++
			return id
		},
		ScopeDescriptions: map[string]string{
			"records.read":  "Read records",
			"records.write": "Write records",
		},
		RequiredScopes: func(request *http.Request) []string {
			if request.Method == http.MethodPost {
				return []string{"records.write"}
			}
			return []string{"records.read"}
		},
		ResolvePerson: func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected:     http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "route-person-token")
	for _, scenario := range []struct {
		method string
		scope  string
		jti    string
	}{
		{method: http.MethodGet, scope: "records.read", jti: "route-resource-token-get"},
		{method: http.MethodPost, scope: "records.write", jti: "route-resource-token-post"},
	} {
		request := signedRequest(t, clock, agentKey, personToken, scenario.method, resourceIssuer+"/records", "")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		requirement := parseAuthTokenRequirement(t, response)
		claims, err := aauth.VerifyResourceToken(context.Background(), requirement.ResourceToken, resolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		if claims.Scope != scenario.scope || claims.JTI != scenario.jti {
			t.Fatalf("%s claims scope = %q, jti = %q; want scope = %q, jti = %q", scenario.method, claims.Scope, claims.JTI, scenario.scope, scenario.jti)
		}
	}
	if issued != len(ids) {
		t.Fatalf("resource-token IDs issued = %d, want %d", issued, len(ids))
	}
}

func TestAuthTokenRequirementDoesNotReleaseHeaderWhenMintingFails(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 14, 40, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "person-key", 47)
	resourceKey := testSigningKey(t, "resource-key", 48)
	agentKey := testSigningKey(t, "agent-key", 49)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
	}
	resolved := 0
	protected := 0
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer:            resourceIssuer,
		AccessServer:      accessIssuer,
		SigningKey:        resourceKey,
		KeyResolver:       resolver,
		Clock:             clock,
		NewID:             func() string { return "" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson: func(context.Context, PersonIdentity, PersonContext) error {
			resolved++
			return nil
		},
		Protected: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { protected++ }),
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "mint-failure-person-token")
	request := signedRequest(t, clock, agentKey, personToken, http.MethodGet, resourceIssuer+"/records", "")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusInternalServerError, response.Body.String())
	}
	if values := response.Header().Values("AAuth-Requirement"); len(values) != 0 {
		t.Fatalf("AAuth-Requirement = %q", values)
	}
	if resolved != 0 || protected != 0 {
		t.Fatalf("failed mint caused application consequences: ResolvePerson=%d Protected=%d", resolved, protected)
	}
}

func TestAuthTokenRequirementRejectsInvalidRouteScopePolicyWithoutChallenge(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name     string
		required []string
	}{
		{name: "no scopes", required: nil},
		{name: "empty scope", required: []string{""}},
		{name: "duplicate scope", required: []string{"records.read", "records.read"}},
		{name: "undeclared scope", required: []string{"records.admin"}},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			now := time.Date(2026, 8, 30, 14, 45, 0, 0, time.UTC)
			clock := aauth.ClockFunc(func() time.Time { return now })
			personKey := testSigningKey(t, "person-key", 40)
			resourceKey := testSigningKey(t, "resource-key", 41)
			agentKey := testSigningKey(t, "agent-key", 42)
			resolver := signaturekey.StaticKeyResolver{
				{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
			}
			issued := 0
			resolved := 0
			protected := 0
			server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
				Issuer:            resourceIssuer,
				AccessServer:      accessIssuer,
				SigningKey:        resourceKey,
				KeyResolver:       resolver,
				Clock:             clock,
				NewID:             func() string { issued++; return "must-not-be-issued" },
				ScopeDescriptions: map[string]string{"records.read": "Read records"},
				RequiredScopes:    func(*http.Request) []string { return append([]string(nil), scenario.required...) },
				ResolvePerson: func(context.Context, PersonIdentity, PersonContext) error {
					resolved++
					return nil
				},
				Protected: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { protected++ }),
			})
			if err != nil {
				t.Fatal(err)
			}
			personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "policy-person-token")
			request := signedRequest(t, clock, agentKey, personToken, http.MethodGet, resourceIssuer+"/records", "")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)

			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusInternalServerError, response.Body.String())
			}
			if values := response.Header().Values("AAuth-Requirement"); len(values) != 0 {
				t.Fatalf("AAuth-Requirement = %q", values)
			}
			if issued != 0 || resolved != 0 || protected != 0 {
				t.Fatalf("invalid policy caused consequences: NewID=%d ResolvePerson=%d Protected=%d", issued, resolved, protected)
			}
			var problem struct {
				Code string `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if problem.Code != "server_error" {
				t.Fatalf("problem error = %q, want server_error", problem.Code)
			}
		})
	}
}

func TestAuthTokenRequirementRejectsScopePolicyBodyFailureWithoutChallenge(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name            string
		getBody         func() (io.ReadCloser, error)
		wantPolicyCalls int
		closeInPolicy   bool
	}{
		{
			name: "body copy fails",
			getBody: func() (io.ReadCloser, error) {
				return nil, errors.New("copy failed")
			},
		},
		{
			name: "independent body close fails",
			getBody: func() (io.ReadCloser, error) {
				return &errorCloseBody{Reader: strings.NewReader("")}, nil
			},
			wantPolicyCalls: 1,
			closeInPolicy:   true,
		},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			now := time.Date(2026, 8, 30, 14, 50, 0, 0, time.UTC)
			clock := aauth.ClockFunc(func() time.Time { return now })
			personKey := testSigningKey(t, "person-key", 53)
			resourceKey := testSigningKey(t, "resource-key", 54)
			agentKey := testSigningKey(t, "agent-key", 55)
			resolver := signaturekey.StaticKeyResolver{
				{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
			}
			policyCalls := 0
			issued := 0
			resolved := 0
			protected := 0
			server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
				Issuer:            resourceIssuer,
				AccessServer:      accessIssuer,
				SigningKey:        resourceKey,
				KeyResolver:       resolver,
				Clock:             clock,
				NewID:             func() string { issued++; return "must-not-be-issued" },
				ScopeDescriptions: map[string]string{"records.read": "Read records"},
				RequiredScopes: func(policyRequest *http.Request) []string {
					policyCalls++
					if scenario.closeInPolicy {
						_ = policyRequest.Body.Close()
					}
					return []string{"records.read"}
				},
				ResolvePerson: func(context.Context, PersonIdentity, PersonContext) error {
					resolved++
					return nil
				},
				Protected: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { protected++ }),
			})
			if err != nil {
				t.Fatal(err)
			}
			personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "policy-body-failure-person-token")
			request := signedRequest(t, clock, agentKey, personToken, http.MethodGet, resourceIssuer+"/records", "")
			request.GetBody = scenario.getBody
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)

			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusInternalServerError, response.Body.String())
			}
			if values := response.Header().Values("AAuth-Requirement"); len(values) != 0 {
				t.Fatalf("AAuth-Requirement = %q", values)
			}
			if policyCalls != scenario.wantPolicyCalls || issued != 0 || resolved != 0 || protected != 0 {
				t.Fatalf("calls: RequiredScopes=%d NewID=%d ResolvePerson=%d Protected=%d", policyCalls, issued, resolved, protected)
			}
			var problem struct {
				Code string `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if problem.Code != "server_error" {
				t.Fatalf("problem error = %q, want server_error", problem.Code)
			}
		})
	}
}

func TestAuthTokenRequirementRejectsIgnoredScopePolicyBodyReadError(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 14, 55, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "person-key", 56)
	resourceKey := testSigningKey(t, "resource-key", 57)
	agentKey := testSigningKey(t, "agent-key", 58)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
	}
	policyCalls := 0
	issued := 0
	resolved := 0
	protected := 0
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer:            resourceIssuer,
		AccessServer:      accessIssuer,
		SigningKey:        resourceKey,
		KeyResolver:       resolver,
		Clock:             clock,
		NewID:             func() string { issued++; return "must-not-be-issued" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes: func(policyRequest *http.Request) []string {
			policyCalls++
			_, _ = io.ReadAll(policyRequest.Body)
			return []string{"records.read"}
		},
		ResolvePerson: func(context.Context, PersonIdentity, PersonContext) error {
			resolved++
			return nil
		},
		Protected: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { protected++ }),
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "body-read-error-person-token")
	readFailure := errors.New("sentinel request body read failure")
	request := httptest.NewRequest(
		http.MethodPost,
		resourceIssuer+"/records",
		&bytesThenErrorBody{reader: strings.NewReader(`{"record":"truncated"}`), err: readFailure},
	)
	request.GetBody = nil
	if err := signaturekey.SignJWTRequest(request, agentKey, personToken, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusInternalServerError, response.Body.String())
	}
	if values := response.Header().Values("AAuth-Requirement"); len(values) != 0 {
		t.Fatalf("AAuth-Requirement = %q", values)
	}
	if policyCalls != 1 || issued != 0 || resolved != 0 || protected != 0 {
		t.Fatalf("calls: RequiredScopes=%d NewID=%d ResolvePerson=%d Protected=%d", policyCalls, issued, resolved, protected)
	}
	var problem struct {
		Code string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != "server_error" {
		t.Fatalf("problem error = %q, want server_error", problem.Code)
	}

	independentRequest := httptest.NewRequest(http.MethodPost, resourceIssuer+"/records", nil)
	independentRequest.GetBody = func() (io.ReadCloser, error) {
		return &bytesThenErrorBody{reader: strings.NewReader(`{"record":"truncated"}`), err: readFailure}, nil
	}
	if err := signaturekey.SignJWTRequest(independentRequest, agentKey, personToken, clock); err != nil {
		t.Fatal(err)
	}
	independentResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(independentResponse, independentRequest)

	if independentResponse.Code != http.StatusInternalServerError {
		t.Fatalf("GetBody status = %d, want %d; body = %s", independentResponse.Code, http.StatusInternalServerError, independentResponse.Body.String())
	}
	if values := independentResponse.Header().Values("AAuth-Requirement"); len(values) != 0 {
		t.Fatalf("GetBody AAuth-Requirement = %q", values)
	}
	if policyCalls != 2 || issued != 0 || resolved != 0 || protected != 0 {
		t.Fatalf("GetBody calls: RequiredScopes=%d NewID=%d ResolvePerson=%d Protected=%d", policyCalls, issued, resolved, protected)
	}
	problem = struct {
		Code string `json:"error"`
	}{}
	if err := json.Unmarshal(independentResponse.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != "server_error" {
		t.Fatalf("GetBody problem error = %q, want server_error", problem.Code)
	}
}

func TestProtectedPersonTokenRefusesInvalidCredentialWithoutChallenge(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 15, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "person-key", 43)
	resourceKey := testSigningKey(t, "resource-key", 44)
	agentKey := testSigningKey(t, "agent-key", 45)
	otherAgentKey := testSigningKey(t, "other-agent-key", 46)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
	}
	valid := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "valid-person-token")
	wrongAudience := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, "https://other-resource.example", "wrong-audience-person-token")
	expired, err := aauth.MintPersonToken(personKey, aauth.PersonTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		Subject: "person-1", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		JTI: "expired-person-token", IssuedAt: now.Add(-2 * time.Hour).Unix(), ExpiresAt: now.Add(-time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	missionBound, err := aauth.MintPersonToken(personKey, aauth.PersonTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		Subject: "person-1", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		JTI: "mission-person-token", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		MissionS256: strings.Repeat("A", 43),
	})
	if err != nil {
		t.Fatal(err)
	}
	unknownClaims := aauth.PersonTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		Subject: "person-1", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		JTI: "unknown-type-token", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	payload, err := json.Marshal(unknownClaims)
	if err != nil {
		t.Fatal(err)
	}
	unknownType, err := jose.SignCompact(personKey, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: "aa-unknown+jwt", KeyID: personKey.ID(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}

	for _, scenario := range []struct {
		name             string
		token            string
		proofKey         jose.SigningKey
		signatureFailure signaturekey.ErrorCode
		problemCode      string
	}{
		{name: "wrong proof key", token: valid, proofKey: otherAgentKey, signatureFailure: signaturekey.ErrorInvalidSignature},
		{name: "wrong audience", token: wrongAudience, proofKey: agentKey, problemCode: "invalid_token"},
		{name: "expired person token", token: expired, proofKey: agentKey, signatureFailure: signaturekey.ErrorExpiredJWT},
		{name: "mission-bound person token", token: missionBound, proofKey: agentKey, problemCode: "invalid_token"},
		{name: "unknown token type", token: unknownType, proofKey: agentKey, signatureFailure: signaturekey.ErrorInvalidJWT},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			issued := 0
			resolved := 0
			protected := 0
			server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
				Issuer:            resourceIssuer,
				AccessServer:      accessIssuer,
				SigningKey:        resourceKey,
				KeyResolver:       resolver,
				Clock:             clock,
				NewID:             func() string { issued++; return "must-not-be-issued" },
				ScopeDescriptions: map[string]string{"records.read": "Read records"},
				RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
				ResolvePerson: func(context.Context, PersonIdentity, PersonContext) error {
					resolved++
					return nil
				},
				Protected: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { protected++ }),
			})
			if err != nil {
				t.Fatal(err)
			}
			request := signedRequest(t, clock, scenario.proofKey, scenario.token, http.MethodGet, resourceIssuer+"/records", "")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusUnauthorized, response.Body.String())
			}
			if values := response.Header().Values("AAuth-Requirement"); len(values) != 0 {
				t.Fatalf("AAuth-Requirement = %q", values)
			}
			if issued != 0 || resolved != 0 || protected != 0 {
				t.Fatalf("refusal caused consequences: NewID=%d ResolvePerson=%d Protected=%d", issued, resolved, protected)
			}
			if scenario.signatureFailure != "" {
				assertSignatureError(t, response, scenario.signatureFailure)
				return
			}
			var problem struct {
				Code string `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if problem.Code != scenario.problemCode {
				t.Fatalf("problem error = %q, want %q", problem.Code, scenario.problemCode)
			}
		})
	}
}

func TestProtectedHandlerPreservesLiveRequestAcrossRequiredScopesPolicy(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name      string
		readBytes int
	}{
		{name: "policy reads entire body", readBytes: -1},
		{name: "policy reads body prefix", readBytes: 7},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
			clock := aauth.ClockFunc(func() time.Time { return now })
			resourceKey := testSigningKey(t, "resource-key", 50)
			accessKey := testSigningKey(t, "access-key", 51)
			agentKey := testSigningKey(t, "agent-key", 52)
			resolver := signaturekey.StaticKeyResolver{
				{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}: accessKey.PublicJWK(),
			}
			const (
				method      = http.MethodPatch
				target      = resourceIssuer + "/records/a%2Fb?view=full%20detail&tag=a%2Fb"
				escapedPath = "/records/a%2Fb"
				rawQuery    = "view=full%20detail&tag=a%2Fb"
				selected    = "original-selection"
				requestBody = `{"record":"alpha","enabled":true}`
			)
			policyCalls := 0
			resolved := 0
			protectedCalls := 0
			server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
				Issuer:                        resourceIssuer,
				AccessServer:                  accessIssuer,
				SigningKey:                    resourceKey,
				KeyResolver:                   resolver,
				Clock:                         clock,
				NewID:                         func() string { return "unused-resource-token" },
				ScopeDescriptions:             map[string]string{"records.read": "Read records"},
				AdditionalSignatureComponents: []string{"x-selected-route"},
				RequiredScopes: func(policyRequest *http.Request) []string {
					policyCalls++
					if policyRequest.Method != method || policyRequest.URL.EscapedPath() != escapedPath ||
						policyRequest.URL.RawQuery != rawQuery || policyRequest.Header.Get("X-Selected-Route") != selected {
						t.Errorf("policy request = %s %s?%s, selected = %q", policyRequest.Method, policyRequest.URL.EscapedPath(), policyRequest.URL.RawQuery, policyRequest.Header.Get("X-Selected-Route"))
					}
					if scenario.readBytes < 0 {
						if _, err := io.ReadAll(policyRequest.Body); err != nil {
							t.Errorf("policy read body: %v", err)
						}
					} else {
						prefix := make([]byte, scenario.readBytes)
						if _, err := io.ReadFull(policyRequest.Body, prefix); err != nil {
							t.Errorf("policy read body prefix: %v", err)
						}
					}
					policyRequest.Method = http.MethodDelete
					policyRequest.URL.Path = "/mutated"
					policyRequest.URL.RawPath = ""
					policyRequest.URL.RawQuery = "mutated=true"
					policyRequest.Header.Set("X-Selected-Route", "mutated")
					if err := policyRequest.Body.Close(); err != nil {
						t.Errorf("policy close body: %v", err)
					}
					return []string{"records.read"}
				},
				ResolvePerson: func(context.Context, PersonIdentity, PersonContext) error {
					resolved++
					return nil
				},
				Protected: http.HandlerFunc(func(response http.ResponseWriter, applicationRequest *http.Request) {
					protectedCalls++
					body, err := io.ReadAll(applicationRequest.Body)
					if err != nil {
						t.Errorf("protected read body: %v", err)
					}
					if applicationRequest.Method != method || applicationRequest.URL.EscapedPath() != escapedPath ||
						applicationRequest.URL.RawQuery != rawQuery || applicationRequest.Header.Get("X-Selected-Route") != selected ||
						string(body) != requestBody {
						t.Errorf("protected request = %s %s?%s, selected = %q, body = %q", applicationRequest.Method, applicationRequest.URL.EscapedPath(), applicationRequest.URL.RawQuery, applicationRequest.Header.Get("X-Selected-Route"), body)
					}
					response.WriteHeader(http.StatusNoContent)
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			authToken := mintAuthToken(t, accessKey, agentKey.PublicJWK(), now, authClaims())
			body := &unbufferedRequestBody{reader: strings.NewReader(requestBody)}
			request := httptest.NewRequest(method, target, body)
			request.GetBody = nil
			request.Header.Set("X-Selected-Route", selected)
			if err := signaturekey.SignJWTRequestWithOptions(request, agentKey, authToken, clock, signaturekey.SignOptions{
				AdditionalComponents: []string{"x-selected-route"},
			}); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)

			if response.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusNoContent, response.Body.String())
			}
			if policyCalls != 1 || resolved != 1 || protectedCalls != 1 {
				t.Fatalf("calls: RequiredScopes=%d ResolvePerson=%d Protected=%d", policyCalls, resolved, protectedCalls)
			}
		})
	}
}

type unbufferedRequestBody struct {
	reader *strings.Reader
	closed bool
}

type errorCloseBody struct{ io.Reader }

func (*errorCloseBody) Close() error { return errors.New("close failed") }

type bytesThenErrorBody struct {
	reader    *strings.Reader
	err       error
	delivered bool
}

func (body *bytesThenErrorBody) Read(buffer []byte) (int, error) {
	if body.delivered {
		return 0, io.EOF
	}
	read, _ := body.reader.Read(buffer)
	if body.reader.Len() == 0 {
		body.delivered = true
		return read, body.err
	}
	return read, nil
}

func (*bytesThenErrorBody) Close() error { return nil }

func (body *unbufferedRequestBody) Read(buffer []byte) (int, error) {
	if body.closed {
		return 0, io.ErrClosedPipe
	}
	return body.reader.Read(buffer)
}

func (body *unbufferedRequestBody) Close() error {
	body.closed = true
	return nil
}

func parseAuthTokenRequirement(t *testing.T, response *httptest.ResponseRecorder) aauth.AuthTokenRequirement {
	t.Helper()
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusUnauthorized, response.Body.String())
	}
	requirement, err := aauth.ParseAuthTokenRequirement(response.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatalf("parse AAuth-Requirement: %v; header = %q", err, response.Header().Values("AAuth-Requirement"))
	}
	return requirement
}
