package resource

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	resourceIssuer = "https://resource.example"
	personIssuer   = "https://ps.example"
	accessIssuer   = "https://as.example"
)

func TestNewFederatedAuthorizationRejectsIncompleteConfiguration(t *testing.T) {
	t.Parallel()

	valid := validConfig(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	enableHeld := func(config *FederatedAuthorizationConfig) {
		config.HeldInvocations = newHeldMemoryStore()
		config.MaxRetainedRequestBodyBytes = 1024
		config.MaxRetainedResponseBodyBytes = 1024
		config.MaxRetainedHeaderBytes = 1024
	}
	tests := []struct {
		name   string
		change func(*FederatedAuthorizationConfig)
	}{
		{name: "issuer", change: func(config *FederatedAuthorizationConfig) { config.Issuer = "" }},
		{name: "access server", change: func(config *FederatedAuthorizationConfig) { config.AccessServer = "" }},
		{name: "signing key", change: func(config *FederatedAuthorizationConfig) { config.SigningKey = jose.SigningKey{} }},
		{name: "key resolver", change: func(config *FederatedAuthorizationConfig) { config.KeyResolver = nil }},
		{name: "clock", change: func(config *FederatedAuthorizationConfig) { config.Clock = nil }},
		{name: "id source", change: func(config *FederatedAuthorizationConfig) { config.NewID = nil }},
		{name: "scope descriptions", change: func(config *FederatedAuthorizationConfig) { config.ScopeDescriptions = nil }},
		{name: "empty scope", change: func(config *FederatedAuthorizationConfig) {
			config.ScopeDescriptions = map[string]string{"": "Read records"}
		}},
		{name: "whitespace scope", change: func(config *FederatedAuthorizationConfig) {
			config.ScopeDescriptions = map[string]string{"records read": "Read records"}
		}},
		{name: "empty description", change: func(config *FederatedAuthorizationConfig) {
			config.ScopeDescriptions = map[string]string{"records.read": ""}
		}},
		{name: "blank description", change: func(config *FederatedAuthorizationConfig) {
			config.ScopeDescriptions = map[string]string{"records.read": " \t"}
		}},
		{name: "invalid signature component", change: func(config *FederatedAuthorizationConfig) {
			config.AdditionalSignatureComponents = []string{"Content-Type"}
		}},
		{name: "non-ASCII signature component", change: func(config *FederatedAuthorizationConfig) { config.AdditionalSignatureComponents = []string{"x-☃"} }},
		{name: "unsupported derived component", change: func(config *FederatedAuthorizationConfig) {
			config.AdditionalSignatureComponents = []string{"@query-param"}
		}},
		{name: "duplicate signature component", change: func(config *FederatedAuthorizationConfig) {
			config.AdditionalSignatureComponents = []string{"content-type", "content-type"}
		}},
		{name: "negative body limit", change: func(config *FederatedAuthorizationConfig) { config.MaxSignedBodyBytes = -1 }},
		{name: "negative held request limit", change: func(config *FederatedAuthorizationConfig) { config.MaxRetainedRequestBodyBytes = -1 }},
		{name: "negative held response limit", change: func(config *FederatedAuthorizationConfig) { config.MaxRetainedResponseBodyBytes = -1 }},
		{name: "negative held header limit", change: func(config *FederatedAuthorizationConfig) { config.MaxRetainedHeaderBytes = -1 }},
		{name: "held limit without store", change: func(config *FederatedAuthorizationConfig) { config.MaxRetainedRequestBodyBytes = 1 }},
		{name: "held selector without store", change: func(config *FederatedAuthorizationConfig) {
			config.HoldAuthTokenRequest = func(*http.Request) bool { return true }
		}},
		{name: "held store without request limit", change: func(config *FederatedAuthorizationConfig) {
			enableHeld(config)
			config.MaxRetainedRequestBodyBytes = 0
		}},
		{name: "held store without response limit", change: func(config *FederatedAuthorizationConfig) {
			enableHeld(config)
			config.MaxRetainedResponseBodyBytes = 0
		}},
		{name: "held store without header limit", change: func(config *FederatedAuthorizationConfig) {
			enableHeld(config)
			config.MaxRetainedHeaderBytes = 0
		}},
		{name: "required scopes", change: func(config *FederatedAuthorizationConfig) { config.RequiredScopes = nil }},
		{name: "person resolver", change: func(config *FederatedAuthorizationConfig) { config.ResolvePerson = nil }},
		{name: "protected handler", change: func(config *FederatedAuthorizationConfig) { config.Protected = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			if _, err := NewFederatedAuthorization(config); err == nil {
				t.Fatal("NewFederatedAuthorization succeeded with incomplete configuration")
			}
		})
	}
}

func TestFederatedBudgetRejectsUnsupportedDeliveryCompositions(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		change func(*FederatedAuthorizationConfig)
		want   string
	}{
		{name: "reactive initial offer", change: func(config *FederatedAuthorizationConfig) {
			config.Budget.InitialOffer = func(context.Context, BudgetInitialOfferRequest) (budgets.Value, error) {
				return budgets.Value{}, nil
			}
		}, want: "reactive four-party Budget"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig(t, http.NotFoundHandler())
			config.Budget = &BudgetConfig{}
			test.change(&config)
			_, err := NewFederatedAuthorization(config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAuthorizationEndpointIssuesCurrentResourceToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 15, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	psKey := testSigningKey(t, "ps-key", 2)
	resourceKey := testSigningKey(t, "resource-key", 3)
	agentKey := testSigningKey(t, "agent-key", 4)
	otherAgentKey := testSigningKey(t, "other-agent-key", 11)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: psKey.ID()}:           psKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer:       resourceIssuer,
		AccessServer: accessIssuer,
		SigningKey:   resourceKey,
		KeyResolver:  resolver,
		Clock:        clock,
		NewID:        func() string { return "resource-token-1" },
		ScopeDescriptions: map[string]string{
			"records.read":  "Read records",
			"records.write": "Write records",
		},
		AdditionalSignatureComponents: []string{"content-type", "content-digest"},
		MaxSignedBodyBytes:            64 << 10,
		RequiredScopes:                func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:                 func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected:                     http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken := mintPersonToken(t, psKey, agentKey.PublicJWK(), now, resourceIssuer, "person-token-1")

	request := signedRequest(
		t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize",
		`{"scope":"records.read","example_extension":{"future":true}}`,
	)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var body struct {
		ResourceToken string `json:"resource_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyResourceToken(context.Background(), body.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	wantJKT, _ := agentKey.PublicJWK().Thumbprint()
	if claims.Issuer != resourceIssuer ||
		claims.DWK != aauth.ResourceDiscoveryDocument ||
		claims.Audience != accessIssuer ||
		claims.JTI != "resource-token-1" ||
		claims.PersonServer != personIssuer ||
		claims.Subject != "person-1" ||
		claims.PresentedJTI != "person-token-1" ||
		claims.AgentJKT != wantJKT ||
		claims.Scope != "records.read" ||
		claims.Account != nil ||
		claims.Tenant != "tenant-1" {
		t.Fatalf("resource-token claims = %#v", claims)
	}

	t.Run("resource token may outlive a person token that was valid at issuance", func(t *testing.T) {
		shortPersonToken, err := aauth.MintPersonToken(psKey, aauth.PersonTokenClaims{
			Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
			Subject: "person-1", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			JTI: "short-person-token", IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Second).Unix(),
			Tenant: "tenant-1",
		})
		if err != nil {
			t.Fatal(err)
		}
		request := signedRequest(
			t, clock, agentKey, shortPersonToken, http.MethodPost, resourceIssuer+"/authorize", `{"scope":"records.read"}`,
		)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		var output struct {
			ResourceToken string `json:"resource_token"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
			t.Fatal(err)
		}
		resourceClaims, err := aauth.VerifyResourceToken(context.Background(), output.ResourceToken, resolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		if resourceClaims.ExpiresAt != now.Add(5*time.Minute).Unix() || resourceClaims.ExpiresAt <= now.Add(30*time.Second).Unix() {
			t.Fatalf("resource-token exp = %d", resourceClaims.ExpiresAt)
		}
	})

	t.Run("wrong person-token audience", func(t *testing.T) {
		wrong := mintPersonToken(t, psKey, agentKey.PublicJWK(), now, "https://other-resource.example", "person-token-2")
		request := signedRequest(t, clock, agentKey, wrong, http.MethodPost, resourceIssuer+"/authorize", `{"scope":"records.read"}`)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code == http.StatusOK {
			t.Fatal("authorization accepted a person token for another resource")
		}
	})

	t.Run("expired person token is answered with Signature-Error", func(t *testing.T) {
		expired, err := aauth.MintPersonToken(psKey, aauth.PersonTokenClaims{
			Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
			Subject: "person-1", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			JTI: "expired-person-token", IssuedAt: now.Add(-2 * time.Hour).Unix(), ExpiresAt: now.Add(-time.Hour).Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		request := signedRequest(t, clock, agentKey, expired, http.MethodPost, resourceIssuer+"/authorize", `{"scope":"records.read"}`)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		var problem struct {
			Code string `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
			t.Fatal(err)
		}
		// A person token that fails verification is answered with 401 and
		// Signature-Error, not with an authorization-endpoint error code.
		if response.Code != http.StatusUnauthorized || problem.Code == "invalid_person_token" {
			t.Fatalf("status = %d, problem = %#v", response.Code, problem)
		}
		if header := response.Header().Get("Signature-Error"); header != "error=expired_jwt" {
			t.Fatalf("Signature-Error = %q, want error=expired_jwt", header)
		}
	})

	t.Run("wrong person-token proof key", func(t *testing.T) {
		request := signedRequest(t, clock, otherAgentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", `{"scope":"records.read"}`)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code == http.StatusOK {
			t.Fatal("authorization accepted a request signed by another key")
		}
	})

	t.Run("scope outside declared set", func(t *testing.T) {
		request := signedRequest(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", `{"scope":"records.delete"}`)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code == http.StatusOK {
			t.Fatal("authorization accepted an undeclared scope")
		}
	})

	t.Run("empty scope", func(t *testing.T) {
		request := signedRequest(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", `{"scope":""}`)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code == http.StatusOK {
			t.Fatal("authorization accepted an empty scope")
		}
	})

	for _, unsupported := range []string{
		`"account":"primary"`,
		`"r3_operations":["records.read"]`,
		`"budget":{"compute":1}`,
	} {
		unsupported := unsupported
		t.Run("known unsupported authorization member "+unsupported, func(t *testing.T) {
			request := signedRequest(
				t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize",
				`{"scope":"records.read",`+unsupported+`}`,
			)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
			}
		})
	}

	t.Run("mission-bound person token preserves the mission digest", func(t *testing.T) {
		missionS256 := aauth.MissionS256([]byte("approved mission content"))
		missionToken, err := aauth.MintPersonToken(psKey, aauth.PersonTokenClaims{
			Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
			Subject: "person-1", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			JTI: "mission-person-token", IssuedAt: now.Unix(), ExpiresAt: now.Add(3 * time.Minute).Unix(),
			MissionS256: missionS256,
		})
		if err != nil {
			t.Fatal(err)
		}
		request := signedRequest(t, clock, agentKey, missionToken, http.MethodPost, resourceIssuer+"/authorize", `{"scope":"records.read"}`)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
		}
		var output struct {
			ResourceToken string `json:"resource_token"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
			t.Fatal(err)
		}
		claims, err := aauth.VerifyResourceToken(context.Background(), output.ResourceToken, resolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		if claims.MissionS256 != missionS256 || claims.ExpiresAt != now.Add(3*time.Minute).Unix() {
			t.Fatalf("mission resource-token claims = %#v", claims)
		}
	})

	t.Run("authorization body components are mandatory", func(t *testing.T) {
		request := signedRequestWithoutBodyComponents(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", `{"scope":"records.read"}`)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusUnauthorized, response.Body.String())
		}
		if response.Header().Get("Signature-Error") == "" {
			t.Fatal("authorization refusal did not advertise missing signature components")
		}

		request = signedRequest(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", `{"scope":"records.read"}`)
		request.Body = io.NopCloser(strings.NewReader(`{"scope":"records.write"}`))
		request.ContentLength = int64(len(`{"scope":"records.write"}`))
		response = httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("mutated body status = %d, want %d; body = %s", response.Code, http.StatusUnauthorized, response.Body.String())
		}
	})
}

func TestAuthorizationEndpointAcceptsPersonTokensFromMultiplePersonServers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 15, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	firstIssuer := "https://ps-one.example"
	secondIssuer := "https://ps-two.example"
	firstKey := testSigningKey(t, "ps-one-key", 12)
	secondKey := testSigningKey(t, "ps-two-key", 13)
	resourceKey := testSigningKey(t, "resource-key", 14)
	agentKey := testSigningKey(t, "agent-key", 15)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: firstIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: firstKey.ID()}:         firstKey.PublicJWK(),
		{Issuer: secondIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: secondKey.ID()}:       secondKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	nextID := 0
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer:       resourceIssuer,
		AccessServer: accessIssuer,
		SigningKey:   resourceKey,
		KeyResolver:  resolver,
		Clock:        clock,
		NewID: func() string {
			nextID++
			return fmt.Sprintf("resource-token-%d", nextID)
		},
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected:         http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, personServer := range []struct {
		issuer string
		key    jose.SigningKey
	}{
		{issuer: firstIssuer, key: firstKey},
		{issuer: secondIssuer, key: secondKey},
	} {
		personToken := mintPersonTokenFrom(t, personServer.issuer, personServer.key, agentKey.PublicJWK(), now, resourceIssuer, "person-token")
		request := signedRequest(t, clock, agentKey, personToken, http.MethodPost, resourceIssuer+"/authorize", `{"scope":"records.read"}`)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("person server %s: status = %d, body = %s", personServer.issuer, response.Code, response.Body.String())
		}
		var body struct {
			ResourceToken string `json:"resource_token"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		claims, err := aauth.VerifyResourceToken(context.Background(), body.ResourceToken, resolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		if claims.PersonServer != personServer.issuer {
			t.Fatalf("person server = %q, want %q", claims.PersonServer, personServer.issuer)
		}
	}
}

func TestProtectedHandlerReceivesCurrentPrincipal(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 5)
	accessKey := testSigningKey(t, "access-key", 6)
	agentKey := testSigningKey(t, "agent-key", 7)
	otherAgentKey := testSigningKey(t, "other-agent-key", 8)
	otherAccessKey := testSigningKey(t, "other-access-key", 9)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:                    accessKey.PublicJWK(),
		{Issuer: "https://other-as.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: otherAccessKey.ID()}: otherAccessKey.PublicJWK(),
	}

	var mu sync.Mutex
	var principals []AuthPrincipal
	var identities []PersonIdentity
	var personContexts []PersonContext
	protected := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		principal, ok := AuthPrincipalFromContext(request.Context())
		if !ok {
			t.Error("protected handler received no principal")
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		mu.Lock()
		principals = append(principals, principal)
		mu.Unlock()
		response.WriteHeader(http.StatusNoContent)
	})
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer:       resourceIssuer,
		AccessServer: accessIssuer,
		SigningKey:   resourceKey,
		KeyResolver:  resolver,
		Clock:        clock,
		NewID:        func() string { return "resource-token-unused" },
		ScopeDescriptions: map[string]string{
			"records.read":   "Read records",
			"records.write":  "Write records",
			"records.delete": "Delete records",
		},
		RequiredScopes: func(request *http.Request) []string {
			switch request.Method {
			case http.MethodGet:
				return []string{"records.read"}
			case http.MethodPost:
				return []string{"records.write"}
			default:
				return []string{"records.delete"}
			}
		},
		ResolvePerson: func(_ context.Context, identity PersonIdentity, personContext PersonContext) error {
			mu.Lock()
			identities = append(identities, identity)
			personContexts = append(personContexts, personContext)
			mu.Unlock()
			return nil
		},
		Protected: protected,
	})
	if err != nil {
		t.Fatal(err)
	}

	initialClaims := authClaims()
	initialClaims.AdditionalClaims = map[string]json.RawMessage{
		"email": json.RawMessage(`"person@example.com"`),
	}
	authToken := mintAuthToken(t, accessKey, agentKey.PublicJWK(), now, initialClaims)
	request := signedRequest(t, clock, agentKey, authToken, http.MethodGet, resourceIssuer+"/records", "")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	mu.Lock()
	if len(principals) != 1 {
		mu.Unlock()
		t.Fatalf("protected calls = %d", len(principals))
	}
	principal := principals[0]
	identity := identities[0]
	personContext := personContexts[0]
	mu.Unlock()
	if principal.PersonServer != personIssuer ||
		principal.Subject != "person-1" ||
		principal.Tenant != "tenant-1" ||
		strings.Join(principal.Scope, " ") != "records.read" ||
		!principal.Confirmation.Equal(agentKey.PublicJWK()) {
		t.Fatalf("principal = %#v", principal)
	}
	if string(principal.AdditionalClaims["email"]) != `"person@example.com"` {
		t.Fatalf("principal additional claims = %#v", principal.AdditionalClaims)
	}
	if identity != (PersonIdentity{Issuer: personIssuer, Subject: "person-1"}) {
		t.Fatalf("resolved person identity = %#v", identity)
	}
	if personContext.Tenant != "tenant-1" || string(personContext.AdditionalClaims["email"]) != `"person@example.com"` {
		t.Fatalf("resolved person context = %#v", personContext)
	}

	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		request := signedRequest(t, clock, agentKey, authToken, method, resourceIssuer+"/records", "")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s with read scope: status = %d, want %d; body = %s", method, response.Code, http.StatusForbidden, response.Body.String())
		}
	}
	mu.Lock()
	resolvedAfterDeniedRoutes := len(identities)
	protectedAfterDeniedRoutes := len(principals)
	mu.Unlock()
	if resolvedAfterDeniedRoutes != 1 || protectedAfterDeniedRoutes != 1 {
		t.Fatalf("denied routes caused side effects: resolved=%d protected=%d", resolvedAfterDeniedRoutes, protectedAfterDeniedRoutes)
	}

	expiredClaims := authClaims()
	expiredClaims.IssuedAt = now.Add(-2 * time.Hour).Unix()
	expiredClaims.ExpiresAt = now.Add(-time.Hour).Unix()
	expiredToken := mintAuthToken(t, accessKey, agentKey.PublicJWK(), now, expiredClaims)
	request = signedRequest(t, clock, agentKey, expiredToken, http.MethodGet, resourceIssuer+"/records", "")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	assertSignatureError(t, response, signaturekey.ErrorExpiredJWT)

	notYetValidClaims := authClaims()
	notYetValidClaims.NotBefore = now.Add(time.Minute).Unix()
	notYetValidClaims.Confirmation = aauth.Confirmation{JWK: agentKey.PublicJWK()}
	payload, err := json.Marshal(notYetValidClaims)
	if err != nil {
		t.Fatal(err)
	}
	notYetValidToken, err := jose.SignCompact(accessKey, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: aauth.AuthTokenType, KeyID: accessKey.ID(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	request = signedRequest(t, clock, agentKey, notYetValidToken, http.MethodGet, resourceIssuer+"/records", "")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	assertSignatureError(t, response, signaturekey.ErrorInvalidJWT)

	unsupportedClaims := authClaims()
	unsupportedKey := agentKey.PublicJWK()
	unsupportedKey.Alg = "EdDSA"
	unsupportedClaims.Confirmation = aauth.Confirmation{JWK: unsupportedKey}
	payload, err = json.Marshal(unsupportedClaims)
	if err != nil {
		t.Fatal(err)
	}
	unsupportedToken, err := jose.SignCompact(accessKey, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: aauth.AuthTokenType, KeyID: accessKey.ID(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	request = signedRequest(t, clock, agentKey, unsupportedToken, http.MethodGet, resourceIssuer+"/records", "")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	assertSignatureError(t, response, signaturekey.ErrorUnsupportedAlgorithm)
	if got := response.Header().Get("Accept-Signature-Alg"); !strings.Contains(got, jose.Ed25519Algorithm) {
		t.Fatalf("Accept-Signature-Alg = %q", got)
	}

	unsupportedHeader, _ := json.Marshal(map[string]any{
		"alg": "PS256", "typ": aauth.AuthTokenType, "kid": accessKey.ID(),
	})
	unsupportedPayload, _ := json.Marshal(func() aauth.AuthTokenClaims {
		claims := authClaims()
		claims.Confirmation = aauth.Confirmation{JWK: agentKey.PublicJWK()}
		return claims
	}())
	unsupportedCompact := base64.RawURLEncoding.EncodeToString(unsupportedHeader) + "." +
		base64.RawURLEncoding.EncodeToString(unsupportedPayload) + "." +
		base64.RawURLEncoding.EncodeToString(make([]byte, 256))
	request = signedRequest(t, clock, agentKey, unsupportedCompact, http.MethodGet, resourceIssuer+"/records", "")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	assertSignatureError(t, response, signaturekey.ErrorUnsupportedAlgorithm)

	unknownIssuerKey := testSigningKey(t, "unknown-access-key", 19)
	unknownToken := mintAuthToken(t, unknownIssuerKey, agentKey.PublicJWK(), now, authClaims())
	request = signedRequest(t, clock, agentKey, unknownToken, http.MethodGet, resourceIssuer+"/records", "")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	assertSignatureError(t, response, signaturekey.ErrorUnknownKey)

	secondClaims := authClaims()
	secondClaims.PersonServer = "https://other-ps.example"
	secondToken := mintAuthToken(t, accessKey, agentKey.PublicJWK(), now, secondClaims)
	request = signedRequest(t, clock, agentKey, secondToken, http.MethodGet, resourceIssuer+"/records", "")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("second person-server status = %d, body = %s", response.Code, response.Body.String())
	}
	mu.Lock()
	secondPrincipal := principals[len(principals)-1]
	mu.Unlock()
	if secondPrincipal.PersonServer != secondClaims.PersonServer || secondPrincipal.Subject != secondClaims.Subject {
		t.Fatalf("second principal = %#v", secondPrincipal)
	}

	missionS256 := aauth.MissionS256([]byte("approved mission content"))
	missionClaims := authClaims()
	missionClaims.MissionS256 = missionS256
	missionToken := mintAuthToken(t, accessKey, agentKey.PublicJWK(), now, missionClaims)
	request = signedRequest(t, clock, agentKey, missionToken, http.MethodGet, resourceIssuer+"/records", "")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("mission-bound status = %d, body = %s", response.Code, response.Body.String())
	}
	mu.Lock()
	missionPrincipal := principals[len(principals)-1]
	missionContext := personContexts[len(personContexts)-1]
	mu.Unlock()
	if missionPrincipal.MissionS256 != missionS256 || missionContext.MissionS256 != missionS256 {
		t.Fatalf("mission-bound principal = %#v, context = %#v", missionPrincipal, missionContext)
	}

	// Repeated concurrent presentations preserve the same principal and must
	// not race.
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			request := signedRequest(t, clock, agentKey, authToken, http.MethodGet, resourceIssuer+"/records", "")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusNoContent {
				t.Errorf("concurrent status = %d", response.Code)
			}
		}()
	}
	wait.Wait()

	tests := []struct {
		name      string
		claims    aauth.AuthTokenClaims
		issuerKey jose.SigningKey
		proofKey  jose.SigningKey
	}{
		{
			name: "wrong issuer",
			claims: func() aauth.AuthTokenClaims {
				claims := authClaims()
				claims.Issuer = "https://other-as.example"
				return claims
			}(),
			issuerKey: otherAccessKey,
			proofKey:  agentKey,
		},
		{
			name: "wrong audience",
			claims: func() aauth.AuthTokenClaims {
				claims := authClaims()
				claims.Audience = "https://other-resource.example"
				return claims
			}(),
			issuerKey: accessKey,
			proofKey:  agentKey,
		},
		{
			name: "account outside immediate slice",
			claims: func() aauth.AuthTokenClaims {
				claims := authClaims()
				claims.Account = testStringPointer("primary")
				return claims
			}(),
			issuerKey: accessKey,
			proofKey:  agentKey,
		},
		{
			name:      "wrong confirmation key",
			claims:    authClaims(),
			issuerKey: accessKey,
			proofKey:  otherAgentKey,
		},
		{
			name: "undeclared scope",
			claims: func() aauth.AuthTokenClaims {
				claims := authClaims()
				claims.Scope = "records.admin"
				return claims
			}(),
			issuerKey: accessKey,
			proofKey:  agentKey,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := mintAuthToken(t, test.issuerKey, agentKey.PublicJWK(), now, test.claims)
			request := signedRequest(t, clock, test.proofKey, token, http.MethodGet, resourceIssuer+"/records", "")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code == http.StatusNoContent {
				t.Fatal("protected request reached the application")
			}
		})
	}

	for _, required := range [][]string{
		nil,
		{"records.unknown"},
		{"records.read", "records.read"},
	} {
		required := append([]string(nil), required...)
		server.requiredScopes = func(*http.Request) []string { return required }
		request := signedRequest(t, clock, agentKey, authToken, http.MethodGet, resourceIssuer+"/records", "")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("required scopes %v: status = %d, want %d; body = %s", required, response.Code, http.StatusInternalServerError, response.Body.String())
		}
	}
}

func TestProtectedHandlerStopsWhenPersonResolutionFails(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 31)
	accessKey := testSigningKey(t, "access-key", 32)
	agentKey := testSigningKey(t, "agent-key", 33)
	protectedCalls := 0
	config := validConfigWithKey(resourceKey, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		protectedCalls++
	}))
	config.Clock = clock
	config.AdditionalSignatureComponents = nil
	config.MaxSignedBodyBytes = 0
	config.KeyResolver = signaturekey.StaticKeyResolver{
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}: accessKey.PublicJWK(),
	}
	config.ResolvePerson = func(context.Context, PersonIdentity, PersonContext) error {
		return errors.New("person directory unavailable")
	}
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	token := mintAuthToken(t, accessKey, agentKey.PublicJWK(), now, authClaims())
	request := signedRequest(t, clock, agentKey, token, http.MethodGet, resourceIssuer+"/records", "")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || protectedCalls != 0 {
		t.Fatalf("status = %d, protected calls = %d, body = %s", response.Code, protectedCalls, response.Body.String())
	}
}

func TestProtectedSignatureRequirementsComeFromConfig(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 16, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "resource-key", 16)
	accessKey := testSigningKey(t, "access-key", 17)
	agentKey := testSigningKey(t, "agent-key", 18)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}: accessKey.PublicJWK(),
	}
	authToken := mintAuthToken(t, accessKey, agentKey.PublicJWK(), now, authClaims())

	newServer := func(components []string, maxBody int64) *Server {
		server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
			Issuer:                        resourceIssuer,
			AccessServer:                  accessIssuer,
			SigningKey:                    resourceKey,
			KeyResolver:                   resolver,
			Clock:                         clock,
			NewID:                         func() string { return "unused" },
			ScopeDescriptions:             map[string]string{"records.read": "Read records"},
			AdditionalSignatureComponents: components,
			MaxSignedBodyBytes:            maxBody,
			RequiredScopes:                func(*http.Request) []string { return []string{"records.read"} },
			ResolvePerson:                 func(context.Context, PersonIdentity, PersonContext) error { return nil },
			Protected:                     http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) }),
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}

	t.Run("body coverage is required by default", func(t *testing.T) {
		server := newServer(nil, 0)
		request := signedRequestWithoutBodyComponents(t, clock, agentKey, authToken, http.MethodPost, resourceIssuer+"/records", `{"query":"all"}`)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("configured body components are required", func(t *testing.T) {
		server := newServer([]string{"content-type", "content-digest"}, 0)
		request := signedRequestWithoutBodyComponents(t, clock, agentKey, authToken, http.MethodPost, resourceIssuer+"/records", `{"query":"all"}`)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusUnauthorized, response.Body.String())
		}

		request = signedRequest(t, clock, agentKey, authToken, http.MethodPost, resourceIssuer+"/records", `{"query":"all"}`)
		response = httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("signed status = %d, body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("configured body limit is enforced", func(t *testing.T) {
		server := newServer([]string{"content-type", "content-digest"}, 4)
		request := signedRequest(t, clock, agentKey, authToken, http.MethodPost, resourceIssuer+"/records", "12345")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusUnauthorized, response.Body.String())
		}
	})
}

func TestHandlerServesResourceDiscovery(t *testing.T) {
	t.Parallel()

	resourceKey := testSigningKey(t, "resource-key", 10)
	config := validConfigWithKey(resourceKey, http.NotFoundHandler())
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	config.ScopeDescriptions["records.read"] = "Changed after construction"
	config.AdditionalSignatureComponents[0] = "authorization"

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, resourceIssuer+"/.well-known/aauth-resource.json", nil)
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("metadata status = %d", response.Code)
	}
	var rawMetadata map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &rawMetadata); err != nil {
		t.Fatal(err)
	}
	if len(rawMetadata) != 6 {
		t.Fatalf("metadata keys = %#v", rawMetadata)
	}
	var metadata struct {
		Issuer                        string            `json:"issuer"`
		JWKSURI                       string            `json:"jwks_uri"`
		AccessMode                    string            `json:"access_mode"`
		AuthorizationEndpoint         string            `json:"authorization_endpoint"`
		ScopeDescriptions             map[string]string `json:"scope_descriptions"`
		AdditionalSignatureComponents []string          `json:"additional_signature_components"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Issuer != resourceIssuer ||
		metadata.JWKSURI != resourceIssuer+"/.well-known/jwks.json" ||
		metadata.AccessMode != string(aauth.AccessModeAuthToken) ||
		metadata.AuthorizationEndpoint != resourceIssuer+"/authorize" {
		t.Fatalf("metadata = %#v", metadata)
	}
	if len(metadata.ScopeDescriptions) != 1 || metadata.ScopeDescriptions["records.read"] != "Read records" {
		t.Fatalf("scope descriptions = %#v", metadata.ScopeDescriptions)
	}
	if strings.Join(metadata.AdditionalSignatureComponents, " ") != "content-type content-digest" {
		t.Fatalf("additional signature components = %#v", metadata.AdditionalSignatureComponents)
	}

	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, resourceIssuer+"/.well-known/jwks.json", nil)
	server.Handler().ServeHTTP(response, request)
	var keys struct {
		Keys []jose.JWK `json:"keys"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || len(keys.Keys) != 1 || keys.Keys[0] != resourceKey.PublicJWK() {
		t.Fatalf("JWKS status = %d, keys = %#v", response.Code, keys.Keys)
	}
}

func validConfig(t *testing.T, protected http.Handler) FederatedAuthorizationConfig {
	t.Helper()
	return validConfigWithKey(testSigningKey(t, "resource-key", 1), protected)
}

func assertSignatureError(t *testing.T, response *httptest.ResponseRecorder, want signaturekey.ErrorCode) {
	t.Helper()
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusUnauthorized, response.Body.String())
	}
	decoded, err := signaturekey.DecodeErrorResponse(response.Result())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Code != want {
		t.Fatalf("Signature-Error = %q, want %q", decoded.Code, want)
	}
}

func validConfigWithKey(key jose.SigningKey, protected http.Handler) FederatedAuthorizationConfig {
	return FederatedAuthorizationConfig{
		Issuer:       resourceIssuer,
		AccessServer: accessIssuer,
		SigningKey:   key,
		KeyResolver:  signaturekey.StaticKeyResolver{},
		Clock:        aauth.SystemClock{},
		NewID:        func() string { return "resource-token-1" },
		ScopeDescriptions: map[string]string{
			"records.read": "Read records",
		},
		AdditionalSignatureComponents: []string{"content-type", "content-digest"},
		MaxSignedBodyBytes:            64 << 10,
		RequiredScopes:                func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:                 func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected:                     protected,
	}
}

func authClaims() aauth.AuthTokenClaims {
	return aauth.AuthTokenClaims{
		Issuer:       accessIssuer,
		DWK:          aauth.AccessDiscoveryDocument,
		Audience:     resourceIssuer,
		JTI:          "auth-token-1",
		PersonServer: personIssuer,
		Subject:      "person-1",
		Scope:        "records.read",
		Tenant:       "tenant-1",
		IssuedAt:     time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC).Unix(),
		ExpiresAt:    time.Date(2026, 8, 29, 17, 0, 0, 0, time.UTC).Unix(),
	}
}

func mintPersonToken(t *testing.T, key jose.SigningKey, confirmation jose.JWK, now time.Time, audience, jti string) string {
	t.Helper()
	return mintPersonTokenFrom(t, personIssuer, key, confirmation, now, audience, jti)
}

func mintPersonTokenFrom(t *testing.T, issuer string, key jose.SigningKey, confirmation jose.JWK, now time.Time, audience, jti string) string {
	t.Helper()
	token, err := aauth.MintPersonToken(key, aauth.PersonTokenClaims{
		Issuer:       issuer,
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     audience,
		Subject:      "person-1",
		Confirmation: aauth.Confirmation{JWK: confirmation},
		JTI:          jti,
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
		Tenant:       "tenant-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func mintAuthToken(t *testing.T, key jose.SigningKey, confirmation jose.JWK, now time.Time, claims aauth.AuthTokenClaims) string {
	t.Helper()
	claims.Confirmation = aauth.Confirmation{JWK: confirmation}
	if claims.IssuedAt == 0 {
		claims.IssuedAt = now.Unix()
	}
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = now.Add(time.Hour).Unix()
	}
	token, err := aauth.MintAuthToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func signedRequest(t *testing.T, clock aauth.Clock, key jose.SigningKey, token, method, target, body string) *http.Request {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, target, reader)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	options := signaturekey.SignOptions{}
	if body != "" {
		options.AdditionalComponents = []string{"content-type", "content-digest"}
	}
	if err := signaturekey.SignJWTRequestWithOptions(request, key, token, clock, options); err != nil {
		t.Fatal(err)
	}
	return request
}

func signedRequestWithoutBodyComponents(t *testing.T, clock aauth.Clock, key jose.SigningKey, token, method, target, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, target, nil)
	if err := signaturekey.SignJWTRequest(request, key, token, clock); err != nil {
		t.Fatal(err)
	}
	request.Body = io.NopCloser(strings.NewReader(body))
	request.ContentLength = int64(len(body))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(body)), nil
	}
	request.Header.Set("Content-Type", "application/json")
	return request
}

func testSigningKey(t *testing.T, id string, fill byte) jose.SigningKey {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testStringPointer(value string) *string { return &value }
