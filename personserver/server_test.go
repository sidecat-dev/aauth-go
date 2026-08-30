package personserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "aauth-go"
	"aauth-go/jose"
	"aauth-go/signaturekey"
)

func TestServerIssuesAndRetainsDirectedPersonToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := personServerTestKey(t, "provider-key")
	personServerKey := personServerTestKey(t, "person-server-key")
	agentKey := personServerTestKey(t, "agent-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
		{Issuer: "https://person.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personServerKey.ID()}: personServerKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken(
		"https://provider.example",
		providerKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:planner@provider.example",
			PersonServer: "https://person.example",
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     10 * time.Minute,
			AdditionalClaims: map[string]json.RawMessage{
				"platform_attestation": json.RawMessage(`{"level":"example"}`),
			},
		},
		now,
		"agent-token-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryTokenStore()
	var bound PersonTokenRequest
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer:                       "https://person.example",
		SigningKey:                   personServerKey,
		KeyResolver:                  resolver,
		Clock:                        clock,
		NewID:                        func() string { return "person-token-1" },
		HTTPClient:                   http.DefaultClient,
		MaximumResourceTokenLifetime: 12 * time.Minute,
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://access.example/token", nil
		},
		Tokens: store,
		BindPerson: func(_ context.Context, request PersonTokenRequest) (Person, error) {
			bound = request
			return Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: 20 * time.Minute}, nil
		},
		Consent: func(context.Context, AuthorizationRequest) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"resource":"https://resource.example","example_extension":{"future":true}}`)
	request := httptest.NewRequest(http.MethodPost, "https://person.example/person", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-AAuth-Client", "test-client")
	if err := signaturekey.SignJWTRequestWithOptions(request, agentKey, agentToken, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest", "x-aauth-client"},
		MaxBodyBytes:         maxRequestBytes,
	}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, headers = %v, body = %s", response.Code, response.Header(), response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("person-token Cache-Control = %q, want no-store", got)
	}
	var output struct {
		PersonToken string `json:"person_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyPersonToken(context.Background(), output.PersonToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "https://person.example" ||
		claims.DWK != aauth.PersonDiscoveryDocument ||
		claims.Audience != "https://resource.example" ||
		claims.Subject != "person-123" ||
		claims.Tenant != "tenant-1" ||
		claims.JTI != "person-token-1" ||
		!claims.Confirmation.JWK.Equal(agentKey.PublicJWK()) ||
		output.ExpiresIn != int64((10*time.Minute)/time.Second) {
		t.Fatalf("person token = %#v; expires_in = %d", claims, output.ExpiresIn)
	}
	if bound.Agent != "aauth:planner@provider.example" || bound.Resource != "https://resource.example" {
		t.Fatalf("person binding request = %#v", bound)
	}
	if string(bound.AgentAdditionalClaims["platform_attestation"]) != `{"level":"example"}` {
		t.Fatalf("person binding agent claims = %#v", bound.AgentAdditionalClaims)
	}
	record, commits, _ := store.observation()
	if commits != 1 || record.JTI != claims.JTI ||
		record.PersonServer != claims.Issuer || record.Resource != claims.Audience ||
		record.Subject != claims.Subject || record.Tenant != claims.Tenant ||
		!record.ExpiresAt.Equal(time.Unix(claims.ExpiresAt, 0)) ||
		!record.RetainUntil.Equal(record.ExpiresAt.Add(12*time.Minute)) {
		t.Fatalf("retained person token = %#v; commits = %d", record, commits)
	}

	expiredAgentToken, err := aauth.MintAgentToken(
		"https://provider.example", providerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:planner@provider.example", PersonServer: "https://person.example",
			PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		},
		now.Add(-2*time.Hour), "expired-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "https://person.example/person", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, agentKey, expiredAgentToken, clock); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	assertPersonServerProblem(t, response, "expired_agent_token")
	_, commits, _ = store.observation()
	if commits != 1 {
		t.Fatalf("expired agent token changed retained records; commits = %d", commits)
	}

	for name, unsupportedBody := range map[string]string{
		"mission":       `{"resource":"https://resource.example","mission_s256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
		"upstream":      `{"resource":"https://resource.example","upstream_token":"token"}`,
		"justification": `{"resource":"https://resource.example","justification":"because"}`,
		"login hint":    `{"resource":"https://resource.example","login_hint":"person@example.com"}`,
		"tenant":        `{"resource":"https://resource.example","tenant":"tenant-1"}`,
		"domain hint":   `{"resource":"https://resource.example","domain_hint":"example.com"}`,
		"prompt":        `{"resource":"https://resource.example","prompt":"consent"}`,
		"platform":      `{"resource":"https://resource.example","platform":"desktop"}`,
		"device":        `{"resource":"https://resource.example","device":"test device"}`,
		"capabilities":  `{"resource":"https://resource.example","capabilities":["interaction"]}`,
	} {
		t.Run("known unsupported person request "+name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://person.example/person", strings.NewReader(unsupportedBody))
			request.Header.Set("Content-Type", "application/json")
			if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			assertPersonServerProblem(t, response, "invalid_request")
		})
	}
}

func TestServerDoesNotReleasePersonTokenWhenRetentionFails(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := personServerTestKey(t, "provider-key")
	personServerKey := personServerTestKey(t, "person-server-key")
	agentKey := personServerTestKey(t, "agent-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken(
		"https://provider.example",
		providerKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:planner@provider.example",
			PersonServer: "https://person.example",
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     time.Hour,
			AdditionalClaims: map[string]json.RawMessage{
				"platform_attestation": json.RawMessage(`{"level":"example"}`),
			},
		},
		now,
		"agent-token-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryTokenStore()
	store.commitErr = errors.New("store unavailable")
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer:      "https://person.example",
		SigningKey:  personServerKey,
		KeyResolver: resolver,
		Clock:       clock,
		NewID:       func() string { return "person-token-1" },
		HTTPClient:  http.DefaultClient,
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://access.example/token", nil
		},
		Tokens: store,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{Subject: "person-123", Lifetime: time.Minute}, nil
		},
		Consent: func(context.Context, AuthorizationRequest) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://person.example/person", bytes.NewReader([]byte(`{"resource":"https://resource.example"}`)))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	var problem map[string]any
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusInternalServerError || problem["error"] != "server_error" || problem["person_token"] != nil {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("problem Cache-Control = %q, want no-store", got)
	}
}

func TestServerExchangesRetainedPersonContextWithAccessServer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 19, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := personServerTestKey(t, "provider-key")
	personServerKey := personServerTestKey(t, "person-server-key")
	resourceKey := personServerTestKey(t, "resource-key")
	accessServerKey := personServerTestKey(t, "access-server-key")
	agentKey := personServerTestKey(t, "agent-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
		{Issuer: "https://person.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personServerKey.ID()}: personServerKey.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessServerKey.ID()}: accessServerKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken(
		"https://provider.example",
		providerKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:planner@provider.example",
			PersonServer: "https://person.example",
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     time.Hour,
			AdditionalClaims: map[string]json.RawMessage{
				"platform_attestation": json.RawMessage(`{"level":"example"}`),
			},
		},
		now,
		"agent-token-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-token-1", AgentJKT: agentJKT,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Scope: "records.read records.write", PersonServer: "https://person.example",
		Subject: "person-123", PresentedJTI: "person-token-1", Tenant: "tenant-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := aauth.MintAuthToken(accessServerKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-token-1",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
		Subject: "person-123", Scope: "records.read", PersonServer: "https://person.example",
		Tenant: "tenant-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	accessResponse, err := json.Marshal(struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}{AuthToken: authToken, ExpiresIn: 1800})
	if err != nil {
		t.Fatal(err)
	}
	accessCalls := 0
	deny := false
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		accessCalls++
		if request.URL.String() != "https://api.access.example/token" {
			t.Fatalf("access-server endpoint = %q", request.URL)
		}
		prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
			RequiredComponents: []string{"content-type", "content-digest"}, RequireExactComponents: true,
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
			MaxBodyBytes:    maxRequestBytes,
		})
		if err != nil {
			t.Fatal(err)
		}
		issuer, document, keyID, ok := prepared.Credential().JWKSURI()
		if !ok || issuer != "https://person.example" || document != aauth.PersonDiscoveryDocument || keyID != personServerKey.ID() {
			t.Fatalf("access-server credential = %q %q %q %v", issuer, document, keyID, ok)
		}
		if _, err := prepared.Verify(personServerKey.PublicJWK()); err != nil {
			t.Fatal(err)
		}
		var input struct {
			ResourceToken string `json:"resource_token"`
			AgentToken    string `json:"agent_token"`
		}
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		if input.ResourceToken != resourceToken || input.AgentToken != agentToken {
			t.Fatalf("access-server input = %#v", input)
		}
		if deny {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Status:     "403 Forbidden",
				Header:     http.Header{"Content-Type": []string{"application/problem+json"}},
				Body:       io.NopCloser(strings.NewReader(`{"status":403,"error":"access_denied"}`)),
				Request:    request,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(accessResponse)),
			Request:    request,
		}, nil
	})}
	store := newMemoryTokenStore()
	personRecord := directPersonTokenRecord(
		"person-token-1", "https://person.example", "https://resource.example", "person-123", "tenant-1",
		"https://provider.example", "aauth:planner@provider.example", agentKey.PublicJWK(),
		now.Add(20*time.Minute), now.Add(25*time.Minute),
	)
	if err := store.Commit(context.Background(), personRecord); err != nil {
		t.Fatal(err)
	}
	var consented AuthorizationRequest
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer:      "https://person.example",
		SigningKey:  personServerKey,
		KeyResolver: resolver,
		Clock:       clock,
		NewID:       func() string { return "unused" },
		HTTPClient:  httpClient,
		AccessServerEndpoint: func(_ context.Context, identifier string) (string, error) {
			if identifier != "https://access.example" {
				t.Fatalf("access-server identifier = %q", identifier)
			}
			return "https://api.access.example/token", nil
		},
		Tokens: store,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{}, errors.New("not used")
		},
		Consent: func(_ context.Context, request AuthorizationRequest) error {
			consented = request
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(struct {
		ResourceToken string `json:"resource_token"`
	}{ResourceToken: resourceToken})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://person.example/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		t.Fatal(err)
	}
	if output.AuthToken != authToken || output.ExpiresIn != 1800 || accessCalls != 1 {
		t.Fatalf("access response = %#v; calls = %d", output, accessCalls)
	}
	if consented.Agent != "aauth:planner@provider.example" ||
		consented.Resource != "https://resource.example" ||
		consented.Subject != "person-123" || consented.Tenant != "tenant-1" ||
		!reflect.DeepEqual(consented.Scopes, []string{"records.read", "records.write"}) {
		t.Fatalf("consent request = %#v", consented)
	}
	if string(consented.AgentAdditionalClaims["platform_attestation"]) != `{"level":"example"}` {
		t.Fatalf("consent agent claims = %#v", consented.AgentAdditionalClaims)
	}
	loaded, _, loads := store.observation()
	assertPersonTokenRecordEqual(t, loaded, personRecord)
	if loads != 1 {
		t.Fatalf("person-token record loads = %d, want 1", loads)
	}

	for name, value := range map[string]any{
		"upstream_token": "token",
		"justification":  "because",
		"login_hint":     "person@example.com",
		"tenant":         "tenant-1",
		"domain_hint":    "example.com",
		"prompt":         "consent",
		"platform":       "desktop",
		"device":         "test device",
		"capabilities":   []string{"interaction"},
	} {
		t.Run("known unsupported token request "+name, func(t *testing.T) {
			requestBody, err := json.Marshal(map[string]any{"resource_token": resourceToken, name: value})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "https://person.example/token", bytes.NewReader(requestBody))
			request.Header.Set("Content-Type", "application/json")
			if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			assertPersonServerProblem(t, response, "invalid_request")
			if accessCalls != 1 {
				t.Fatalf("unsupported request reached Access Server; calls = %d", accessCalls)
			}
		})
	}

	expiredResourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "expired-resource-token", AgentJKT: agentJKT,
		IssuedAt: now.Add(-10 * time.Minute).Unix(), ExpiresAt: now.Add(-5 * time.Minute).Unix(),
		Scope: "records.read", PersonServer: "https://person.example", Subject: "person-123",
		PresentedJTI: "person-token-1", Tenant: "tenant-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	expiredBody, err := json.Marshal(struct {
		ResourceToken string `json:"resource_token"`
	}{ResourceToken: expiredResourceToken})
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "https://person.example/token", bytes.NewReader(expiredBody))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	assertPersonServerProblem(t, response, "expired_resource_token")
	if accessCalls != 1 {
		t.Fatalf("expired resource token reached Access Server; calls = %d", accessCalls)
	}

	deny = true
	request = httptest.NewRequest(http.MethodPost, "https://person.example/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	var denial struct {
		Code string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&denial); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusForbidden || denial.Code != "access_denied" {
		t.Fatalf("denial status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestServerRefusesResourceTokenThatChangesRetainedPerson(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 19, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := personServerTestKey(t, "provider-key")
	personServerKey := personServerTestKey(t, "person-server-key")
	resourceKey := personServerTestKey(t, "resource-key")
	agentKey := personServerTestKey(t, "agent-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken(
		"https://provider.example", providerKey,
		aauth.AgentTokenRequest{Agent: "aauth:planner@provider.example", PersonServer: "https://person.example", PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour},
		now, "agent-token-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-token-1", AgentJKT: agentJKT,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Scope: "records.read",
		PersonServer: "https://person.example", Subject: "changed-person",
		PresentedJTI: "person-token-1", Tenant: "tenant-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryTokenStore()
	if err := store.Commit(context.Background(), directPersonTokenRecord(
		"person-token-1", "https://person.example", "https://resource.example", "person-123", "tenant-1",
		"https://provider.example", "aauth:planner@provider.example", agentKey.PublicJWK(),
		now.Add(20*time.Minute), now.Add(25*time.Minute),
	)); err != nil {
		t.Fatal(err)
	}
	accessCalls := 0
	consentCalls := 0
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: "https://person.example", SigningKey: personServerKey,
		KeyResolver: resolver, Clock: clock, NewID: func() string { return "unused" },
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			accessCalls++
			return nil, errors.New("must not call access server")
		})},
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://access.example/token", nil
		},
		Tokens:     store,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
		Consent: func(context.Context, AuthorizationRequest) error {
			consentCalls++
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(struct {
		ResourceToken string `json:"resource_token"`
	}{ResourceToken: resourceToken})
	request := httptest.NewRequest(http.MethodPost, "https://person.example/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || accessCalls != 0 || consentCalls != 0 {
		t.Fatalf("response = %d %s; access=%d consent=%d", response.Code, response.Body.String(), accessCalls, consentCalls)
	}
}

func TestServerRefusesUnusableResourceTokenBeforePolicy(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 19, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := personServerTestKey(t, "provider-key")
	personServerKey := personServerTestKey(t, "person-server-key")
	resourceKey := personServerTestKey(t, "resource-key")
	agentKey := personServerTestKey(t, "agent-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken(
		"https://provider.example", providerKey,
		aauth.AgentTokenRequest{Agent: "aauth:planner@provider.example", PersonServer: "https://person.example", PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour},
		now, "agent-token-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name                  string
		resourceTokenLifetime time.Duration
		personTokenLifetime   time.Duration
		retainFor             time.Duration
		account               string
		interaction           *aauth.ResourceInteraction
		missionS256           string
	}{
		{
			name:                  "resource token exceeds configured maximum",
			resourceTokenLifetime: 6 * time.Minute,
			personTokenLifetime:   20 * time.Minute,
			retainFor:             25 * time.Minute,
		},
		{
			name:                  "resource token outlives retained person context",
			resourceTokenLifetime: 5 * time.Minute,
			personTokenLifetime:   2 * time.Minute,
			retainFor:             4 * time.Minute,
		},
		{
			name:                  "account branch is outside the immediate flow",
			resourceTokenLifetime: 5 * time.Minute,
			personTokenLifetime:   20 * time.Minute,
			retainFor:             25 * time.Minute,
			account:               "account-123",
		},
		{
			name:                  "interaction branch requires the deferred flow",
			resourceTokenLifetime: 5 * time.Minute,
			personTokenLifetime:   20 * time.Minute,
			retainFor:             25 * time.Minute,
			interaction: &aauth.ResourceInteraction{
				URL: "https://resource.example/interaction", Code: "ABCD-EFGH",
			},
		},
		{
			name:                  "mission branch requires mission verification",
			resourceTokenLifetime: 5 * time.Minute,
			personTokenLifetime:   20 * time.Minute,
			retainFor:             25 * time.Minute,
			missionS256:           strings.Repeat("A", 43),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			resourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
				Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
				Audience: "https://access.example", JTI: "resource-token-1", AgentJKT: agentJKT,
				IssuedAt: now.Unix(), ExpiresAt: now.Add(test.resourceTokenLifetime).Unix(), Scope: "records.read",
				PersonServer: "https://person.example", Subject: "person-123",
				PresentedJTI: "person-token-1", Tenant: "tenant-1",
				Account: test.account, Interaction: test.interaction,
				MissionS256: test.missionS256,
			})
			if err != nil {
				t.Fatal(err)
			}
			store := newMemoryTokenStore()
			if err := store.Commit(context.Background(), directPersonTokenRecord(
				"person-token-1", "https://person.example", "https://resource.example", "person-123", "tenant-1",
				"https://provider.example", "aauth:planner@provider.example", agentKey.PublicJWK(),
				now.Add(test.personTokenLifetime), now.Add(test.retainFor),
			)); err != nil {
				t.Fatal(err)
			}
			accessCalls := 0
			consentCalls := 0
			server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
				Issuer: "https://person.example", SigningKey: personServerKey,
				KeyResolver: resolver, Clock: clock, NewID: func() string { return "unused" },
				HTTPClient:                   http.DefaultClient,
				MaximumResourceTokenLifetime: 5 * time.Minute,
				AccessServerEndpoint: func(context.Context, string) (string, error) {
					accessCalls++
					return "https://access.example/token", nil
				},
				Tokens:     store,
				BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
				Consent: func(context.Context, AuthorizationRequest) error {
					consentCalls++
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(struct {
				ResourceToken string `json:"resource_token"`
			}{ResourceToken: resourceToken})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "https://person.example/token", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			var problem struct {
				Code string `json:"error"`
			}
			if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusBadRequest || problem.Code != "invalid_resource_token" || accessCalls != 0 || consentCalls != 0 {
				t.Fatalf("response=%d %q access=%d consent=%d", response.Code, problem.Code, accessCalls, consentCalls)
			}
		})
	}
}

func TestServerPublishesPersonMetadataAndJWKS(t *testing.T) {
	t.Parallel()

	key := personServerTestKey(t, "person-server-key")
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer:      "https://person.example",
		SigningKey:  key,
		KeyResolver: signaturekey.StaticKeyResolver{},
		Clock:       aauth.ClockFunc(time.Now),
		NewID:       func() string { return "unused" },
		HTTPClient:  http.DefaultClient,
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://access.example/token", nil
		},
		Tokens:     newMemoryTokenStore(),
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
		Consent:    func(context.Context, AuthorizationRequest) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	metadataResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(metadataResponse, httptest.NewRequest(
		http.MethodGet, "https://person.example/.well-known/aauth-person.json", nil,
	))
	if metadataResponse.Code != http.StatusOK {
		t.Fatalf("metadata status = %d, body = %s", metadataResponse.Code, metadataResponse.Body.String())
	}
	if got := metadataResponse.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("metadata Cache-Control = %q, want empty", got)
	}
	var metadata map[string]string
	if err := json.NewDecoder(metadataResponse.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	wantMetadata := map[string]string{
		"issuer":                "https://person.example",
		"person_token_endpoint": "https://person.example/person",
		"auth_token_endpoint":   "https://person.example/token",
		"jwks_uri":              "https://person.example/.well-known/jwks.json",
	}
	if !reflect.DeepEqual(metadata, wantMetadata) {
		t.Fatalf("metadata = %#v, want %#v", metadata, wantMetadata)
	}

	jwksResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(jwksResponse, httptest.NewRequest(
		http.MethodGet, "https://person.example/.well-known/jwks.json", nil,
	))
	if jwksResponse.Code != http.StatusOK {
		t.Fatalf("JWKS status = %d, body = %s", jwksResponse.Code, jwksResponse.Body.String())
	}
	if got := jwksResponse.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("JWKS Cache-Control = %q, want empty", got)
	}
	var jwks struct {
		Keys []jose.JWK `json:"keys"`
	}
	if err := json.NewDecoder(jwksResponse.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 1 || !jwks.Keys[0].Equal(key.PublicJWK()) {
		t.Fatalf("JWKS = %#v", jwks)
	}
}

func TestNewFederatedAuthorizationClonesHTTPClientAndRefusesAccessServerRedirects(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			firstOriginCalls := 0
			secondOriginCalls := 0
			callerRedirectCalls := 0
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.Host {
				case "access.example":
					firstOriginCalls++
					return &http.Response{
						StatusCode: status,
						Status:     http.StatusText(status),
						Header:     http.Header{"Location": []string{"https://other.example/token"}},
						Body:       io.NopCloser(bytes.NewReader(nil)),
						Request:    request,
					}, nil
				case "other.example":
					secondOriginCalls++
					return &http.Response{
						StatusCode: http.StatusNoContent,
						Status:     "204 No Content",
						Header:     make(http.Header),
						Body:       io.NopCloser(bytes.NewReader(nil)),
						Request:    request,
					}, nil
				default:
					return nil, errors.New("unexpected origin")
				}
			})
			callerClient := &http.Client{
				Transport: transport,
				CheckRedirect: func(*http.Request, []*http.Request) error {
					callerRedirectCalls++
					return nil
				},
			}
			server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
				Issuer:      "https://person.example",
				SigningKey:  personServerTestKey(t, "person-server-key"),
				KeyResolver: signaturekey.StaticKeyResolver{},
				Clock:       aauth.ClockFunc(time.Now),
				NewID:       func() string { return "unused" },
				HTTPClient:  callerClient,
				AccessServerEndpoint: func(context.Context, string) (string, error) {
					return "https://access.example/token", nil
				},
				Tokens:     newMemoryTokenStore(),
				BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
				Consent:    func(context.Context, AuthorizationRequest) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}

			response, err := server.httpClient.Get("https://access.example/token")
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != status || firstOriginCalls != 1 || secondOriginCalls != 0 || callerRedirectCalls != 0 {
				t.Fatalf("server request: status=%d first=%d second=%d caller_redirects=%d", response.StatusCode, firstOriginCalls, secondOriginCalls, callerRedirectCalls)
			}

			response, err = callerClient.Get("https://access.example/token")
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusNoContent || firstOriginCalls != 2 || secondOriginCalls != 1 || callerRedirectCalls != 1 {
				t.Fatalf("caller request: status=%d first=%d second=%d caller_redirects=%d", response.StatusCode, firstOriginCalls, secondOriginCalls, callerRedirectCalls)
			}
		})
	}
}

func TestNewFederatedAuthorizationRejectsIncompleteConfiguration(t *testing.T) {
	t.Parallel()

	if _, err := NewFederatedAuthorization(FederatedAuthorizationConfig{}); err == nil {
		t.Fatal("empty configuration was accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func assertPersonServerProblem(t *testing.T, response *httptest.ResponseRecorder, code string) {
	t.Helper()
	var problem struct {
		Code string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusBadRequest || problem.Code != code {
		t.Fatalf("status = %d, problem = %#v", response.Code, problem)
	}
}

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type memoryTokenStore struct {
	mu        sync.Mutex
	records   map[string]PersonTokenRecord
	last      PersonTokenRecord
	commits   int
	loads     int
	commitErr error
}

func directPersonTokenRecord(
	jti string,
	personServer string,
	resource string,
	subject string,
	tenant string,
	agentProvider string,
	agent string,
	confirmation jose.JWK,
	expiresAt time.Time,
	retainUntil time.Time,
) PersonTokenRecord {
	return PersonTokenRecord{
		JTI: jti, PersonServer: personServer, Resource: resource, Subject: subject, Tenant: tenant,
		AgentProvider: agentProvider, Agent: agent, Confirmation: confirmation,
		ExpiresAt: expiresAt, RetainUntil: retainUntil,
	}
}

func newMemoryTokenStore() *memoryTokenStore {
	return &memoryTokenStore{records: make(map[string]PersonTokenRecord)}
}

func (store *memoryTokenStore) Commit(_ context.Context, record PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.commits++
	if store.commitErr != nil {
		return store.commitErr
	}
	store.last = record
	store.records[record.PersonServer+"\x00"+record.JTI] = record
	return nil
}

func (store *memoryTokenStore) Load(_ context.Context, personServer, jti string) (PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.loads++
	record, ok := store.records[personServer+"\x00"+jti]
	if !ok {
		return PersonTokenRecord{}, ErrPersonTokenNotFound
	}
	return record, nil
}

func (store *memoryTokenStore) observation() (PersonTokenRecord, int, int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.last, store.commits, store.loads
}

func personServerTestKey(t *testing.T, id string) jose.SigningKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signPersonServerTestRequest(request *http.Request, key jose.SigningKey, compact string, clock aauth.Clock) error {
	return signaturekey.SignJWTRequestWithOptions(request, key, compact, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
		MaxBodyBytes:         maxRequestBytes,
	})
}

func assertPersonTokenRecordEqual(t *testing.T, got, want PersonTokenRecord) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("person token record = %#v, want %#v", got, want)
	}
}
