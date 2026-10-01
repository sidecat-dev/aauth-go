package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestAgentTokenRevocationEndpointRequiresIssuerProofAndExactReference(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := personServerTestKey(t, "agent-revocation-provider-key")
	rogueKey := personServerTestKey(t, "agent-revocation-rogue-key")
	store := &testAgentTokenRevocationStore{}
	server := newAgentRevocationTestServer(t, clock, providerKey, store)

	tests := []struct {
		name       string
		body       string
		sign       bool
		signingKey jose.SigningKey
		wantStatus int
		wantCode   string
	}{
		{
			name: "unsigned", body: `{"iss":"https://provider.example","jti":"agent-token-1"}`,
			wantStatus: http.StatusUnauthorized, wantCode: "invalid_request",
		},
		{
			name: "unknown proof key", body: `{"iss":"https://provider.example","jti":"agent-token-1"}`,
			sign: true, signingKey: rogueKey, wantStatus: http.StatusUnauthorized, wantCode: "invalid_request",
		},
		{
			name: "reference issuer differs from signer", body: `{"iss":"https://other.example","jti":"agent-token-1"}`,
			sign: true, signingKey: providerKey, wantStatus: http.StatusForbidden, wantCode: "unsupported_iss",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://person.example/revoke", bytes.NewBufferString(test.body))
			request.Header.Set("Content-Type", "application/json")
			if test.sign {
				if err := signaturekey.SignJWKSURIRequestWithOptions(request, test.signingKey, "https://provider.example", aauth.AgentDiscoveryDocument, clock, signaturekey.SignOptions{
					AdditionalComponents: []string{"content-type", "content-digest"}, MaxBodyBytes: maxRequestBytes,
				}); err != nil {
					t.Fatal(err)
				}
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			var problem struct {
				Code string `json:"error"`
			}
			if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.wantStatus || problem.Code != test.wantCode {
				t.Fatalf("response = %d %q, want %d %q", response.Code, problem.Code, test.wantStatus, test.wantCode)
			}
		})
	}
	if store.revokes != 0 {
		t.Fatalf("invalid requests reached revocation store; calls=%d", store.revokes)
	}
}

func TestAgentTokenRevocationConfigurationControlsMetadataAndRoute(t *testing.T) {
	t.Parallel()
	clock := aauth.ClockFunc(func() time.Time { return time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC) })
	providerKey := personServerTestKey(t, "metadata-provider-key")
	without := newAgentRevocationTestServer(t, clock, providerKey, nil)
	with := newAgentRevocationTestServer(t, clock, providerKey, &testAgentTokenRevocationStore{})
	federated := newAgentRevocationFederatedTestServer(t, clock, providerKey, &testAgentTokenRevocationStore{})

	for _, test := range []struct {
		name            string
		server          *Server
		wantEndpoint    string
		wantRouteStatus int
	}{
		{name: "unconfigured", server: without, wantRouteStatus: http.StatusNotFound},
		{name: "configured", server: with, wantEndpoint: "https://person.example/revoke", wantRouteStatus: http.StatusUnauthorized},
		{name: "configured federated", server: federated, wantEndpoint: "https://person.example/revoke", wantRouteStatus: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadataResponse := httptest.NewRecorder()
			test.server.Handler().ServeHTTP(metadataResponse, httptest.NewRequest(http.MethodGet, "https://person.example/.well-known/aauth-person.json", nil))
			var metadata map[string]string
			if err := json.NewDecoder(metadataResponse.Body).Decode(&metadata); err != nil {
				t.Fatal(err)
			}
			if metadata["revocation_endpoint"] != test.wantEndpoint {
				t.Fatalf("revocation_endpoint = %q, want %q", metadata["revocation_endpoint"], test.wantEndpoint)
			}
			response := httptest.NewRecorder()
			test.server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://person.example/revoke", nil))
			if response.Code != test.wantRouteStatus {
				t.Fatalf("route status = %d, want %d", response.Code, test.wantRouteStatus)
			}
		})
	}
}

func TestAgentTokenRevocationMutationFailureIsServerError(t *testing.T) {
	t.Parallel()
	clock := aauth.ClockFunc(func() time.Time { return time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC) })
	providerKey := personServerTestKey(t, "mutation-failure-provider-key")
	store := &testAgentTokenRevocationStore{revokeErr: errors.New("revocation write unavailable")}
	server := newAgentRevocationTestServer(t, clock, providerKey, store)
	request := httptest.NewRequest(http.MethodPost, "https://person.example/revoke", bytes.NewBufferString(`{"iss":"https://provider.example","jti":"agent-token-1"}`))
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequestWithOptions(request, providerKey, "https://provider.example", aauth.AgentDiscoveryDocument, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"}, MaxBodyBytes: maxRequestBytes,
	}); err != nil {
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
	if response.Code != http.StatusInternalServerError || problem.Code != "server_error" || store.revokes != 1 {
		t.Fatalf("response=%d %q revokes=%d", response.Code, problem.Code, store.revokes)
	}
}

func TestAgentTokenRevocationStoreFailureIsServerErrorBeforePolicy(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := personServerTestKey(t, "store-failure-provider-key")
	agentKey := personServerTestKey(t, "store-failure-agent-key")
	store := &testAgentTokenRevocationStore{lookupErr: errors.New("revocation store unavailable")}
	policyCalls := 0
	server := newAgentRevocationTestServerWithPolicy(t, clock, providerKey, store, func(context.Context, PersonTokenRequest) (Person, error) {
		policyCalls++
		return Person{Subject: "person-123", Lifetime: time.Minute}, nil
	})
	agentToken, err := aauth.MintAgentToken("https://provider.example", providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:agent@provider.example", PersonServer: "https://person.example",
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "agent-token-1")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://person.example/person", bytes.NewBufferString(`{"resource":"https://resource.example"}`))
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
	if response.Code != http.StatusInternalServerError || problem.Code != "server_error" || policyCalls != 0 {
		t.Fatalf("response=%d %q policy_calls=%d", response.Code, problem.Code, policyCalls)
	}
}

type testAgentTokenRevocationStore struct {
	revokes   int
	revoked   bool
	revokeErr error
	lookupErr error
}

func (store *testAgentTokenRevocationStore) Revoke(context.Context, aauth.RevocationRequest) error {
	store.revokes++
	if store.revokeErr != nil {
		return store.revokeErr
	}
	store.revoked = true
	return nil
}

func newAgentRevocationFederatedTestServer(t *testing.T, clock aauth.Clock, providerKey jose.SigningKey, store AgentTokenRevocationStore) *Server {
	t.Helper()
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: "https://person.example", SigningKey: personServerTestKey(t, "agent-revocation-federated-person-key"),
		KeyResolver: signaturekey.StaticKeyResolver{
			{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
		},
		Clock: clock, NewID: func() string { return "unused" }, Tokens: newMemoryTokenStore(),
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{Subject: "person-123", Lifetime: time.Minute}, nil
		},
		HTTPClient: http.DefaultClient,
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://access.example/token", nil
		},
		Consent:               func(context.Context, AuthorizationRequest) error { return nil },
		AgentTokenRevocations: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func (store *testAgentTokenRevocationStore) IsRevoked(context.Context, aauth.TokenReference) (bool, error) {
	return store.revoked, store.lookupErr
}

func newAgentRevocationTestServer(t *testing.T, clock aauth.Clock, providerKey jose.SigningKey, store AgentTokenRevocationStore) *Server {
	t.Helper()
	return newAgentRevocationTestServerWithPolicy(t, clock, providerKey, store, func(context.Context, PersonTokenRequest) (Person, error) {
		return Person{Subject: "person-123", Lifetime: time.Minute}, nil
	})
}

func newAgentRevocationTestServerWithPolicy(t *testing.T, clock aauth.Clock, providerKey jose.SigningKey, store AgentTokenRevocationStore, bind func(context.Context, PersonTokenRequest) (Person, error)) *Server {
	t.Helper()
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: "https://person.example", SigningKey: personServerTestKey(t, "agent-revocation-person-key"),
		KeyResolver: signaturekey.StaticKeyResolver{
			{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
		},
		Clock: clock, NewID: func() string { return "unused" }, Tokens: newMemoryTokenStore(), BindPerson: bind,
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: []string{"unused"}, Lifetime: time.Minute}, nil
		},
		AgentTokenRevocations: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}
