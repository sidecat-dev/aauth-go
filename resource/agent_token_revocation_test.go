package resource

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestDirectAgentResourceRevocationRequiresIssuingProviderAndRetainsMarker(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := testSigningKey(t, "direct-revocation-provider", 0xa1)
	personKey := testSigningKey(t, "direct-revocation-person", 0xa2)
	store := newAgentTokenRevocationTestStore()
	server := newDirectAgentRevocationTestServer(t, clock, providerKey, personKey, store, http.NotFoundHandler())

	metadataResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(metadataResponse, httptest.NewRequest(http.MethodGet, resourceIssuer+"/.well-known/aauth-resource.json", nil))
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(metadataResponse.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if string(metadata["revocation_endpoint"]) != `"`+resourceIssuer+`/revoke"` {
		t.Fatalf("metadata = %s", metadataResponse.Body.String())
	}

	reference := aauth.TokenReference{Issuer: "https://provider.example", JTI: "agent-token-1"}
	revoke := signedRevocationRequestWith(
		t, clock, providerKey, "https://provider.example", aauth.AgentDiscoveryDocument,
		reference, nil, nil,
	)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, revoke)
	if response.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", response.Code, response.Body.String())
	}
	if revoked, err := store.IsRevoked(context.Background(), reference); err != nil || !revoked {
		t.Fatalf("retained revocation = %t, %v", revoked, err)
	}

	// A later use of the revoked Agent token is 401 revoked_jwt.
	agentKey := testSigningKey(t, "direct-revoked-use-agent", 0xa5)
	agentToken, err := aauth.MintAgentToken("https://provider.example", providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:local@provider.example", PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "agent-token-1")
	if err != nil {
		t.Fatal(err)
	}
	use := httptest.NewRequest(http.MethodGet, resourceIssuer+"/records", nil)
	if err := signaturekey.SignJWTRequest(use, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	useResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(useResponse, use)
	if useResponse.Code != http.StatusUnauthorized || !strings.Contains(useResponse.Header().Get("Signature-Error"), "revoked_jwt") {
		t.Fatalf("revoked Agent-token use = %d %q %s", useResponse.Code, useResponse.Header().Get("Signature-Error"), useResponse.Body.String())
	}

	// A body iss is ignored; the revocation is recorded under the verified signer.
	bodyIssuer := signedRevocationBody(
		t, clock, providerKey, "https://provider.example", aauth.AgentDiscoveryDocument,
		[]byte(`{"iss":"https://other.example","jti":"agent-token-2","exp":2000000000}`), nil, nil,
	)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, bodyIssuer)
	if response.Code != http.StatusOK || store.revokeCalls != 2 {
		t.Fatalf("body issuer = %d %s; revokes=%d", response.Code, response.Body.String(), store.revokeCalls)
	}
	if revoked, _ := store.IsRevoked(context.Background(), aauth.TokenReference{Issuer: "https://provider.example", JTI: "agent-token-2"}); !revoked {
		t.Fatal("revocation was not recorded under the signer")
	}
	if revoked, _ := store.IsRevoked(context.Background(), aauth.TokenReference{Issuer: "https://other.example", JTI: "agent-token-2"}); revoked {
		t.Fatal("body iss was honored")
	}

	wrongRole := signedRevocationRequestWith(
		t, clock, personKey, personIssuer, aauth.PersonDiscoveryDocument,
		aauth.TokenReference{Issuer: personIssuer, JTI: "auth-token-1"}, nil, nil,
	)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, wrongRole)
	if response.Code != http.StatusForbidden || store.revokeCalls != 2 {
		t.Fatalf("unconfigured token role = %d %s; revokes=%d", response.Code, response.Body.String(), store.revokeCalls)
	}
}

func TestDirectAgentResourceRevocationStoreFailuresDoNotReachApplication(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := testSigningKey(t, "direct-store-failure-provider", 0xa3)
	agentKey := testSigningKey(t, "direct-store-failure-agent", 0xa4)
	store := newAgentTokenRevocationTestStore()
	applicationCalls := 0
	server := newDirectAgentRevocationTestServer(t, clock, providerKey, jose.SigningKey{}, store, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		applicationCalls++
	}))

	store.revokeErr = errors.New("revocation write unavailable")
	revoke := signedRevocationRequestWith(
		t, clock, providerKey, "https://provider.example", aauth.AgentDiscoveryDocument,
		aauth.TokenReference{Issuer: "https://provider.example", JTI: "agent-token-1"}, nil, nil,
	)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, revoke)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("mutation failure = %d %s", response.Code, response.Body.String())
	}

	store.revokeErr = nil
	store.lookupErr = errors.New("revocation lookup unavailable")
	agentToken, err := aauth.MintAgentToken("https://provider.example", providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:local@provider.example", PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "agent-token-2")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, resourceIssuer+"/records", nil)
	if err := signaturekey.SignJWTRequest(request, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || applicationCalls != 0 {
		t.Fatalf("lookup failure = %d %s; application_calls=%d", response.Code, response.Body.String(), applicationCalls)
	}
}

type agentTokenRevocationTestStore struct {
	mu          sync.Mutex
	revoked     map[aauth.TokenReference]struct{}
	revokeCalls int
	revokeErr   error
	lookupErr   error
}

func newAgentTokenRevocationTestStore() *agentTokenRevocationTestStore {
	return &agentTokenRevocationTestStore{revoked: make(map[aauth.TokenReference]struct{})}
}

func (store *agentTokenRevocationTestStore) Revoke(_ context.Context, request aauth.RevocationRequest) error {
	reference := request.Reference
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revokeCalls++
	if store.revokeErr != nil {
		return store.revokeErr
	}
	store.revoked[reference] = struct{}{}
	return nil
}

func (store *agentTokenRevocationTestStore) IsRevoked(_ context.Context, reference aauth.TokenReference) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lookupErr != nil {
		return false, store.lookupErr
	}
	_, revoked := store.revoked[reference]
	return revoked, nil
}

func newDirectAgentRevocationTestServer(
	t *testing.T,
	clock aauth.Clock,
	providerKey, personKey jose.SigningKey,
	store AgentTokenRevocationStore,
	protected http.Handler,
) *Server {
	t.Helper()
	resolver := signaturekey.StaticKeyResolver{}
	if providerKey.ID() != "" {
		resolver[signaturekey.StaticKeyReference{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}] = providerKey.PublicJWK()
	}
	if personKey.ID() != "" {
		resolver[signaturekey.StaticKeyReference{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}] = personKey.PublicJWK()
	}
	server, err := NewAgentIdentity(AgentIdentityConfig{
		Issuer: resourceIssuer, KeyResolver: resolver, Clock: clock,
		Protected: protected, AgentTokenRevocations: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}
