package aauth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestCurrentThreePartyMissionAuthorizationJourney(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 6, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs(
		"agent-token-1",
		"person-token-1",
		"resource-token-1",
		"auth-token-1",
	)

	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	resourceKey := testSigningKey(t, "resource-key")
	agentKey := testSigningKey(t, "agent-key")

	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: apKey,
		Clock:      clock,
		NewID:      ids,
	})
	if err != nil {
		t.Fatal(err)
	}

	discoveryClient := &http.Client{}
	keyResolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: discoveryClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			for _, allowed := range []string{
				"https://ap.example/",
				"https://ps.example/",
				"https://resource.example/",
			} {
				if strings.HasPrefix(endpoint, allowed) {
					return nil
				}
			}
			return fmt.Errorf("discovery endpoint is outside the test trust boundary: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	agentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:planner@ap.example",
		PersonServer: "https://ps.example",
		PublicKey:    agentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	personTokenStore, missionIssuanceStore := testCurrentPersonServerCustody(t)
	ps, err := reference.NewPersonServer(reference.PersonServerConfig{
		AuthorizationStore:   testAuthorizationStateStore(t),
		Identifier:           "https://ps.example",
		SigningKey:           psKey,
		KeyResolver:          keyResolver,
		Clock:                clock,
		NewID:                ids,
		PersonTokenStore:     personTokenStore,
		MissionIssuanceStore: missionIssuanceStore,
		PersonTokenPolicy: func(_ context.Context, request aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			return aauth.PersonTokenDecision{Subject: "pairwise-user-for-resource", Lifetime: time.Hour}, nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{
				Description:  evaluation.Proposal.Description,
				Tools:        evaluation.Proposal.Tools,
				Capabilities: []string{"interaction"},
			}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{
				Subject: "pairwise-user-for-resource",
				Scope:   request.Scope,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var executionCount int
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier:                   "https://resource.example",
		AccessMode:                   aauth.AccessModeAuthToken,
		PersonServer:                 "https://ps.example",
		SigningKey:                   resourceKey,
		KeyResolver:                  keyResolver,
		Clock:                        clock,
		NewID:                        ids,
		Scopes:                       []string{"documents.read"},
		ScopeDescriptions:            map[string]string{"documents.read": "Read documents"},
		RequiredScopesForRequest:     testRequiredResourceScopes("documents.read"),
		ReplayStore:                  testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error { return nil },
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			executionCount++
			return map[string]any{
				"ps":    request.PersonServer,
				"sub":   request.Subject,
				"items": []string{"design.md"},
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example":       ap.Handler(),
		"ps.example":       ps.Handler(),
		"resource.example": resource.Handler(),
	})
	defer gateway.Close()
	discoveryClient.Transport = gateway.Client().Transport

	agent, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:planner@ap.example",
		SigningKey:         agentKey,
		AgentToken:         agentToken,
		KeyResolver:        keyResolver,
		HTTPClient:         gateway.Client(),
		Clock:              clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	person, err := agent.RequestPersonToken(
		context.Background(),
		"https://ps.example/person",
		"https://resource.example",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := agent.AuthorizeWithPersonToken(
		context.Background(),
		"https://resource.example/authorize",
		"https://ps.example/token",
		[]string{"documents.read"},
		person.PersonToken,
	)
	if err != nil {
		t.Fatal(err)
	}

	response, err := agent.DoAuthorized(
		context.Background(),
		http.MethodGet,
		"https://resource.example/documents",
		grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("protected operation status = %d, body = %s", response.StatusCode, body)
	}
	if executionCount != 1 {
		t.Fatal("protected operation was not invoked")
	}

	var result struct {
		PS    string   `json:"ps"`
		Sub   string   `json:"sub"`
		Items []string `json:"items"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.PS != "https://ps.example" || result.Sub != "pairwise-user-for-resource" {
		t.Fatalf("authorized person = (%q, %q)", result.PS, result.Sub)
	}
	if len(result.Items) != 1 || result.Items[0] != "design.md" {
		t.Fatalf("unexpected protected result: %#v", result.Items)
	}

	second, err := agent.DoAuthorized(
		context.Background(),
		http.MethodGet,
		"https://resource.example/documents",
		grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(second.Body)
		t.Fatalf("independent operation status = %d, want 200; body = %s", second.StatusCode, body)
	}
	if executionCount != 2 {
		t.Fatalf("independent operation execution count = %d", executionCount)
	}
}

func testSigningKey(t *testing.T, id string) aauth.SigningKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := aauth.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testCurrentPersonServerCustody(t *testing.T) (reference.PersonTokenStore, reference.MissionIssuanceStore) {
	t.Helper()
	personTokens, err := reference.NewFilePersonTokenStore(t.TempDir() + "/person-tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	missionIssuances, err := reference.NewFileMissionIssuanceStore(t.TempDir() + "/mission-issuances.json")
	if err != nil {
		t.Fatal(err)
	}
	return personTokens, missionIssuances
}

func testPersonTokenStore(t *testing.T) reference.PersonTokenStore {
	t.Helper()
	store, _ := testCurrentPersonServerCustody(t)
	return store
}

func testMissionIssuanceStore(t *testing.T) reference.MissionIssuanceStore {
	t.Helper()
	_, store := testCurrentPersonServerCustody(t)
	return store
}

func testPersonTokenPolicy(_ context.Context, request aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
	return aauth.PersonTokenDecision{Subject: request.Agent, Lifetime: time.Hour}, nil
}

func testRoleDiscoveryHandler(
	t *testing.T,
	issuer string,
	discoveryDocument string,
	key aauth.SigningKey,
) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/"+discoveryDocument, func(response http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, response, map[string]string{
			"issuer":   issuer,
			"jwks_uri": issuer + "/jwks",
		})
	})
	mux.HandleFunc("GET /jwks", func(response http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, response, map[string]any{"keys": []aauth.JWK{key.PublicJWK()}})
	})
	return mux
}

func writeTestJSON(t *testing.T, response http.ResponseWriter, value any) {
	t.Helper()
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Error(err)
	}
}

func privateTestDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(t.TempDir(), "private-")
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func sequentialIDs(values ...string) func() string {
	next := 0
	return func() string {
		if next >= len(values) {
			panic("test requested more identifiers than provided")
		}
		value := values[next]
		next++
		return value
	}
}

func newLogicalGateway(t *testing.T, handlers map[string]http.Handler) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		handler := handlers[request.Host]
		if handler == nil {
			http.Error(response, "unknown logical host", http.StatusBadGateway)
			return
		}
		handler.ServeHTTP(response, request)
	}))

	target, err := url.Parse(server.URL)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	transport := &logicalTransport{
		target: target,
		base:   server.Client().Transport,
	}
	server.Client().Transport = transport
	return server
}

func testResourceReplayStore(t *testing.T, clock aauth.Clock) reference.ProofReplayStore {
	t.Helper()
	store, err := reference.NewMemoryProofReplayStore(clock, 1024)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testAuthorizationStateStore(t *testing.T) reference.AuthorizationStateStore {
	t.Helper()
	store, err := reference.NewMemoryAuthorizationStateStore(1024, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func openTestFileAuthorizationStateStore(t *testing.T, directory string) *reference.FileAuthorizationStateStore {
	t.Helper()
	store, err := reference.OpenFileAuthorizationStateStore(reference.FileAuthorizationStateStoreConfig{
		Directory: directory, MaxEntries: 1024, MaxBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func testRequiredResourceScopes(scopes ...string) func(context.Context, *http.Request) ([]string, error) {
	return func(context.Context, *http.Request) ([]string, error) {
		return append([]string(nil), scopes...), nil
	}
}

type logicalTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (transport *logicalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	cloned := request.Clone(request.Context())
	cloned.URL.Scheme = transport.target.Scheme
	cloned.URL.Host = transport.target.Host
	cloned.Host = request.URL.Host
	response, err := transport.base.RoundTrip(cloned)
	if response != nil {
		response.Request = request
	}
	return response, err
}

func TestLogicalGatewayPreservesSignedAuthority(t *testing.T) {
	t.Parallel()

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			_, _ = io.WriteString(response, request.Host)
		}),
	})
	defer gateway.Close()

	request, err := http.NewRequest(http.MethodGet, "https://resource.example/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := gateway.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(body)) != "resource.example" {
		t.Fatalf("logical authority = %q", body)
	}
}
