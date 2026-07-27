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
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestThreePartyMissionAuthorizationJourney(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 6, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs(
		"agent-token-1",
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

	ps, err := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier:  "https://ps.example",
		SigningKey:  psKey,
		KeyResolver: keyResolver,
		Clock:       clock,
		NewID:       ids,
		MissionPolicy: func(_ context.Context, proposal aauth.MissionProposal) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{
				Description:  proposal.Description,
				Tools:        proposal.Tools,
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
		Identifier:   "https://resource.example",
		PersonServer: "https://ps.example",
		SigningKey:   resourceKey,
		KeyResolver:  keyResolver,
		Clock:        clock,
		NewID:        ids,
		Scopes:       []string{"documents.read"},
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			executionCount++
			return map[string]any{
				"agent": request.Agent,
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
		Identifier:  "aauth:planner@ap.example",
		SigningKey:  agentKey,
		AgentToken:  agentToken,
		KeyResolver: keyResolver,
		HTTPClient:  gateway.Client(),
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	mission, err := agent.CreateMission(context.Background(), "https://ps.example/mission", aauth.MissionProposal{
		Description: "Read the design document and summarize it.",
		Tools: []aauth.Tool{{
			Name:        "Read",
			Description: "Read documents.",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := mission.Reference.S256, aauth.S256(mission.Bytes); got != want {
		t.Fatalf("mission hash = %q, want exact-byte hash %q", got, want)
	}

	grant, err := agent.Authorize(
		context.Background(),
		"https://resource.example/authorize",
		"https://ps.example/token",
		[]string{"documents.read"},
		mission,
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
		Agent string   `json:"agent"`
		Items []string `json:"items"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Agent != "aauth:planner@ap.example" {
		t.Fatalf("authorized agent = %q", result.Agent)
	}
	if len(result.Items) != 1 || result.Items[0] != "design.md" {
		t.Fatalf("unexpected protected result: %#v", result.Items)
	}

	replayed, err := agent.DoAuthorized(
		context.Background(),
		http.MethodGet,
		"https://resource.example/documents",
		grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Body.Close()
	if replayed.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(replayed.Body)
		t.Fatalf("replayed operation status = %d, want 401; body = %s", replayed.StatusCode, body)
	}
	if executionCount != 1 {
		t.Fatalf("replayed proof invoked operation; execution count = %d", executionCount)
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

type logicalTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (transport *logicalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	cloned := request.Clone(request.Context())
	cloned.URL.Scheme = transport.target.Scheme
	cloned.URL.Host = transport.target.Host
	cloned.Host = request.URL.Host
	return transport.base.RoundTrip(cloned)
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
