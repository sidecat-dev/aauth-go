package personserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestPersonEndpointAcceptsHintsAndRefusesUnreachableAgents(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 24, 22, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := personServerTestKey(t, "hint-provider")
	personKey := personServerTestKey(t, "hint-person")
	agentKey := personServerTestKey(t, "hint-agent")
	agentToken, err := aauth.MintAgentToken("https://provider.example", providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:planner@provider.example", PersonServer: "https://person.example",
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "hint-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
		{Issuer: "https://person.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:    personKey.PublicJWK(),
	}
	var binds int
	nextID := 0
	newServer := func(require bool) *Server {
		t.Helper()
		config := FederatedAuthorizationConfig{
			Issuer: "https://person.example", SigningKey: personKey, KeyResolver: resolver,
			Clock: clock, NewID: func() string {
				nextID++
				return "hint-person-token-" + string(rune('a'+nextID))
			},
			HTTPClient: http.DefaultClient,
			AccessServerEndpoint: func(context.Context, string) (string, error) {
				return "https://access.example/token", nil
			},
			Tokens: newMemoryDeferredTokenStore(),
			BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
				binds++
				return Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: 10 * time.Minute}, nil
			},
			Consent: func(context.Context, AuthorizationRequest) error { return nil },
		}
		if require {
			config.RequirePersonTokenInteraction = func(context.Context, PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error) {
				return PersonTokenInteractionPolicy{
					URL: "https://person.example/interaction", Lifetime: time.Minute, RetryAfter: time.Second,
				}, true, nil
			}
		}
		server, err := NewFederatedAuthorization(config)
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	post := func(server *Server, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "https://person.example/person", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	accepted := post(newServer(false), `{"resource":"https://resource.example","login_hint":"person@example.com","platform":"desktop","prompt":"none","device":"desk"}`)
	if accepted.Code != http.StatusOK || binds != 1 {
		t.Fatalf("accepted hints = %d %s binds=%d", accepted.Code, accepted.Body.String(), binds)
	}
	rejected := post(newServer(false), `{"resource":"https://resource.example","platform":"fridge"}`)
	if binds != 1 {
		t.Fatalf("invalid platform reached binding; binds=%d", binds)
	}
	assertPersonServerProblem(t, rejected, "invalid_request")

	unreachable := post(newServer(true), `{"resource":"https://resource.example"}`)
	if unreachable.Code != http.StatusForbidden || unreachable.Header().Get("AAuth-Requirement") != "" || !strings.Contains(unreachable.Body.String(), `"error":"user_unreachable"`) {
		t.Fatalf("unreachable = %d requirement=%q body=%s", unreachable.Code, unreachable.Header().Get("AAuth-Requirement"), unreachable.Body.String())
	}
	started := post(newServer(true), `{"resource":"https://resource.example","capabilities":["interaction"]}`)
	if started.Code != http.StatusAccepted || started.Header().Get("AAuth-Requirement") == "" {
		t.Fatalf("interaction = %d %s", started.Code, started.Body.String())
	}
}
