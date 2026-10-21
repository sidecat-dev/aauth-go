package agentprovider_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Bootstrap 28e8258, Sub-Agents Under a Hosted AP: the parent signs a request
// with its own key and token; the AP verifies both, applies host policy and
// returns the child token. The path and member names are this library's
// choice, following the draft's illustrative example.
type hostedSubagentFixture struct {
	*subagentProviderFixture
	parentCompact string
	parentClient  *agent.Client
	policy        func(context.Context, agentprovider.SubagentRequest) (agentprovider.SubagentDecision, error)
	seen          []agentprovider.SubagentRequest
	routes        map[string]http.Handler
}

func newHostedSubagentFixture(t *testing.T) *hostedSubagentFixture {
	t.Helper()
	f := &hostedSubagentFixture{subagentProviderFixture: newSubagentProviderFixture(t), routes: make(map[string]http.Handler)}
	f.parentCompact = f.parentToken(t, time.Hour)
	f.policy = func(_ context.Context, request agentprovider.SubagentRequest) (agentprovider.SubagentDecision, error) {
		discriminator := request.Discriminator
		if discriminator == "" {
			discriminator = "lane1"
		}
		return agentprovider.SubagentDecision{Discriminator: discriminator, Lifetime: 10 * time.Minute}, nil
	}
	mux := http.NewServeMux()
	mux.Handle("/", f.provider.Handler())
	mux.Handle("POST /subagent", f.provider.SubagentHandler(func(ctx context.Context, request agentprovider.SubagentRequest) (agentprovider.SubagentDecision, error) {
		f.seen = append(f.seen, request)
		return f.policy(ctx, request)
	}))
	f.routes["https://ap.example"] = mux
	client := &http.Client{Transport: f}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client, Clock: f.clock, Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.parentClient, err = agent.New(context.Background(), agent.Config{
		Identifier: "aauth:planner@ap.example", SigningKey: f.parent, AgentToken: f.parentCompact,
		KeyResolver: resolver, HTTPClient: client, Clock: f.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *hostedSubagentFixture) RoundTrip(request *http.Request) (*http.Response, error) {
	handler := f.routes[request.URL.Scheme+"://"+request.URL.Host]
	if handler == nil {
		return nil, errors.New("no route for " + request.URL.Host)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}

func TestHostedSubagentRequestIssuesToTheSigningParent(t *testing.T) {
	t.Parallel()

	for _, offered := range []string{"search", ""} {
		t.Run("discriminator "+map[bool]string{true: "offered", false: "chosen by host"}[offered != ""], func(t *testing.T) {
			t.Parallel()
			f := newHostedSubagentFixture(t)
			compact, err := f.parentClient.RequestSubagentToken(context.Background(), agent.SubagentTokenRequest{
				Endpoint: "https://ap.example/subagent", PublicKey: f.child.PublicJWK(), Discriminator: offered,
			})
			if err != nil {
				t.Fatal(err)
			}
			parent, err := aauth.VerifyAgentToken(context.Background(), f.parentCompact, f.resolver, f.clock)
			if err != nil {
				t.Fatal(err)
			}
			child, err := aauth.VerifySubagentToken(context.Background(), compact, parent, f.resolver, f.clock)
			if err != nil {
				t.Fatal(err)
			}
			want := "aauth:planner+" + map[bool]string{true: offered, false: "lane1"}[offered != ""] + "@ap.example"
			if child.Subject != want || !child.Confirmation.JWK.Equal(f.child.PublicJWK()) || child.PersonServer != "https://ps.example" {
				t.Fatalf("child = %#v", child)
			}
			if len(f.seen) != 1 || f.seen[0].Parent.Subject != "aauth:planner@ap.example" || f.seen[0].Discriminator != offered ||
				!f.seen[0].PublicKey.Equal(f.child.PublicJWK()) {
				t.Fatalf("policy saw %#v", f.seen)
			}
		})
	}
}

func TestHostedSubagentRequestRefusesWithoutIssuing(t *testing.T) {
	t.Parallel()

	signed := func(t *testing.T, f *hostedSubagentFixture, key jose.SigningKey, token, target string, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := signaturekey.SignJWTRequestWithOptions(request, key, token, f.clock, signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
		}); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		f.routes["https://ap.example"].ServeHTTP(response, request)
		return response
	}
	childJWK := func(f *hostedSubagentFixture) string {
		encoded, err := json.Marshal(map[string]any{"jwk": f.child.PublicJWK(), "discriminator": "search"})
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	// Only the policy denial reaches host policy: a request issuance would
	// refuse never reaches a policy that records the parent's sub-agents.
	for _, test := range []struct {
		name     string
		send     func(*testing.T, *hostedSubagentFixture) *httptest.ResponseRecorder
		status   int
		code     string
		consults bool
	}{
		{name: "unsigned", status: http.StatusUnauthorized, send: func(t *testing.T, f *hostedSubagentFixture) *httptest.ResponseRecorder {
			request := httptest.NewRequest(http.MethodPost, "https://ap.example/subagent", strings.NewReader(childJWK(f)))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			f.routes["https://ap.example"].ServeHTTP(response, request)
			return response
		}},
		{name: "parent token from another provider key", status: http.StatusUnauthorized, send: func(t *testing.T, f *hostedSubagentFixture) *httptest.ResponseRecorder {
			foreign, err := aauth.MintAgentToken("https://ap.example", testSigningKey(t, "ap-key", 45), aauth.AgentTokenRequest{
				Agent: "aauth:planner@ap.example", PublicKey: f.parent.PublicJWK(), Lifetime: time.Hour,
			}, f.now, "foreign-parent")
			if err != nil {
				t.Fatal(err)
			}
			return signed(t, f, f.parent, foreign, "https://ap.example/subagent", childJWK(f))
		}},
		{name: "signed for another authority", status: http.StatusUnauthorized, send: func(t *testing.T, f *hostedSubagentFixture) *httptest.ResponseRecorder {
			return signed(t, f, f.parent, f.parentCompact, "https://other.example/subagent", childJWK(f))
		}},
		{name: "sub-agent as parent", status: http.StatusForbidden, code: "subagent_denied", send: func(t *testing.T, f *hostedSubagentFixture) *httptest.ResponseRecorder {
			child, err := f.provider.IssueSubagent(context.Background(), f.parentCompact, agentprovider.SubagentTokenRequest{
				Discriminator: "lane", PublicKey: f.child.PublicJWK(), Lifetime: time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(map[string]any{"jwk": personKey(t).PublicJWK()})
			return signed(t, f, f.child, child, "https://ap.example/subagent", string(body))
		}},
		{name: "missing key", status: http.StatusBadRequest, code: "invalid_request", send: func(t *testing.T, f *hostedSubagentFixture) *httptest.ResponseRecorder {
			return signed(t, f, f.parent, f.parentCompact, "https://ap.example/subagent", `{"discriminator":"search"}`)
		}},
		{name: "parent key reused", status: http.StatusBadRequest, code: "invalid_request", send: func(t *testing.T, f *hostedSubagentFixture) *httptest.ResponseRecorder {
			body, _ := json.Marshal(map[string]any{"jwk": f.parent.PublicJWK()})
			return signed(t, f, f.parent, f.parentCompact, "https://ap.example/subagent", string(body))
		}},
		{name: "malformed discriminator", status: http.StatusBadRequest, code: "invalid_request", send: func(t *testing.T, f *hostedSubagentFixture) *httptest.ResponseRecorder {
			body, _ := json.Marshal(map[string]any{"jwk": f.child.PublicJWK(), "discriminator": "bad@part"})
			return signed(t, f, f.parent, f.parentCompact, "https://ap.example/subagent", string(body))
		}},
		{name: "nested discriminator", status: http.StatusBadRequest, code: "invalid_request", send: func(t *testing.T, f *hostedSubagentFixture) *httptest.ResponseRecorder {
			body, _ := json.Marshal(map[string]any{"jwk": f.child.PublicJWK(), "discriminator": "a+b"})
			return signed(t, f, f.parent, f.parentCompact, "https://ap.example/subagent", string(body))
		}},
		{name: "policy denial", status: http.StatusForbidden, code: "subagent_denied", consults: true, send: func(t *testing.T, f *hostedSubagentFixture) *httptest.ResponseRecorder {
			f.policy = func(context.Context, agentprovider.SubagentRequest) (agentprovider.SubagentDecision, error) {
				return agentprovider.SubagentDecision{}, agentprovider.ErrSubagentDenied
			}
			return signed(t, f, f.parent, f.parentCompact, "https://ap.example/subagent", childJWK(f))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newHostedSubagentFixture(t)
			issued := len(f.ids)
			response := test.send(t, f)
			if response.Code != test.status {
				t.Fatalf("status = %d %s", response.Code, response.Body.String())
			}
			if test.code != "" {
				var problem struct {
					Code string `json:"error"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || problem.Code != test.code {
					t.Fatalf("problem = %s", response.Body.String())
				}
			}
			if strings.Contains(response.Body.String(), "agent_token") {
				t.Fatal("refusal released a token")
			}
			if test.name != "sub-agent as parent" && len(f.ids) != issued {
				t.Fatal("refusal consumed a token identifier")
			}
			if consulted := len(f.seen) != 0; consulted != test.consults {
				t.Fatalf("host policy consulted = %t, want %t", consulted, test.consults)
			}
		})
	}
}

// The parent's helper sends only to its own provider's origin and accepts
// only a child bound to the requested key and naming this parent.
func TestRequestSubagentTokenChecksEndpointAndResult(t *testing.T) {
	t.Parallel()

	f := newHostedSubagentFixture(t)
	foreignCalls := 0
	f.routes["https://other.example"] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignCalls++
		f.routes["https://ap.example"].ServeHTTP(w, r)
	})
	if _, err := f.parentClient.RequestSubagentToken(context.Background(), agent.SubagentTokenRequest{
		Endpoint: "https://other.example/subagent", PublicKey: f.child.PublicJWK(),
	}); err == nil || foreignCalls != 0 {
		t.Fatalf("helper sent the parent's credentials to another origin: %v, %d calls", err, foreignCalls)
	}
	f.routes["https://ap.example"] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/subagent" {
			f.provider.Handler().ServeHTTP(w, r)
			return
		}
		// A provider that binds the child to a key the parent did not request.
		compact, err := f.provider.IssueSubagent(r.Context(), f.parentCompact, agentprovider.SubagentTokenRequest{
			Discriminator: "search", PublicKey: personKey(t).PublicJWK(), Lifetime: time.Minute,
		})
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"agent_token": compact})
	})
	if _, err := f.parentClient.RequestSubagentToken(context.Background(), agent.SubagentTokenRequest{
		Endpoint: "https://ap.example/subagent", PublicKey: f.child.PublicJWK(),
	}); err == nil {
		t.Fatal("helper accepted a child bound to another key")
	}
}

func personKey(t *testing.T) jose.SigningKey { return testSigningKey(t, "unrelated-key", 46) }

// Request members other than jwk and discriminator do not reach the token:
// the provider, not the parent, asserts parent_agent and the child's name.
func TestHostedSubagentRequestIgnoresAssertedClaims(t *testing.T) {
	t.Parallel()

	f := newHostedSubagentFixture(t)
	body, err := json.Marshal(map[string]any{
		"jwk": f.child.PublicJWK(), "discriminator": "search",
		"parent_agent": "aauth:other@ap.example", "sub": "aauth:other+search@ap.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://ap.example/subagent", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWTRequestWithOptions(request, f.parent, f.parentCompact, f.clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
	}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	f.routes["https://ap.example"].ServeHTTP(response, request)
	var output struct {
		AgentToken string `json:"agent_token"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &output) != nil {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	child, err := aauth.VerifyAgentToken(context.Background(), output.AgentToken, f.resolver, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	if child.ParentAgent != "aauth:planner@ap.example" || child.Subject != "aauth:planner+search@ap.example" {
		t.Fatalf("child = %#v", child)
	}
}
