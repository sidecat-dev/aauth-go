package personserver

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
)

// Protocol 28e8258, Token Endpoint Error Codes and Sub-Agent Identity: a
// sub-agent token is a request parameter, so its failures use the
// <invalid|expired|revoked>_subagent_token codes at both PS token endpoints.
func TestSubagentTokenFailuresUseSubagentErrorCodes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		code  string
		child func(*testing.T, *subagentPersonServerProtocol) string
	}{
		{name: "another parent", code: "invalid_subagent_token", child: func(t *testing.T, p *subagentPersonServerProtocol) string {
			return p.mintAgentToken(t, "aauth:other+search@ap.example", "aauth:other@ap.example", p.childKey.PublicJWK(), time.Hour, "wrong-parent", nil)
		}},
		{name: "top-level token", code: "invalid_subagent_token", child: func(t *testing.T, p *subagentPersonServerProtocol) string {
			return p.mintAgentToken(t, "aauth:other@ap.example", "", p.childKey.PublicJWK(), time.Hour, "not-a-child", nil)
		}},
		{name: "parent key reused", code: "invalid_subagent_token", child: func(t *testing.T, p *subagentPersonServerProtocol) string {
			return p.mintAgentToken(t, "aauth:planner+search@ap.example", "aauth:planner@ap.example", p.parentKey.PublicJWK(), time.Hour, "shared-key", nil)
		}},
		{name: "grandchild", code: "invalid_subagent_token", child: func(t *testing.T, p *subagentPersonServerProtocol) string {
			return p.forgeAgentToken(t, map[string]any{
				"sub": "aauth:planner+search+deep@ap.example", "parent_agent": "aauth:planner+search@ap.example",
				"jti": "grandchild",
			})
		}},
		{name: "untrusted signature", code: "invalid_subagent_token", child: func(t *testing.T, p *subagentPersonServerProtocol) string {
			compact, err := aauth.MintAgentToken("https://ap.example", p.resourceKey, aauth.AgentTokenRequest{
				Agent: "aauth:planner+search@ap.example", ParentAgent: "aauth:planner@ap.example",
				PublicKey: p.childKey.PublicJWK(), Lifetime: time.Hour,
			}, p.now, "forged-child")
			if err != nil {
				t.Fatal(err)
			}
			return compact
		}},
		{name: "another person server", code: "invalid_subagent_token", child: func(t *testing.T, p *subagentPersonServerProtocol) string {
			compact, err := aauth.MintAgentToken("https://ap.example", p.providerKey, aauth.AgentTokenRequest{
				Agent: "aauth:planner+search@ap.example", ParentAgent: "aauth:planner@ap.example",
				PersonServer: "https://other-ps.example", PublicKey: p.childKey.PublicJWK(), Lifetime: time.Hour,
			}, p.now, "other-ps-child")
			if err != nil {
				t.Fatal(err)
			}
			return compact
		}},
		{name: "expired", code: "expired_subagent_token", child: func(t *testing.T, p *subagentPersonServerProtocol) string {
			compact, err := aauth.MintAgentToken("https://ap.example", p.providerKey, aauth.AgentTokenRequest{
				Agent: "aauth:planner+search@ap.example", ParentAgent: "aauth:planner@ap.example",
				PublicKey: p.childKey.PublicJWK(), Lifetime: time.Minute,
			}, p.now.Add(-2*time.Minute), "expired-child")
			if err != nil {
				t.Fatal(err)
			}
			return compact
		}},
	} {
		for _, endpoint := range []string{"person", "token"} {
			t.Run(test.name+"/"+endpoint, func(t *testing.T) {
				t.Parallel()
				p := newSubagentPersonServerProtocol(t)
				server := p.directServer(t, PSAuthorizationConfig{})
				response := p.subagentEndpointRequest(t, server, endpoint, test.child(t, p))
				assertSubagentProblem(t, response, http.StatusBadRequest, test.code)
				if response.Header().Get("Signature-Error") != "" {
					t.Fatalf("parameter token failure used Signature-Error: %v", response.Header())
				}
				_, commits, loads := p.store.observation()
				if p.bindCalls != 0 || p.authorizationCalls != 0 || commits != 0 || loads != 0 {
					t.Fatalf("refused child reached policy or store: bind=%d authorize=%d commits=%d loads=%d",
						p.bindCalls, p.authorizationCalls, commits, loads)
				}
			})
		}
	}
}

// Protocol 28e8258, Token Endpoint Error Codes: revoked_subagent_token names a
// sub-agent token its Agent Provider revoked at this Person Server.
func TestProviderRevokedSubagentTokenUsesRevokedSubagentToken(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{"person", "token"} {
		t.Run(endpoint, func(t *testing.T) {
			t.Parallel()
			p := newSubagentPersonServerProtocol(t)
			revocations := newReferenceAgentTokenRevocationStore()
			revocations.revoked[aauth.TokenReference{Issuer: "https://ap.example", JTI: "child-token"}] = true
			server := p.directServer(t, PSAuthorizationConfig{AgentTokenRevocations: revocations})
			response := p.subagentEndpointRequest(t, server, endpoint, p.childToken)
			assertSubagentProblem(t, response, http.StatusBadRequest, "revoked_subagent_token")
			if p.bindCalls != 0 || p.authorizationCalls != 0 {
				t.Fatalf("revoked child reached policy: bind=%d authorize=%d", p.bindCalls, p.authorizationCalls)
			}
			// The parent's own token is unaffected by the child's revocation.
			if response := p.subagentEndpointRequest(t, server, endpoint, ""); response.Code != http.StatusOK && endpoint == "person" {
				t.Fatalf("parent person token after child revocation = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

// Protocol 28e8258, Agent-Person Binding and Parent-Mediated Authorization:
// the parent's binding authorizes its children. Once the host revokes it, no
// new Person token is issued to the parent or any child it mediates.
func TestRevokedAgentBindingRefusesNewPersonTokens(t *testing.T) {
	t.Parallel()

	for _, delegated := range []bool{false, true} {
		name := "parent"
		if delegated {
			name = "child"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := newSubagentPersonServerProtocol(t)
			bindings := newMemoryAgentBindingRevocations()
			server := p.directServer(t, PSAuthorizationConfig{AgentBindingRevocations: bindings})
			if err := server.RevokeAgentBinding(context.Background(), AgentBinding{
				AgentProvider: "https://ap.example", Agent: "aauth:planner@ap.example",
			}); err != nil {
				t.Fatal(err)
			}
			child := ""
			if delegated {
				child = p.childToken
			}
			response := p.subagentEndpointRequest(t, server, "person", child)
			assertSubagentProblem(t, response, http.StatusForbidden, "person_token_denied")
			_, commits, _ := p.store.observation()
			if p.bindCalls != 0 || commits != 0 {
				t.Fatalf("revoked binding reached person policy or retention: bind=%d commits=%d", p.bindCalls, commits)
			}
		})
	}
}

// Protocol 28e8258, Sub-Agents and Token Endpoint Error Codes: revoking the
// parent's binding makes the next authorization fail. A presented credential
// issued under it is answered revoked_presented_token, before any policy or
// Access Server call, in both authorization modes.
func TestRevokedAgentBindingRefusesTokenRequests(t *testing.T) {
	t.Parallel()

	for _, federated := range []bool{false, true} {
		for _, delegated := range []bool{false, true} {
			name := map[bool]string{false: "person-server", true: "federated"}[federated] + "/" +
				map[bool]string{false: "parent", true: "child"}[delegated]
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				p := newSubagentPersonServerProtocol(t)
				bindings := newMemoryAgentBindingRevocations()
				downstream := 0
				var server *Server
				audience := "https://ps.example"
				if federated {
					audience = "https://as.example"
					var err error
					server, err = NewFederatedAuthorization(FederatedAuthorizationConfig{
						Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
						Clock: p.clock, NewID: func() string { return "unused" }, Tokens: p.store,
						HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
							downstream++
							return nil, errors.New("must not call the Access Server")
						})},
						AccessServerEndpoint: func(context.Context, string) (string, error) { return "https://as.example/token", nil },
						BindPerson:           p.policyPerson,
						Consent: func(context.Context, AuthorizationRequest) error {
							p.authorizationCalls++
							return nil
						},
						AgentBindingRevocations: bindings,
					})
					if err != nil {
						t.Fatal(err)
					}
				} else {
					server = p.directServer(t, PSAuthorizationConfig{AgentBindingRevocations: bindings})
				}
				key, child := p.parentKey.PublicJWK(), ""
				if delegated {
					key, child = p.childKey.PublicJWK(), p.childToken
				}
				resourceToken := p.resourceToken(t, audience, "person-token", key)
				if response := p.tokenRequestFor(t, server, child, resourceToken); response.Code == http.StatusBadRequest {
					t.Fatalf("unrevoked request was refused: %s", response.Body.String())
				}
				p.authorizationCalls, downstream = 0, 0
				if err := server.RevokeAgentBinding(context.Background(), AgentBinding{
					AgentProvider: "https://ap.example", Agent: "aauth:planner@ap.example",
				}); err != nil {
					t.Fatal(err)
				}
				response := p.tokenRequestFor(t, server, child, resourceToken)
				assertSubagentProblem(t, response, http.StatusBadRequest, "revoked_presented_token")
				if p.authorizationCalls != 0 || downstream != 0 {
					t.Fatalf("revoked binding reached policy or AS: policy=%d downstream=%d", p.authorizationCalls, downstream)
				}
			})
		}
	}
}

// Binding revocation is a host-authenticated administrative action. The
// library validates the binding name and requires a configured store.
func TestRevokeAgentBindingRequiresStoreAndTopLevelIdentity(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	unconfigured := p.directServer(t, PSAuthorizationConfig{})
	if err := unconfigured.RevokeAgentBinding(context.Background(), AgentBinding{
		AgentProvider: "https://ap.example", Agent: "aauth:planner@ap.example",
	}); err == nil {
		t.Fatal("binding revocation without a store was accepted")
	}
	bindings := newMemoryAgentBindingRevocations()
	server := p.directServer(t, PSAuthorizationConfig{AgentBindingRevocations: bindings})
	for _, binding := range []AgentBinding{
		{AgentProvider: "http://ap.example", Agent: "aauth:planner@ap.example"},
		{AgentProvider: "https://ap.example", Agent: "planner@ap.example"},
		{AgentProvider: "https://ap.example", Agent: "aauth:planner@other.example"},
		{AgentProvider: "https://ap.example", Agent: "aauth:planner+search@ap.example"},
	} {
		if err := server.RevokeAgentBinding(context.Background(), binding); err == nil {
			t.Fatalf("binding %#v was accepted", binding)
		}
	}
	if len(bindings.snapshot()) != 0 {
		t.Fatalf("invalid bindings were stored: %v", bindings.snapshot())
	}
	failing := newMemoryAgentBindingRevocations()
	failing.revokeErr = errors.New("store unavailable")
	server = p.directServer(t, PSAuthorizationConfig{AgentBindingRevocations: failing})
	if err := server.RevokeAgentBinding(context.Background(), AgentBinding{
		AgentProvider: "https://ap.example", Agent: "aauth:planner@ap.example",
	}); !errors.Is(err, failing.revokeErr) {
		t.Fatalf("store failure = %v", err)
	}
}

// An unavailable binding store is an operational failure, not a refusal.
func TestAgentBindingStoreFailureIsServerError(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{"person", "token"} {
		t.Run(endpoint, func(t *testing.T) {
			t.Parallel()
			p := newSubagentPersonServerProtocol(t)
			bindings := newMemoryAgentBindingRevocations()
			bindings.lookupErr = errors.New("store unavailable")
			server := p.directServer(t, PSAuthorizationConfig{AgentBindingRevocations: bindings})
			response := p.subagentEndpointRequest(t, server, endpoint, p.childToken)
			assertSubagentProblem(t, response, http.StatusInternalServerError, "server_error")
			if p.bindCalls != 0 || p.authorizationCalls != 0 {
				t.Fatalf("store failure reached policy: bind=%d authorize=%d", p.bindCalls, p.authorizationCalls)
			}
		})
	}
}

func (p *subagentPersonServerProtocol) directServer(t *testing.T, config PSAuthorizationConfig) *Server {
	t.Helper()
	ids := []string{"person-token", "auth-token", "spare-1", "spare-2"}
	var mu sync.Mutex
	config.Issuer, config.SigningKey, config.KeyResolver = "https://ps.example", p.personKey, p.resolver
	config.Clock, config.Tokens = p.clock, p.store
	config.NewID = func() string {
		mu.Lock()
		defer mu.Unlock()
		id := ids[0]
		ids = ids[1:]
		return id
	}
	config.BindPerson = p.policyPersonFor
	config.Authorize = p.policyAuthorizationFor
	server, err := NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

// policyPersonFor and policyAuthorizationFor accept the parent alone or the
// parent mediating the fixture child.
func (p *subagentPersonServerProtocol) policyPersonFor(ctx context.Context, request PersonTokenRequest) (Person, error) {
	if request.Subagent == "" {
		p.bindCalls++
		return Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: 30 * time.Minute}, nil
	}
	return p.policyPerson(ctx, request)
}

func (p *subagentPersonServerProtocol) policyAuthorizationFor(ctx context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
	if request.Subagent == "" {
		p.authorizationCalls++
		return AuthorizationDecision{Scopes: request.Scopes, Lifetime: 30 * time.Minute}, nil
	}
	return p.policyAuthorization(ctx, request)
}

// subagentEndpointRequest sends a parent-signed request to /person or /token;
// a nonempty child adds subagent_token and binds the Resource token to the child.
func (p *subagentPersonServerProtocol) subagentEndpointRequest(t *testing.T, server *Server, endpoint, child string) *httptest.ResponseRecorder {
	t.Helper()
	if endpoint == "person" {
		if child == "" {
			return p.parentPersonRequest(t, server)
		}
		return p.personRequest(t, server, child)
	}
	key := p.parentKey.PublicJWK()
	if child != "" {
		key = p.childKey.PublicJWK()
	}
	return p.tokenRequestFor(t, server, child, p.resourceToken(t, "https://ps.example", "person-token", key))
}

func (p *subagentPersonServerProtocol) parentPersonRequest(t *testing.T, server *Server) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://ps.example/person", strings.NewReader(`{"resource":"https://resource.example"}`))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, p.parentKey, p.parentToken, p.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

// tokenRequestFor posts one parent-signed token request, with subagent_token
// only when child is nonempty.
func (p *subagentPersonServerProtocol) tokenRequestFor(t *testing.T, server *Server, child, resourceToken string) *httptest.ResponseRecorder {
	t.Helper()
	input := map[string]any{"resource_token": resourceToken, "presented_token": p.presentedToken(t, resourceToken)}
	if child != "" {
		input["subagent_token"] = child
	}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://ps.example/token", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, p.parentKey, p.parentToken, p.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

// forgeAgentToken signs Agent-token claims that MintAgentToken would refuse,
// such as a grandchild, with the trusted provider key.
func (p *subagentPersonServerProtocol) forgeAgentToken(t *testing.T, members map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss": "https://ap.example", "dwk": aauth.AgentDiscoveryDocument,
		"iat": p.now.Unix(), "exp": p.now.Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": personServerTestKey(t, "forged-holder").PublicJWK()},
	}
	for name, value := range members {
		claims[name] = value
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.SignCompact(p.providerKey, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: aauth.AgentTokenType, KeyID: p.providerKey.ID(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

type memoryAgentBindingRevocations struct {
	mu        sync.Mutex
	states    map[AgentBinding]AgentBindingRevocation
	revokeErr error
	lookupErr error
}

func newMemoryAgentBindingRevocations() *memoryAgentBindingRevocations {
	return &memoryAgentBindingRevocations{states: make(map[AgentBinding]AgentBindingRevocation)}
}

func (store *memoryAgentBindingRevocations) RevokeAgentBinding(_ context.Context, binding AgentBinding, at time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.revokeErr != nil {
		return store.revokeErr
	}
	state := store.states[binding]
	if !at.After(state.RevokedAt) || !at.After(state.ReestablishedAt) {
		return nil
	}
	state.RevokedAt = at
	state.ReestablishedAt = time.Time{}
	store.states[binding] = state
	return nil
}

func (store *memoryAgentBindingRevocations) ReestablishAgentBinding(_ context.Context, binding AgentBinding, at time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.revokeErr != nil {
		return store.revokeErr
	}
	state, ok := store.states[binding]
	if !ok {
		return ErrAgentBindingNotRevoked
	}
	if !at.After(state.RevokedAt) {
		return ErrAgentBindingStale
	}
	if state.ReestablishedAt.IsZero() {
		state.ReestablishedAt = at
		store.states[binding] = state
	}
	return nil
}

func (store *memoryAgentBindingRevocations) LoadAgentBindingRevocation(_ context.Context, binding AgentBinding) (AgentBindingRevocation, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lookupErr != nil {
		return AgentBindingRevocation{}, store.lookupErr
	}
	return store.states[binding], nil
}

// set replaces one binding's state directly, as a host's own store could.
func (store *memoryAgentBindingRevocations) set(binding AgentBinding, state AgentBindingRevocation) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.states[binding] = state
}

func (store *memoryAgentBindingRevocations) snapshot() []AgentBinding {
	store.mu.Lock()
	defer store.mu.Unlock()
	var bindings []AgentBinding
	for binding := range store.states {
		bindings = append(bindings, binding)
	}
	return bindings
}

// Protocol 28e8258, Upstream Token Verification: a PS that has revoked the
// calling Agent's binding rejects the chain with revoked_upstream_token. When
// the upstream token was issued to a sub-agent, that binding is its parent's.
func TestCallChainingRefusesARevokedCallerBinding(t *testing.T) {
	t.Parallel()

	for _, child := range []bool{false, true} {
		t.Run(map[bool]string{false: "caller", true: "caller's parent"}[child], func(t *testing.T) {
			t.Parallel()
			protocol := newCallChainingProtocol(t)
			if child {
				record := protocol.identifyUpstream(t, protocol.upstreamToken)
				record.Agent = "aauth:original+worker@original-agent.example"
				record.ParentAgent = callChainOriginalAgent
				if err := validateIssuedAuthTokenRecord(record); err != nil {
					t.Fatal(err)
				}
				protocol.issued.mu.Lock()
				protocol.issued.records[record.Reference] = record
				protocol.issued.mu.Unlock()
			}
			bindings := newMemoryAgentBindingRevocations()
			config := protocol.config()
			config.AgentBindingRevocations = bindings
			server := protocol.newServer(t, config)
			personClaims := decodeCallChainingPersonToken(
				t, protocol, protocol.personRequest(t, server, protocol.upstreamToken, ""),
			)
			resourceToken := protocol.resourceToken(t, personClaims, protocol.personServerID, "payments.charge", nil)
			bindings.set(AgentBinding{AgentProvider: callChainOriginalAgentProvider, Agent: callChainOriginalAgent}, AgentBindingRevocation{RevokedAt: protocol.now})
			binds := protocol.chainBindCalls
			assertCallChainingProblem(t, protocol.personRequest(t, server, protocol.upstreamToken, ""), http.StatusBadRequest, "revoked_upstream_token")
			assertCallChainingProblem(t, protocol.tokenRequest(t, server, resourceToken, protocol.upstreamToken, ""), http.StatusBadRequest, "revoked_upstream_token")
			if protocol.chainBindCalls != binds || protocol.chainAuthorizeCalls != 0 {
				t.Fatalf("revoked caller binding reached policy: bind %d authorize %d", protocol.chainBindCalls-binds, protocol.chainAuthorizeCalls)
			}
		})
	}
}

// A parent-mediated issuance records the parent beside the child recipient,
// so a later chain from the child's token can find the authorizing binding.
func TestIssuedAuthTokenRecordRetainsTheMediatingParent(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	issued := newTestIssuedAuthTokenStore()
	server := p.directServer(t, PSAuthorizationConfig{IssuedTokens: issued})
	if response := p.personRequest(t, server, p.childToken); response.Code != http.StatusOK {
		t.Fatalf("child Person token = %d %s", response.Code, response.Body.String())
	}
	resourceToken := p.resourceToken(t, "https://ps.example", "person-token", p.childKey.PublicJWK())
	if response := p.tokenRequestFor(t, server, p.childToken, resourceToken); response.Code != http.StatusOK {
		t.Fatalf("child Auth token = %d %s", response.Code, response.Body.String())
	}
	record, err := issued.LoadIssuedAuthToken(context.Background(), aauth.TokenReference{Issuer: "https://ps.example", JTI: "auth-token"})
	if err != nil {
		t.Fatal(err)
	}
	if record.Agent != "aauth:planner+search@ap.example" || record.ParentAgent != "aauth:planner@ap.example" {
		t.Fatalf("issued record recipient = %q parent = %q", record.Agent, record.ParentAgent)
	}
	record.ParentAgent = "aauth:other@ap.example"
	if err := validateIssuedAuthTokenRecord(record); err == nil {
		t.Fatal("record accepted a parent that does not match the recipient")
	}
}

// A pending PS-hosted consent cannot outlive a revoked binding: the host can
// no longer approve it, and a retained approval is not released.
func TestRevokedAgentBindingClosesPSHostedConsent(t *testing.T) {
	t.Parallel()

	for _, approveFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "before approval", true: "after approval"}[approveFirst], func(t *testing.T) {
			t.Parallel()
			protocol := newAuthorizationInteractionProtocol(t)
			bindings := newMemoryAgentBindingRevocations()
			config := protocol.config(newMemoryDeferredAuthorizationStore())
			config.AgentBindingRevocations = bindings
			server, err := NewPSAuthorization(config)
			if err != nil {
				t.Fatal(err)
			}
			response := protocol.exchange(t, server, []string{"interaction"})
			if response.Code != http.StatusAccepted {
				t.Fatalf("consent request = %d %s", response.Code, response.Body.String())
			}
			location := response.Header().Get("Location")
			requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
			if err != nil {
				t.Fatal(err)
			}
			value, err := server.ConsumeAuthorizationInteractionCode(context.Background(), strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/"), requirement.Code)
			if err != nil {
				t.Fatal(err)
			}
			decision := AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}
			if approveFirst {
				if err := server.ApproveAuthorizationInteraction(context.Background(), value, decision); err != nil {
					t.Fatal(err)
				}
			}
			if err := server.RevokeAgentBinding(context.Background(), AgentBinding{AgentProvider: protocol.providerID, Agent: protocol.agentID}); err != nil {
				t.Fatal(err)
			}
			minted := protocol.tokenIDCalls()
			if !approveFirst {
				if err := server.ApproveAuthorizationInteraction(context.Background(), value, decision); !errors.Is(err, ErrAgentBindingRevoked) {
					t.Fatalf("approval under a revoked binding = %v", err)
				}
				if protocol.tokenIDCalls() != minted {
					t.Fatal("approval under a revoked binding minted a token")
				}
			}
			assertAuthorizationInteractionProblem(t, protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken), http.StatusBadRequest, "revoked_presented_token")
			if approveFirst {
				// The withheld approval was consumed rather than left for release.
				assertAuthorizationInteractionProblem(t, protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken), http.StatusGone, "invalid_code")
			}
		})
	}
}

// A pending Person-token interaction cannot outlive a revoked binding either.
func TestRevokedAgentBindingClosesPersonTokenInteractions(t *testing.T) {
	t.Parallel()

	for _, approveFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "before approval", true: "after approval"}[approveFirst], func(t *testing.T) {
			t.Parallel()
			protocol := newPersonInteractionProtocol(t)
			bindings := newMemoryAgentBindingRevocations()
			protocol.bindings = bindings
			store := newMemoryDeferredTokenStore()
			server := protocol.newServer(t, store, true)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, protocol.personTokenRequest(t))
			if response.Code != http.StatusAccepted {
				t.Fatalf("person-token interaction = %d %s", response.Code, response.Body.String())
			}
			location := response.Header().Get("Location")
			requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
			if err != nil {
				t.Fatal(err)
			}
			interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), personInteractionReference(t, requirement.URL), requirement.Code)
			if err != nil {
				t.Fatal(err)
			}
			person := Person{Subject: "person-123", Lifetime: 10 * time.Minute}
			if approveFirst {
				if err := server.ApprovePersonTokenInteraction(context.Background(), interaction, person); err != nil {
					t.Fatal(err)
				}
			}
			if err := server.RevokeAgentBinding(context.Background(), AgentBinding{AgentProvider: "https://provider.example", Agent: protocol.agentID}); err != nil {
				t.Fatal(err)
			}
			if !approveFirst {
				if err := server.ApprovePersonTokenInteraction(context.Background(), interaction, person); !errors.Is(err, ErrAgentBindingRevoked) {
					t.Fatalf("approval under a revoked binding = %v", err)
				}
				if store.tokenCommitCount() != 0 {
					t.Fatal("approval under a revoked binding retained a Person token")
				}
			}
			poll := httptest.NewRecorder()
			server.Handler().ServeHTTP(poll, protocol.pollRequest(t, location, protocol.agentKey, protocol.agentToken))
			assertPersonInteractionProblem(t, poll, http.StatusForbidden, "person_token_denied")
			if approveFirst {
				again := httptest.NewRecorder()
				server.Handler().ServeHTTP(again, protocol.pollRequest(t, location, protocol.agentKey, protocol.agentToken))
				assertPersonInteractionProblem(t, again, http.StatusGone, "invalid_code")
			}
		})
	}
}
