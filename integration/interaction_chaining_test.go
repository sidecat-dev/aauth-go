package integration_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

const (
	chainAgentProvider = "https://ap.example"
	chainPersonServer  = "https://ps.example"
	chainOrders        = "https://orders.example"
	chainOrdersAgents  = "https://orders-agents.example"
	chainOrdersAgent   = "aauth:fulfillment@orders-agents.example"
	chainInventory     = "https://inventory.example"
	chainAgentCallback = "https://ap.example/callback/order-42"
)

// interactionChainFixture composes an Agent, a three-party Person Server,
// Resource 1 (orders), which calls Resource 2 (inventory) as an Agent, and
// Resource 2, which needs the person before it opens a session. Resource 1
// chains that interaction back to the original Agent (Core, Interaction
// Chaining). The test plays the person's browser and the hosts' pages.
type interactionChainFixture struct {
	ctx       context.Context
	orders    *resource.Server
	inventory *resource.ResourceManagedServer
	readers   map[string]*clientagent.Client
	tokens    map[string]string
	relay     *clientagent.Client

	mu         sync.Mutex
	downstream map[string]clientagent.PendingResourceSession
	chainErr   error
}

func newInteractionChainFixture(t *testing.T) *interactionChainFixture {
	t.Helper()
	fixture := &interactionChainFixture{
		ctx: context.Background(), readers: map[string]*clientagent.Client{}, tokens: map[string]string{},
		downstream: map[string]clientagent.PendingResourceSession{},
	}
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	keyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true, Clock: clock,
		Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentTokens := 0
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: chainAgentProvider, SigningKey: newSigningKey(t, "chain-ap"), Clock: clock,
		NewID: func() string {
			agentTokens++
			return "chain-agent-token-" + string(rune('a'+agentTokens))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ordersProvider, err := agentprovider.New(agentprovider.Config{
		Issuer: chainOrdersAgents, SigningKey: newSigningKey(t, "chain-orders-ap"), Clock: clock,
		NewID: func() string { return "chain-orders-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	relayKey := newSigningKey(t, "chain-orders-agent")
	relayToken, err := ordersProvider.Issue(t.Context(), aauth.AgentTokenRequest{
		Agent: chainOrdersAgent, PublicKey: relayKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := 0
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: chainPersonServer, SigningKey: newSigningKey(t, "chain-ps"), KeyResolver: keyResolver,
		Clock: clock, Tokens: newMemoryPersonTokenStore(),
		NewID: func() string {
			ids++
			return "chain-ps-token-" + string(rune('a'+ids))
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-" + strings.TrimPrefix(request.Agent, "aauth:"), Lifetime: 20 * time.Minute}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: 15 * time.Minute}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.inventory, err = resource.NewResourceManaged(resource.ResourceManagedConfig{
		Issuer: chainInventory, KeyResolver: keyResolver, Clock: clock,
		ScopeDescriptions: map[string]string{"inventory.reserve": "Reserve inventory"},
		RequiredScopes:    func(*http.Request) []string { return []string{"inventory.reserve"} },
		Interaction: resource.SessionInteractionPolicy{
			URL: chainInventory + "/interaction", Lifetime: 5 * time.Minute, MaximumCodeAttempts: 3,
		},
		Sessions: newIntegrationSessionStore(),
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(response, "reserved")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.orders, err = resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: chainOrders, SigningKey: newSigningKey(t, "chain-orders"), KeyResolver: keyResolver,
		Clock: clock, NewID: func() string { return "chain-orders-resource-token" },
		ScopeDescriptions: map[string]string{"orders.fulfill": "Fulfill orders"},
		RequiredScopes:    func(*http.Request) []string { return []string{"orders.fulfill"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		ChainedInteractions: &resource.ChainedInteractionConfig{
			URL: chainOrders + "/continue", CallbackURL: chainOrders + "/returned",
			Lifetime: 10 * time.Minute, Store: testutil.NewChainedInteractionStore(),
		},
		// Resource 1 acts as an Agent toward Resource 2 and meets its
		// interaction, so it answers its own caller with its own 202.
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			downstreamRequest, err := http.NewRequestWithContext(request.Context(), http.MethodPost, chainInventory+"/reserve", nil)
			if err != nil {
				http.Error(response, err.Error(), http.StatusInternalServerError)
				return
			}
			downstreamRequest.Header.Set("AAuth-Capabilities", "interaction")
			begin, err := fixture.relay.BeginResourceSession(request.Context(), downstreamRequest)
			if err != nil {
				http.Error(response, err.Error(), http.StatusBadGateway)
				return
			}
			pending, ok := begin.Pending()
			if !ok {
				http.Error(response, "inventory did not ask for an interaction", http.StatusBadGateway)
				return
			}
			chained, err := fixture.orders.ChainInteraction(response, request, aauth.InteractionRequirement{
				URL: pending.InteractionURL(), Code: pending.InteractionCode(),
			})
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			if err != nil {
				fixture.chainErr = err
				http.Error(response, "interaction_unavailable", http.StatusForbidden)
				return
			}
			fixture.downstream[chained.Reference()] = pending
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(chainAgentProvider, provider.Handler())
	network.Handle(chainOrdersAgents, ordersProvider.Handler())
	network.Handle(chainPersonServer, people.Handler())
	network.Handle(chainOrders, fixture.orders.Handler())
	network.Handle(chainInventory, fixture.inventory.Handler())
	fixture.relay, err = clientagent.New(fixture.ctx, clientagent.Config{
		Identifier: chainOrdersAgent, SigningKey: relayKey, AgentToken: relayToken,
		KeyResolver: keyResolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"reader", "other"} {
		agentKey := newSigningKey(t, "chain-"+name)
		identifier := "aauth:" + name + "@ap.example"
		agentToken, err := provider.Issue(fixture.ctx, aauth.AgentTokenRequest{
			Agent: identifier, PersonServer: chainPersonServer, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		client, err := clientagent.New(fixture.ctx, clientagent.Config{
			Identifier: identifier, SigningKey: agentKey, AgentToken: agentToken,
			KeyResolver: keyResolver, HTTPClient: httpClient, Clock: clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		fixture.readers[name] = client
		fixture.tokens[name] = fixture.authorize(t, client)
	}
	return fixture
}

func (fixture *interactionChainFixture) authorize(t *testing.T, client *clientagent.Client) string {
	t.Helper()
	personResult, err := client.PersonToken(fixture.ctx, clientagent.PersonTokenRequest{
		PersonServer: chainPersonServer, Resource: chainOrders,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatal("person token was not issued immediately")
	}
	resourceToken, err := client.Authorize(fixture.ctx, clientagent.AuthorizeRequest{
		Resource: chainOrders, PersonToken: personToken, Scopes: []string{"orders.fulfill"},
	})
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := client.Exchange(fixture.ctx, clientagent.ExchangeRequest{
		PersonServer: chainPersonServer, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authToken
}

// call makes the original call to Resource 1 as the named Agent.
func (fixture *interactionChainFixture) call(t *testing.T, name string, declared bool) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(fixture.ctx, http.MethodPost, chainOrders+"/orders/42/fulfill", nil)
	if err != nil {
		t.Fatal(err)
	}
	if declared {
		request.Header.Set("AAuth-Capabilities", "interaction")
	}
	response, err := fixture.readers[name].Do(fixture.ctx, clientagent.Call{Request: request, AuthToken: fixture.tokens[name]})
	if err != nil {
		t.Fatal(err)
	}
	return response
}

// visitOrders plays the person arriving at Resource 1's page with the
// Agent's callback; Resource 1 sends them on to Resource 2's interaction.
func (fixture *interactionChainFixture) visitOrders(t *testing.T, pending clientagent.PendingInteractionCall) (string, string) {
	t.Helper()
	target, err := aauth.FormatInteractionVisitURL(pending.InteractionURL(), pending.InteractionCode(), chainAgentCallback)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	visit, err := aauth.ParseInteractionVisit(parsed.RawQuery, aauth.InteractionVisitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(parsed.Path, "/continue/")
	if _, err := fixture.orders.VisitChainedInteraction(fixture.ctx, reference, aauth.InteractionVisit{Code: "0000-0000"}); !errors.Is(err, resource.ErrChainedInteractionCodeInvalid) {
		t.Fatalf("wrong code = %v", err)
	}
	redirect, err := fixture.orders.VisitChainedInteraction(fixture.ctx, reference, visit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.orders.VisitChainedInteraction(fixture.ctx, reference, visit); !errors.Is(err, resource.ErrChainedInteractionCodeUsed) {
		t.Fatalf("second visit = %v", err)
	}
	return reference, redirect
}

// decideAtInventory plays Resource 2's own page: it correlates its code,
// records the person's decision, and returns the browser to the callback
// Resource 1 sent, with an error when the person declined.
func (fixture *interactionChainFixture) decideAtInventory(t *testing.T, redirect string, approve bool) string {
	t.Helper()
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	visit, err := aauth.ParseInteractionVisit(parsed.RawQuery, aauth.InteractionVisitOptions{})
	if err != nil || !strings.HasPrefix(visit.Callback, chainOrders+"/returned/") {
		t.Fatalf("inventory visit = %#v, %v", visit, err)
	}
	interaction, err := fixture.inventory.ConsumeSessionInteractionCode(
		fixture.ctx, strings.TrimPrefix(parsed.Path, "/interaction/"), visit.Code,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !approve {
		if err := fixture.inventory.DenySessionInteraction(fixture.ctx, interaction); err != nil {
			t.Fatal(err)
		}
		back, err := aauth.InteractionCallbackURL(visit.Callback, aauth.InteractionCallbackAccessDenied)
		if err != nil {
			t.Fatal(err)
		}
		return back
	}
	if err := fixture.inventory.ApproveSessionInteraction(fixture.ctx, interaction, resource.SessionGrant{
		Subject: "inventory-person", Scope: []string{"inventory.reserve"}, Lifetime: 10 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	back, err := aauth.InteractionCallbackURL(visit.Callback, "")
	if err != nil {
		t.Fatal(err)
	}
	return back
}

func (fixture *interactionChainFixture) returned(t *testing.T, callback string) (resource.ChainedInteraction, string, error) {
	t.Helper()
	parsed, err := url.Parse(callback)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/returned/"), "/")
	if len(parts) != 2 {
		t.Fatalf("callback path = %q", parsed.Path)
	}
	chained, err := fixture.orders.ReceiveChainedInteractionCallback(fixture.ctx, parts[0], parts[1], parsed.RawQuery)
	return chained, parts[0], err
}

func TestResourceChainsADownstreamInteractionToItsCaller(t *testing.T) {
	t.Parallel()
	fixture := newInteractionChainFixture(t)
	response := fixture.call(t, "reader", true)
	pending, err := fixture.readers["reader"].ReadInteractionCall(response)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pending.InteractionURL(), chainOrders+"/continue/") ||
		!strings.HasPrefix(pending.Location(), chainOrders+"/chain/pending/") {
		t.Fatalf("chained 202 = %#v", pending)
	}
	reference, redirect := fixture.visitOrders(t, pending)
	fixture.mu.Lock()
	downstream := fixture.downstream[reference]
	fixture.mu.Unlock()
	if !strings.HasPrefix(redirect, downstream.InteractionURL()+"?code=") {
		t.Fatalf("Resource 1 redirect %q does not continue at Resource 2 %q", redirect, downstream.InteractionURL())
	}
	interacting, err := fixture.readers["reader"].PollInteractionCall(fixture.ctx, clientagent.InteractionCallPoll{
		Pending: pending, AuthToken: fixture.tokens["reader"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if next, ok := interacting.Pending(); !ok || !next.Interacting() {
		t.Fatalf("poll while interacting = %#v", interacting)
	}
	// Another Agent with its own authorization at Resource 1 learns nothing.
	if _, err := fixture.readers["other"].PollInteractionCall(fixture.ctx, clientagent.InteractionCallPoll{
		Pending: pending, AuthToken: fixture.tokens["other"],
	}); err == nil || !strings.Contains(err.Error(), "unknown to this caller") {
		t.Fatalf("another caller's poll = %v", err)
	}

	back := fixture.decideAtInventory(t, redirect, true)
	chained, _, err := fixture.returned(t, back)
	if err != nil {
		t.Fatal(err)
	}
	// Resource 1 obtains the downstream session, completes the original
	// request, and returns the result at its own pending URL.
	session, err := fixture.relay.PollResourceSession(fixture.ctx, downstream)
	if err != nil {
		t.Fatal(err)
	}
	granted, ok := session.Session()
	if !ok {
		t.Fatalf("downstream session = %#v", session)
	}
	if terminal, ok := session.Response(); ok {
		terminal.Body.Close()
	}
	reserve, err := http.NewRequestWithContext(fixture.ctx, http.MethodPost, chainInventory+"/reserve", nil)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := fixture.relay.DoWithResourceSession(fixture.ctx, reserve, granted)
	if err != nil {
		t.Fatal(err)
	}
	reservedResponse, ok := reserved.Response()
	if !ok {
		t.Fatalf("downstream call = %#v", reserved)
	}
	body, _ := io.ReadAll(reservedResponse.Body)
	reservedResponse.Body.Close()
	if err := fixture.orders.CompleteChainedInteraction(fixture.ctx, chained, resource.ChainedInteractionResult{
		Status: http.StatusOK, ContentType: "text/plain", Body: append([]byte("order 42 fulfilled: "), body...),
	}); err != nil {
		t.Fatal(err)
	}
	toAgent, err := fixture.orders.ChainedInteractionCallbackURL(fixture.ctx, chained.Reference())
	if err != nil || toAgent != chainAgentCallback {
		t.Fatalf("Agent callback = %q, %v", toAgent, err)
	}

	completed, err := fixture.readers["reader"].PollInteractionCall(fixture.ctx, clientagent.InteractionCallPoll{
		Pending: pending, AuthToken: fixture.tokens["reader"],
	})
	if err != nil {
		t.Fatal(err)
	}
	result, ok := completed.Response()
	if !ok {
		t.Fatalf("completed poll = %#v", completed)
	}
	resultBody, _ := io.ReadAll(result.Body)
	result.Body.Close()
	if result.StatusCode != http.StatusOK || string(resultBody) != "order 42 fulfilled: reserved" ||
		result.Header.Get("Content-Type") != "text/plain" {
		t.Fatalf("result = %d %q %q", result.StatusCode, resultBody, result.Header.Get("Content-Type"))
	}
	_, err = fixture.readers["reader"].PollInteractionCall(fixture.ctx, clientagent.InteractionCallPoll{
		Pending: pending, AuthToken: fixture.tokens["reader"],
	})
	var gone *aauth.ProblemError
	if !errors.As(err, &gone) || gone.Status != http.StatusGone {
		t.Fatalf("poll after delivery = %v", err)
	}
}

// A downstream refusal reaches the original Agent twice: through its own
// callback, as an error it must surface, and at the pending URL, as the
// polling error. Neither treats the call as completable.
func TestChainedInteractionPropagatesADownstreamCallbackError(t *testing.T) {
	t.Parallel()
	fixture := newInteractionChainFixture(t)
	pending, err := fixture.readers["reader"].ReadInteractionCall(fixture.call(t, "reader", true))
	if err != nil {
		t.Fatal(err)
	}
	reference, redirect := fixture.visitOrders(t, pending)
	back := fixture.decideAtInventory(t, redirect, false)
	if _, _, err := fixture.returned(t, back[:strings.Index(back, "?")]+"x"+back[strings.Index(back, "?"):]); !errors.Is(err, resource.ErrChainedInteractionCallbackInvalid) {
		t.Fatalf("callback with a forged flow = %v", err)
	}
	_, _, err = fixture.returned(t, back)
	if !errors.Is(err, aauth.InteractionCallbackAccessDenied) {
		t.Fatalf("Resource 1 callback = %v", err)
	}
	toAgent, err := fixture.orders.ChainedInteractionCallbackURL(fixture.ctx, reference)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(toAgent)
	if err != nil {
		t.Fatal(err)
	}
	if failure := aauth.ReadInteractionCallback(parsed.RawQuery); !errors.Is(failure, aauth.InteractionCallbackAccessDenied) {
		t.Fatalf("Agent callback %q read as %v", toAgent, failure)
	}
	_, err = fixture.readers["reader"].PollInteractionCall(fixture.ctx, clientagent.InteractionCallPoll{
		Pending: pending, AuthToken: fixture.tokens["reader"],
	})
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Code != "denied" {
		t.Fatalf("poll after a downstream denial = %v", err)
	}
}

func TestChainedInteractionNeedsTheCallersInteractionCapability(t *testing.T) {
	t.Parallel()
	fixture := newInteractionChainFixture(t)
	response := fixture.call(t, "reader", false)
	response.Body.Close()
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if response.StatusCode != http.StatusForbidden || !errors.Is(fixture.chainErr, resource.ErrChainedInteractionUndeclared) ||
		len(fixture.downstream) != 0 {
		t.Fatalf("undeclared caller = %d, %v", response.StatusCode, fixture.chainErr)
	}
}

// A downstream wait that ends with revoked, for example because the Resource
// it waited on withdrew its Resource token, ends the chained request with
// revoked as well; the caller's callback reports that it did not complete.
func TestChainedInteractionRelaysADownstreamRevocation(t *testing.T) {
	t.Parallel()
	fixture := newInteractionChainFixture(t)
	pending, err := fixture.readers["reader"].ReadInteractionCall(fixture.call(t, "reader", true))
	if err != nil {
		t.Fatal(err)
	}
	reference, _ := fixture.visitOrders(t, pending)
	chained, err := fixture.orders.ResumeChainedInteraction(fixture.ctx, reference)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.orders.FailChainedInteraction(fixture.ctx, chained, "revoked"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.orders.CompleteChainedInteraction(fixture.ctx, chained, resource.ChainedInteractionResult{
		Status: http.StatusOK,
	}); !errors.Is(err, resource.ErrChainedInteractionConflict) {
		t.Fatalf("completion after a revocation = %v", err)
	}
	toAgent, err := fixture.orders.ChainedInteractionCallbackURL(fixture.ctx, reference)
	if err != nil || toAgent != chainAgentCallback+"?error=server_error" {
		t.Fatalf("Agent callback = %q, %v", toAgent, err)
	}
	_, err = fixture.readers["reader"].PollInteractionCall(fixture.ctx, clientagent.InteractionCallPoll{
		Pending: pending, AuthToken: fixture.tokens["reader"],
	})
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Code != "revoked" {
		t.Fatalf("poll after a downstream revocation = %v", err)
	}
}
