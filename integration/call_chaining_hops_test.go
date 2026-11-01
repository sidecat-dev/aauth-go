package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

const (
	hopCallerProvider = "https://agents-hop.example"
	hopCaller         = "aauth:shopper@agents-hop.example"
	hopPersonServer   = "https://person-hop.example"
	hopRelayOwnPS     = "https://relay-person-hop.example"
	hopOrders         = "https://orders-hop.example"
	hopInventory      = "https://inventory-hop.example"
	hopWarehouse      = "https://warehouse-hop.example"
	hopOrdersAS       = "https://orders-as-hop.example"
	hopStockAS        = "https://stock-as-hop.example"
)

// hopFixture is a calling Agent, one four-party Person Server and three
// Resources, each behind an Access Server: orders behind one, inventory and
// warehouse behind another. Orders and inventory act as Agents, each its own
// Agent Provider, so a call can be chained orders -> inventory -> warehouse.
type hopFixture struct {
	t       *testing.T
	ctx     context.Context
	nowMu   sync.Mutex
	now     time.Time
	clock   aauth.Clock
	network *logicalTransport
	client  *http.Client
	admit   signaturekey.EgressAdmitter

	callerProvider *agentprovider.Server
	callerToken    string
	caller         *clientagent.Client
	ordersRelay    *clientagent.Client
	inventoryRelay *clientagent.Client
	people         *personserver.Server

	mu              sync.Mutex
	requests        []string
	interceptor     func(http.ResponseWriter, *http.Request) bool
	holdStock       bool
	askStock        bool
	chainedBindings []personserver.PersonTokenRequest
	chainedConsents []personserver.AuthorizationRequest
	ceilings        []personserver.AuthorizationRequest
	accessRequests  []accessserver.AuthorizationRequest
}

type hopOptions struct {
	missions *personserver.MissionConfig
	// budget meters inventory: it offers what is asked, the Person Server
	// lowers that to hopBudgetCeiling, and the stock Access Server grants the
	// Person Server's ceiling.
	budget bool
}

// The denomination and Person Server ceiling of a budgeted hop fixture.
const (
	hopBudgetCeiling = 300
	hopBudgetCost    = 40
)

func hopBudgetValue(t *testing.T, amount int64) budgets.Value {
	t.Helper()
	unit, err := budgets.NewUnit("credits", 0)
	if err != nil {
		t.Fatal(err)
	}
	return integrationBudgetValue(t, amount, unit)
}

func newHopFixture(t *testing.T, options hopOptions) *hopFixture {
	t.Helper()
	fixture := &hopFixture{
		t: t, ctx: context.Background(), now: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC),
		network: newLogicalTransport(),
	}
	fixture.clock = aauth.ClockFunc(func() time.Time {
		fixture.nowMu.Lock()
		defer fixture.nowMu.Unlock()
		return fixture.now
	})
	fixture.client = &http.Client{Transport: contextTransport{base: fixture.network}}
	fixture.admit = func(_ context.Context, endpoint string) error {
		if strings.HasPrefix(endpoint, "https://") && strings.Contains(endpoint, "-hop.example/") {
			return nil
		}
		return errors.New("unexpected egress endpoint: " + endpoint)
	}
	keys := map[string]jose.SigningKey{}
	for _, name := range []string{
		"caller-provider", "caller", "ps", "orders", "orders-agent", "inventory", "inventory-agent",
		"warehouse", "orders-as", "stock-as",
	} {
		keys[name] = newSigningKey(t, "hop-"+name)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: hopCallerProvider, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: keys["caller-provider"].ID()}: keys["caller-provider"].PublicJWK(),
		{Issuer: hopPersonServer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: keys["ps"].ID()}:               keys["ps"].PublicJWK(),
		{Issuer: hopOrders, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: keys["orders"].ID()}:                  keys["orders"].PublicJWK(),
		{Issuer: hopOrders, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: keys["orders"].ID()}:               keys["orders"].PublicJWK(),
		{Issuer: hopInventory, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: keys["inventory"].ID()}:            keys["inventory"].PublicJWK(),
		{Issuer: hopInventory, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: keys["inventory"].ID()}:         keys["inventory"].PublicJWK(),
		{Issuer: hopWarehouse, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: keys["warehouse"].ID()}:         keys["warehouse"].PublicJWK(),
		{Issuer: hopOrdersAS, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: keys["orders-as"].ID()}:            keys["orders-as"].PublicJWK(),
		{Issuer: hopStockAS, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: keys["stock-as"].ID()}:              keys["stock-as"].PublicJWK(),
	}
	ids := newSequence()

	var units []budgets.UnitDeclaration
	var accessBudget *accessserver.BudgetConfig
	if options.budget {
		declaration, err := budgets.NewBoundedUnitDeclaration(hopBudgetValue(t, 1).Unit(), 1_000, "Stock credits")
		if err != nil {
			t.Fatal(err)
		}
		units = []budgets.UnitDeclaration{declaration}
		accessBudget = &accessserver.BudgetConfig{
			ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) { return units, nil },
		}
	}

	for _, server := range []struct {
		issuer string
		key    jose.SigningKey
		hold   bool
	}{
		{issuer: hopOrdersAS, key: keys["orders-as"]},
		{issuer: hopStockAS, key: keys["stock-as"], hold: true},
	} {
		hold := server.hold
		access, err := accessserver.New(accessserver.Config{
			Issuer: server.issuer, SigningKey: server.key, KeyResolver: resolver, Clock: fixture.clock,
			NewID: ids.source(strings.TrimPrefix(server.issuer, "https://") + "-auth-token"),
			TrustPersonServer: func(_ context.Context, issuer string) error {
				if issuer != hopPersonServer {
					return accessserver.ErrAccessDenied
				}
				return nil
			},
			Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
				fixture.mu.Lock()
				defer fixture.mu.Unlock()
				fixture.accessRequests = append(fixture.accessRequests, request)
				if hold && fixture.askStock {
					return accessserver.Decision{Pending: &accessserver.PendingDecision{
						RetryAfter: time.Second, InteractionURL: hopStockAS + "/consent",
					}}, nil
				}
				if hold && fixture.holdStock {
					return accessserver.Decision{Pending: &accessserver.PendingDecision{RetryAfter: time.Second}}, nil
				}
				return accessserver.Decision{Scopes: request.Scopes, Lifetime: 30 * time.Minute, Budget: request.Budget}, nil
			},
			Budget:   accessBudget,
			Deferred: &accessserver.DeferredConfig{Store: testutil.NewAccessAuthorizationStore(), Lifetime: 30 * time.Minute},
			Revocation: &accessserver.RevocationConfig{
				Revocations: testutil.NewTokenRevocationStore(), IssuedTokens: testutil.NewAccessIssuedAuthTokenStore(),
				HTTPClient: fixture.client, Admit: fixture.admit,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		fixture.route(server.issuer, access.Handler())
	}

	for _, protected := range []struct {
		issuer, accessServer, scope string
		key                         jose.SigningKey
	}{
		{issuer: hopOrders, accessServer: hopOrdersAS, scope: "orders.fulfill", key: keys["orders"]},
		{issuer: hopInventory, accessServer: hopStockAS, scope: "inventory.reserve", key: keys["inventory"]},
		{issuer: hopWarehouse, accessServer: hopStockAS, scope: "warehouse.pick", key: keys["warehouse"]},
	} {
		scope := protected.scope
		var budget *resource.BudgetConfig
		if options.budget && protected.issuer == hopInventory {
			budget = &resource.BudgetConfig{
				Units: units,
				Offer: func(_ context.Context, request resource.BudgetOfferRequest) (budgets.Value, error) {
					return request.Requested, nil
				},
				RetainLineage: func(context.Context, resource.BudgetLineage) error { return nil },
				Cost:          func(context.Context, resource.BudgetCostRequest) (int64, error) { return hopBudgetCost, nil },
				Store:         newIntegrationBudgetStore(),
				Challenge: func(context.Context, resource.BudgetChallengeRequest) (string, error) {
					return "", errors.New("the hop fixture asks for no Budget step-up")
				},
			}
		}
		server, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
			Issuer: protected.issuer, AccessServer: protected.accessServer, SigningKey: protected.key,
			KeyResolver: resolver, Clock: fixture.clock,
			NewID:             ids.source(strings.TrimPrefix(protected.issuer, "https://") + "-resource-token"),
			ScopeDescriptions: map[string]string{scope: scope},
			RequiredScopes:    func(*http.Request) []string { return []string{scope} },
			ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
			Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				principal, _ := resource.AuthPrincipalFromContext(request.Context())
				_, _ = io.WriteString(response, "served "+principal.Subject)
			}),
			AuthTokenStatuses: testutil.NewAuthTokenStatusStore(),
			Revocation: &resource.RevocationConfig{
				PersonTokens: testutil.NewTokenRevocationStore(), HTTPClient: fixture.client, Admit: fixture.admit,
			},
			Budget: budget,
		})
		if err != nil {
			t.Fatal(err)
		}
		fixture.route(protected.issuer, server.Handler())
	}

	// The calling Agent's person is directed per Resource; a chained request
	// derives the person at the downstream Resource from the upstream one.
	directed := func(resource string) string { return "person-at-" + strings.TrimPrefix(resource, "https://") }
	config := personserver.FederatedAuthorizationConfig{
		Issuer: hopPersonServer, SigningKey: keys["ps"], KeyResolver: resolver, Clock: fixture.clock,
		NewID: ids.source("hop-person-token"), HTTPClient: fixture.client,
		Tokens: testutil.NewMissionStore(), IssuedTokens: testutil.NewIssuedAuthTokenStore(),
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) { return issuer + "/token", nil },
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != hopCaller {
				return personserver.Person{}, errors.New("only the calling Agent is bound to the person")
			}
			return personserver.Person{Subject: directed(request.Resource), Lifetime: 20 * time.Minute}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		CallChaining: &personserver.FederatedCallChainingConfig{
			BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
				fixture.mu.Lock()
				fixture.chainedBindings = append(fixture.chainedBindings, request)
				fixture.mu.Unlock()
				return personserver.Person{Subject: directed(request.Resource), Lifetime: time.Hour}, nil
			},
			Consent: func(_ context.Context, request personserver.AuthorizationRequest) error {
				fixture.mu.Lock()
				fixture.chainedConsents = append(fixture.chainedConsents, request)
				fixture.mu.Unlock()
				return nil
			},
		},
		Deferred: &personserver.FederatedDeferredConfig{Store: testutil.NewFederatedAuthorizationStore(), Lifetime: 30 * time.Minute},
		TokenRevocation: &personserver.TokenRevocationConfig{
			Revocations: testutil.NewTokenRevocationStore(), HTTPClient: fixture.client, Admit: fixture.admit,
			Hold: 2 * time.Second,
		},
		AgentTokenRevocations: testutil.NewTokenRevocationStore(),
		Missions:              options.missions,
	}
	if options.budget {
		config.Budget = &personserver.FederatedBudgetConfig{
			ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) { return units, nil },
			Ceiling: func(_ context.Context, request personserver.AuthorizationRequest) (*budgets.Value, error) {
				fixture.mu.Lock()
				fixture.ceilings = append(fixture.ceilings, request)
				fixture.mu.Unlock()
				ceiling := hopBudgetValue(t, hopBudgetCeiling)
				return &ceiling, nil
			},
		}
	}
	var err error
	fixture.people, err = personserver.NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	fixture.route(hopPersonServer, fixture.people.Handler())

	fixture.callerProvider, err = agentprovider.New(agentprovider.Config{
		Issuer: hopCallerProvider, SigningKey: keys["caller-provider"], Clock: fixture.clock,
		NewID: ids.source("hop-caller-agent-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.callerToken, err = fixture.callerProvider.Issue(aauth.AgentTokenRequest{
		Agent: hopCaller, PersonServer: hopPersonServer, PublicKey: keys["caller"].PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.caller = fixture.agent(hopCaller, keys["caller"], fixture.callerToken, resolver)
	// Each intermediary is its own Agent Provider. Its Agent token names its
	// own Person Server, which no chained request is routed to.
	for _, relay := range []struct {
		issuer string
		key    jose.SigningKey
		agent  jose.SigningKey
		client **clientagent.Client
	}{
		{issuer: hopOrders, key: keys["orders"], agent: keys["orders-agent"], client: &fixture.ordersRelay},
		{issuer: hopInventory, key: keys["inventory"], agent: keys["inventory-agent"], client: &fixture.inventoryRelay},
	} {
		identifier := "aauth:relay@" + strings.TrimPrefix(relay.issuer, "https://")
		token, err := aauth.MintAgentToken(relay.issuer, relay.key, aauth.AgentTokenRequest{
			Agent: identifier, PersonServer: hopRelayOwnPS, PublicKey: relay.agent.PublicJWK(), Lifetime: time.Hour,
		}, fixture.now, strings.TrimPrefix(relay.issuer, "https://")+"-agent-token")
		if err != nil {
			t.Fatal(err)
		}
		*relay.client = fixture.agent(identifier, relay.agent, token, resolver)
	}
	return fixture
}

func (fixture *hopFixture) agent(identifier string, key jose.SigningKey, token string, resolver signaturekey.KeyResolver) *clientagent.Client {
	fixture.t.Helper()
	client, err := clientagent.New(fixture.ctx, clientagent.Config{
		Identifier: identifier, SigningKey: key, AgentToken: token,
		KeyResolver: resolver, HTTPClient: fixture.client, Clock: fixture.clock,
	})
	if err != nil {
		fixture.t.Fatal(err)
	}
	return client
}

// route serves origin with handler, recording each request and letting the
// test intercept one before it reaches the role.
func (fixture *hopFixture) route(origin string, handler http.Handler) {
	fixture.network.Handle(origin, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		fixture.mu.Lock()
		fixture.requests = append(fixture.requests, request.Method+" "+origin+request.URL.Path)
		interceptor := fixture.interceptor
		fixture.mu.Unlock()
		if interceptor != nil && interceptor(response, request) {
			return
		}
		handler.ServeHTTP(response, request)
	}))
}

func (fixture *hopFixture) count(request string) int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	count := 0
	for _, seen := range fixture.requests {
		if seen == request {
			count++
		}
	}
	return count
}

func (fixture *hopFixture) advance(delay time.Duration) {
	fixture.nowMu.Lock()
	defer fixture.nowMu.Unlock()
	fixture.now = fixture.now.Add(delay)
}

func (fixture *hopFixture) setStockHold(hold bool) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.holdStock = hold
}

// setStockInteraction makes the stock Access Server ask for the person at
// its own consent page.
func (fixture *hopFixture) setStockInteraction(ask bool) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.askStock = ask
}

// hopLink is what one hop of a chain obtained: the person token for the
// Resource, its resource token, and the auth token it was exchanged for.
type hopLink struct {
	person, resourceToken, auth string
}

// callerLink is the calling Agent's own authorization at the orders Resource.
func (fixture *hopFixture) callerLink(personToken string) hopLink {
	fixture.t.Helper()
	if personToken == "" {
		result, err := fixture.caller.PersonToken(fixture.ctx, clientagent.PersonTokenRequest{PersonServer: hopPersonServer, Resource: hopOrders})
		if err != nil {
			fixture.t.Fatal(err)
		}
		var ok bool
		if personToken, ok = result.Token(); !ok {
			fixture.t.Fatalf("person-token result = %#v", result)
		}
	}
	resourceToken, err := fixture.caller.Authorize(fixture.ctx, clientagent.AuthorizeRequest{
		Resource: hopOrders, PersonToken: personToken, Scopes: []string{"orders.fulfill"},
	})
	if err != nil {
		fixture.t.Fatal(err)
	}
	authToken, err := fixture.caller.Exchange(fixture.ctx, clientagent.ExchangeRequest{
		PersonServer: hopPersonServer, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		fixture.t.Fatal(err)
	}
	fixture.serve(fixture.caller, hopOrders, authToken, "", "served person-at-orders-hop.example")
	return hopLink{person: personToken, resourceToken: resourceToken, auth: authToken}
}

// chainedLink takes the first two steps of a chained hop: a person token for
// the downstream Resource, obtained with upstream, and its resource token.
func (fixture *hopFixture) chainedLink(relay *clientagent.Client, downstream, scope, upstream string) hopLink {
	fixture.t.Helper()
	result, err := relay.PersonToken(fixture.ctx, clientagent.PersonTokenRequest{Resource: downstream, UpstreamToken: upstream})
	if err != nil {
		fixture.t.Fatal(err)
	}
	personToken, ok := result.Token()
	if !ok {
		fixture.t.Fatalf("chained person-token result = %#v", result)
	}
	resourceToken, err := relay.Authorize(fixture.ctx, clientagent.AuthorizeRequest{
		Resource: downstream, PersonToken: personToken, UpstreamToken: upstream, Scopes: []string{scope},
	})
	if err != nil {
		fixture.t.Fatal(err)
	}
	return hopLink{person: personToken, resourceToken: resourceToken}
}

// chainedHop completes a chained hop with an immediate exchange and serves one
// downstream call with the auth token.
func (fixture *hopFixture) chainedHop(relay *clientagent.Client, downstream, scope, upstream string) hopLink {
	fixture.t.Helper()
	link := fixture.chainedLink(relay, downstream, scope, upstream)
	authToken, err := relay.Exchange(fixture.ctx, clientagent.ExchangeRequest{
		ResourceToken: link.resourceToken, PresentedToken: link.person, UpstreamToken: upstream,
	})
	if err != nil {
		fixture.t.Fatal(err)
	}
	link.auth = authToken
	fixture.serve(relay, downstream, authToken, upstream, "served person-at-"+strings.TrimPrefix(downstream, "https://"))
	return link
}

func (fixture *hopFixture) call(agent *clientagent.Client, origin, authToken, upstream string) (string, error) {
	fixture.t.Helper()
	request, err := http.NewRequestWithContext(fixture.ctx, http.MethodPost, origin+"/work", nil)
	if err != nil {
		fixture.t.Fatal(err)
	}
	response, err := agent.Do(fixture.ctx, clientagent.Call{Request: request, AuthToken: authToken, UpstreamToken: upstream})
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		return "", errors.New("protected response " + response.Status)
	}
	return string(body), nil
}

func (fixture *hopFixture) serve(agent *clientagent.Client, origin, authToken, upstream, want string) {
	fixture.t.Helper()
	body, err := fixture.call(agent, origin, authToken, upstream)
	if err != nil || body != want {
		fixture.t.Fatalf("call to %s = %q, %v; want %q", origin, body, err, want)
	}
}

func hopExpiry(t *testing.T, compact string) int64 {
	t.Helper()
	return int64(tokenClaims(t, compact)["exp"].(float64))
}

// Protocol 70d6737, Call Chaining, Upstream Token Verification and PS-to-AS
// Token Request: an intermediary presents the auth token an Access Server
// issued to its caller as upstream_token, and the Person Server accepts it
// because it delivered that token and kept a receipt naming the calling
// Agent. The chain repeats from the intermediary's own downstream auth token,
// each Access Server receives the exact upstream_token, and no downstream
// token outlives the token it was chained from. Revocation Cascade: revoking
// the caller's person token revokes the chain hop by hop.
func TestFourPartyCallChainRepeatsOnAccessServerAuthTokens(t *testing.T) {
	t.Parallel()
	fixture := newHopFixture(t, hopOptions{})
	ctx := fixture.ctx

	caller := fixture.callerLink("")
	fixture.advance(time.Minute)
	first := fixture.chainedHop(fixture.ordersRelay, hopInventory, "inventory.reserve", caller.auth)
	fixture.advance(time.Minute)
	second := fixture.chainedHop(fixture.inventoryRelay, hopWarehouse, "warehouse.pick", first.auth)

	callerAuth := tokenClaims(t, caller.auth)
	firstAuth := tokenClaims(t, first.auth)
	if callerAuth["iss"] != hopOrdersAS || firstAuth["iss"] != hopStockAS || tokenClaims(t, second.auth)["iss"] != hopStockAS {
		t.Fatalf("auth-token issuers = %v, %v", callerAuth["iss"], firstAuth["iss"])
	}
	for _, bound := range []struct {
		label      string
		downstream string
		upstream   string
	}{
		{"first person token", first.person, caller.auth},
		{"first auth token", first.auth, caller.auth},
		{"second person token", second.person, first.auth},
		{"second auth token", second.auth, first.auth},
	} {
		if hopExpiry(t, bound.downstream) > hopExpiry(t, bound.upstream) {
			t.Fatalf("%s outlives its upstream token", bound.label)
		}
	}
	if len(fixture.chainedBindings) != 2 || len(fixture.chainedConsents) != 2 {
		t.Fatalf("chained policy calls = %d bindings, %d consents", len(fixture.chainedBindings), len(fixture.chainedConsents))
	}
	for index, want := range []struct {
		agent, upstreamJTI, subject string
	}{
		{"aauth:relay@orders-hop.example", callerAuth["jti"].(string), "person-at-inventory-hop.example"},
		{"aauth:relay@inventory-hop.example", firstAuth["jti"].(string), "person-at-warehouse-hop.example"},
	} {
		binding, consent := fixture.chainedBindings[index], fixture.chainedConsents[index]
		if binding.Agent != want.agent || binding.Upstream == nil || binding.Upstream.JTI != want.upstreamJTI ||
			binding.Upstream.DWK != aauth.AccessDiscoveryDocument || consent.Upstream == nil ||
			consent.Upstream.JTI != want.upstreamJTI || consent.Subject != want.subject {
			t.Fatalf("hop %d policy = %#v, %#v", index+1, binding, consent)
		}
	}
	// Each Access Server verified the exact upstream_token itself.
	var chained []string
	for _, request := range fixture.accessRequests {
		if request.Upstream != nil {
			chained = append(chained, request.Resource+" "+request.Upstream.JTI)
		}
	}
	if strings.Join(chained, ", ") != hopInventory+" "+callerAuth["jti"].(string)+", "+hopWarehouse+" "+firstAuth["jti"].(string) {
		t.Fatalf("Access Server chained requests = %v", chained)
	}

	revoked, err := fixture.people.RevokePersonToken(ctx, tokenClaims(t, caller.person)["jti"].(string))
	if err != nil {
		t.Fatal(err)
	}
	requireAttempts(t, "chain revocation", revoked.Attempts,
		hopOrders+" recorded", hopOrdersAS+" recorded", hopInventory+" recorded", hopStockAS+" recorded", hopWarehouse+" recorded")

	// Every Access Server revoked the auth tokens it issued along the chain.
	for _, refused := range []struct {
		label    string
		agent    *clientagent.Client
		origin   string
		token    string
		upstream string
	}{
		{"caller auth token", fixture.caller, hopOrders, caller.auth, ""},
		{"first chained auth token", fixture.ordersRelay, hopInventory, first.auth, caller.auth},
		{"second chained auth token", fixture.inventoryRelay, hopWarehouse, second.auth, first.auth},
	} {
		_, err := fixture.call(refused.agent, refused.origin, refused.token, refused.upstream)
		requireRevokedJWT(t, err, refused.label)
	}
	// The Person Server refuses both delivered auth tokens as upstream tokens.
	tokenRequests := fixture.count("POST " + hopPersonServer + "/person")
	for _, refused := range []struct {
		label    string
		relay    *clientagent.Client
		resource string
		upstream string
	}{
		{"caller auth token", fixture.ordersRelay, hopInventory, caller.auth},
		{"first chained auth token", fixture.inventoryRelay, hopWarehouse, first.auth},
	} {
		_, err := refused.relay.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: refused.resource, UpstreamToken: refused.upstream})
		requireProblem(t, err, http.StatusBadRequest, "revoked_upstream_token", refused.label+" as upstream_token")
	}
	if fixture.count("POST "+hopPersonServer+"/person") != tokenRequests+2 {
		t.Fatal("a refused chain request did not reach the Person Server")
	}
}

// Protocol 70d6737, Revocation Cascade: an Agent Provider's revocation of an
// Agent token revokes every person token the Person Server issued to that
// Agent, at its Resource and at each Access Server it was presented to, and
// the call chains built on them. Revocation Response: the Person Server holds
// the request until that cascade is terminal, answers 202 while a recipient
// has not answered, and an empty 200 once each has.
func TestAgentTokenRevocationReachesEachPersonTokenAndItsChain(t *testing.T) {
	t.Parallel()
	fixture := newHopFixture(t, hopOptions{})
	ctx := fixture.ctx

	caller := fixture.callerLink("")
	// A second person token for the same Resource, presented to the same
	// Access Server, is revoked there in its own right.
	again := fixture.callerLink("")
	chain := fixture.chainedHop(fixture.ordersRelay, hopInventory, "inventory.reserve", caller.auth)

	revoker, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider: fixture.callerProvider, HTTPClient: fixture.client, Admit: fixture.admit,
	})
	if err != nil {
		t.Fatal(err)
	}
	agentClaims := tokenClaims(t, fixture.callerToken)
	revocation := aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: hopCallerProvider, JTI: agentClaims["jti"].(string)},
		ExpiresAt: time.Unix(int64(agentClaims["exp"].(float64)), 0),
	}
	// The stock Access Server is rate limiting for now, so the cascade cannot
	// finish: the Person Server answers 202.
	fixture.mu.Lock()
	fixture.interceptor = func(response http.ResponseWriter, request *http.Request) bool {
		if request.Method != http.MethodPost || !strings.HasPrefix(request.URL.String(), hopStockAS+"/revoke") {
			return false
		}
		response.Header().Set("Retry-After", "1")
		response.Header().Set("Content-Type", "application/problem+json")
		response.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(response, `{"type":"about:blank","title":"Too Many Requests","status":429,"error":"rate_limited"}`)
		return true
	}
	fixture.mu.Unlock()
	err = revoker.RevokeAgentToken(ctx, hopPersonServer, revocation)
	var pending *agentprovider.RevocationPendingError
	if !errors.As(err, &pending) || !strings.HasPrefix(pending.Location, hopPersonServer+"/revoke/pending/") || pending.RetryAfter <= 0 {
		t.Fatalf("revocation during the cascade = %v", err)
	}
	// The revocation itself is recorded before anyone is called.
	_, err = fixture.caller.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: hopPersonServer, Resource: hopOrders})
	if err == nil {
		t.Fatal("the revoked Agent token still obtained a person token")
	}

	fixture.mu.Lock()
	fixture.interceptor = nil
	fixture.mu.Unlock()
	fixture.advance(2 * time.Second)
	stockRevocations := fixture.count("POST " + hopStockAS + "/revoke")
	if err := revoker.RevokeAgentToken(ctx, hopPersonServer, revocation); err != nil {
		t.Fatalf("revocation after Retry-After = %v", err)
	}
	if fixture.count("POST "+hopStockAS+"/revoke") != stockRevocations+1 {
		t.Fatal("the repeated revocation did not reach the stock Access Server once")
	}
	if ordersAS := fixture.count("POST " + hopOrdersAS + "/revoke"); ordersAS != 2 {
		t.Fatalf("orders Access Server revocations = %d, want one per person token", ordersAS)
	}

	for _, refused := range []struct {
		label    string
		agent    *clientagent.Client
		origin   string
		token    string
		upstream string
	}{
		{"caller auth token", fixture.caller, hopOrders, caller.auth, ""},
		{"second caller auth token", fixture.caller, hopOrders, again.auth, ""},
		{"chained auth token", fixture.ordersRelay, hopInventory, chain.auth, caller.auth},
	} {
		_, err := fixture.call(refused.agent, refused.origin, refused.token, refused.upstream)
		requireRevokedJWT(t, err, refused.label)
	}
	_, err = fixture.ordersRelay.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: hopInventory, UpstreamToken: again.auth})
	requireProblem(t, err, http.StatusBadRequest, "revoked_upstream_token", "an auth token of the revoked Agent as upstream_token")
}

// Protocol 70d6737, Call Chaining and Deferred Responses: a chained exchange
// can wait for the Access Server like any other, through Exchange or
// BeginExchange. The intermediary polls its pending URL although its own Agent
// token names another Person Server, and the grant is delivered with the
// chain's ceilings. Presenting a Revoked
// Token: a chained request whose upstream token is revoked while it waits ends
// with revoked, detail saying so.
func TestChainedExchangeWaitsForTheAccessServerUntilItsUpstreamIsRevoked(t *testing.T) {
	t.Parallel()
	fixture := newHopFixture(t, hopOptions{})
	ctx := fixture.ctx

	caller := fixture.callerLink("")
	link := fixture.chainedLink(fixture.ordersRelay, hopInventory, "inventory.reserve", caller.auth)
	fixture.setStockHold(true)
	exchange := clientagent.ExchangeRequest{
		ResourceToken: link.resourceToken, PresentedToken: link.person, UpstreamToken: caller.auth,
	}
	// The immediate Exchange hands back the wait it met.
	_, err := fixture.ordersRelay.Exchange(ctx, exchange)
	var deferred *clientagent.PendingExchangeError
	if !errors.As(err, &deferred) {
		t.Fatalf("immediate chained exchange of a waiting request = %v", err)
	}
	waiting := deferred.Pending()
	if waiting.Requirement() != aauth.RequirementApproval || waiting.WaitReason() != "awaiting_approval" ||
		waiting.PersonServer() != hopPersonServer {
		t.Fatalf("chained exchange = %#v", waiting)
	}
	polled, err := fixture.ordersRelay.PollExchange(ctx, waiting)
	if err != nil {
		t.Fatal(err)
	}
	if _, still := polled.Pending(); !still {
		t.Fatalf("poll before the host advanced = %#v", polled)
	}
	fixture.setStockHold(false)
	fixture.advance(2 * time.Second)
	reference := waiting.Location()[strings.LastIndex(waiting.Location(), "/")+1:]
	if err := fixture.people.AdvanceFederation(ctx, reference); err != nil {
		t.Fatal(err)
	}
	delivered, err := fixture.ordersRelay.PollExchange(ctx, waiting)
	if err != nil {
		t.Fatal(err)
	}
	authToken, ok := delivered.Token()
	if !ok || hopExpiry(t, authToken) > hopExpiry(t, caller.auth) {
		t.Fatalf("delivered chained grant = %#v", delivered)
	}
	fixture.serve(fixture.ordersRelay, hopInventory, authToken, caller.auth, "served person-at-inventory-hop.example")

	// A second request waits, and the caller's person token is revoked: the
	// upstream auth token obtained with it is revoked in the same cascade.
	fixture.setStockHold(true)
	second, err := fixture.ordersRelay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: hopInventory, PersonToken: link.person, UpstreamToken: caller.auth, Scopes: []string{"inventory.reserve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	begun, err := fixture.ordersRelay.BeginExchange(ctx, clientagent.ExchangeRequest{
		ResourceToken: second, PresentedToken: link.person, UpstreamToken: caller.auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	waiting, ok = begun.Pending()
	if !ok {
		t.Fatalf("second chained exchange = %#v", begun)
	}
	if _, err := fixture.people.RevokePersonToken(ctx, tokenClaims(t, caller.person)["jti"].(string)); err != nil {
		t.Fatal(err)
	}
	_, err = fixture.ordersRelay.PollExchange(ctx, waiting)
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Code != "revoked" ||
		!strings.Contains(problem.Detail, "upstream token") {
		t.Fatalf("poll after the upstream token was revoked = %v", err)
	}
	_, err = fixture.ordersRelay.PollExchange(ctx, waiting)
	if !errors.As(err, &problem) || problem.Status != http.StatusGone {
		t.Fatalf("poll after the revoked ending = %v", err)
	}
}

// Protocol 70d6737, AS Response, PS Response and Interaction Chaining: when
// the Access Server needs the person for a chained request, the Person Server
// answers the intermediary 202 with the Access Server's own interaction URL
// and code, for the intermediary to chain to its caller, and the wait
// completes once the person has finished there. An intermediary that did not
// declare the interaction capability cannot reach the person and is answered
// user_unreachable.
func TestChainedExchangeRelaysTheAccessServersInteraction(t *testing.T) {
	t.Parallel()
	fixture := newHopFixture(t, hopOptions{})
	ctx := fixture.ctx

	caller := fixture.callerLink("")
	link := fixture.chainedLink(fixture.ordersRelay, hopInventory, "inventory.reserve", caller.auth)
	fixture.setStockInteraction(true)
	exchange := clientagent.ExchangeRequest{
		ResourceToken: link.resourceToken, PresentedToken: link.person, UpstreamToken: caller.auth,
	}
	_, err := fixture.ordersRelay.BeginExchange(ctx, exchange)
	requireDeferredProblem(t, err, http.StatusForbidden, "user_unreachable")

	exchange.Capabilities = []string{"interaction"}
	begun, err := fixture.ordersRelay.BeginExchange(ctx, exchange)
	if err != nil {
		t.Fatal(err)
	}
	waiting, ok := begun.Pending()
	if !ok {
		t.Fatalf("chained exchange the Access Server asked about = %#v", begun)
	}
	fixture.mu.Lock()
	asked := fixture.accessRequests[len(fixture.accessRequests)-1]
	fixture.mu.Unlock()
	if waiting.Requirement() != aauth.RequirementInteraction || waiting.InteractionURL() != hopStockAS+"/consent" ||
		asked.InteractionCode == "" || waiting.InteractionCode() != asked.InteractionCode ||
		waiting.PersonServer() != hopPersonServer || asked.Upstream == nil {
		t.Fatalf("relayed %q %q %q for the Access Server's code %q", waiting.Requirement(), waiting.InteractionURL(), waiting.InteractionCode(), asked.InteractionCode)
	}

	// The person finishes at the Access Server's page; the host's next
	// advance collects the grant for the intermediary.
	fixture.setStockInteraction(false)
	fixture.advance(2 * time.Second)
	reference := waiting.Location()[strings.LastIndex(waiting.Location(), "/")+1:]
	if err := fixture.people.AdvanceFederation(ctx, reference); err != nil {
		t.Fatal(err)
	}
	delivered, err := fixture.ordersRelay.PollExchange(ctx, waiting)
	if err != nil {
		t.Fatal(err)
	}
	authToken, ok := delivered.Token()
	if !ok || hopExpiry(t, authToken) > hopExpiry(t, caller.auth) {
		t.Fatalf("delivered chained grant = %#v", delivered)
	}
	fixture.serve(fixture.ordersRelay, hopInventory, authToken, caller.auth, "served person-at-inventory-hop.example")
}

// Budgets (Person Server and Access Server issuance) with Protocol Call
// Chaining and PS-to-AS Token Request: a chained four-party request carries
// the Person Server's ceiling for the downstream Resource token's own offer
// to the Access Server beside the upstream token, and the downstream auth
// token carries the Access Server's grant. Nothing is drawn from, or added
// to, the upstream token.
func TestFourPartyChainedBudgetIsSizedForTheDownstreamToken(t *testing.T) {
	t.Parallel()
	fixture := newHopFixture(t, hopOptions{budget: true})
	ctx := fixture.ctx

	caller := fixture.callerLink("")
	result, err := fixture.ordersRelay.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: hopInventory, UpstreamToken: caller.auth})
	if err != nil {
		t.Fatal(err)
	}
	person, _ := result.Token()
	requested := hopBudgetValue(t, 500)
	resourceToken, err := fixture.ordersRelay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: hopInventory, PersonToken: person, UpstreamToken: caller.auth,
		Scopes: []string{"inventory.reserve"}, Budget: &requested,
	})
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := fixture.ordersRelay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken: resourceToken, PresentedToken: person, UpstreamToken: caller.auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	granted, _ := json.Marshal(tokenClaims(t, authToken)["budget"])
	if string(granted) != `{"amount":300,"decimals":0,"unit":"credits"}` {
		t.Fatalf("downstream auth token budget = %s", granted)
	}
	if _, upstreamBudget := tokenClaims(t, caller.auth)["budget"]; upstreamBudget {
		t.Fatal("the upstream token carries a budget")
	}
	fixture.mu.Lock()
	ceilings := append([]personserver.AuthorizationRequest(nil), fixture.ceilings...)
	asked := fixture.accessRequests[len(fixture.accessRequests)-1]
	fixture.mu.Unlock()
	if len(ceilings) != 1 || ceilings[0].Upstream == nil || ceilings[0].Budget == nil || ceilings[0].Budget.Amount() != 500 {
		t.Fatalf("Person Server ceiling requests = %#v", ceilings)
	}
	if asked.Upstream == nil || asked.Upstream.JTI != tokenClaims(t, caller.auth)["jti"] ||
		asked.Budget == nil || asked.Budget.Amount() != hopBudgetCeiling {
		t.Fatalf("Access Server request budget %v upstream %v", asked.Budget, asked.Upstream)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, hopInventory+"/work", nil)
	if err != nil {
		t.Fatal(err)
	}
	call, err := fixture.ordersRelay.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: request, AuthToken: authToken, UpstreamToken: caller.auth})
	if err != nil {
		t.Fatal(err)
	}
	response, ok := call.Response()
	if !ok {
		t.Fatalf("budgeted chained call = %#v", call)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if cost, _ := call.Cost(); string(body) != "served person-at-inventory-hop.example" || cost != hopBudgetCost {
		t.Fatalf("budgeted chained call = %q at cost %d", body, cost)
	}
}

// Budgets with Protocol Call Chaining, Upstream Token Verification: an auth
// token that carries a budget is an upstream token like any other. The
// intermediary's Agent client, the Person Server and the Access Server each
// verify it with its Budget claim, and the next hop is granted and served on
// its own token, which carries no budget from it.
func TestFourPartyBudgetedAuthTokenChainsAsAnUpstreamToken(t *testing.T) {
	t.Parallel()
	fixture := newHopFixture(t, hopOptions{budget: true})
	ctx := fixture.ctx

	caller := fixture.callerLink("")
	result, err := fixture.ordersRelay.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: hopInventory, UpstreamToken: caller.auth})
	if err != nil {
		t.Fatal(err)
	}
	person, _ := result.Token()
	requested := hopBudgetValue(t, 500)
	resourceToken, err := fixture.ordersRelay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: hopInventory, PersonToken: person, UpstreamToken: caller.auth,
		Scopes: []string{"inventory.reserve"}, Budget: &requested,
	})
	if err != nil {
		t.Fatal(err)
	}
	budgeted, err := fixture.ordersRelay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken: resourceToken, PresentedToken: person, UpstreamToken: caller.auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tokenClaims(t, budgeted)["budget"]; !ok {
		t.Fatal("the inventory auth token carries no budget")
	}

	fixture.advance(time.Minute)
	next := fixture.chainedHop(fixture.inventoryRelay, hopWarehouse, "warehouse.pick", budgeted)
	if _, ok := tokenClaims(t, next.auth)["budget"]; ok {
		t.Fatal("the warehouse auth token carries a budget")
	}
	if hopExpiry(t, next.person) > hopExpiry(t, budgeted) || hopExpiry(t, next.auth) > hopExpiry(t, budgeted) {
		t.Fatal("a warehouse token outlives its budgeted upstream token")
	}
	fixture.mu.Lock()
	asked := fixture.accessRequests[len(fixture.accessRequests)-1]
	fixture.mu.Unlock()
	if asked.Resource != hopWarehouse || asked.Upstream == nil || asked.Upstream.JTI != tokenClaims(t, budgeted)["jti"] {
		t.Fatalf("Access Server chained request = %s upstream %v", asked.Resource, asked.Upstream)
	}
}

// Protocol 70d6737, Person Token Endpoint ("Which person") and Call Chaining:
// an upstream token that carries mission_s256 has the chain evaluated against
// that mission of the calling Agent, and the downstream person and auth tokens
// carry it, so its termination reaches the chain. Mission Approval and
// Deferred Responses: a mission-bound request, chained or not, can wait for
// the Access Server, is delivered with its mission, and ends with
// mission_terminated when the mission does.
func TestCallChainCarriesTheCallingAgentsMission(t *testing.T) {
	t.Parallel()
	var missionExpiry time.Time
	var completed int
	fixture := newHopFixture(t, hopOptions{missions: &personserver.MissionConfig{
		Approve: func(_ context.Context, request personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
			return personserver.MissionDecision{
				Description: request.Proposal.Description, ApprovedResources: []string{hopOrders, hopInventory},
				ExpiresAt: &missionExpiry,
			}, nil
		},
		ConfirmPersonAcceptedCompletion: func(context.Context, personserver.MissionCompletionPolicyRequest) error {
			completed++
			return nil
		},
	}})
	ctx := fixture.ctx
	missionExpiry = fixture.now.Add(15 * time.Minute)

	result, err := fixture.caller.ProposeMission(ctx, clientagent.MissionRequest{
		PersonServer: hopPersonServer,
		Proposal:     aauth.MissionProposal{Description: "# Fulfil order 42", Resources: []string{hopOrders, hopInventory}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mission := result.Mission()
	personToken, ok := result.PersonToken(hopOrders)
	if !ok {
		t.Fatal("mission approval omitted the orders person token")
	}
	caller := fixture.callerLink(personToken)
	if tokenClaims(t, caller.auth)["mission_s256"] != mission.S256 {
		t.Fatal("the caller's auth token does not carry its mission")
	}

	chain := fixture.chainedHop(fixture.ordersRelay, hopInventory, "inventory.reserve", caller.auth)
	for label, compact := range map[string]string{"person token": chain.person, "auth token": chain.auth} {
		claims := tokenClaims(t, compact)
		if claims["mission_s256"] != mission.S256 || hopExpiry(t, compact) > missionExpiry.Unix() {
			t.Fatalf("chained %s = %v, mission %s until %v", label, claims, mission.S256, missionExpiry)
		}
	}
	for _, consent := range fixture.chainedConsents {
		if consent.Mission == nil || consent.Mission.S256 != mission.S256 || consent.Agent != "aauth:relay@orders-hop.example" {
			t.Fatalf("chained consent = %#v", consent)
		}
	}

	// The intermediary names no mission of its own.
	_, err = fixture.ordersRelay.PersonToken(ctx, clientagent.PersonTokenRequest{
		Resource: hopWarehouse, UpstreamToken: caller.auth, MissionS256: mission.S256,
	})
	if err == nil || !strings.Contains(err.Error(), "carries the mission") {
		t.Fatalf("intermediary mission_s256 = %v", err)
	}

	// The caller's own mission-bound request waits for the stock Access
	// Server and is delivered with the mission.
	fixture.setStockHold(true)
	inventoryPerson, ok := result.PersonToken(hopInventory)
	if !ok {
		t.Fatal("mission approval omitted the inventory person token")
	}
	inventoryResource, err := fixture.caller.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: hopInventory, PersonToken: inventoryPerson, Scopes: []string{"inventory.reserve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	begun, err := fixture.caller.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: hopPersonServer, ResourceToken: inventoryResource, PresentedToken: inventoryPerson,
	})
	if err != nil {
		t.Fatal(err)
	}
	waiting, ok := begun.Pending()
	if !ok {
		t.Fatalf("mission-bound exchange = %#v", begun)
	}
	fixture.setStockHold(false)
	fixture.advance(2 * time.Second)
	if err := fixture.people.AdvanceFederation(ctx, waiting.Location()[strings.LastIndex(waiting.Location(), "/")+1:]); err != nil {
		t.Fatal(err)
	}
	delivered, err := fixture.caller.PollExchange(ctx, waiting)
	if err != nil {
		t.Fatal(err)
	}
	if authToken, ok := delivered.Token(); !ok || tokenClaims(t, authToken)["mission_s256"] != mission.S256 ||
		hopExpiry(t, authToken) > missionExpiry.Unix() {
		t.Fatalf("delivered mission-bound grant = %#v", delivered)
	}

	// A chained mission-bound request waits too, and completing the mission
	// terminates it: the wait and the chain end with it.
	fixture.setStockHold(true)
	pending := fixture.chainedLink(fixture.ordersRelay, hopInventory, "inventory.reserve", caller.auth)
	begun, err = fixture.ordersRelay.BeginExchange(ctx, clientagent.ExchangeRequest{
		ResourceToken: pending.resourceToken, PresentedToken: pending.person, UpstreamToken: caller.auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	if waiting, ok = begun.Pending(); !ok {
		t.Fatalf("chained mission-bound exchange = %#v", begun)
	}
	if err := fixture.caller.CompleteMission(ctx, clientagent.MissionCompletionRequest{
		PersonServer: hopPersonServer, MissionS256: mission.S256, Summary: "Order 42 fulfilled",
	}); err != nil || completed != 1 {
		t.Fatalf("mission completion = %v, confirmations %d", err, completed)
	}
	var problem *aauth.ProblemError
	_, err = fixture.ordersRelay.PollExchange(ctx, waiting)
	if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Code != "mission_terminated" ||
		problem.TerminationReason != "completed" {
		t.Fatalf("chained wait after completion = %v", err)
	}
	if _, err = fixture.ordersRelay.PollExchange(ctx, waiting); !errors.As(err, &problem) || problem.Status != http.StatusGone {
		t.Fatalf("poll after the mission ended the wait = %v", err)
	}
	_, err = fixture.ordersRelay.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: hopInventory, UpstreamToken: caller.auth})
	if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Code != "mission_terminated" ||
		problem.TerminationReason != "completed" {
		t.Fatalf("chained person token after completion = %v", err)
	}
	_, err = fixture.ordersRelay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken: pending.resourceToken, PresentedToken: pending.person, UpstreamToken: caller.auth,
	})
	if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Code != "mission_terminated" {
		t.Fatalf("chained exchange after completion = %v", err)
	}
}
