package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
	"gitlab.com/sidecat-dev/aauth-go/supervisionserver"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

const supervisedAccessServerID = "https://access.example"

// fourPartySupervisionWorld is a supervisionWorld whose Person Server
// federates with an Access Server that can defer its decision, for the
// records Resource and an R3 catalog. Consent and R3 consent fail the test
// when they decide for a supervised Agent.
type fourPartySupervisionWorld struct {
	*supervisionWorld
	r3        supervisionR3Fixture
	accessKey jose.SigningKey
	access    http.Handler
	accessMu  sync.Mutex
	decide    func(accessserver.AuthorizationRequest) accessserver.Decision
	evaluated []accessserver.AuthorizationRequest
	// widen, when set, has the Access Server's tokens re-issued with every
	// scope the resource token requested, as an Access Server that ignores
	// the Person Server's narrowing would issue them.
	widen bool
}

func newFourPartySupervisionWorld(t *testing.T) *fourPartySupervisionWorld {
	t.Helper()
	world := &supervisionWorld{
		t: t, ctx: context.Background(), now: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC),
		network: newLogicalTransport(), store: testutil.NewSupervisionStore(),
		tokens: testutil.NewMissionStore(), routes: map[string]personserver.Supervisor{},
		supervisors: map[string]*supervisorHost{}, agentTokens: map[string]string{},
	}
	world.clock = aauth.ClockFunc(func() time.Time {
		world.mu.Lock()
		defer world.mu.Unlock()
		return world.now
	})
	world.httpClient = &http.Client{Transport: world.network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: world.httpClient, TransportEnforcesEgress: true, Clock: world.clock, Admit: admitExampleOrigins,
	})
	if err != nil {
		t.Fatal(err)
	}
	world.resolver = resolver
	world.provider, err = agentprovider.New(agentprovider.Config{
		Issuer: supervisedProviderID, SigningKey: newSigningKey(t, "four-party-ap"), Clock: world.clock, NewID: world.id,
	})
	if err != nil {
		t.Fatal(err)
	}
	four := &fourPartySupervisionWorld{
		supervisionWorld: world, r3: newSupervisionR3Fixture(t), accessKey: newSigningKey(t, "four-party-as"),
		decide: func(request accessserver.AuthorizationRequest) accessserver.Decision {
			return accessserver.Decision{Scopes: append([]string(nil), request.Scopes...), Lifetime: 30 * time.Minute}
		},
	}
	access, err := accessserver.New(accessserver.Config{
		Issuer: supervisedAccessServerID, SigningKey: four.accessKey, KeyResolver: resolver,
		Clock: world.clock, NewID: world.id,
		TrustPersonServer: func(context.Context, string) error { return nil },
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			four.accessMu.Lock()
			four.evaluated = append(four.evaluated, request)
			decide := four.decide
			four.accessMu.Unlock()
			return decide(request), nil
		},
		Deferred: &accessserver.DeferredConfig{Store: testutil.NewAccessAuthorizationStore(), Lifetime: 10 * time.Minute},
		R3: &accessserver.R3Config{
			Registry: four.r3.registry, HTTPClient: world.httpClient, Admit: four.r3.admit,
			AuthorizeDocument: func(_ context.Context, request accessserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (accessserver.R3DocumentDecision, error) {
				four.accessMu.Lock()
				four.evaluated = append(four.evaluated, request)
				four.accessMu.Unlock()
				return grantR3Document(four.r3, request, document)
			},
			Issuances: &integrationR3IssuanceStore{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: supervisedCatalogID, AccessServer: supervisedAccessServerID, SigningKey: newSigningKey(t, "four-party-catalog"),
		KeyResolver: resolver, Clock: world.clock, NewID: world.id,
		ResolvePerson: func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		R3:            four.r3.resource,
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	records, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: supervisedResourceID, AccessServer: supervisedAccessServerID, SigningKey: newSigningKey(t, "four-party-resource"),
		KeyResolver: resolver, Clock: world.clock, NewID: world.id,
		ScopeDescriptions: map[string]string{"records.read": "Read records", "records.write": "Change records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read", "records.write"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(response, "records")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	world.people, err = personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: supervisedPersonID, SigningKey: newSigningKey(t, "four-party-ps"), KeyResolver: resolver,
		Clock: world.clock, NewID: world.id, HTTPClient: world.httpClient, Tokens: world.tokens,
		AccessServerEndpoint: func(context.Context, string) (string, error) { return supervisedAccessServerID + "/token", nil },
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-at-records", Lifetime: time.Hour}, nil
		},
		Consent: func(_ context.Context, request personserver.AuthorizationRequest) error {
			world.hostDecided("Consent", request.Agent)
			return nil
		},
		Deferred: &personserver.FederatedDeferredConfig{Store: testutil.NewFederatedAuthorizationStore(), Lifetime: 10 * time.Minute},
		R3: &personserver.R3Config{
			Registry: four.r3.registry, Admit: four.r3.admit,
			ConsentDocument: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, _ r3.Document) error {
				world.hostDecided("R3.ConsentDocument", request.Agent)
				return nil
			},
		},
		Supervision: &personserver.SupervisionConfig{
			Route: func(_ context.Context, agent personserver.SupervisedAgent) (personserver.Supervisor, bool, error) {
				world.mu.Lock()
				defer world.mu.Unlock()
				supervisor, ok := world.routes[agent.Agent]
				return supervisor, ok, nil
			},
			Store: world.store, HTTPClient: world.httpClient, Admit: admitExampleOrigins,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	four.access = access.Handler()
	world.network.Handle(supervisedProviderID, world.provider.Handler())
	world.network.Handle(supervisedPersonID, world.people.Handler())
	world.network.Handle(supervisedResourceID, records.Handler())
	world.network.Handle(supervisedCatalogID, catalog.Handler())
	world.network.Handle(supervisedAccessServerID, http.HandlerFunc(four.serveAccess))
	return four
}

// grantR3Document is the Access Server's R3 policy: every operation of the
// document, outright, for half an hour.
func grantR3Document(fixture supervisionR3Fixture, request accessserver.AuthorizationRequest, document r3.Document) (accessserver.R3DocumentDecision, error) {
	operations := document.OperationSet()
	vocabulary, _ := fixture.registry.Vocabulary(operations.Vocabulary())
	granted, err := r3.NewGrantedOperations(vocabulary, operations.Operations()...)
	if err != nil {
		return accessserver.R3DocumentDecision{}, err
	}
	perCall, err := r3.NewGrantedOperations(vocabulary)
	if err != nil {
		return accessserver.R3DocumentDecision{}, err
	}
	authorization, err := r3.NewAuthorization(granted, perCall, document)
	if err != nil {
		return accessserver.R3DocumentDecision{}, err
	}
	return accessserver.R3DocumentDecision{
		Scopes: append([]string(nil), request.Scopes...), Lifetime: 30 * time.Minute, Authorization: &authorization,
	}, nil
}

// serveAccess serves the Access Server, re-issuing its tokens wider when
// widen is set.
func (four *fourPartySupervisionWorld) serveAccess(response http.ResponseWriter, request *http.Request) {
	four.accessMu.Lock()
	widen := four.widen
	four.accessMu.Unlock()
	if !widen {
		four.access.ServeHTTP(response, request)
		return
	}
	recorder := httptest.NewRecorder()
	four.access.ServeHTTP(recorder, request)
	body := recorder.Body.Bytes()
	if recorder.Code == http.StatusOK {
		var issued struct {
			AuthToken string `json:"auth_token"`
			ExpiresIn int64  `json:"expires_in"`
		}
		if json.Unmarshal(body, &issued) == nil && issued.AuthToken != "" {
			claims, err := aauth.VerifyAuthToken(four.ctx, issued.AuthToken, signaturekey.StaticKeyResolver{
				signaturekey.StaticKeyReference{Issuer: supervisedAccessServerID, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: four.accessKey.PublicJWK().Kid}: four.accessKey.PublicJWK(),
			}, four.clock)
			if err != nil {
				four.t.Error(err)
				return
			}
			claims.Scope = "records.read records.write"
			if issued.AuthToken, err = aauth.MintAuthToken(four.accessKey, claims); err != nil {
				four.t.Error(err)
				return
			}
			body, _ = json.Marshal(issued)
		}
	}
	for name, values := range recorder.Header() {
		response.Header()[name] = values
	}
	response.Header().Set("Content-Length", strconv.Itoa(len(body)))
	response.WriteHeader(recorder.Code)
	_, _ = io.Copy(response, bytes.NewReader(body))
}

func (four *fourPartySupervisionWorld) setDecide(decide func(accessserver.AuthorizationRequest) accessserver.Decision) {
	four.accessMu.Lock()
	defer four.accessMu.Unlock()
	four.decide = decide
}

func (four *fourPartySupervisionWorld) setWiden(widen bool) {
	four.accessMu.Lock()
	defer four.accessMu.Unlock()
	four.widen = widen
}

// lastEvaluated returns the request the Access Server's policy saw last.
func (four *fourPartySupervisionWorld) lastEvaluated() accessserver.AuthorizationRequest {
	four.accessMu.Lock()
	defer four.accessMu.Unlock()
	if len(four.evaluated) == 0 {
		four.t.Fatal("the Access Server evaluated no request")
	}
	return four.evaluated[len(four.evaluated)-1]
}

// beginExchange has the Agent obtain a person token and a resource token for
// both scopes, then make one auth-token request of its Person Server.
func (four *fourPartySupervisionWorld) beginExchange(agent *clientagent.Client) clientagent.ExchangeResult {
	four.t.Helper()
	ctx := four.ctx
	personResult, err := agent.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: supervisedPersonID, Resource: supervisedResourceID})
	if err != nil {
		four.t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		four.t.Fatal("person token was not issued")
	}
	resourceToken, err := agent.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: supervisedResourceID, PersonToken: personToken, Scopes: []string{"records.read", "records.write"},
	})
	if err != nil {
		four.t.Fatal(err)
	}
	result, err := agent.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: supervisedPersonID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		four.t.Fatal(err)
	}
	return result
}

func (four *fourPartySupervisionWorld) verifyAuthToken(result clientagent.ExchangeResult) aauth.AuthTokenClaims {
	four.t.Helper()
	token, ok := result.Token()
	if !ok {
		four.t.Fatal("the exchange did not end with an auth token")
	}
	claims, err := aauth.VerifyAuthToken(four.ctx, token, four.resolver, four.clock)
	if err != nil || claims.Issuer != supervisedAccessServerID {
		four.t.Fatalf("auth token %#v, %v; want one from the Access Server", claims, err)
	}
	return claims
}

func requireProblemStatus(t *testing.T, err error, status int) {
	t.Helper()
	if problem := (*aauth.ProblemError)(nil); err == nil || !errors.As(err, &problem) || problem.Status != status {
		t.Fatalf("error = %v, want status %d", err, status)
	}
}

// TestFourPartySupervisorDecidesAndThePersonServerEnforcesIt puts a
// four-party auth-token request to a supervisor in place of Consent. The
// Access Server issues the token, which the supervisor is told came from it.
// A narrowing allow reaches the Access Server, which issues within it; a
// token broader than the supervisor allowed, from an Access Server that
// ignores the narrowing, is refused.
func TestFourPartySupervisorDecidesAndThePersonServerEnforcesIt(t *testing.T) {
	t.Parallel()
	world := newFourPartySupervisionWorld(t)
	var narrowMu sync.Mutex
	narrowTo := supervision.Decision{}
	home := world.addSupervisor(homeSupervisorID, true, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		narrowMu.Lock()
		defer narrowMu.Unlock()
		if request.Request.Kind == supervision.KindAuthToken {
			allow := narrowTo
			allow.Verdict = supervision.VerdictAllow
			return decided(allow)
		}
		return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
	})
	assistant, assistantID := world.newAgent("assistant")
	route := personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"}
	world.route(assistantID, route)

	whole := world.verifyAuthToken(world.beginExchange(assistant))
	if whole.Scope != "records.read records.write" || !slices.Equal(world.lastEvaluated().Scopes, []string{"records.read", "records.write"}) {
		t.Fatalf("an allow that narrows nothing issued %q", whole.Scope)
	}

	bound := world.clock.Now().Add(10 * time.Minute).Unix()
	narrowMu.Lock()
	narrowTo = supervision.Decision{Scope: "records.read", ExpiresAt: bound}
	narrowMu.Unlock()
	narrowed := world.verifyAuthToken(world.beginExchange(assistant))
	if narrowed.Scope != "records.read" || narrowed.ExpiresAt > bound {
		t.Fatalf("narrowed token scope %q exp %d, want records.read by %d", narrowed.Scope, narrowed.ExpiresAt, bound)
	}
	if evaluated := world.lastEvaluated(); !slices.Equal(evaluated.Scopes, []string{"records.read"}) {
		t.Fatalf("the Access Server evaluated scopes %v, want the supervisor's narrowing", evaluated.Scopes)
	}

	world.setWiden(true)
	personResult, err := assistant.PersonToken(world.ctx, clientagent.PersonTokenRequest{PersonServer: supervisedPersonID, Resource: supervisedResourceID})
	if err != nil {
		t.Fatal(err)
	}
	personToken, _ := personResult.Token()
	resourceToken, err := assistant.Authorize(world.ctx, clientagent.AuthorizeRequest{
		Resource: supervisedResourceID, PersonToken: personToken, Scopes: []string{"records.read", "records.write"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = assistant.Exchange(world.ctx, clientagent.ExchangeRequest{
		PersonServer: supervisedPersonID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	requireProblemStatus(t, err, http.StatusForbidden)

	if _, err := world.people.DeliverSupervisionEvents(world.ctx, route); err != nil {
		t.Fatal(err)
	}
	issued := home.events(supervision.EventAuthTokenIssued)
	if len(issued) != 2 || issued[0].JTI != whole.JTI || issued[1].JTI != narrowed.JTI ||
		issued[1].Issuer != supervisedAccessServerID || issued[1].Scope != "records.read" {
		t.Fatalf("auth_token.issued = %#v, want the two tokens the Access Server issued and the Agent received", issued)
	}
}

// TestFourPartySupervisedRequestWaitsForTheAccessServer has an Access Server
// defer two supervised requests. One the supervisor allowed at once, narrowed:
// the Access Server's later grant is checked against the narrowing and
// reported under the supervisor's decision. The other the person allowed after
// the supervisor asked: it then waits for the Access Server at the pending URL
// the Agent already polls, and the grant is reported under the same decision.
func TestFourPartySupervisedRequestWaitsForTheAccessServer(t *testing.T) {
	t.Parallel()
	world := newFourPartySupervisionWorld(t)
	var askMu sync.Mutex
	ask := false
	home := world.addSupervisor(homeSupervisorID, true, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		askMu.Lock()
		defer askMu.Unlock()
		switch {
		case request.Request.Kind != supervision.KindAuthToken:
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
		case ask:
			return decided(supervision.Decision{Verdict: supervision.VerdictAsk, Summary: "The agent wants to change records."})
		default:
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow, Scope: "records.read"})
		}
	})
	assistant, assistantID := world.newAgent("assistant")
	route := personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"}
	world.route(assistantID, route)
	ctx := world.ctx
	// The Access Server defers every first evaluation of a request and
	// grants what was asked once it is polled.
	var deferMu sync.Mutex
	deferred := map[string]bool{}
	world.setDecide(func(request accessserver.AuthorizationRequest) accessserver.Decision {
		deferMu.Lock()
		defer deferMu.Unlock()
		if !deferred[request.InteractionCode] {
			deferred[request.InteractionCode] = true
			return accessserver.Decision{Pending: &accessserver.PendingDecision{}}
		}
		return accessserver.Decision{Scopes: append([]string(nil), request.Scopes...), Lifetime: 30 * time.Minute}
	})
	advance := func(pending clientagent.PendingExchange) clientagent.ExchangeResult {
		t.Helper()
		if err := world.people.AdvanceFederation(ctx, path.Base(pending.Location())); err != nil {
			t.Fatal(err)
		}
		world.advance(time.Second)
		result, err := assistant.PollExchange(ctx, pending)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}

	first, ok := world.beginExchange(assistant).Pending()
	if !ok {
		t.Fatal("the Access Server's deferral did not leave the request pending")
	}
	narrowed := world.verifyAuthToken(advance(first))
	if narrowed.Scope != "records.read" {
		t.Fatalf("deferred grant scope %q, want the supervisor's narrowing", narrowed.Scope)
	}

	// An Access Server that ignores the narrowing has its deferred grant
	// refused.
	world.setWiden(true)
	wide, ok := world.beginExchange(assistant).Pending()
	if !ok {
		t.Fatal("the second request was not deferred")
	}
	if err := world.people.AdvanceFederation(ctx, path.Base(wide.Location())); err != nil {
		t.Fatal(err)
	}
	_, err := assistant.PollExchange(ctx, wide)
	requireProblemStatus(t, err, http.StatusForbidden)
	world.setWiden(false)

	askMu.Lock()
	ask = true
	askMu.Unlock()
	held, ok := world.beginExchange(assistant).Pending()
	if !ok {
		t.Fatal("the supervisor's ask did not leave the request pending")
	}
	reference := path.Base(held.Location())
	if err := world.people.ResolveSupervision(ctx, reference, personserver.SupervisionAnswer{Answer: supervision.AnswerAllow}); err != nil {
		t.Fatal(err)
	}
	review, err := world.people.ReviewSupervision(ctx, reference)
	if err != nil || review.State != personserver.SupervisedWithAccessServer {
		t.Fatalf("review = %#v, %v; want the request waiting for the Access Server", review, err)
	}
	waiting, err := world.people.PendingFederatedAuthorizationReferences(ctx, 10)
	if err != nil || !slices.Contains(waiting, reference) {
		t.Fatalf("pending federations %v, %v; want the request under its own reference", waiting, err)
	}
	world.advance(5 * time.Second)
	still, err := assistant.PollExchange(ctx, held)
	if err != nil {
		t.Fatal(err)
	}
	again, ok := still.Pending()
	if !ok || again.Location() != held.Location() {
		t.Fatalf("poll while the Access Server decides = %#v, want pending at the same URL", still)
	}
	granted := world.verifyAuthToken(advance(again))
	if granted.Scope != "records.read records.write" {
		t.Fatalf("the person's allow issued %q", granted.Scope)
	}
	world.advance(time.Second)
	_, err = assistant.PollExchange(ctx, again)
	requireProblemStatus(t, err, http.StatusGone)

	if _, err := world.people.DeliverSupervisionEvents(ctx, route); err != nil {
		t.Fatal(err)
	}
	var authSDIs []string
	for _, request := range home.asked() {
		if request.Request.Kind == supervision.KindAuthToken {
			authSDIs = append(authSDIs, request.Request.SDI)
		}
	}
	issued := home.events(supervision.EventAuthTokenIssued)
	if len(authSDIs) != 3 || len(issued) != 2 ||
		issued[0].SDI != authSDIs[0] || issued[0].JTI != narrowed.JTI || issued[0].Issuer != supervisedAccessServerID ||
		issued[1].SDI != authSDIs[2] || issued[1].JTI != granted.JTI {
		t.Fatalf("auth_token.issued = %#v for decisions %v, want each delivered grant once under its decision", issued, authSDIs)
	}
	resolved := home.events(supervision.EventDecisionResolved)
	if len(resolved) != 1 || resolved[0].SDI != authSDIs[2] || resolved[0].Answer != supervision.AnswerAllow {
		t.Fatalf("decision.resolved = %#v", resolved)
	}
}

// TestFourPartySupervisorDecidesAnR3Authorization puts a four-party R3
// auth-token request to the supervisor in place of the Person Server's R3
// consent. The supervisor's exp reaches the Access Server, which issues the
// R3 grant within it, and the supervisor is told the Access Server issued it.
func TestFourPartySupervisorDecidesAnR3Authorization(t *testing.T) {
	t.Parallel()
	world := newFourPartySupervisionWorld(t)
	bound := world.clock.Now().Add(15 * time.Minute).Unix()
	home := world.addSupervisor(homeSupervisorID, true, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		if request.Request.Kind == supervision.KindAuthToken {
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow, ExpiresAt: bound})
		}
		return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
	})
	assistant, assistantID := world.newR3Agent("assistant", world.r3)
	route := personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"}
	world.route(assistantID, route)

	token, ok := world.beginR3Exchange(assistant, world.r3).Token()
	if !ok {
		t.Fatal("the supervised R3 request did not end with an auth token")
	}
	claims, _, operations, err := r3.VerifyAuthTokenClaims(world.ctx, world.r3.registry, token, world.resolver, world.clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != supervisedAccessServerID || claims.ExpiresAt > bound || len(operations.GrantedOperations().Operations()) != 2 {
		t.Fatalf("R3 auth token from %s exp %d grants %v, want the Access Server's grant by %d", claims.Issuer, claims.ExpiresAt, operations.GrantedOperations().Operations(), bound)
	}
	call, _ := http.NewRequestWithContext(world.ctx, http.MethodGet, supervisedCatalogID+"/records/export", nil)
	response, err := assistant.Do(world.ctx, clientagent.Call{Request: call, AuthToken: token})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("export with the supervised grant = %d", response.StatusCode)
	}
	if _, err := world.people.DeliverSupervisionEvents(world.ctx, route); err != nil {
		t.Fatal(err)
	}
	if issued := home.events(supervision.EventAuthTokenIssued); len(issued) != 1 || issued[0].JTI != claims.JTI ||
		issued[0].Issuer != supervisedAccessServerID || issued[0].Scope != "" {
		t.Fatalf("auth_token.issued = %#v, want the Access Server's R3 token", issued)
	}
}
