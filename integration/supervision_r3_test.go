package integration_test

import (
	"context"
	"errors"
	"net/http"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
	"gitlab.com/sidecat-dev/aauth-go/supervisionserver"
)

const supervisedCatalogID = "https://catalog.example"

// supervisionR3Fixture is an MCP vocabulary with two operations, read and
// export, and the R3 configuration of a Resource that publishes both in one
// document.
type supervisionR3Fixture struct {
	registry  r3.Registry
	requested r3.OperationSet
	export    r3.Operation
	display   r3.Display
	resource  *resource.R3Config
}

func newSupervisionR3Fixture(t *testing.T) supervisionR3Fixture {
	t.Helper()
	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	if err != nil {
		t.Fatal(err)
	}
	readMCP, err := mcp.NewOperation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	exportMCP, err := mcp.NewOperation("records.export")
	if err != nil {
		t.Fatal(err)
	}
	requested, err := mcp.NewOperationSet(readMCP, exportMCP)
	if err != nil {
		t.Fatal(err)
	}
	export, err := exportMCP.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	display, err := r3.NewDisplay("Read and export records", "Exports may leave the system", "Record contents", "Exported copies cannot be recalled")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := mcp.ParseDefinition(supervisedCatalogID+"/mcp", mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(`{
		"tools":[
			{"name":"records.read","inputSchema":{"type":"object"}},
			{"name":"records.export","inputSchema":{"type":"object"}}
		]
	}`))))
	if err != nil {
		t.Fatal(err)
	}
	fixture := supervisionR3Fixture{registry: registry, requested: requested, export: export, display: display}
	fixture.resource = &resource.R3Config{
		Registry: registry, Definitions: definitions,
		Vocabularies: []resource.R3VocabularyConfig{{
			Definition: definition,
			DisplayForOperations: func(context.Context, r3.OperationSet, *string) (*r3.Display, error) {
				return &fixture.display, nil
			},
		}},
		Documents: newDirectR3DocumentStore(),
		HTTP: resource.R3HTTPAdapter{OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
			if request.URL.Path == "/records/export" {
				return export, true, nil
			}
			return r3.Operation{}, false, nil
		}},
	}
	return fixture
}

// admit lets a Person Server or an Access Server fetch the catalog's R3
// documents.
func (supervisionR3Fixture) admit(_ context.Context, endpoint string) error {
	if !strings.HasPrefix(endpoint, supervisedCatalogID+"/r3/") {
		return errors.New("unexpected R3 document endpoint")
	}
	return nil
}

// newR3Agent issues an Agent token and returns a client that reads the
// fixture's vocabulary.
func (world *supervisionWorld) newR3Agent(local string, fixture supervisionR3Fixture) (*clientagent.Client, string) {
	world.t.Helper()
	agentID := "aauth:" + local + "@agents.example"
	key := newSigningKey(world.t, "agent-r3-"+local)
	token, err := world.provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: supervisedPersonID, PublicKey: key.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	client, err := clientagent.New(world.ctx, clientagent.Config{
		Identifier: agentID, SigningKey: key, AgentToken: token, KeyResolver: world.resolver,
		HTTPClient: world.httpClient, Clock: world.clock, R3: &clientagent.R3Config{Registry: fixture.registry},
	})
	if err != nil {
		world.t.Fatal(err)
	}
	return client, agentID
}

// beginR3Exchange has the Agent obtain a person token and a resource token
// for both catalog operations, then make one auth-token request.
func (world *supervisionWorld) beginR3Exchange(agent *clientagent.Client, fixture supervisionR3Fixture) clientagent.ExchangeResult {
	world.t.Helper()
	personResult, err := agent.PersonToken(world.ctx, clientagent.PersonTokenRequest{PersonServer: supervisedPersonID, Resource: supervisedCatalogID})
	if err != nil {
		world.t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		world.t.Fatal("person token was not issued")
	}
	resourceToken, err := agent.Authorize(world.ctx, clientagent.AuthorizeRequest{
		Resource: supervisedCatalogID, PersonToken: personToken, R3Operations: &fixture.requested,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	result, err := agent.BeginExchange(world.ctx, clientagent.ExchangeRequest{
		PersonServer: supervisedPersonID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	return result
}

// TestSupervisorDecidesAnR3Authorization puts a three-party R3 auth-token
// request to the supervised Agent's supervisor in place of the Person
// Server's own R3 policy. The supervisor's allow grants the document as the
// Resource described it, within the exp it set. When the supervisor asks, the
// host shows the person the document's display, which the supervisor cannot
// fetch, and the person's allow issues the token.
func TestSupervisorDecidesAnR3Authorization(t *testing.T) {
	t.Parallel()
	world := newSupervisionWorld(t, supervisionWorldOptions{})
	ctx := world.ctx
	fixture := newSupervisionR3Fixture(t)
	catalog, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: supervisedCatalogID, SigningKey: newSigningKey(t, "supervision-r3-resource"), KeyResolver: world.resolver,
		Clock: world.clock, NewID: world.id,
		ResolvePerson: func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		R3:            fixture.resource,
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	world.network.Handle(supervisedCatalogID, catalog.Handler())
	config := world.personConfig
	config.R3 = &personserver.DirectR3Config{
		Registry: fixture.registry, HTTPClient: world.httpClient, Admit: fixture.admit,
		AuthorizeDocument: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, _ r3.Document) (personserver.DirectR3Decision, error) {
			world.hostDecided("R3.AuthorizeDocument", request.Agent)
			return personserver.DirectR3Decision{}, errors.New("not expected")
		},
		Issuances: &integrationR3IssuanceStore{},
	}
	world.people, err = personserver.NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	world.network.Handle(supervisedPersonID, world.people.Handler())

	bound := world.clock.Now().Add(20 * time.Minute).Unix()
	var askMu sync.Mutex
	ask := false
	home := world.addSupervisor(homeSupervisorID, true, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		askMu.Lock()
		defer askMu.Unlock()
		switch {
		case request.Request.Kind != supervision.KindAuthToken:
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
		case ask:
			return decided(supervision.Decision{Verdict: supervision.VerdictAsk, Summary: "The agent wants to export records."})
		default:
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow, ExpiresAt: bound})
		}
	})
	assistant, agentID := world.newR3Agent("assistant", fixture)
	route := personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"}
	world.route(agentID, route)
	verify := func(result clientagent.ExchangeResult) (string, aauth.AuthTokenClaims) {
		t.Helper()
		token, ok := result.Token()
		if !ok {
			t.Fatal("the exchange did not end with an auth token")
		}
		claims, _, granted, err := r3.VerifyDirectAuthToken(ctx, fixture.registry, token, world.resolver, world.clock)
		if err != nil {
			t.Fatal(err)
		}
		if within, err := granted.IsSubsetOf(fixture.requested); err != nil || !within || len(granted.Operations()) != 2 || claims.Issuer != supervisedPersonID {
			t.Fatalf("R3 grant %v from %s, want both requested operations from the Person Server", granted.Operations(), claims.Issuer)
		}
		return token, claims
	}

	token, allowed := verify(world.beginR3Exchange(assistant, fixture))
	if allowed.ExpiresAt > bound {
		t.Fatalf("auth token exp %d is past the supervisor's %d", allowed.ExpiresAt, bound)
	}
	call, _ := http.NewRequestWithContext(ctx, http.MethodGet, supervisedCatalogID+"/records/export", nil)
	response, err := assistant.Do(ctx, clientagent.Call{Request: call, AuthToken: token})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("export with the supervised grant = %d", response.StatusCode)
	}

	askMu.Lock()
	ask = true
	askMu.Unlock()
	pending, ok := world.beginR3Exchange(assistant, fixture).Pending()
	if !ok {
		t.Fatal("the supervisor's ask did not leave the R3 request pending")
	}
	reference := path.Base(pending.Location())
	artifact, err := world.people.SupervisedR3Artifact(ctx, reference)
	if err != nil {
		t.Fatal(err)
	}
	document, ok := artifact.Document()
	shown, shownOK := document.Display()
	if !ok || !shownOK || shown.Summary() != fixture.display.Summary() {
		t.Fatalf("the host was given %#v, want the document's display", artifact)
	}
	if err := world.people.ResolveSupervision(ctx, reference, personserver.SupervisionAnswer{Answer: supervision.AnswerAllow}); err != nil {
		t.Fatal(err)
	}
	world.advance(5 * time.Second)
	polled, err := assistant.PollExchange(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	_, personAllowed := verify(polled)

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
	if len(authSDIs) != 2 || len(issued) != 2 ||
		issued[0].SDI != authSDIs[0] || issued[0].JTI != allowed.JTI || issued[0].Issuer != supervisedPersonID ||
		issued[1].SDI != authSDIs[1] || issued[1].JTI != personAllowed.JTI {
		t.Fatalf("auth_token.issued = %#v for decisions %v, want each R3 token under its decision", issued, authSDIs)
	}
}
