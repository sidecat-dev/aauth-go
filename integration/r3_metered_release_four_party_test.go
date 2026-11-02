package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

// TestR3MeteredReleaseFourPartyJourney meters the release of a held R3
// result through both servers (R3 Approving Release Rather Than Execution;
// Budgets PS-to-AS Token Request and Deferred Delivery). The Resource runs a
// budget:true operation first and offers the release cost on the proposal's
// Resource token. The Person Server sends its ceiling for that offer to the
// Access Server, which grants it on the per-call Auth token, and the Agent's
// poll with that token releases the result and draws the cost down once.
func TestR3MeteredReleaseFourPartyJourney(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 10, 31, 15, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:analyst@ap.example"
		personServerID  = "https://ps.example"
		accessServerID  = "https://as.example"
		resourceID      = "https://resource.example"
		scope           = "reports.read"
	)
	providerKey := newSigningKey(t, "metered-release-ap")
	agentKey := newSigningKey(t, "metered-release-agent")
	personKey := newSigningKey(t, "metered-release-ps")
	accessKey := newSigningKey(t, "metered-release-as")
	resourceKey := newSigningKey(t, "metered-release-resource")
	keys := signaturekey.StaticKeyResolver{
		{Issuer: agentProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
		{Issuer: personServerID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:   personKey.PublicJWK(),
		{Issuer: accessServerID, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:   accessKey.PublicJWK(),
		{Issuer: resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}:   resourceKey.PublicJWK(),
	}
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	admitR3 := func(_ context.Context, endpoint string) error {
		if !strings.HasPrefix(endpoint, resourceID+"/r3/") {
			return errors.New("unexpected R3 endpoint")
		}
		return nil
	}
	registry := newIntegrationR3Registry(t)
	unit, err := budgets.NewUnit("credits", 0)
	if err != nil {
		t.Fatal(err)
	}
	cost := integrationBudgetValue(t, 40, unit)
	declaration, err := budgets.NewBoundedUnitDeclaration(unit, 1000, "Report credits")
	if err != nil {
		t.Fatal(err)
	}
	units := func(context.Context, string) ([]budgets.UnitDeclaration, error) {
		return []budgets.UnitDeclaration{declaration}, nil
	}
	export, err := mcp.NewOperation("reports.export")
	if err != nil {
		t.Fatal(err)
	}
	exportOperation, err := export.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	classOperations, err := r3.NewOperationSet(exportOperation)
	if err != nil {
		t.Fatal(err)
	}
	noOperations, err := r3.NewGrantedOperations(mcp.Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	perCallOperations, err := r3.NewGrantedOperations(mcp.Vocabulary(), exportOperation)
	if err != nil {
		t.Fatal(err)
	}

	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "metered-release-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(ctx, aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	runs := 0
	ledger := testutil.NewBudgetStore()
	definition, err := mcp.ParseDefinition(resourceID+"/mcp", mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(
		`{"tools":[{"name":"reports.export","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}}]}`,
	))))
	if err != nil {
		t.Fatal(err)
	}
	ids := newSequence()
	protected, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: resourceID, AccessServer: accessServerID, SigningKey: resourceKey, KeyResolver: keys,
		Clock: clock, NewID: ids.source("metered-release-resource-token"),
		ScopeDescriptions: map[string]string{scope: "Read reports"},
		RequiredScopes:    func(*http.Request) []string { return []string{scope} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			runs++
			_, _ = io.WriteString(response, "quarterly report")
		}),
		R3: &resource.R3Config{
			Registry: registry, Definitions: newIntegrationR3DefinitionRegistry(t),
			Vocabularies: []resource.R3VocabularyConfig{{Definition: definition}},
			Documents:    newIntegrationR3DocumentStore(),
			HTTP: resource.R3HTTPAdapter{
				OperationForRequest: func(*http.Request) (r3.Operation, bool, error) { return exportOperation, true, nil },
				PresentParameters: func(*http.Request, r3.Operation) (map[string]r3.PresentedParameter, error) {
					return nil, nil
				},
			},
			PerCall: &resource.R3PerCallConfig{
				DescribeCall: func(context.Context, r3.Invocation, *string) (resource.R3CallDescription, error) {
					return resource.R3CallDescription{}, errors.New("a metered release is never proposed for execution")
				},
				Proposals: newR3PerCallProposalStore(registry), Retries: newR3PerCallRetryStore(),
				Release: &resource.R3ReleaseConfig{
					Eligible:     func(context.Context, r3.Invocation) (bool, error) { return true, nil },
					MeterRelease: true,
					DescribeResult: func(context.Context, resource.R3ReleaseRequest) (resource.R3ReleaseDescription, error) {
						display, err := r3.NewDisplay("Release the quarterly report", "", "One report", "")
						if err != nil {
							return resource.R3ReleaseDescription{}, err
						}
						none, err := r3.NewParameters(nil)
						if err != nil {
							return resource.R3ReleaseDescription{}, err
						}
						return resource.R3ReleaseDescription{
							Parameters: none, Result: json.RawMessage(`{"reports":1}`), Display: display, Cost: &cost,
						}, nil
					},
				},
			},
		},
		Budget: &resource.BudgetConfig{
			Units:         []budgets.UnitDeclaration{declaration},
			Metered:       func(*http.Request) bool { return false },
			RetainLineage: func(context.Context, resource.BudgetLineage) error { return nil },
			Cost:          func(context.Context, resource.BudgetCostRequest) (int64, error) { return 0, nil },
			Store:         ledger,
			Challenge: func(context.Context, resource.BudgetChallengeRequest) (string, error) {
				return "", errors.New("no Budget step-up in this journey")
			},
		},
		HeldInvocations:              newR3PerCallHeldStore(),
		HoldAuthTokenRequest:         func(*http.Request) bool { return true },
		MaxRetainedRequestBodyBytes:  64 << 10,
		MaxRetainedResponseBodyBytes: 64 << 10,
		MaxRetainedHeaderBytes:       16 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	var asked []accessserver.AuthorizationRequest
	access, err := accessserver.New(accessserver.Config{
		Issuer: accessServerID, SigningKey: accessKey, KeyResolver: keys, Clock: clock,
		NewID:             ids.source("metered-release-auth-token"),
		TrustPersonServer: func(context.Context, string) error { return nil },
		Authorize: func(context.Context, accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Decision{}, errors.New("Core policy must not receive an R3 request")
		},
		Budget: &accessserver.BudgetConfig{ResolveResourceUnits: units},
		R3: &accessserver.R3Config{
			Registry: registry, HTTPClient: httpClient, Admit: admitR3,
			AuthorizeDocument: func(_ context.Context, request accessserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (accessserver.R3DocumentDecision, error) {
				authorization, err := r3.NewAuthorization(noOperations, perCallOperations, document)
				if err != nil {
					return accessserver.R3DocumentDecision{}, err
				}
				return accessserver.R3DocumentDecision{Scopes: request.Scopes, Lifetime: 30 * time.Minute, Authorization: &authorization}, nil
			},
			AuthorizeProposal: func(_ context.Context, request accessserver.AuthorizationRequest, _ r3.Reference, _ r3.Proposal) (accessserver.R3ProposalDecision, error) {
				asked = append(asked, request)
				return accessserver.R3ProposalDecision{Scopes: request.Scopes, Lifetime: 5 * time.Minute, Budget: request.Budget}, nil
			},
			Issuances: newR3PerCallIssuanceStore(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var ceilings []personserver.AuthorizationRequest
	people, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: keys, Clock: clock,
		NewID: ids.source("metered-release-person-token"), HTTPClient: httpClient, Tokens: newMemoryPersonTokenStore(),
		AccessServerEndpoint: func(context.Context, string) (string, error) { return accessServerID + "/token", nil },
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-1", Lifetime: time.Hour}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error {
			return errors.New("Core consent must not receive an R3 request")
		},
		Budget: &personserver.FederatedBudgetConfig{
			ResolveResourceUnits: units,
			// The person allows the release at its stated cost.
			Ceiling: func(_ context.Context, request personserver.AuthorizationRequest) (*budgets.Value, error) {
				ceilings = append(ceilings, request)
				return request.Budget, nil
			},
		},
		R3: &personserver.R3Config{
			Registry: registry, Admit: admitR3,
			ConsentDocument: func(context.Context, personserver.AuthorizationRequest, r3.Reference, r3.Document) error { return nil },
			ConsentProposal: func(context.Context, personserver.AuthorizationRequest, r3.Reference, r3.Proposal) error { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(personServerID, people.Handler())
	network.Handle(accessServerID, access.Handler())
	network.Handle(resourceID, protected.Handler())

	agent, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: keys, HTTPClient: httpClient, Clock: clock,
		R3: &clientagent.R3Config{Registry: registry},
	})
	if err != nil {
		t.Fatal(err)
	}
	personResult, err := agent.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: personServerID, Resource: resourceID})
	if err != nil {
		t.Fatal(err)
	}
	personToken, _ := personResult.Token()
	classResourceToken, err := agent.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: []string{scope}, R3Operations: &classOperations,
	})
	if err != nil {
		t.Fatal(err)
	}
	classAuthToken, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: classResourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}

	call, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/reports/q3", nil)
	if err != nil {
		t.Fatal(err)
	}
	begun, err := agent.BeginR3Call(ctx, clientagent.R3Call{Request: call, ClassAuthToken: classAuthToken, Operation: exportOperation})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := begun.Pending()
	if !ok || runs != 1 {
		t.Fatalf("metered release call = %#v after %d runs", begun, runs)
	}
	offer, _ := json.Marshal(tokenClaims(t, pending.ResourceToken())["budget"])
	if string(offer) != `{"amount":40,"decimals":0,"unit":"credits"}` {
		t.Fatalf("proposal Resource token budget = %s", offer)
	}
	perCallToken, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: pending.ResourceToken(), PresentedToken: classAuthToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	granted, _ := json.Marshal(tokenClaims(t, perCallToken)["budget"])
	if string(granted) != string(offer) || len(ceilings) != 1 || ceilings[0].Budget == nil ||
		len(asked) != 1 || asked[0].Budget == nil || asked[0].Budget.Amount() != cost.Amount() {
		t.Fatalf("per-call budget %s; Person Server ceilings %d; Access Server budget %v", granted, len(ceilings), asked)
	}

	for _, attempt := range []string{"release", "replay"} {
		polled, err := agent.PollR3Call(ctx, clientagent.R3Poll{Pending: pending, AuthToken: perCallToken})
		if err != nil {
			t.Fatalf("%s: %v", attempt, err)
		}
		response, ok := polled.Response()
		if !ok {
			t.Fatalf("%s returned no response", attempt)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		feedback, err := budgets.ParseFeedback(response.Header.Values("AAuth-Budget"))
		if err != nil {
			t.Fatal(err)
		}
		if charged, _ := feedback.Cost(); response.StatusCode != http.StatusOK || string(body) != "quarterly report" ||
			charged != cost.Amount() || feedback.Remaining() != 0 || runs != 1 {
			t.Fatalf("%s = %d %q, AAuth-Budget %q, %d runs", attempt, response.StatusCode, body, response.Header.Values("AAuth-Budget"), runs)
		}
	}
}
