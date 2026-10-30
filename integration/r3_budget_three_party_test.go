package integration_test

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestR3BudgetDirectThreePartyConnectorCall(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 6, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:connector@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://connector.example"
	)

	providerKey := newSigningKey(t, "connector-provider")
	agentKey := newSigningKey(t, "connector-agent")
	personKey := newSigningKey(t, "connector-person")
	resourceKey := newSigningKey(t, "connector-resource")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasSuffix(endpoint, ".example/.well-known/aauth-agent.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-person.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-resource.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/jwks.json") {
				return nil
			}
			return errors.New("unexpected discovery endpoint: " + endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "connector-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	if err != nil {
		t.Fatal(err)
	}
	sendMCP, err := mcp.NewOperation("messages.send")
	if err != nil {
		t.Fatal(err)
	}
	send, err := sendMCP.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	deleteMCP, err := mcp.NewOperation("messages.delete")
	if err != nil {
		t.Fatal(err)
	}
	deleteOperation, err := deleteMCP.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	requested, err := mcp.NewOperationSet(sendMCP)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := mcp.ParseDefinition(
		resourceID+"/mcp",
		mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(`{
			"tools":[
				{"name":"messages.send","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}},
				{"name":"messages.delete","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}}
			]
		}`))),
	)
	if err != nil {
		t.Fatal(err)
	}
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := budgets.NewBoundedUnitDeclaration(unit, 1_000_000, "US dollars at micro-dollar precision")
	if err != nil {
		t.Fatal(err)
	}
	requestedBudget := integrationBudgetValue(t, 600_000, unit)
	offeredBudget := integrationBudgetValue(t, 500_000, unit)
	grantedBudget := integrationBudgetValue(t, 250_000, unit)

	documents := newDirectR3DocumentStore()
	lineages := &connectorBudgetLineageStore{}
	budgetStore := newIntegrationBudgetStore()
	issuances := &integrationR3IssuanceStore{}
	personTokens := newMemoryPersonTokenStore()
	var resourceIDs atomic.Int64
	var personIDs atomic.Int64
	var cost atomic.Int64
	cost.Store(150_000)
	var protectedCalls atomic.Int64

	newResource := func() *resource.Server {
		server, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
			Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
			NewID:          func() string { return "connector-resource-token-" + strconv.FormatInt(resourceIDs.Add(1), 10) },
			RequiredScopes: func(*http.Request) []string { return nil },
			ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
				if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) {
					return errors.New("unexpected connector person")
				}
				return nil
			},
			R3: &resource.R3Config{
				Registry: registry, Definitions: definitions,
				Vocabularies: []resource.R3VocabularyConfig{{Definition: definition}},
				Documents:    documents,
				HTTP: resource.R3HTTPAdapter{OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
					if request.URL.Path == "/messages/send" {
						return send, true, nil
					}
					if request.URL.Path == "/messages/delete" {
						return deleteOperation, true, nil
					}
					return r3.Operation{}, false, nil
				}},
			},
			Budget: &resource.BudgetConfig{
				Units: []budgets.UnitDeclaration{declaration},
				Offer: func(_ context.Context, request resource.BudgetOfferRequest) (budgets.Value, error) {
					if !integrationSameBudget(request.Requested, requestedBudget) {
						return budgets.Value{}, errors.New("unexpected connector Budget request")
					}
					return offeredBudget, nil
				},
				RetainLineage: lineages.Retain,
				Cost: func(_ context.Context, request resource.BudgetCostRequest) (int64, error) {
					if request.Request.URL.Path != "/messages/send" || !integrationSameBudget(request.Grant, grantedBudget) {
						return 0, errors.New("unexpected connector cost request")
					}
					return cost.Load(), nil
				},
				Store: budgetStore,
				Challenge: func(_ context.Context, request resource.BudgetChallengeRequest) (string, error) {
					if request.R3Reference == nil {
						return "", errors.New("connector challenge lost R3 reference")
					}
					lineage, ok := lineages.Latest()
					if !ok {
						return "", errors.New("connector challenge has no retained lineage")
					}
					record, err := documents.Load(ctx, request.R3Reference.URI())
					if err != nil {
						return "", err
					}
					var consumed *budgets.ConsumptionRecord
					if request.Grant.Unit().Equal(offeredBudget.Unit()) {
						metered, meterErr := budgets.ConsumptionForPresentedGrant(request.Token.JTI, request.Grant, request.Remaining)
						if meterErr != nil {
							return "", meterErr
						}
						consumed = &metered
					}
					return compactResult(r3.MintBudgetResourceToken(
						registry, resourceKey, aauth.ResourceTokenClaims{
							Issuer: resourceID, DWK: aauth.ResourceDiscoveryDocument,
							Audience: personServerID, JTI: "connector-step-up-resource-token",
							PersonServer: lineage.Person.Issuer, Subject: lineage.Person.Subject,
							PresentedJTI: request.Token.JTI, AgentJKT: lineage.AgentJKT,
							IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
						}, request.R3Reference.URI(), record.ExactJSON, offeredBudget, consumed,
					))
				},
			},
			Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				protectedCalls.Add(1)
				response.WriteHeader(http.StatusNoContent)
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}

	personServer, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string {
			if personIDs.Add(1) == 1 {
				return "connector-person-token"
			}
			return "connector-auth-token"
		},
		Tokens: personTokens,
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-123", Lifetime: time.Hour}, nil
		},
		Budget: &personserver.BudgetConfig{ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
			return []budgets.UnitDeclaration{declaration}, nil
		}},
		R3: &personserver.DirectR3Config{
			Registry: registry, HTTPClient: httpClient,
			Admit: func(_ context.Context, endpoint string) error {
				if !strings.HasPrefix(endpoint, resourceID+"/r3/") {
					return errors.New("unexpected connector R3 endpoint")
				}
				return nil
			},
			AuthorizeDocument: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (personserver.DirectR3Decision, error) {
				if request.Budget == nil || !integrationSameBudget(*request.Budget, offeredBudget) {
					return personserver.DirectR3Decision{}, errors.New("connector policy did not receive Budget offer")
				}
				granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), send)
				if err != nil {
					return personserver.DirectR3Decision{}, err
				}
				operationGrant, err := r3.NewGrant(granted, document)
				if err != nil {
					return personserver.DirectR3Decision{}, err
				}
				return personserver.DirectR3Decision{
					Lifetime: 30 * time.Minute,
					Grant:    operationGrant, Budget: &grantedBudget,
				}, nil
			},
			Issuances: issuances,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, personServer.Handler())
	network.Handle(resourceID, newResource().Handler())
	client, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
		R3: &clientagent.R3Config{Registry: registry},
	})
	if err != nil {
		t.Fatal(err)
	}
	personResult, err := client.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatal("connector Person token did not complete")
	}
	resourceToken, err := client.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken,
		R3Operations: &requested, Budget: &requestedBudget,
	})
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := client.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}

	deleteRequest, _ := http.NewRequestWithContext(ctx, http.MethodDelete, resourceID+"/messages/delete", nil)
	refused, err := client.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: deleteRequest, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	if response, ok := refused.Response(); !ok || response.StatusCode != http.StatusForbidden {
		t.Fatalf("ungranted operation=%#v", refused)
	} else {
		response.Body.Close()
	}
	feedback := integrationBudgetFeedback(t, refused)
	if cost, ok := feedback.Cost(); !ok || cost != 0 || feedback.Remaining() != grantedBudget.Amount() {
		t.Fatalf("ungranted operation feedback=%#v", feedback)
	}
	if got := budgetStore.personTotal(personServerID, "person-123", resourceID); got != 0 || protectedCalls.Load() != 0 {
		t.Fatalf("ungranted operation charged/dispatched = %d/%d", got, protectedCalls.Load())
	}

	call := func() (clientagent.BudgetCallResult, error) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, resourceID+"/messages/send", nil)
		return client.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: request, AuthToken: authToken})
	}
	firstResult, err := call()
	if err != nil {
		t.Fatal(err)
	}
	firstResponse, ok := firstResult.Response()
	if !ok || firstResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("first connector call = %#v", firstResult)
	}
	firstResponse.Body.Close()
	if feedback, ok := firstResult.Feedback(); !ok || feedback.Remaining() != 100_000 || protectedCalls.Load() != 1 {
		t.Fatalf("first connector feedback/protected = %#v/%d", feedback, protectedCalls.Load())
	}

	// Recompose the Resource around the same retained document, lineage, and
	// Budget stores. The next call costs more than the remaining hard cap.
	network.Handle(resourceID, newResource().Handler())
	cost.Store(150_001)
	secondResult, err := call()
	if err != nil {
		t.Fatal(err)
	}
	authorization, ok := secondResult.AuthorizationRequired()
	if !ok {
		t.Fatalf("second connector call = %#v", secondResult)
	}
	reason, ok := authorization.Reason()
	if !ok || reason != budgets.ReasonInsufficientBudget || protectedCalls.Load() != 1 {
		t.Fatalf("second connector refusal = %q/%t protected=%d", reason, ok, protectedCalls.Load())
	}
	_, reference, _, _, err := r3.VerifyBudgetResourceToken(
		ctx, registry, authorization.ResourceToken(), resolver, clock,
	)
	if err != nil || reference.URI() == "" {
		t.Fatalf("step-up Resource token = %#v, %v", reference, err)
	}
}

func compactResult(compact string, _ r3.Reference, err error) (string, error) { return compact, err }

type connectorBudgetLineageStore struct {
	mu     sync.Mutex
	latest resource.BudgetLineage
	set    bool
}

func (store *connectorBudgetLineageStore) Retain(_ context.Context, lineage resource.BudgetLineage) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.latest = lineage
	store.set = true
	return nil
}

func (store *connectorBudgetLineageStore) Latest() (resource.BudgetLineage, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.latest, store.set
}
