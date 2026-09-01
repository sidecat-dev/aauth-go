// The budget example first acquires a fixed Budget reactively from an ordinary
// Person-token call, then runs two declared MCP operations through a proactive
// direct R3 Budget grant. An over-remainder call preserves the R3 reference in
// its fresh Resource-token challenge and is never retried.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	agentProviderID = "https://agents.example"
	agentID         = "aauth:budget-reader@agents.example"
	personServerID  = "https://person.example"
	resourceID      = "https://resource.example"
	scope           = "records.read"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(output io.Writer) error {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 19, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })

	providerKey, err := newSigningKey("budget-provider-key")
	if err != nil {
		return err
	}
	registry, err := r3.NewRegistry(mcp.Vocabulary())
	if err != nil {
		return err
	}
	definitions, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	if err != nil {
		return err
	}
	currentMCP, err := mcp.NewOperation("records.current")
	if err != nil {
		return err
	}
	exportMCP, err := mcp.NewOperation("records.export")
	if err != nil {
		return err
	}
	currentOperation, err := currentMCP.ToR3()
	if err != nil {
		return err
	}
	exportOperation, err := exportMCP.ToR3()
	if err != nil {
		return err
	}
	requestedOperations, err := mcp.NewOperationSet(currentMCP, exportMCP)
	if err != nil {
		return err
	}
	definition, err := mcp.ParseDefinition(
		resourceID+"/mcp",
		mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(`{
			"tools":[
				{"name":"records.current","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}},
				{"name":"records.export","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}}
			]
		}`))),
	)
	if err != nil {
		return err
	}
	documents := newR3DocumentStore()
	issuances := newR3IssuanceStore()
	agentKey, err := newSigningKey("budget-agent-key")
	if err != nil {
		return err
	}
	personKey, err := newSigningKey("budget-person-key")
	if err != nil {
		return err
	}
	resourceKey, err := newSigningKey("budget-resource-key")
	if err != nil {
		return err
	}
	agentThumbprint, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		return err
	}

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: network.Admit,
	})
	if err != nil {
		return err
	}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "agent-token-1" },
	})
	if err != nil {
		return err
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		return err
	}

	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		return err
	}
	requested, err := budgets.NewValue(800_000, unit)
	if err != nil {
		return err
	}
	resourceOffer, err := budgets.NewValue(600_000, unit)
	if err != nil {
		return err
	}
	personGrant, err := budgets.NewValue(400_000, unit)
	if err != nil {
		return err
	}
	unitDeclaration, err := budgets.NewBoundedUnitDeclaration(
		unit, 1_000_000, "US dollars at micro-dollar precision",
	)
	if err != nil {
		return err
	}

	lineage := newPersonLineageStore()
	var personIDSequence atomic.Int64
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, Tokens: newPersonTokenStore(),
		NewID: func() string {
			switch personIDSequence.Add(1) {
			case 1:
				return "person-token-1"
			case 2:
				return "reactive-auth-token-1"
			case 3:
				return "r3-auth-token-1"
			case 4:
				return "r3-reauthorized-auth-token-1"
			default:
				return "unexpected-person-token"
			}
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != resourceID {
				return personserver.Person{}, errors.New("budget example: unexpected person binding")
			}
			return personserver.Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: time.Hour}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			if request.Agent != agentID || request.Resource != resourceID || request.Subject != "person-123" ||
				request.Tenant != "tenant-1" || len(request.Scopes) != 1 || request.Scopes[0] != scope ||
				request.Budget == nil || !sameBudget(*request.Budget, resourceOffer) {
				return personserver.AuthorizationDecision{}, errors.New("budget example: unexpected reactive Budget context")
			}
			return personserver.AuthorizationDecision{
				Scopes: []string{scope}, Lifetime: 30 * time.Minute, Budget: &personGrant,
			}, nil
		},
		Budget: &personserver.BudgetConfig{ResolveResourceUnits: func(_ context.Context, resource string) ([]budgets.UnitDeclaration, error) {
			if resource != resourceID {
				return nil, errors.New("budget example: unexpected Resource metadata request")
			}
			return []budgets.UnitDeclaration{unitDeclaration}, nil
		}},
		R3: &personserver.DirectR3Config{
			Registry: registry, HTTPClient: httpClient, Admit: network.Admit,
			AuthorizeDocument: func(_ context.Context, request personserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (personserver.DirectR3Decision, error) {
				if request.Agent != agentID || request.Resource != resourceID || request.Subject != "person-123" ||
					request.Tenant != "tenant-1" || len(request.Scopes) != 0 ||
					request.Budget == nil || !sameBudget(*request.Budget, resourceOffer) {
					return personserver.DirectR3Decision{}, errors.New("budget example: unexpected Person Server R3 Budget context")
				}
				grantedOperations, err := r3.NewGrantedOperations(mcp.Vocabulary(), currentOperation, exportOperation)
				if err != nil {
					return personserver.DirectR3Decision{}, err
				}
				operationGrant, err := r3.NewGrant(grantedOperations, document)
				if err != nil {
					return personserver.DirectR3Decision{}, err
				}
				return personserver.DirectR3Decision{
					Lifetime: 30 * time.Minute, Grant: operationGrant, Budget: &personGrant,
				}, nil
			},
			Issuances: issuances,
		},
	})
	if err != nil {
		return err
	}

	budgetStore := newMemoryBudgetStore()
	var protectedCalls atomic.Int64
	var resourceIDSequence atomic.Int64
	protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string {
			switch resourceIDSequence.Add(1) {
			case 1:
				return "reactive-resource-token-1"
			case 2:
				return "r3-resource-token-1"
			default:
				return "unexpected-resource-token"
			}
		},
		ScopeDescriptions: map[string]string{scope: "Read records"},
		RequiredScopes: func(request *http.Request) []string {
			if request.URL.Path == "/records/reactive" {
				return []string{scope}
			}
			return nil
		},
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) ||
				personContext.Tenant != "tenant-1" {
				return errors.New("budget example: unexpected Resource person")
			}
			return nil
		},
		R3: &resource.R3Config{
			Registry: registry, Definitions: definitions,
			Vocabularies: []resource.R3VocabularyConfig{{Definition: definition}},
			Documents:    documents,
			HTTP: resource.R3HTTPAdapter{OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
				switch request.URL.Path {
				case "/records/current":
					return currentOperation, true, nil
				case "/records/export":
					return exportOperation, true, nil
				default:
					return r3.Operation{}, false, nil
				}
			}},
		},
		Budget: &resource.BudgetConfig{
			Units: []budgets.UnitDeclaration{unitDeclaration},
			InitialOffer: func(_ context.Context, request resource.BudgetInitialOfferRequest) (budgets.Value, error) {
				if request.Request == nil || request.Request.URL.Path != "/records/reactive" ||
					request.Person != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) ||
					request.PersonContext.Tenant != "tenant-1" || len(request.Scope) != 1 || request.Scope[0] != scope {
					return budgets.Value{}, errors.New("budget example: unexpected initial Budget context")
				}
				return resourceOffer, nil
			},
			RetainLineage: lineage.Retain,
			Offer: func(_ context.Context, request resource.BudgetOfferRequest) (budgets.Value, error) {
				if len(request.Scope) != 0 || !sameBudget(request.Requested, requested) {
					return budgets.Value{}, errors.New("budget example: unexpected proactive Budget request")
				}
				return resourceOffer, nil
			},
			Cost: func(_ context.Context, request resource.BudgetCostRequest) (int64, error) {
				if !request.Grant.Unit().Equal(unit) {
					return 0, errors.New("budget example: unexpected signed Budget denomination")
				}
				switch request.Request.URL.Path {
				case "/records/reactive":
					return 100_000, nil
				case "/records/current":
					return 150_000, nil
				case "/records/export":
					return 300_000, nil
				default:
					return 0, errors.New("budget example: no fixed price for request")
				}
			},
			Store: budgetStore,
			Challenge: func(_ context.Context, challenge resource.BudgetChallengeRequest) (string, error) {
				retained, ok := lineage.Load()
				if !ok {
					return "", errors.New("budget example: Person-token lineage is unavailable")
				}
				if challenge.R3Reference == nil || challenge.Reason != budgets.ReasonInsufficientBudget || challenge.Remaining != 250_000 ||
					challenge.Required != 300_000 || !sameBudget(challenge.Grant, personGrant) ||
					challenge.Principal.PersonServer != personServerID || challenge.Principal.Subject != retained.Subject {
					return "", errors.New("budget example: unexpected Budget challenge context")
				}
				document, err := documents.Load(ctx, challenge.R3Reference.URI())
				if err != nil {
					return "", err
				}
				compact, reference, err := r3.MintBudgetResourceToken(registry, resourceKey, aauth.ResourceTokenClaims{
					Issuer: resourceID, DWK: aauth.ResourceDiscoveryDocument,
					Audience: personServerID, JTI: "resource-token-2",
					PersonServer: personServerID, Subject: retained.Subject,
					PresentedJTI: retained.JTI, AgentJKT: agentThumbprint,
					IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
					Tenant: retained.Tenant,
				}, challenge.R3Reference.URI(), document.ExactJSON, resourceOffer, nil)
				if err != nil || reference != *challenge.R3Reference {
					return "", errors.New("budget example: replacement token changed the R3 reference")
				}
				return compact, nil
			},
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			protectedCalls.Add(1)
			response.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		return err
	}

	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, protectedResource.Handler())

	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
		R3: &clientagent.R3Config{Registry: registry},
	})
	if err != nil {
		return err
	}
	personResult, err := reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if err != nil {
		return err
	}
	personToken, ok := personResult.Token()
	if !ok {
		return errors.New("budget example: Person Server unexpectedly required interaction")
	}
	reactiveRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/reactive", nil)
	if err != nil {
		return err
	}
	reactiveResult, err := reader.Begin(ctx, clientagent.InitialCall{Request: reactiveRequest, PersonToken: personToken})
	if err != nil {
		return err
	}
	reactiveRequirement, ok := reactiveResult.AuthorizationRequired()
	if !ok {
		return errors.New("budget example: initial Person-token call returned no Budget authorization requirement")
	}
	_, reactiveOffer, _, err := budgets.VerifyResourceToken(ctx, reactiveRequirement.ResourceToken, resolver, clock)
	if err != nil || !sameBudget(reactiveOffer, resourceOffer) {
		return errors.New("budget example: reactive Resource token carried the wrong offer")
	}
	reactiveAuthToken, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: reactiveRequirement.ResourceToken,
	})
	if err != nil {
		return err
	}
	_, reactiveGrant, err := budgets.VerifyAuthToken(ctx, reactiveAuthToken, resolver, clock)
	if err != nil || !sameBudget(reactiveGrant, personGrant) {
		return errors.New("budget example: reactive Auth token carried the wrong grant")
	}
	reactiveCall, err := budgetCall(ctx, reader, "/records/reactive", reactiveAuthToken)
	if err != nil {
		return err
	}
	reactiveResponse, ok := reactiveCall.Response()
	if !ok || reactiveResponse.StatusCode != http.StatusNoContent {
		return errors.New("budget example: reactive Budget call returned no application response")
	}
	reactiveResponse.Body.Close()
	reactiveFeedback, ok := reactiveCall.Feedback()
	if !ok || reactiveFeedback.Remaining() != 300_000 || protectedCalls.Load() != 1 {
		return errors.New("budget example: reactive Budget call returned unexpected feedback")
	}
	reactiveProtectedCalls := protectedCalls.Load()

	resourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken,
		R3Operations: &requestedOperations, Budget: &requested,
	})
	if err != nil {
		return err
	}
	retainedLineage, ok := lineage.Load()
	if !ok {
		return errors.New("budget example: Resource did not retain Person-token lineage before releasing its token")
	}
	initialClaims, initialReference, offered, _, err := r3.VerifyBudgetResourceToken(
		ctx, registry, resourceToken, resolver, clock,
	)
	if err != nil {
		return err
	}
	if retainedLineage.ResourceToken != (aauth.TokenReference{Issuer: initialClaims.Issuer, JTI: initialClaims.JTI}) {
		return errors.New("budget example: retained lineage does not name the released Resource token")
	}
	authToken, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	})
	if err != nil {
		return err
	}
	_, authReference, _, granted, err := r3.VerifyBudgetAuthToken(
		ctx, registry, authToken, resolver, clock,
	)
	if err != nil {
		return err
	}
	if authReference != initialReference {
		return errors.New("budget example: Auth token changed the R3 reference")
	}
	first, err := budgetCall(ctx, reader, "/records/current", authToken)
	if err != nil {
		return err
	}
	firstResponse, ok := first.Response()
	if !ok || firstResponse.StatusCode != http.StatusNoContent {
		return errors.New("budget example: typed Budget result omitted the successful application response")
	}
	defer firstResponse.Body.Close()
	firstFeedback, ok := first.Feedback()
	if !ok {
		return errors.New("budget example: typed Budget result omitted validated feedback")
	}
	firstCost, hasCost := first.Cost()
	firstGrant, hasGrant := first.Grant()
	if !hasCost || firstCost != 150_000 || firstFeedback.Remaining() != 250_000 ||
		!hasGrant || !sameBudget(firstGrant, granted) {
		return errors.New("budget example: first call returned unexpected Budget feedback")
	}

	second, err := budgetCall(ctx, reader, "/records/export", authToken)
	if err != nil {
		return err
	}
	if _, ok := second.Response(); ok {
		return errors.New("budget example: over-remainder call returned an application response")
	}
	secondFeedback, ok := second.Feedback()
	if !ok {
		return errors.New("budget example: typed Budget refusal omitted validated feedback")
	}
	required, hasRequired := secondFeedback.Required()
	secondGrant, hasGrant := second.Grant()
	if !hasRequired || required != 300_000 || secondFeedback.Remaining() != 250_000 ||
		!hasGrant || !sameBudget(secondGrant, granted) {
		return errors.New("budget example: refusal returned unexpected Budget feedback")
	}
	authorization, ok := second.AuthorizationRequired()
	if !ok {
		return errors.New("budget example: refusal omitted a verified authorization step-up")
	}
	reason, ok := authorization.Reason()
	if !ok || reason != budgets.ReasonInsufficientBudget || authorization.ResourceToken() == "" {
		return errors.New("budget example: refusal did not return a typed fresh-Resource-token challenge")
	}
	freshClaims, freshReference, freshOffer, consumed, err := r3.VerifyBudgetResourceToken(
		ctx, registry, authorization.ResourceToken(), resolver, clock,
	)
	if err != nil {
		return err
	}
	if freshClaims.PresentedJTI != retainedLineage.JTI || freshReference != initialReference ||
		!sameBudget(freshOffer, resourceOffer) || len(consumed) != 0 {
		return errors.New("budget example: fresh Resource token did not preserve retained Person-token lineage")
	}
	r3ProtectedCalls := protectedCalls.Load() - reactiveProtectedCalls
	if r3ProtectedCalls != 1 {
		return errors.New("budget example: Agent retried the refused consequence")
	}
	reauthorizedToken, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: authorization.ResourceToken(),
	})
	if err != nil {
		return err
	}
	_, reauthorizedReference, _, reauthorizedGrant, err := r3.VerifyBudgetAuthToken(
		ctx, registry, reauthorizedToken, resolver, clock,
	)
	if err != nil || reauthorizedReference != initialReference || !sameBudget(reauthorizedGrant, personGrant) {
		return errors.New("budget example: replacement exchange changed the R3 or Budget grant")
	}
	retried, err := budgetCall(ctx, reader, "/records/export", reauthorizedToken)
	if err != nil {
		return err
	}
	retriedResponse, ok := retried.Response()
	if !ok || retriedResponse.StatusCode != http.StatusNoContent {
		return errors.New("budget example: reauthorized retry returned no application response")
	}
	retriedResponse.Body.Close()
	retriedFeedback, ok := retried.Feedback()
	if !ok {
		return errors.New("budget example: reauthorized retry omitted Budget feedback")
	}
	retriedCost, hasRetriedCost := retried.Cost()
	recoveredProtectedCalls := protectedCalls.Load() - reactiveProtectedCalls
	if !hasRetriedCost || retriedCost != 300_000 || retriedFeedback.Remaining() != 100_000 || recoveredProtectedCalls != 2 {
		return errors.New("budget example: reauthorized retry returned unexpected Budget evidence")
	}

	if _, err := fmt.Fprintf(output,
		"AAuth Core reactive Budget success: first Person-token call returned a %d offer; Person Server granted %d; charged %d; remaining %d\n",
		reactiveOffer.Amount(), reactiveGrant.Amount(), 100_000, reactiveFeedback.Remaining(),
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(output,
		"AAuth R3 Budget success: operations records.current and records.export; Resource offered %d; Person Server granted %d; charged %d; remaining %d\n",
		offered.Amount(), granted.Amount(), firstCost, firstFeedback.Remaining(),
	); err != nil {
		return err
	}
	if _, err = fmt.Fprintf(output,
		"AAuth R3 Budget refusal: %s; required %d; remaining %d; R3 reference preserved; protected calls %d\n",
		reason, required, secondFeedback.Remaining(), r3ProtectedCalls,
	); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output,
		"AAuth R3 Budget recovery: replacement offer exchanged; fresh grant %d; retry charged %d; remaining %d; protected calls %d\n",
		reauthorizedGrant.Amount(), retriedCost, retriedFeedback.Remaining(), recoveredProtectedCalls,
	)
	return err
}

func budgetCall(
	ctx context.Context,
	client *clientagent.Client,
	path string,
	authToken string,
) (clientagent.BudgetCallResult, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+path, nil)
	if err != nil {
		return clientagent.BudgetCallResult{}, err
	}
	return client.BeginBudgetCall(ctx, clientagent.BudgetCall{
		Request: request, AuthToken: authToken,
	})
}

func newSigningKey(id string) (jose.SigningKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(id, privateKey)
}
