// The budget example runs the direct AP-Agent-Resource-PS-Resource Budget
// path. The Resource narrows a proactive request, the Person Server narrows it
// again, and a later over-remainder call returns a fresh Resource-token
// challenge without an automatic retry.
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
	"slices"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
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
				return "auth-token-1"
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
				request.Tenant != "tenant-1" || !slices.Equal(request.Scopes, []string{scope}) ||
				request.Budget == nil || !sameBudget(*request.Budget, resourceOffer) {
				return personserver.AuthorizationDecision{}, errors.New("budget example: unexpected Person Server authorization context")
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
	})
	if err != nil {
		return err
	}

	budgetStore := newMemoryBudgetStore()
	var protectedCalls atomic.Int64
	protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "resource-token-1" },
		ScopeDescriptions: map[string]string{scope: "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{scope} },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) ||
				personContext.Tenant != "tenant-1" {
				return errors.New("budget example: unexpected Resource person")
			}
			return nil
		},
		Budget: &resource.BudgetConfig{
			Units:         []budgets.UnitDeclaration{unitDeclaration},
			RetainLineage: lineage.Retain,
			Offer: func(_ context.Context, request resource.BudgetOfferRequest) (budgets.Value, error) {
				if !sameBudget(request.Requested, requested) {
					return budgets.Value{}, errors.New("budget example: unexpected proactive Budget request")
				}
				return resourceOffer, nil
			},
			Cost: func(_ context.Context, request resource.BudgetCostRequest) (int64, error) {
				if !request.Grant.Unit().Equal(unit) {
					return 0, errors.New("budget example: unexpected signed Budget denomination")
				}
				switch request.Request.URL.Path {
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
				if challenge.Reason != budgets.ReasonInsufficientBudget || challenge.Remaining != 250_000 ||
					challenge.Required != 300_000 || !sameBudget(challenge.Grant, personGrant) ||
					challenge.Principal.PersonServer != personServerID || challenge.Principal.Subject != retained.Subject {
					return "", errors.New("budget example: unexpected Budget challenge context")
				}
				return budgets.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
					Issuer: resourceID, DWK: aauth.ResourceDiscoveryDocument,
					Audience: personServerID, JTI: "resource-token-2",
					PersonServer: personServerID, Subject: retained.Subject,
					PresentedJTI: retained.JTI, AgentJKT: agentThumbprint,
					IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
					Scope: scope, Tenant: retained.Tenant,
				}, resourceOffer, nil)
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
	resourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken,
		Scopes: []string{scope}, Budget: &requested,
	})
	if err != nil {
		return err
	}
	retainedLineage, ok := lineage.Load()
	if !ok {
		return errors.New("budget example: Resource did not retain Person-token lineage before releasing its token")
	}
	initialClaims, offered, _, err := budgets.VerifyResourceToken(ctx, resourceToken, resolver, clock)
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
	_, granted, err := budgets.VerifyAuthToken(ctx, authToken, resolver, clock)
	if err != nil {
		return err
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
	freshClaims, freshOffer, consumed, err := budgets.VerifyResourceToken(
		ctx, authorization.ResourceToken(), resolver, clock,
	)
	if err != nil {
		return err
	}
	if freshClaims.PresentedJTI != retainedLineage.JTI || !sameBudget(freshOffer, resourceOffer) || len(consumed) != 0 {
		return errors.New("budget example: fresh Resource token did not preserve retained Person-token lineage")
	}
	if protectedCalls.Load() != 1 {
		return errors.New("budget example: Agent retried the refused consequence")
	}

	if _, err := fmt.Fprintf(output,
		"AAuth Budget success: Resource offered %d; Person Server granted %d; charged %d; remaining %d\n",
		offered.Amount(), granted.Amount(), firstCost, firstFeedback.Remaining(),
	); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output,
		"AAuth Budget refusal: %s; required %d; remaining %d; fresh Resource token uses %s; protected calls %d\n",
		reason, required, secondFeedback.Remaining(), freshClaims.PresentedJTI, protectedCalls.Load(),
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
