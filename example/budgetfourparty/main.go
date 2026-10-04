// The budgetfourparty example shows one proactive fixed-price Budget crossing
// a Resource, Person Server, Access Server, Agent, and protected Resource call.
// Each role communicates through its ordinary HTTP handler. The in-memory
// stores illustrate interfaces; deployment applications provide durable
// implementations and run the corresponding storetest contracts.
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
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
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
	agentID         = "aauth:budget-agent@agents.example"
	personServerID  = "https://person.example"
	accessServerID  = "https://access.example"
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
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
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
	accessKey, err := newSigningKey("budget-access-key")
	if err != nil {
		return err
	}
	resourceKey, err := newSigningKey("budget-resource-key")
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
		NewID: func() string { return "budget-agent-token" },
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
	personCeiling, err := budgets.NewValue(450_000, unit)
	if err != nil {
		return err
	}
	accessGrant, err := budgets.NewValue(300_000, unit)
	if err != nil {
		return err
	}
	account := "primary"
	declaration, err := budgets.NewBoundedUnitDeclaration(
		unit, 1_000_000, "US dollars at micro-dollar precision",
	)
	if err != nil {
		return err
	}

	access, err := accessserver.New(accessserver.Config{
		Issuer: accessServerID, SigningKey: accessKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "budget-auth-token" },
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != personServerID {
				return errors.Join(accessserver.ErrAccessDenied, errors.New("untrusted Person Server"))
			}
			return nil
		},
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			if request.Budget == nil || !sameBudget(*request.Budget, personCeiling) ||
				request.Account == nil || *request.Account != account {
				return accessserver.Decision{}, errors.New("unexpected Person Server Budget ceiling")
			}
			return accessserver.Decision{
				Scopes:   append([]string(nil), request.Scopes...),
				Lifetime: 30 * time.Minute, Budget: &accessGrant,
			}, nil
		},
		Budget: &accessserver.BudgetConfig{
			ResolveResourceUnits: resourceUnits(resourceID, declaration),
		},
	})
	if err != nil {
		return err
	}

	var protectedCalls atomic.Int64
	lineages := newLineageStore()
	protectedResource, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: resourceID, AccessServer: accessServerID,
		SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "budget-resource-token" },
		ScopeDescriptions: map[string]string{scope: "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{scope} },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, _ resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) {
				return errors.New("unexpected person")
			}
			return nil
		},
		ValidateAccount: func(_ context.Context, identity resource.PersonIdentity, got string) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) || got != account {
				return errors.New("unexpected Resource account")
			}
			return nil
		},
		Budget: &resource.BudgetConfig{
			Units: []budgets.UnitDeclaration{declaration},
			Offer: func(_ context.Context, request resource.BudgetOfferRequest) (budgets.Value, error) {
				if !sameBudget(request.Requested, requested) || request.Account == nil || *request.Account != account {
					return budgets.Value{}, errors.New("unexpected Agent Budget request")
				}
				return resourceOffer, nil
			},
			RetainLineage: lineages.Retain,
			Cost: func(_ context.Context, request resource.BudgetCostRequest) (int64, error) {
				if !sameBudget(request.Grant, accessGrant) ||
					request.Principal.Account == nil || *request.Principal.Account != account {
					return 0, errors.New("unexpected signed Budget grant")
				}
				return 125_000, nil
			},
			Store: newBudgetStore(),
			Challenge: func(context.Context, resource.BudgetChallengeRequest) (string, error) {
				return "", errors.New("Budget step-up is outside this example")
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

	people, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "budget-person-token" },
		HTTPClient: httpClient, Tokens: newPersonTokenStore(),
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			if issuer != accessServerID {
				return "", errors.New("unknown Access Server")
			}
			return accessServerID + "/token", nil
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != resourceID {
				return personserver.Person{}, errors.New("unexpected person-token request")
			}
			return personserver.Person{Subject: "person-123", Lifetime: time.Hour}, nil
		},
		Consent: func(_ context.Context, request personserver.AuthorizationRequest) error {
			if request.Budget == nil || !sameBudget(*request.Budget, resourceOffer) ||
				request.Account == nil || *request.Account != account {
				return errors.Join(personserver.ErrAccessDenied, errors.New("unexpected Resource Budget offer"))
			}
			return nil
		},
		Budget: &personserver.FederatedBudgetConfig{
			ResolveResourceUnits: resourceUnits(resourceID, declaration),
			Ceiling: func(_ context.Context, request personserver.AuthorizationRequest) (*budgets.Value, error) {
				if request.Budget == nil || !sameBudget(*request.Budget, resourceOffer) ||
					request.Account == nil || *request.Account != account {
					return nil, errors.New("unexpected Budget ceiling input")
				}
				return &personCeiling, nil
			},
		},
	})
	if err != nil {
		return err
	}

	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(accessServerID, access.Handler())
	network.Handle(resourceID, protectedResource.Handler())

	agent, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		return err
	}
	personResult, err := agent.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if err != nil {
		return err
	}
	personToken, ok := personResult.Token()
	if !ok {
		return errors.New("Person Server unexpectedly required interaction")
	}
	resourceToken, err := agent.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken,
		Scopes: []string{scope}, Account: &account, Budget: &requested,
	})
	if err != nil {
		return err
	}
	authToken, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records/current", nil)
	if err != nil {
		return err
	}
	result, err := agent.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: request, AuthToken: authToken})
	if err != nil {
		return err
	}
	response, ok := result.Response()
	if !ok {
		return errors.New("protected call returned an authorization step-up")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("protected call returned %s", response.Status)
	}
	cost, hasCost := result.Cost()
	feedback, hasFeedback := result.Feedback()
	if !hasCost || !hasFeedback || cost != 125_000 || feedback.Remaining() != 175_000 || protectedCalls.Load() != 1 {
		return errors.New("protected Budget result is incomplete")
	}
	lineage, ok := lineages.Load()
	if !ok || lineage.ResourceToken != (aauth.TokenReference{Issuer: resourceID, JTI: "budget-resource-token"}) ||
		lineage.Account == nil || *lineage.Account != account || !sameBudget(lineage.Offer, resourceOffer) {
		return errors.New("Resource did not retain the Budget authorization lineage")
	}
	_, err = fmt.Fprintf(
		output,
		"AAuth four-party Budget success: account %s; Resource offered %d %s/%d; Person Server ceiling %d; Access Server granted %d; charged %d; remaining %d; protected calls %d\n",
		account, resourceOffer.Amount(), unit.Name(), unit.Decimals(), personCeiling.Amount(), accessGrant.Amount(),
		cost, feedback.Remaining(), protectedCalls.Load(),
	)
	return err
}

func resourceUnits(expected string, declaration budgets.UnitDeclaration) func(context.Context, string) ([]budgets.UnitDeclaration, error) {
	return func(_ context.Context, resourceID string) ([]budgets.UnitDeclaration, error) {
		if resourceID != expected {
			return nil, errors.New("unexpected Resource metadata request")
		}
		return []budgets.UnitDeclaration{declaration}, nil
	}
}

func sameBudget(left, right budgets.Value) bool {
	return left.Amount() == right.Amount() && left.Unit().Equal(right.Unit())
}

func newSigningKey(id string) (jose.SigningKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(id, privateKey)
}
