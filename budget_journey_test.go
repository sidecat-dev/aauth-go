package aauth_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/reference"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentFourPartyBudgetJourneyNarrowsEveryIssuanceBoundary(t *testing.T) {
	now := time.Date(2026, 8, 29, 11, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "budget-ap")
	psKey := testSigningKey(t, "budget-ps")
	asKey := testSigningKey(t, "budget-as")
	resourceKey := testSigningKey(t, "budget-resource")
	agentKey := testSigningKey(t, "budget-agent")

	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example", SigningKey: apKey, Clock: clock,
		NewID: sequentialIDs("budget-agent-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent: "aauth:budgeter@ap.example", PersonServer: "https://ps.example",
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			for _, prefix := range []string{"https://ap.example/", "https://ps.example/", "https://as.example/", "https://resource.example/"} {
				if strings.HasPrefix(endpoint, prefix) {
					return nil
				}
			}
			return fmt.Errorf("endpoint outside test trust: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	personTokens, _ := reference.NewFilePersonTokenStore(t.TempDir() + "/person-tokens.json")
	missionIssuance, _ := reference.NewFileMissionIssuanceStore(t.TempDir() + "/mission-issuance.json")
	personPolicyCalls := 0
	personServer, err := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier: "https://ps.example", SigningKey: psKey, KeyResolver: resolver,
		Clock: clock, NewID: sequentialIDs("budget-person-token"),
		AuthorizationStore: testAuthorizationStateStore(t),
		PersonTokenStore:   personTokens, MissionIssuanceStore: missionIssuance,
		PersonTokenPolicy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			return aauth.PersonTokenDecision{Subject: "directed-person", Lifetime: time.Hour}, nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: evaluation.Proposal.Description}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		},
		BudgetPolicy: func(_ context.Context, _ aauth.AuthorizationRequest, evaluation reference.BudgetEvaluation) (budgets.Budget, error) {
			personPolicyCalls++
			offer := evaluation.Offer
			if offer != (budgets.Budget{Amount: 5_000_000, Unit: "USD", Decimals: 6}) {
				return budgets.Budget{}, errors.New("unexpected resource offer")
			}
			return budgets.Narrow(offer, 3_000_000)
		},
		FederationClient: client,
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://as.example/token", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	accessPolicyCalls := 0
	accessServer, err := reference.NewAccessServer(reference.AccessServerConfig{
		Identifier: "https://as.example", SigningKey: asKey, KeyResolver: resolver,
		Clock: clock, NewID: sequentialIDs("budget-auth-token"),
		AuthorizationStore: testAuthorizationStateStore(t),
		TrustedPersonServer: func(_ context.Context, identifier string) error {
			if identifier != "https://ps.example" {
				return errors.New("untrusted person server")
			}
			return nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		},
		BudgetPolicy: func(_ context.Context, _ aauth.AuthorizationRequest, evaluation reference.BudgetEvaluation) (budgets.Budget, error) {
			accessPolicyCalls++
			offer := evaluation.Offer
			if offer != (budgets.Budget{Amount: 3_000_000, Unit: "USD", Decimals: 6}) {
				return budgets.Budget{}, errors.New("unexpected person-server allocation")
			}
			return budgets.Narrow(offer, 2_000_000)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resourceOfferCalls := 0
	budgetOperationCalls := 0
	protectedPolicyCalls := 0
	denyFreshPolicy := false
	changedPricing := false
	blockBudgetOperation := false
	budgetOperationStarted := make(chan struct{}, 1)
	budgetOperationContinue := make(chan struct{})
	budgetPath := t.TempDir() + "/budget-state.json"
	lineagePath := t.TempDir() + "/resource-token-lineage.json"
	newResource := func() *reference.Resource {
		budgetStore, openErr := reference.NewFileBudgetStore(budgetPath)
		if openErr != nil {
			t.Fatal(openErr)
		}
		resource, resourceErr := reference.NewResource(reference.ResourceConfig{
			Identifier: "https://resource.example", AccessMode: aauth.AccessModeAuthToken,
			AccessServer: "https://as.example", SigningKey: resourceKey,
			KeyResolver: resolver, Clock: clock, NewID: sequentialIDs("budget-resource-token"),
			Scopes:            []string{"inference.completions"},
			ScopeDescriptions: map[string]string{"inference.completions": "Generate metered completions"},
			RequiredScopesForRequest: func(context.Context, *http.Request) ([]string, error) {
				return []string{"inference.completions"}, nil
			},
			ReplayStore: mustMemoryReplayStore(t, clock),
			ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error {
				protectedPolicyCalls++
				if denyFreshPolicy {
					return errors.New("fresh policy disabled")
				}
				return nil
			},
			Budget: &reference.ResourceBudgetConfig{
				Offer: func(_ context.Context, requested *budgets.Budget) (budgets.Budget, error) {
					resourceOfferCalls++
					if requested != nil && requested.Amount != 10_000_000 {
						return budgets.Budget{}, errors.New("missing requested budget")
					}
					return budgets.Budget{Amount: 5_000_000, Unit: "USD", Decimals: 6}, nil
				},
				Store: budgetStore,
				ResourceTokenStore: func() reference.ResourceTokenLineageStore {
					store, lineageErr := reference.NewFileResourceTokenLineageStore(lineagePath)
					if lineageErr != nil {
						t.Fatal(lineageErr)
					}
					return store
				}(),
				MaximumCost: func(_ context.Context, request aauth.AuthorizedRequest) (int64, error) {
					if changedPricing {
						return 900_000, nil
					}
					if request.Path == "/expensive" {
						return 1_600_000, nil
					}
					return 700_000, nil
				},
				CallKey: func(_ context.Context, request aauth.AuthorizedRequest) (string, error) {
					if request.Path == "/expensive" {
						return "completion-2", nil
					}
					return "completion-1", nil
				},
				Operation: func(context.Context, aauth.AuthorizedRequest, string) (reference.BudgetOperationResult, error) {
					budgetOperationCalls++
					if blockBudgetOperation {
						budgetOperationStarted <- struct{}{}
						<-budgetOperationContinue
					}
					return reference.BudgetOperationResult{Value: map[string]string{"output": "done"}, Cost: 500_000}, nil
				},
			},
		})
		if resourceErr != nil {
			t.Fatal(resourceErr)
		}
		return resource
	}
	resource := newResource()
	resourceHandler := resource.Handler()

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": personServer.Handler(),
		"as.example": accessServer.Handler(),
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			resourceHandler.ServeHTTP(response, request)
		}),
	})
	defer gateway.Close()
	dropBudgetResponse := false
	client.Transport = &budgetLostResponseTransport{base: gateway.Client().Transport, drop: &dropBudgetResponse}

	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:budgeter@ap.example", SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: client, Clock: clock,
		AuthorizationStore: testAuthorizationStateStore(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	personGrant, err := agent.RequestPersonToken(context.Background(), "https://ps.example/person", "https://resource.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	resourceGrant, err := agent.RequestBudgetedResourceTokenWithPersonToken(
		context.Background(), "https://resource.example/authorize", []string{"inference.completions"}, personGrant.PersonToken,
		budgets.Budget{Amount: 10_000_000, Unit: "tokens", Decimals: 0},
	)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := resourceGrant.Budget.Budget()
	if err != nil || offer != (budgets.Budget{Amount: 5_000_000, Unit: "USD", Decimals: 6}) {
		t.Fatalf("resource offer = %#v, %v", offer, err)
	}
	grant, err := agent.ExchangeResourceToken(context.Background(), "https://ps.example/token", resourceGrant)
	if err != nil {
		t.Fatal(err)
	}
	granted, err := grant.Budget.Budget()
	if err != nil || granted != (budgets.Budget{Amount: 2_000_000, Unit: "USD", Decimals: 6}) {
		t.Fatalf("final grant = %#v, %v", granted, err)
	}
	if resourceOfferCalls != 1 || personPolicyCalls != 1 || accessPolicyCalls != 1 {
		t.Fatalf("policy calls = %d/%d/%d", resourceOfferCalls, personPolicyCalls, accessPolicyCalls)
	}
	blockBudgetOperation = true
	dropBudgetResponse = true
	lostResult := make(chan error, 1)
	go func() {
		_, requestErr := agent.DoAuthorized(context.Background(), http.MethodGet, "https://resource.example/completions", grant)
		lostResult <- requestErr
	}()
	<-budgetOperationStarted
	response, err := agent.DoAuthorized(context.Background(), http.MethodGet, "https://resource.example/completions", grant)
	if err != nil {
		t.Fatal(err)
	}
	problem, problemErr := aauth.DecodeProblemResponse(response)
	response.Body.Close()
	if response.StatusCode != http.StatusConflict || problemErr != nil || problem.Code != "budget_call_in_progress" || budgetOperationCalls != 1 {
		t.Fatalf("concurrent metered response = %d %#v err=%v calls=%d", response.StatusCode, problem, problemErr, budgetOperationCalls)
	}
	close(budgetOperationContinue)
	if err := <-lostResult; !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("lost metered result = %v", err)
	}
	denyFreshPolicy = true
	changedPricing = true
	resource = newResource()
	resourceHandler = resource.Handler()
	response, err = agent.DoAuthorized(context.Background(), http.MethodGet, "https://resource.example/completions", grant)
	if err != nil {
		t.Fatal(err)
	}
	header, err := budgets.ParseHeader(response.Header.Values("AAuth-Budget"))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || header.Cost == nil || *header.Cost != 500_000 || header.Remaining != 1_500_000 || budgetOperationCalls != 1 || protectedPolicyCalls != 2 {
		t.Fatalf("retained metered response = %d header=%#v err=%v operation/policy=%d/%d", response.StatusCode, header, err, budgetOperationCalls, protectedPolicyCalls)
	}
	denyFreshPolicy = false
	changedPricing = false
	response, err = agent.DoAuthorized(context.Background(), http.MethodGet, "https://resource.example/expensive", grant)
	if err != nil {
		t.Fatal(err)
	}
	header, headerErr := budgets.ParseHeader(response.Header.Values("AAuth-Budget"))
	requirement, requirementErr := aauth.ParseRequirementHeader(response.Header.Get("AAuth-Requirement"))
	problem, problemErr = aauth.DecodeProblemResponse(response)
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || headerErr != nil || header.Remaining != 1_500_000 ||
		header.Required == nil || *header.Required != 1_600_000 || requirementErr != nil ||
		requirement.Type != aauth.RequirementAuthToken || requirement.Reason != "insufficient-budget" ||
		problemErr != nil || problem.Code != "insufficient_budget" || budgetOperationCalls != 1 {
		t.Fatalf("insufficient response = %d header=%#v requirement=%#v problem=%#v errors=%v/%v/%v calls=%d",
			response.StatusCode, header, requirement, problem, headerErr, requirementErr, problemErr, budgetOperationCalls)
	}
}

type budgetLostResponseTransport struct {
	base http.RoundTripper
	drop *bool
}

func (transport *budgetLostResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil || transport.drop == nil || !*transport.drop || request.URL.Host != "resource.example" ||
		request.URL.Path != "/completions" || response.StatusCode != http.StatusOK {
		return response, err
	}
	*transport.drop = false
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return nil, io.ErrUnexpectedEOF
}

func mustMemoryReplayStore(t *testing.T, clock aauth.Clock) reference.ProofReplayStore {
	t.Helper()
	store, err := reference.NewMemoryProofReplayStore(clock, 128)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
