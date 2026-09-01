package integration_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestBudgetImmediateFourPartyFixedPriceJourney(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:budget-reader@ap.example"
		personServerID  = "https://ps.example"
		accessServerID  = "https://as.example"
		resourceID      = "https://resource.example"
		scope           = "records.read"
	)

	providerKey := newSigningKey(t, "budget-four-party-provider")
	agentKey := newSigningKey(t, "budget-four-party-agent")
	personKey := newSigningKey(t, "budget-four-party-person")
	accessKey := newSigningKey(t, "budget-four-party-access")
	resourceKey := newSigningKey(t, "budget-four-party-resource")

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.Contains(endpoint, ".example/.well-known/") {
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
		NewID: func() string { return "budget-four-party-agent-token" },
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

	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	requested := integrationBudgetValue(t, 800_000, unit)
	resourceOffer := integrationBudgetValue(t, 600_000, unit)
	personCeiling := integrationBudgetValue(t, 450_000, unit)
	accessGrant := integrationBudgetValue(t, 300_000, unit)
	account := "primary"
	declaration, err := budgets.NewBoundedUnitDeclaration(
		unit, 1_000_000, "US dollars at micro-dollar precision",
	)
	if err != nil {
		t.Fatal(err)
	}
	wrongScaleUnit, err := budgets.NewUnit("USD", 2)
	if err != nil {
		t.Fatal(err)
	}
	wrongScaleDeclaration, err := budgets.NewBoundedUnitDeclaration(wrongScaleUnit, 1_000_000, "")
	if err != nil {
		t.Fatal(err)
	}

	var accessPolicyRequest accessserver.AuthorizationRequest
	var accessMetadataChecks atomic.Int64
	var accessMetadataWrongScale atomic.Bool
	var accessMetadataFailure atomic.Bool
	access, err := accessserver.New(accessserver.Config{
		Issuer: accessServerID, SigningKey: accessKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "budget-four-party-auth-token" },
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != personServerID {
				return errors.New("untrusted Person Server")
			}
			return nil
		},
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			if request.Account == nil || *request.Account != account {
				return accessserver.Decision{}, errors.New("Access Server policy omitted the account")
			}
			accessPolicyRequest = request
			capturedAccount := *request.Account
			accessPolicyRequest.Account = &capturedAccount
			*request.Account = "mutated-by-access-policy"
			return accessserver.Decision{
				Scopes: append([]string(nil), request.Scopes...),
				Budget: &accessGrant, Lifetime: 30 * time.Minute,
			}, nil
		},
		Budget: &accessserver.BudgetConfig{
			ResolveResourceUnits: func(_ context.Context, resource string) ([]budgets.UnitDeclaration, error) {
				accessMetadataChecks.Add(1)
				if resource != resourceID {
					return nil, errors.New("unexpected Resource")
				}
				if accessMetadataWrongScale.Load() {
					return []budgets.UnitDeclaration{wrongScaleDeclaration}, nil
				}
				if accessMetadataFailure.Load() {
					return nil, errors.New("Access Server Resource metadata unavailable")
				}
				return []budgets.UnitDeclaration{declaration}, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ledger := newIntegrationBudgetStore()
	var protectedCalls atomic.Int64
	protectedResource, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: resourceID, AccessServer: accessServerID,
		SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "budget-four-party-resource-token" },
		RequiredScopes:    func(*http.Request) []string { return []string{scope} },
		ScopeDescriptions: map[string]string{scope: "Read records"},
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
				if !integrationSameBudget(request.Requested, requested) || request.Account == nil || *request.Account != account {
					return budgets.Value{}, errors.New("unexpected requested Budget")
				}
				return resourceOffer, nil
			},
			RetainLineage: func(context.Context, resource.BudgetLineage) error { return nil },
			Cost: func(_ context.Context, request resource.BudgetCostRequest) (int64, error) {
				if !integrationSameBudget(request.Grant, accessGrant) ||
					request.Principal.Account == nil || *request.Principal.Account != account {
					return 0, errors.New("unexpected signed Budget grant")
				}
				return 125_000, nil
			},
			Store: ledger,
			Challenge: func(context.Context, resource.BudgetChallengeRequest) (string, error) {
				return "", errors.New("Budget step-up is outside this journey")
			},
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			protectedCalls.Add(1)
			response.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	var personMetadataChecks atomic.Int64
	var consentCalls atomic.Int64
	var ceilingCalls atomic.Int64
	var omitPersonCeiling atomic.Bool
	people, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "budget-four-party-person-token" },
		HTTPClient: httpClient, Tokens: newMemoryPersonTokenStore(),
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
			consentCalls.Add(1)
			if request.Budget == nil || !integrationSameBudget(*request.Budget, resourceOffer) ||
				request.Account == nil || *request.Account != account {
				return errors.New("Person Server consent did not receive the Resource offer")
			}
			*request.Account = "mutated-by-consent-policy"
			return nil
		},
		Budget: &personserver.FederatedBudgetConfig{
			ResolveResourceUnits: func(_ context.Context, resource string) ([]budgets.UnitDeclaration, error) {
				personMetadataChecks.Add(1)
				if resource != resourceID {
					return nil, errors.New("unexpected Resource")
				}
				return []budgets.UnitDeclaration{declaration}, nil
			},
			Ceiling: func(_ context.Context, request personserver.AuthorizationRequest) (*budgets.Value, error) {
				ceilingCalls.Add(1)
				if request.Budget == nil || !integrationSameBudget(*request.Budget, resourceOffer) ||
					request.Account == nil || *request.Account != account {
					return nil, errors.New("unexpected Person Server Budget input")
				}
				*request.Account = "mutated-by-ceiling-policy"
				if omitPersonCeiling.Load() {
					return nil, nil
				}
				return &personCeiling, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var accessRequestBody string
	var accessProofHeaders http.Header
	var accessStatus int
	var accessResponseBody string
	var personExchangeStatus int
	var personExchangeBody string
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/token" {
			people.Handler().ServeHTTP(response, request)
			return
		}
		recorded := httptest.NewRecorder()
		people.Handler().ServeHTTP(recorded, request)
		personExchangeStatus = recorded.Code
		personExchangeBody = recorded.Body.String()
		for name, values := range recorded.Header() {
			for _, value := range values {
				response.Header().Add(name, value)
			}
		}
		response.WriteHeader(recorded.Code)
		_, _ = response.Write(recorded.Body.Bytes())
	}))
	network.Handle(resourceID, protectedResource.Handler())
	network.Handle(accessServerID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && request.URL.Path == "/token" {
			accessProofHeaders = request.Header.Clone()
			body, readErr := request.GetBody()
			if readErr == nil && body != nil {
				defer body.Close()
				encoded, _ := io.ReadAll(body)
				accessRequestBody = string(encoded)
			}
		}
		recorded := httptest.NewRecorder()
		access.Handler().ServeHTTP(recorded, request)
		accessStatus = recorded.Code
		accessResponseBody = recorded.Body.String()
		for name, values := range recorded.Header() {
			for _, value := range values {
				response.Header().Add(name, value)
			}
		}
		response.WriteHeader(recorded.Code)
		_, _ = response.Write(recorded.Body.Bytes())
	}))

	agent, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	personResult, err := agent.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatal("person-token request did not complete")
	}
	resourceToken, err := agent.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken,
		Scopes: []string{scope}, Account: &account, Budget: &requested,
	})
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	})
	if err != nil {
		t.Fatalf("exchange: %v; Person Server response=%d %s; PS metadata=%d consent=%d ceiling=%d; Access Server response=%d %s; request=%s",
			err, personExchangeStatus, personExchangeBody, personMetadataChecks.Load(), consentCalls.Load(), ceilingCalls.Load(),
			accessStatus, accessResponseBody, accessRequestBody)
	}

	if accessPolicyRequest.Budget == nil || !integrationSameBudget(*accessPolicyRequest.Budget, personCeiling) ||
		accessPolicyRequest.Account == nil || *accessPolicyRequest.Account != account ||
		!slices.Equal(accessPolicyRequest.Scopes, []string{scope}) {
		t.Fatalf("Access Server policy request = %#v", accessPolicyRequest)
	}
	if personMetadataChecks.Load() != 1 || accessMetadataChecks.Load() != 1 {
		t.Fatalf("Budget metadata checks: Person Server=%d Access Server=%d, want 1/1",
			personMetadataChecks.Load(), accessMetadataChecks.Load())
	}
	if !strings.Contains(accessRequestBody, `"budget":{"amount":450000,"unit":"USD","decimals":6}`) {
		t.Fatalf("signed PS-to-AS request did not carry the Person Server ceiling: %s", accessRequestBody)
	}
	if signatureInput := accessProofHeaders.Get("Signature-Input"); !strings.Contains(signatureInput, `"content-type"`) || !strings.Contains(signatureInput, `"content-digest"`) {
		t.Fatalf("PS-to-AS request did not sign its Budget-bearing JSON body: %s", signatureInput)
	}
	verifiedClaims, verifiedGrant, err := budgets.VerifyAuthToken(ctx, authToken, resolver, clock)
	if err != nil || verifiedClaims.Account == nil || *verifiedClaims.Account != account ||
		!integrationSameBudget(verifiedGrant, accessGrant) {
		t.Fatalf("AS-issued Budget = %#v, error %v", verifiedGrant, err)
	}

	call := integrationBudgetCall(t, ctx, agent, resourceID, authToken)
	response, ok := call.result.Response()
	if call.err != nil || !ok || response.StatusCode != http.StatusNoContent {
		t.Fatalf("protected Budget call = result %#v, error %v", call.result, call.err)
	}
	response.Body.Close()
	if feedback := integrationBudgetFeedback(t, call.result); feedback.Remaining() != 175_000 {
		t.Fatalf("remaining Budget = %d, want 175000", feedback.Remaining())
	}
	if protectedCalls.Load() != 1 {
		t.Fatalf("protected calls = %d, want 1", protectedCalls.Load())
	}

	// The Budgets draft makes the PS-to-AS member optional. If the Person
	// Server omits it, the Access Server must use the Resource offer as the
	// ceiling rather than treating Budget as absent.
	omitPersonCeiling.Store(true)
	accessRequestBody = ""
	accessPolicyRequest = accessserver.AuthorizationRequest{}
	if _, err := agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	}); err != nil {
		t.Fatalf("exchange with omitted Person Server ceiling: %v", err)
	}
	if strings.Contains(accessRequestBody, `"budget"`) {
		t.Fatalf("PS-to-AS request carried an omitted Budget ceiling: %s", accessRequestBody)
	}
	if accessPolicyRequest.Budget == nil || !integrationSameBudget(*accessPolicyRequest.Budget, resourceOffer) {
		t.Fatalf("Access Server omission fallback = %#v, want Resource offer", accessPolicyRequest.Budget)
	}

	accessMetadataWrongScale.Store(true)
	_, err = agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	})
	var invalidBudget *aauth.ProblemError
	if !errors.As(err, &invalidBudget) || invalidBudget.Status != http.StatusBadRequest || invalidBudget.Code != "invalid_budget" {
		t.Fatalf("Access Server metadata mismatch error = %v, problem=%#v", err, invalidBudget)
	}

	accessMetadataWrongScale.Store(false)
	accessMetadataFailure.Store(true)
	_, err = agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	})
	var serverFailure *aauth.ProblemError
	if !errors.As(err, &serverFailure) || serverFailure.Status != http.StatusInternalServerError || serverFailure.Code != "server_error" {
		t.Fatalf("Access Server metadata lookup error = %v, problem=%#v", err, serverFailure)
	}
}
