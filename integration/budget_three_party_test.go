package integration_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestBudgetDirectThreePartyProactiveAndReactiveFixedPriceJourneys(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 19, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:budget-agent@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
		scope           = "records.read"
	)
	providerKey := newSigningKey(t, "budget-provider")
	agentKey := newSigningKey(t, "budget-agent")
	personKey := newSigningKey(t, "budget-person")
	resourceKey := newSigningKey(t, "budget-resource")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true, Clock: clock,
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
		NewID: func() string { return "budget-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(ctx, aauth.AgentTokenRequest{
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
	personGrant := integrationBudgetValue(t, 400_000, unit)
	account := "primary"
	declaration, err := budgets.NewBoundedUnitDeclaration(
		unit, 1_000_000, "US dollars at micro-dollar precision",
	)
	if err != nil {
		t.Fatal(err)
	}
	personTokens := exampleutil.NewMissionStore()
	personIDs := []string{
		"budget-person-token", "budget-reactive-auth-token", "budget-proactive-auth-token", "budget-reauthorized-auth-token",
		"budget-mission-person-token", "budget-mission-auth-token",
	}
	personPolicyCalls := 0
	missionPolicyCalls := 0
	accountPolicyCalls := 0
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
		Clock: clock, Tokens: personTokens,
		NewID: func() string {
			id := personIDs[0]
			personIDs = personIDs[1:]
			return id
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != resourceID {
				return personserver.Person{}, errors.New("unexpected person binding")
			}
			return personserver.Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: time.Hour}, nil
		},
		Missions: &personserver.MissionConfig{
			Approve: func(_ context.Context, request personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				expiresAt := now.Add(20 * time.Minute)
				return personserver.MissionDecision{
					Description: request.Proposal.Description, ApprovedResources: request.Proposal.Resources, ExpiresAt: &expiresAt,
				}, nil
			},
			ConfirmPersonAcceptedCompletion: func(context.Context, personserver.MissionCompletionPolicyRequest) error { return nil },
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			personPolicyCalls++
			if request.Agent != agentID || request.Resource != resourceID || request.Subject != "person-123" ||
				request.Tenant != "tenant-1" || !slices.Equal(request.Scopes, []string{scope}) ||
				request.Budget == nil || !integrationSameBudget(*request.Budget, resourceOffer) {
				return personserver.AuthorizationDecision{}, errors.New("unexpected Budget authorization context")
			}
			if request.Mission != nil {
				missionPolicyCalls++
				if request.Mission.S256 == "" || request.Mission.Blob.Description != "Read records within a fixed Budget." {
					return personserver.AuthorizationDecision{}, errors.New("unexpected mission Budget context")
				}
			}
			if request.Account != nil {
				accountPolicyCalls++
				if *request.Account != account {
					return personserver.AuthorizationDecision{}, errors.New("unexpected Budget account")
				}
				*request.Account = "mutated-by-person-policy"
			}
			return personserver.AuthorizationDecision{
				Scopes: []string{scope}, Lifetime: 30 * time.Minute, Budget: &personGrant,
			}, nil
		},
		Budget: &personserver.BudgetConfig{ResolveResourceUnits: func(_ context.Context, resource string) ([]budgets.UnitDeclaration, error) {
			if resource != resourceID {
				return nil, errors.New("unexpected Budget metadata Resource")
			}
			return []budgets.UnitDeclaration{declaration}, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	ledger := newIntegrationBudgetStore()
	var cost atomic.Int64
	cost.Store(150_000)
	var protectedCalls atomic.Int64
	var retainedLineage resource.BudgetLineage
	var accountValidationCalls atomic.Int64
	var accountOfferCalls atomic.Int64
	var accountCostCalls atomic.Int64
	var refreshIDs atomic.Int64
	var resourceIDs atomic.Int64
	resourceServer, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return fmt.Sprintf("budget-resource-token-%d", resourceIDs.Add(1)) },
		ScopeDescriptions: map[string]string{scope: "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{scope} },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) ||
				personContext.Tenant != "tenant-1" {
				return errors.New("unexpected Resource person")
			}
			return nil
		},
		ValidateAccount: func(_ context.Context, identity resource.PersonIdentity, got string) error {
			accountValidationCalls.Add(1)
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) || got != account {
				return errors.New("unexpected Resource Budget account")
			}
			return nil
		},
		Budget: &resource.BudgetConfig{
			Units: []budgets.UnitDeclaration{declaration},
			InitialOffer: func(_ context.Context, request resource.BudgetInitialOfferRequest) (budgets.Value, error) {
				if request.Request == nil || request.Request.URL.Path != "/records/reactive" ||
					request.Person != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) ||
					request.PersonContext.Tenant != "tenant-1" || !slices.Equal(request.Scope, []string{scope}) {
					return budgets.Value{}, errors.New("unexpected reactive Resource Budget context")
				}
				return resourceOffer, nil
			},
			RetainLineage: func(_ context.Context, lineage resource.BudgetLineage) error {
				retainedLineage = lineage
				return nil
			},
			Offer: func(_ context.Context, request resource.BudgetOfferRequest) (budgets.Value, error) {
				if !integrationSameBudget(request.Requested, requested) {
					return budgets.Value{}, errors.New("unexpected Resource Budget request")
				}
				if request.Account != nil {
					accountOfferCalls.Add(1)
					if *request.Account != account {
						return budgets.Value{}, errors.New("unexpected Resource Budget offer account")
					}
					*request.Account = "mutated-by-offer-policy"
				}
				return resourceOffer, nil
			},
			Cost: func(_ context.Context, request resource.BudgetCostRequest) (int64, error) {
				if !integrationSameBudget(request.Grant, personGrant) {
					return 0, errors.New("unexpected signed Budget grant at pricing")
				}
				if request.Principal.Account != nil {
					accountCostCalls.Add(1)
					if *request.Principal.Account != account {
						return 0, errors.New("unexpected Budget pricing account")
					}
				}
				return cost.Load(), nil
			},
			Store: ledger,
			Challenge: func(_ context.Context, challenge resource.BudgetChallengeRequest) (string, error) {
				if retainedLineage.PresentedJTI == "" || !integrationSameBudget(challenge.Grant, personGrant) {
					return "", errors.New("missing retained Budget challenge lineage")
				}
				thumbprint, thumbprintErr := agentKey.PublicJWK().Thumbprint()
				if thumbprintErr != nil {
					return "", thumbprintErr
				}
				var consumed *budgets.ConsumptionRecord
				if challenge.Grant.Unit().Equal(resourceOffer.Unit()) {
					record, recordErr := budgets.ConsumptionForPresentedGrant(challenge.Token.JTI, challenge.Grant, challenge.Remaining)
					if recordErr != nil {
						return "", recordErr
					}
					consumed = &record
				}
				return budgets.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
					Issuer: resourceID, DWK: aauth.ResourceDiscoveryDocument,
					Audience:     personServerID,
					JTI:          "budget-refresh-" + time.Unix(refreshIDs.Add(1), 0).Format("150405"),
					PersonServer: personServerID, Subject: retainedLineage.Person.Subject,
					PresentedJTI: challenge.Token.JTI, AgentJKT: thumbprint,
					IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
					Scope: scope, Tenant: retainedLineage.PersonContext.Tenant,
					Account: cloneIntegrationString(challenge.Principal.Account),
				}, resourceOffer, consumed)
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
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, resourceServer.Handler())

	client, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
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
		t.Fatal("Budget person-token request did not complete")
	}
	reactiveRequest, err := http.NewRequest(http.MethodGet, resourceID+"/records/reactive", nil)
	if err != nil {
		t.Fatal(err)
	}
	reactiveResult, err := client.Begin(ctx, clientagent.InitialCall{Request: reactiveRequest, PersonToken: personToken})
	if err != nil {
		t.Fatal(err)
	}
	reactiveRequirement, ok := reactiveResult.AuthorizationRequired()
	if !ok {
		t.Fatalf("reactive first call = %#v, want auth-token requirement", reactiveResult)
	}
	reactiveClaims, reactiveOffer, consumed, err := budgets.VerifyResourceToken(
		ctx, reactiveRequirement.ResourceToken, resolver, clock,
	)
	if err != nil || !integrationSameBudget(reactiveOffer, resourceOffer) || consumed != nil {
		t.Fatalf("reactive Resource Budget = %#v consumed=%#v err=%v", reactiveOffer, consumed, err)
	}
	if retainedLineage.ResourceToken != (aauth.TokenReference{Issuer: reactiveClaims.Issuer, JTI: reactiveClaims.JTI}) ||
		retainedLineage.PresentedJTI == "" || protectedCalls.Load() != 0 {
		t.Fatalf("reactive retained lineage = %#v; protected calls = %d", retainedLineage, protectedCalls.Load())
	}
	reactiveAuthToken, err := client.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: reactiveRequirement.ResourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, reactiveGrant, err := budgets.VerifyAuthToken(ctx, reactiveAuthToken, resolver, clock)
	if err != nil || !integrationSameBudget(reactiveGrant, personGrant) {
		t.Fatalf("reactive Auth Budget = %#v err=%v", reactiveGrant, err)
	}
	reactiveCall := integrationBudgetCall(t, ctx, client, resourceID, reactiveAuthToken)
	reactiveResponse, reactiveOK := reactiveCall.result.Response()
	if reactiveCall.err != nil || !reactiveOK || reactiveResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("reactive Budget call = result %#v, error %v", reactiveCall.result, reactiveCall.err)
	}
	if feedback := integrationBudgetFeedback(t, reactiveCall.result); feedback.Remaining() != 250_000 {
		t.Fatalf("reactive remaining = %d, want 250000", feedback.Remaining())
	}
	reactiveResponse.Body.Close()

	resourceToken, err := client.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken,
		Scopes: []string{scope}, Account: &account, Budget: &requested,
	})
	if err != nil {
		t.Fatal(err)
	}
	initialClaims, offered, consumed, err := budgets.VerifyResourceToken(ctx, resourceToken, resolver, clock)
	if err != nil || initialClaims.Account == nil || *initialClaims.Account != account ||
		!integrationSameBudget(offered, resourceOffer) || consumed != nil {
		t.Fatalf("Resource Budget = %#v consumed=%#v err=%v", offered, consumed, err)
	}
	if retainedLineage.ResourceToken != (aauth.TokenReference{Issuer: initialClaims.Issuer, JTI: initialClaims.JTI}) ||
		retainedLineage.PresentedJTI == "" || retainedLineage.Account == nil || *retainedLineage.Account != account {
		t.Fatalf("retained Budget lineage = %#v", retainedLineage)
	}
	authToken, err := client.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	authClaims, granted, err := budgets.VerifyAuthToken(ctx, authToken, resolver, clock)
	if err != nil || authClaims.Account == nil || *authClaims.Account != account || !integrationSameBudget(granted, personGrant) {
		t.Fatalf("Auth Budget = %#v err=%v", granted, err)
	}

	first := integrationBudgetCall(t, ctx, client, resourceID, authToken)
	firstResponse, firstOK := first.result.Response()
	if first.err != nil || !firstOK || firstResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("first Budget call = result %#v, error %v", first.result, first.err)
	}
	firstFeedback := integrationBudgetFeedback(t, first.result)
	if firstFeedback.Remaining() != 250_000 {
		t.Fatalf("first remaining = %d, want 250000", firstFeedback.Remaining())
	}
	firstResponse.Body.Close()

	cost.Store(200_000)
	start := make(chan struct{})
	results := make(chan integrationBudgetCallResult, 2)
	var calls sync.WaitGroup
	for range 2 {
		calls.Add(1)
		go func() {
			defer calls.Done()
			<-start
			results <- integrationBudgetCall(t, ctx, client, resourceID, authToken)
		}()
	}
	close(start)
	calls.Wait()
	close(results)
	statuses := map[int]int{}
	var stepUp clientagent.BudgetAuthorization
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent Budget call error = %v", result.err)
		}
		feedback := integrationBudgetFeedback(t, result.result)
		if response, ok := result.result.Response(); ok {
			statuses[response.StatusCode]++
			response.Body.Close()
			continue
		}
		authorization, ok := result.result.AuthorizationRequired()
		if !ok {
			t.Fatalf("Budget call returned no response or authorization: %#v", result.result)
		}
		stepUp = authorization
		statuses[http.StatusUnauthorized]++
		reason, reasonOK := authorization.Reason()
		if authorization.ResourceToken() == "" || !reasonOK || reason != budgets.ReasonInsufficientBudget ||
			feedback.Remaining() != 50_000 {
			t.Fatalf("Budget refusal = authorization %#v reason %q/%t feedback %#v", authorization, reason, reasonOK, feedback)
		}
	}
	reauthorizedToken, err := client.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: stepUp.ResourceToken(), PresentedToken: authToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	reauthorizedClaims, reauthorizedGrant, err := budgets.VerifyAuthToken(ctx, reauthorizedToken, resolver, clock)
	if err != nil || reauthorizedClaims.Account == nil || *reauthorizedClaims.Account != account ||
		!integrationSameBudget(reauthorizedGrant, personGrant) {
		t.Fatalf("reauthorized Auth Budget = %#v err=%v", reauthorizedGrant, err)
	}
	retried := integrationBudgetCall(t, ctx, client, resourceID, reauthorizedToken)
	retriedResponse, retriedOK := retried.result.Response()
	if retried.err != nil || !retriedOK || retriedResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("reauthorized Budget retry = result %#v, error %v", retried.result, retried.err)
	}
	if feedback := integrationBudgetFeedback(t, retried.result); feedback.Remaining() != 200_000 {
		t.Fatalf("reauthorized retry remaining = %d, want 200000", feedback.Remaining())
	}
	retriedResponse.Body.Close()
	if statuses[http.StatusNoContent] != 1 || statuses[http.StatusUnauthorized] != 1 ||
		protectedCalls.Load() != 4 || personPolicyCalls != 3 || accountValidationCalls.Load() != 1 ||
		accountPolicyCalls != 2 || accountOfferCalls.Load() != 1 || accountCostCalls.Load() != 4 {
		t.Fatalf("Budget consequences: statuses=%v Protected=%d policy=%d account validation/policy/offer/cost=%d/%d/%d/%d",
			statuses, protectedCalls.Load(), personPolicyCalls, accountValidationCalls.Load(),
			accountPolicyCalls, accountOfferCalls.Load(), accountCostCalls.Load())
	}
	if got := ledger.personTotal(personServerID, "person-123", resourceID); got != 700_000 {
		t.Fatalf("person Budget consumption = %d, want 700000", got)
	}
	mission, err := client.ProposeMission(ctx, clientagent.MissionRequest{
		PersonServer: personServerID,
		Proposal: aauth.MissionProposal{
			Description: "Read records within a fixed Budget.", Resources: []string{resourceID},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	missionPersonToken, ok := mission.PersonToken(resourceID)
	if !ok {
		t.Fatal("mission approval omitted its Resource Person token")
	}
	missionResourceToken, err := client.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: missionPersonToken,
		Scopes: []string{scope}, Budget: &requested,
	})
	if err != nil {
		t.Fatal(err)
	}
	missionResourceClaims, missionOffer, _, err := budgets.VerifyResourceToken(ctx, missionResourceToken, resolver, clock)
	if err != nil || missionResourceClaims.MissionS256 != mission.Mission().S256 || !integrationSameBudget(missionOffer, resourceOffer) {
		t.Fatalf("mission Resource Budget = claims %#v offer %#v err=%v", missionResourceClaims, missionOffer, err)
	}
	missionAuthToken, err := client.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: missionResourceToken, PresentedToken: missionPersonToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	missionAuthClaims, missionGrant, err := budgets.VerifyAuthToken(ctx, missionAuthToken, resolver, clock)
	if err != nil || missionAuthClaims.MissionS256 != mission.Mission().S256 || !integrationSameBudget(missionGrant, personGrant) {
		t.Fatalf("mission Auth Budget = claims %#v grant %#v err=%v", missionAuthClaims, missionGrant, err)
	}
	missionCall := integrationBudgetCall(t, ctx, client, resourceID, missionAuthToken)
	missionResponse, missionOK := missionCall.result.Response()
	if missionCall.err != nil || !missionOK || missionResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("mission Budget call = result %#v, error %v", missionCall.result, missionCall.err)
	}
	missionResponse.Body.Close()
	if feedback := integrationBudgetFeedback(t, missionCall.result); feedback.Remaining() != 200_000 {
		t.Fatalf("mission Budget remaining = %d, want 200000", feedback.Remaining())
	}
	if protectedCalls.Load() != 5 || personPolicyCalls != 4 || missionPolicyCalls != 1 {
		t.Fatalf("mission Budget consequences: protected=%d policy=%d mission-policy=%d", protectedCalls.Load(), personPolicyCalls, missionPolicyCalls)
	}
	if got := ledger.personTotal(personServerID, "person-123", resourceID); got != 900_000 {
		t.Fatalf("person Budget consumption after mission = %d, want 900000", got)
	}
	if err := client.CompleteMission(ctx, clientagent.MissionCompletionRequest{
		PersonServer: personServerID, MissionS256: mission.Mission().S256, Summary: "Budgeted read completed",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: missionResourceToken, PresentedToken: missionPersonToken,
	}); err == nil || !strings.Contains(err.Error(), "mission") {
		t.Fatalf("terminated mission Budget exchange error = %v", err)
	}
	if personPolicyCalls != 4 || missionPolicyCalls != 1 {
		t.Fatalf("terminated mission reached policy: policy=%d mission-policy=%d", personPolicyCalls, missionPolicyCalls)
	}
}

type integrationBudgetCallResult struct {
	result clientagent.BudgetCallResult
	err    error
}

func integrationBudgetCall(
	t *testing.T,
	ctx context.Context,
	client *clientagent.Client,
	resourceID string,
	authToken string,
) integrationBudgetCallResult {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	if err != nil {
		return integrationBudgetCallResult{err: err}
	}
	result, err := client.BeginBudgetCall(ctx, clientagent.BudgetCall{
		Request: request, AuthToken: authToken,
	})
	return integrationBudgetCallResult{result: result, err: err}
}

func integrationBudgetFeedback(t *testing.T, result clientagent.BudgetCallResult) budgets.Feedback {
	t.Helper()
	feedback, ok := result.Feedback()
	if !ok {
		t.Fatal("typed Budget result omitted feedback")
	}
	return feedback
}

func integrationBudgetValue(t *testing.T, amount int64, unit budgets.Unit) budgets.Value {
	t.Helper()
	value, err := budgets.NewValue(amount, unit)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func integrationSameBudget(left, right budgets.Value) bool {
	return left.Amount() == right.Amount() && left.Unit().Equal(right.Unit())
}

type integrationBudgetStore struct {
	mu      sync.Mutex
	tokens  map[aauth.TokenReference]integrationBudgetAccount
	persons map[string]int64
}

type integrationBudgetAccount struct {
	charge   resource.BudgetCharge
	consumed int64
}

func newIntegrationBudgetStore() *integrationBudgetStore {
	return &integrationBudgetStore{
		tokens:  make(map[aauth.TokenReference]integrationBudgetAccount),
		persons: make(map[string]int64),
	}
}

func (store *integrationBudgetStore) Charge(
	_ context.Context,
	charge resource.BudgetCharge,
) (resource.BudgetChargeResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	account, found := store.tokens[charge.Token]
	if found && !integrationSameBudgetCharge(account.charge, charge) {
		return resource.BudgetChargeResult{}, resource.ErrBudgetConflict
	}
	remaining := charge.Grant.Amount() - account.consumed
	if charge.Cost > remaining {
		result := resource.BudgetChargeResult{Remaining: remaining, Consumed: account.consumed}
		if remaining == 0 {
			return result, resource.ErrBudgetExhausted
		}
		return result, resource.ErrBudgetInsufficient
	}
	account.charge = charge
	account.consumed += charge.Cost
	store.tokens[charge.Token] = account
	store.persons[integrationBudgetPersonKey(charge.PersonServer, charge.Subject, charge.Audience)] += charge.Cost
	return resource.BudgetChargeResult{Cost: charge.Cost, Remaining: remaining - charge.Cost}, nil
}

func (store *integrationBudgetStore) personTotal(personServer, subject, resourceID string) int64 {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.persons[integrationBudgetPersonKey(personServer, subject, resourceID)]
}

func integrationBudgetPersonKey(personServer, subject, resourceID string) string {
	return personServer + "\x00" + subject + "\x00" + resourceID
}

func integrationSameBudgetCharge(left, right resource.BudgetCharge) bool {
	return left.Token == right.Token && left.PersonServer == right.PersonServer &&
		left.Subject == right.Subject && left.Audience == right.Audience &&
		left.MissionS256 == right.MissionS256 && left.Tenant == right.Tenant &&
		integrationSameOptionalString(left.Account, right.Account) && integrationSameBudget(left.Grant, right.Grant)
}

func integrationSameOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func cloneIntegrationString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
