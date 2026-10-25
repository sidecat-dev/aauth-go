package resource

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestBudgetResourcePublishesDeclaredUnitsAndNarrowsAnAuthorizationOffer(t *testing.T) {
	t.Parallel()

	protocol := newBudgetResourceProtocol(t, 200_000, http.NotFoundHandler())
	account := "primary"
	accountChecks := 0
	protocol.config.ValidateAccount = func(_ context.Context, identity PersonIdentity, got string) error {
		accountChecks++
		if identity != (PersonIdentity{Issuer: personIssuer, Subject: "person-1"}) || got != account {
			return errors.New("unexpected Budget account")
		}
		return nil
	}
	var retained BudgetLineage
	protocol.config.Budget.RetainLineage = func(_ context.Context, lineage BudgetLineage) error {
		retained = lineage
		return nil
	}
	protocol.config.Budget.Offer = func(_ context.Context, request BudgetOfferRequest) (budgets.Value, error) {
		if request.Person != (PersonIdentity{Issuer: personIssuer, Subject: "person-1"}) ||
			request.PersonContext.Tenant != "tenant-1" ||
			request.Account == nil || *request.Account != account ||
			len(request.Scope) != 1 || request.Scope[0] != "records.read" ||
			request.Requested.Amount() != 800_000 {
			t.Fatalf("Budget offer request = %#v", request)
		}
		*request.Account = "mutated-by-offer-policy"
		return budgetValue(t, 600_000, protocol.unit), nil
	}
	server := protocol.server(t)

	metadataResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(
		metadataResponse,
		httptest.NewRequest(http.MethodGet, resourceIssuer+"/.well-known/aauth-resource.json", nil),
	)
	if metadataResponse.Code != http.StatusOK {
		t.Fatalf("metadata status = %d, body = %s", metadataResponse.Code, metadataResponse.Body.String())
	}
	var metadata struct {
		BudgetUnits []struct {
			Unit        string `json:"unit"`
			Decimals    int64  `json:"decimals"`
			Maximum     int64  `json:"max"`
			Description string `json:"description"`
		} `json:"budget_units"`
	}
	if err := json.Unmarshal(metadataResponse.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.BudgetUnits) != 1 || metadata.BudgetUnits[0].Unit != "USD" ||
		metadata.BudgetUnits[0].Decimals != 6 || metadata.BudgetUnits[0].Maximum != 1_000_000 ||
		metadata.BudgetUnits[0].Description != "US dollars at micro-dollar precision" {
		t.Fatalf("budget_units = %#v", metadata.BudgetUnits)
	}

	personToken := mintPersonToken(
		t, protocol.personKey, protocol.agentKey.PublicJWK(), protocol.now,
		resourceIssuer, "budget-person-token",
	)
	authorize := signedRequest(
		t, protocol.clock, protocol.agentKey, personToken,
		http.MethodPost, resourceIssuer+"/authorize",
		`{"scope":"records.read","account":"primary","budget":{"amount":800000,"unit":"USD","decimals":6}}`,
	)
	authorizeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(authorizeResponse, authorize)
	if authorizeResponse.Code != http.StatusOK {
		t.Fatalf("authorize status = %d, body = %s", authorizeResponse.Code, authorizeResponse.Body.String())
	}
	var output struct {
		ResourceToken string `json:"resource_token"`
	}
	if err := json.Unmarshal(authorizeResponse.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	claims, offer, _, err := budgets.VerifyResourceToken(
		context.Background(), output.ResourceToken, protocol.resolver, protocol.clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if retained.ResourceToken != (aauth.TokenReference{Issuer: resourceIssuer, JTI: claims.JTI}) ||
		retained.Person != (PersonIdentity{Issuer: personIssuer, Subject: "person-1"}) ||
		retained.PresentedJTI != "budget-person-token" || retained.AgentJKT != thumbprint ||
		retained.Account == nil || *retained.Account != account ||
		retained.PersonContext.Tenant != "tenant-1" || len(retained.Scope) != 1 ||
		retained.Scope[0] != "records.read" || retained.Offer.Amount() != offer.Amount() ||
		!retained.Offer.Unit().Equal(offer.Unit()) ||
		retained.ExpiresAt != claims.ExpiresAt {
		t.Fatalf("retained Budget lineage = %#v", retained)
	}
	if claims.Audience != personIssuer || claims.Account == nil || *claims.Account != account ||
		accountChecks != 1 || offer.Amount() != 600_000 || !offer.Unit().Equal(protocol.unit) {
		t.Fatalf("Resource token claims = %#v, offer = %d %q/%d", claims, offer.Amount(), offer.Unit().Name(), offer.Unit().Decimals())
	}
}

func TestBudgetAuthorizationRefusesUnvalidatedAccountBeforeOfferAndLineage(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		validate   func(context.Context, PersonIdentity, string) error
		wantStatus int
		wantError  string
	}{
		{name: "validator absent", wantStatus: http.StatusBadRequest, wantError: "invalid_account"},
		{name: "account rejected", validate: func(context.Context, PersonIdentity, string) error {
			return errors.Join(ErrInvalidAccount, errors.New("account is unavailable"))
		}, wantStatus: http.StatusBadRequest, wantError: "invalid_account"},
		{name: "validator unavailable", validate: func(context.Context, PersonIdentity, string) error {
			return errors.New("account database is unavailable")
		}, wantStatus: http.StatusInternalServerError, wantError: "server_error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newBudgetResourceProtocol(t, 1, http.NotFoundHandler())
			protocol.config.ValidateAccount = test.validate
			offerCalls := 0
			lineageCalls := 0
			protocol.config.Budget.Offer = func(context.Context, BudgetOfferRequest) (budgets.Value, error) {
				offerCalls++
				return budgetValue(t, 1, protocol.unit), nil
			}
			protocol.config.Budget.RetainLineage = func(context.Context, BudgetLineage) error {
				lineageCalls++
				return nil
			}
			personToken := mintPersonToken(
				t, protocol.personKey, protocol.agentKey.PublicJWK(), protocol.now,
				resourceIssuer, "unvalidated-account-person-token",
			)
			request := signedRequest(
				t, protocol.clock, protocol.agentKey, personToken,
				http.MethodPost, resourceIssuer+"/authorize",
				`{"scope":"records.read","account":"primary","budget":{"amount":1,"unit":"USD","decimals":6}}`,
			)
			response := httptest.NewRecorder()
			protocol.server(t).Handler().ServeHTTP(response, request)
			if response.Code != test.wantStatus || offerCalls != 0 || lineageCalls != 0 {
				t.Fatalf("unvalidated account = status %d offer %d lineage %d body=%s",
					response.Code, offerCalls, lineageCalls, response.Body.String())
			}
			var problem struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || problem.Error != test.wantError {
				t.Fatalf("unvalidated account problem = %#v, %v", problem, err)
			}
		})
	}
}

func TestBudgetAuthorizationUsesTheDeclaredMaximumByDefaultAndRefusesInvalidBudgets(t *testing.T) {
	t.Parallel()

	protocol := newBudgetResourceProtocol(t, 200_000, http.NotFoundHandler())
	server := protocol.server(t)
	personToken := mintPersonToken(
		t, protocol.personKey, protocol.agentKey.PublicJWK(), protocol.now,
		resourceIssuer, "budget-default-person-token",
	)

	for _, test := range []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
		wantAmount int64
	}{
		{
			name: "request below maximum", body: `{"scope":"records.read","budget":{"amount":400000,"unit":"USD","decimals":6}}`,
			wantStatus: http.StatusOK, wantAmount: 400_000,
		},
		{
			name: "request above maximum narrows", body: `{"scope":"records.read","budget":{"amount":2000000,"unit":"USD","decimals":6}}`,
			wantStatus: http.StatusOK, wantAmount: 1_000_000,
		},
		{
			name: "undeclared unit", body: `{"scope":"records.read","budget":{"amount":1,"unit":"tokens","decimals":0}}`,
			wantStatus: http.StatusBadRequest, wantError: "invalid_budget",
		},
		{
			name: "wrong scale", body: `{"scope":"records.read","budget":{"amount":1,"unit":"USD","decimals":2}}`,
			wantStatus: http.StatusBadRequest, wantError: "invalid_budget",
		},
		{
			name: "malformed", body: `{"scope":"records.read","budget":{"amount":1.5,"unit":"USD","decimals":6}}`,
			wantStatus: http.StatusBadRequest, wantError: "invalid_budget",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := signedRequest(
				t, protocol.clock, protocol.agentKey, personToken,
				http.MethodPost, resourceIssuer+"/authorize", test.body,
			)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.wantStatus, response.Body.String())
			}
			if test.wantError != "" {
				var problem struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
					t.Fatal(err)
				}
				if problem.Error != test.wantError {
					t.Fatalf("problem = %#v", problem)
				}
				return
			}
			var output struct {
				ResourceToken string `json:"resource_token"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
				t.Fatal(err)
			}
			_, offer, _, err := budgets.VerifyResourceToken(
				context.Background(), output.ResourceToken, protocol.resolver, protocol.clock,
			)
			if err != nil {
				t.Fatal(err)
			}
			if offer.Amount() != test.wantAmount {
				t.Fatalf("offer amount = %d, want %d", offer.Amount(), test.wantAmount)
			}
		})
	}

	t.Run("omitted Budget remains omitted", func(t *testing.T) {
		request := signedRequest(
			t, protocol.clock, protocol.agentKey, personToken,
			http.MethodPost, resourceIssuer+"/authorize", `{"scope":"records.read"}`,
		)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		var output struct {
			ResourceToken string `json:"resource_token"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
			t.Fatal(err)
		}
		if carries, err := budgets.TokenCarriesClaims(output.ResourceToken); err != nil || carries {
			t.Fatalf("omitted Budget token carries claims = %t, %v", carries, err)
		}
	})
}

func TestBudgetResourceMaySelectAnotherDeclaredDenomination(t *testing.T) {
	t.Parallel()

	protocol := newBudgetResourceProtocol(t, 1, http.NotFoundHandler())
	tokens, err := budgets.NewUnit("tokens", 0)
	if err != nil {
		t.Fatal(err)
	}
	tokenDeclaration, err := budgets.NewBoundedUnitDeclaration(tokens, 2_000_000, "Model tokens")
	if err != nil {
		t.Fatal(err)
	}
	protocol.config.Budget.Units = append(protocol.config.Budget.Units, tokenDeclaration)
	protocol.config.Budget.Offer = func(_ context.Context, request BudgetOfferRequest) (budgets.Value, error) {
		if request.Requested.Amount() != 800_000 || !request.Requested.Unit().Equal(tokens) {
			return budgets.Value{}, errors.New("unexpected conversion input")
		}
		return budgetValue(t, 600_000, protocol.unit), nil
	}
	server := protocol.server(t)
	personToken := mintPersonToken(
		t, protocol.personKey, protocol.agentKey.PublicJWK(), protocol.now,
		resourceIssuer, "budget-conversion-person-token",
	)
	request := signedRequest(
		t, protocol.clock, protocol.agentKey, personToken,
		http.MethodPost, resourceIssuer+"/authorize",
		`{"scope":"records.read","budget":{"amount":800000,"unit":"tokens","decimals":0}}`,
	)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
	var output struct {
		ResourceToken string `json:"resource_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	_, offer, _, err := budgets.VerifyResourceToken(context.Background(), output.ResourceToken, protocol.resolver, protocol.clock)
	if err != nil || offer.Amount() != 600_000 || !offer.Unit().Equal(protocol.unit) {
		t.Fatalf("converted offer = %#v, %v", offer, err)
	}
}

func TestMeteredApplicationFailureStaysOnTheHeaderAndTheLedger(t *testing.T) {
	t.Parallel()

	protectedCalls := 0
	protocol := newBudgetResourceProtocol(t, 200_000, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		protectedCalls++
		http.Error(response, "boom", http.StatusInternalServerError)
	}))
	protocol.config.Budget.Challenge = protocol.challenge(t, nil)
	grant := budgetValue(t, 200_000, protocol.unit)
	authToken := protocol.authToken(t, "failed-after-meter", grant)
	server := protocol.server(t)

	failed := protocol.call(t, server, authToken)
	if failed.Code != http.StatusInternalServerError || protectedCalls != 1 {
		t.Fatalf("status = %d, protected = %d, body = %s", failed.Code, protectedCalls, failed.Body.String())
	}
	feedback, err := budgets.ParseFeedback(failed.Header().Values("AAuth-Budget"))
	if err != nil {
		t.Fatal(err)
	}
	cost, hasCost := feedback.Cost()
	if !hasCost || cost != 200_000 || feedback.Remaining() != 0 {
		t.Fatalf("failed-call feedback = cost %d/%t remaining %d", cost, hasCost, feedback.Remaining())
	}
	if consumed := protocol.store.personConsumed(personIssuer, "person-1", resourceIssuer); consumed != 200_000 {
		t.Fatalf("person ledger after failed call = %d", consumed)
	}

	refusal := protocol.call(t, server, authToken)
	assertBudgetRefusal(
		t, refusal, budgets.ReasonBudgetExhausted,
		0, 0, false, protocol.unit, protocol.resolver, protocol.clock,
	)
	if protectedCalls != 1 {
		t.Fatalf("exhausted follow-up dispatched the application: protected = %d", protectedCalls)
	}
	requirement, _, err := budgets.ParseAuthTokenRequirement(refusal.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, record, err := budgets.VerifyResourceToken(context.Background(), requirement.ResourceToken, protocol.resolver, protocol.clock)
	if err != nil || record == nil || record.JTI() != "failed-after-meter" || record.Consumed() != 200_000 {
		t.Fatalf("consumption record = %#v, %v", record, err)
	}
}

func TestBudgetProtectedCallChargesOnceAndRetainedStoreSurvivesResourceRecomposition(t *testing.T) {
	t.Parallel()

	protectedCalls := 0
	protocol := newBudgetResourceProtocol(t, 200_000, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		protectedCalls++
		response.WriteHeader(http.StatusNoContent)
	}))
	challengeReasons := make([]budgets.Reason, 0, 1)
	protocol.config.Budget.Challenge = protocol.challenge(t, func(request BudgetChallengeRequest) {
		challengeReasons = append(challengeReasons, request.Reason)
	})
	grant := budgetValue(t, 500_000, protocol.unit)
	authToken := protocol.authToken(t, "budget-auth-token", grant)

	first := protocol.call(t, protocol.server(t), authToken)
	assertBudgetSuccess(t, first, 200_000, 300_000, protocol.unit)

	// Reconstruct the Resource around the same retained store. The second call
	// must continue the first process's token-local and person ledgers.
	second := protocol.call(t, protocol.server(t), authToken)
	assertBudgetSuccess(t, second, 200_000, 100_000, protocol.unit)

	third := protocol.call(t, protocol.server(t), authToken)
	assertBudgetRefusal(
		t, third, budgets.ReasonInsufficientBudget,
		100_000, 200_000, true, protocol.unit, protocol.resolver, protocol.clock,
	)
	if protectedCalls != 2 {
		t.Fatalf("Protected calls = %d, want 2", protectedCalls)
	}
	if len(challengeReasons) != 1 || challengeReasons[0] != budgets.ReasonInsufficientBudget {
		t.Fatalf("challenge reasons = %#v", challengeReasons)
	}
	if consumed := protocol.store.personConsumed(personIssuer, "person-1", resourceIssuer); consumed != 400_000 {
		t.Fatalf("person consumed = %d, want 400000", consumed)
	}
	state := protocol.store.tokens[aauth.TokenReference{Issuer: personIssuer, JTI: "budget-auth-token"}]
	thumbprint, err := protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if state.charge.AgentJKT != thumbprint || !state.charge.ChargedAt.Equal(protocol.now) {
		t.Fatalf("metered charge attribution = jkt %q at %s", state.charge.AgentJKT, state.charge.ChargedAt)
	}
}

func TestBudgetProtectedCallReportsExhaustionWithoutChargingOrCallingTheApplication(t *testing.T) {
	t.Parallel()

	protectedCalls := 0
	protocol := newBudgetResourceProtocol(t, 200_000, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		protectedCalls++
		response.WriteHeader(http.StatusNoContent)
	}))
	protocol.config.Budget.Challenge = protocol.challenge(t, nil)
	grant := budgetValue(t, 200_000, protocol.unit)
	authToken := protocol.authToken(t, "exhausted-budget-auth-token", grant)

	first := protocol.call(t, protocol.server(t), authToken)
	assertBudgetSuccess(t, first, 200_000, 0, protocol.unit)
	second := protocol.call(t, protocol.server(t), authToken)
	assertBudgetRefusal(
		t, second, budgets.ReasonBudgetExhausted,
		0, 0, false, protocol.unit, protocol.resolver, protocol.clock,
	)
	if protectedCalls != 1 || protocol.store.personConsumed(personIssuer, "person-1", resourceIssuer) != 200_000 {
		t.Fatalf("exhausted call consequences: Protected=%d consumed=%d", protectedCalls, protocol.store.personConsumed(personIssuer, "person-1", resourceIssuer))
	}
	requirement, _, err := budgets.ParseAuthTokenRequirement(second.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, consumed, err := budgets.VerifyResourceToken(context.Background(), requirement.ResourceToken, protocol.resolver, protocol.clock)
	if err != nil || consumed == nil || consumed.JTI() != "exhausted-budget-auth-token" || consumed.Consumed() != 200_000 {
		t.Fatalf("consumption record = %#v, %v", consumed, err)
	}
}

func TestBudgetProtectedCallEnforcesTheCapAtomicallyAcrossConcurrentRequests(t *testing.T) {
	t.Parallel()

	protectedCalls := 0
	var protectedMu sync.Mutex
	protocol := newBudgetResourceProtocol(t, 600_000, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		protectedMu.Lock()
		protectedCalls++
		protectedMu.Unlock()
		response.WriteHeader(http.StatusNoContent)
	}))
	protocol.config.Budget.Challenge = protocol.challenge(t, nil)
	authToken := protocol.authToken(t, "concurrent-budget-auth-token", budgetValue(t, 1_000_000, protocol.unit))
	server := protocol.server(t)

	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, 2)
	var calls sync.WaitGroup
	for index := 0; index < 2; index++ {
		calls.Add(1)
		go func() {
			defer calls.Done()
			<-start
			responses <- protocol.call(t, server, authToken)
		}()
	}
	close(start)
	calls.Wait()
	close(responses)

	statuses := map[int]int{}
	for response := range responses {
		statuses[response.Code]++
	}
	if statuses[http.StatusNoContent] != 1 || statuses[http.StatusUnauthorized] != 1 {
		t.Fatalf("concurrent statuses = %#v", statuses)
	}
	protectedMu.Lock()
	defer protectedMu.Unlock()
	if protectedCalls != 1 || protocol.store.personConsumed(personIssuer, "person-1", resourceIssuer) != 600_000 {
		t.Fatalf("concurrent consequences: Protected=%d consumed=%d", protectedCalls, protocol.store.personConsumed(personIssuer, "person-1", resourceIssuer))
	}
}

func TestBudgetProtectedCallFailsClosedBeforeApplicationDispatch(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		configure func(*budgetResourceProtocol)
		budgeted  bool
	}{
		{
			name:      "auth token has no signed Budget",
			configure: func(*budgetResourceProtocol) {},
			budgeted:  false,
		},
		{
			name: "cost policy fails",
			configure: func(protocol *budgetResourceProtocol) {
				protocol.config.Budget.Cost = func(context.Context, BudgetCostRequest) (int64, error) {
					return 0, errors.New("price unavailable")
				}
			},
			budgeted: true,
		},
		{
			name: "store fails",
			configure: func(protocol *budgetResourceProtocol) {
				protocol.store.failure = errors.New("ledger unavailable")
			},
			budgeted: true,
		},
		{
			name: "store reports a conflicting token binding",
			configure: func(protocol *budgetResourceProtocol) {
				protocol.store.failure = ErrBudgetConflict
			},
			budgeted: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			protectedCalls := 0
			protocol := newBudgetResourceProtocol(t, 200_000, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				protectedCalls++
			}))
			protocol.config.Budget.Challenge = protocol.challenge(t, nil)
			test.configure(protocol)
			var authToken string
			if test.budgeted {
				authToken = protocol.authToken(t, "failed-budget-auth-token", budgetValue(t, 500_000, protocol.unit))
			} else {
				authToken = protocol.coreAuthToken(t, "unbudgeted-auth-token")
			}
			response := protocol.call(t, protocol.server(t), authToken)
			if test.budgeted && response.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500; body = %s", response.Code, response.Body.String())
			}
			if !test.budgeted && response.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body = %s", response.Code, response.Body.String())
			}
			if protectedCalls != 0 || protocol.store.personConsumed(personIssuer, "person-1", resourceIssuer) != 0 {
				t.Fatalf("failed request consequences: Protected=%d consumed=%d", protectedCalls, protocol.store.personConsumed(personIssuer, "person-1", resourceIssuer))
			}
		})
	}
}

func TestBudgetRefusalWithInvalidHostChallengeFailsClosed(t *testing.T) {
	t.Parallel()

	protectedCalls := 0
	protocol := newBudgetResourceProtocol(t, 200_000, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		protectedCalls++
	}))
	protocol.config.Budget.Challenge = func(context.Context, BudgetChallengeRequest) (string, error) {
		return "not-a-resource-token", nil
	}
	authToken := protocol.authToken(t, "invalid-challenge-auth-token", budgetValue(t, 100_000, protocol.unit))
	response := protocol.call(t, protocol.server(t), authToken)
	if response.Code != http.StatusInternalServerError || protectedCalls != 0 {
		t.Fatalf("invalid challenge status=%d Protected=%d body=%s", response.Code, protectedCalls, response.Body.String())
	}
	if response.Header().Get("AAuth-Requirement") != "" {
		t.Fatalf("invalid challenge exposed headers: requirement=%q budget=%q", response.Header().Get("AAuth-Requirement"), response.Header().Get("AAuth-Budget"))
	}
	feedback, err := budgets.ParseFeedback(response.Header().Values("AAuth-Budget"))
	if err != nil {
		t.Fatal(err)
	}
	if cost, ok := feedback.Cost(); !ok || cost != 0 || feedback.Remaining() != 100_000 {
		t.Fatalf("refusal feedback=%#v", feedback)
	}
}

func TestBudgetRefusalRejectsAValidlySignedChallengeForAnotherContext(t *testing.T) {
	t.Parallel()

	protectedCalls := 0
	protocol := newBudgetResourceProtocol(t, 200_000, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		protectedCalls++
	}))
	protocol.config.Budget.Challenge = func(_ context.Context, request BudgetChallengeRequest) (string, error) {
		return protocol.challengeToken(t, request, func(claims *aauth.ResourceTokenClaims, _ *budgets.Value) {
			claims.Tenant = "other-tenant"
		})
	}
	authToken := protocol.authToken(t, "wrong-context-challenge", budgetValue(t, 100_000, protocol.unit))
	response := protocol.call(t, protocol.server(t), authToken)
	if response.Code != http.StatusInternalServerError || protectedCalls != 0 {
		t.Fatalf("wrong-context challenge status=%d Protected=%d body=%s", response.Code, protectedCalls, response.Body.String())
	}
	if response.Header().Get("AAuth-Requirement") != "" {
		t.Fatalf("wrong-context challenge exposed headers: requirement=%q budget=%q", response.Header().Get("AAuth-Requirement"), response.Header().Get("AAuth-Budget"))
	}
	feedback, err := budgets.ParseFeedback(response.Header().Values("AAuth-Budget"))
	if err != nil {
		t.Fatal(err)
	}
	if cost, ok := feedback.Cost(); !ok || cost != 0 || feedback.Remaining() != 100_000 {
		t.Fatalf("refusal feedback=%#v", feedback)
	}
}

func TestBudgetRefusalRejectsAChallengeNamingTheRetainedPersonToken(t *testing.T) {
	t.Parallel()

	protectedCalls := 0
	protocol := newBudgetResourceProtocol(t, 200_000, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		protectedCalls++
	}))
	protocol.config.Budget.Challenge = func(_ context.Context, request BudgetChallengeRequest) (string, error) {
		return protocol.challengeToken(t, request, func(claims *aauth.ResourceTokenClaims, _ *budgets.Value) {
			claims.PresentedJTI = "retained-person-token"
		})
	}
	authToken := protocol.authToken(t, "person-jti-challenge-auth-token", budgetValue(t, 100_000, protocol.unit))
	response := protocol.call(t, protocol.server(t), authToken)
	if response.Code != http.StatusInternalServerError || protectedCalls != 0 {
		t.Fatalf("person-token challenge status=%d Protected=%d body=%s", response.Code, protectedCalls, response.Body.String())
	}
	if response.Header().Get("AAuth-Requirement") != "" {
		t.Fatalf("person-token challenge exposed headers: requirement=%q budget=%q", response.Header().Get("AAuth-Requirement"), response.Header().Get("AAuth-Budget"))
	}
	feedback, err := budgets.ParseFeedback(response.Header().Values("AAuth-Budget"))
	if err != nil {
		t.Fatal(err)
	}
	if cost, ok := feedback.Cost(); !ok || cost != 0 || feedback.Remaining() != 100_000 {
		t.Fatalf("refusal feedback=%#v", feedback)
	}
}

func TestBudgetStoreBindsAnAuthTokenReferenceToOneGrantAndContext(t *testing.T) {
	t.Parallel()

	protectedCalls := 0
	protocol := newBudgetResourceProtocol(t, 200_000, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		protectedCalls++
		response.WriteHeader(http.StatusNoContent)
	}))
	protocol.config.Budget.Challenge = protocol.challenge(t, nil)
	server := protocol.server(t)
	first := protocol.authToken(t, "rebound-budget-token", budgetValue(t, 500_000, protocol.unit))
	second := protocol.authToken(t, "rebound-budget-token", budgetValue(t, 600_000, protocol.unit))
	assertBudgetSuccess(t, protocol.call(t, server, first), 200_000, 300_000, protocol.unit)
	conflict := protocol.call(t, server, second)
	if conflict.Code != http.StatusInternalServerError || protectedCalls != 1 {
		t.Fatalf("rebound token status=%d Protected=%d body=%s", conflict.Code, protectedCalls, conflict.Body.String())
	}
	if consumed := protocol.store.personConsumed(personIssuer, "person-1", resourceIssuer); consumed != 200_000 {
		t.Fatalf("person consumed after conflict = %d, want 200000", consumed)
	}
}

func TestBudgetUnsupportedGrantShapesStopBeforePoliciesStoresAndPersonResolution(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		token func(*budgetResourceProtocol) string
	}{
		{
			name: "no signed Budget",
			token: func(protocol *budgetResourceProtocol) string {
				return protocol.coreAuthToken(t, "early-unbudgeted-token")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requiredScopes, resolved, costed, protected int
			protocol := newBudgetResourceProtocol(t, 1, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				protected++
			}))
			protocol.config.RequiredScopes = func(*http.Request) []string {
				requiredScopes++
				return []string{"records.read"}
			}
			protocol.config.ResolvePerson = func(context.Context, PersonIdentity, PersonContext) error {
				resolved++
				return nil
			}
			protocol.config.Budget.Cost = func(_ context.Context, request BudgetCostRequest) (int64, error) {
				costed++
				if request.Request == nil || request.Principal.Subject == "" || request.Grant.Amount() == 0 {
					return 0, errors.New("incomplete Budget cost input")
				}
				return 1, nil
			}
			statuses := &countingBudgetAuthTokenStore{}
			protocol.config.AuthTokenStatuses = statuses
			response := protocol.call(t, protocol.server(t), test.token(protocol))
			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body = %s", response.Code, response.Body.String())
			}
			if requiredScopes != 0 || resolved != 0 || costed != 0 || protected != 0 ||
				protocol.store.chargeCount() != 0 || statuses.observeCount() != 0 {
				t.Fatalf(
					"early refusal callbacks: statuses=%d scopes=%d resolved=%d cost=%d charges=%d protected=%d",
					statuses.observeCount(), requiredScopes, resolved, costed, protocol.store.chargeCount(), protected,
				)
			}
		})
	}
}

func TestBudgetAccountBoundGrantPreservesContextAtProtectedUse(t *testing.T) {
	t.Parallel()

	account := "primary"
	var principal AuthPrincipal
	protocol := newBudgetResourceProtocol(t, 25_000, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var ok bool
		principal, ok = AuthPrincipalFromContext(request.Context())
		if !ok {
			t.Fatal("protected request omitted Auth principal")
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	protocol.config.ValidateAccount = func(context.Context, PersonIdentity, string) error { return nil }
	protocol.config.Budget.Cost = func(_ context.Context, request BudgetCostRequest) (int64, error) {
		if request.Principal.Account == nil || *request.Principal.Account != account {
			return 0, errors.New("Budget pricing omitted the validated account")
		}
		return 25_000, nil
	}
	grant := budgetValue(t, 100_000, protocol.unit)
	token := protocol.authTokenWith(t, "account-budget-token", grant, func(claims *aauth.AuthTokenClaims) {
		claims.Account = &account
	})
	assertBudgetSuccess(t, protocol.call(t, protocol.server(t), token), 25_000, 75_000, protocol.unit)
	if principal.Account == nil || *principal.Account != account {
		t.Fatalf("protected principal account = %#v", principal.Account)
	}
	protocol.store.mu.Lock()
	retained := protocol.store.tokens[aauth.TokenReference{Issuer: personIssuer, JTI: "account-budget-token"}].charge
	protocol.store.mu.Unlock()
	if retained.Account == nil || *retained.Account != account {
		t.Fatalf("retained Budget charge account = %#v", retained.Account)
	}
}

func TestBudgetProtectedUseFollowsTheSignedGrantAcrossMetadataChanges(t *testing.T) {
	t.Parallel()

	protected := 0
	protocol := newBudgetResourceProtocol(t, 200_000, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		protected++
		response.WriteHeader(http.StatusNoContent)
	}))
	priorUnit, err := budgets.NewUnit("prior-credits", 3)
	if err != nil {
		t.Fatal(err)
	}
	grant := budgetValue(t, 500_000, priorUnit)
	protocol.config.Budget.Cost = func(_ context.Context, request BudgetCostRequest) (int64, error) {
		if !request.Grant.Unit().Equal(priorUnit) {
			return 0, errors.New("pricing did not receive the signed historical denomination")
		}
		return 200_000, nil
	}
	response := protocol.call(t, protocol.server(t), protocol.authToken(t, "prior-metadata-auth-token", grant))
	if response.Code != http.StatusNoContent || protected != 1 {
		t.Fatalf("status=%d Protected=%d body=%s", response.Code, protected, response.Body.String())
	}
	feedback, err := budgets.ParseFeedback(response.Header().Values("AAuth-Budget"))
	if err != nil {
		t.Fatal(err)
	}
	unit, present := feedback.Unit()
	if !present || !unit.Equal(priorUnit) || feedback.Remaining() != 300_000 {
		t.Fatalf("feedback = %#v", feedback)
	}
}

func TestBudgetConfigurationIsCompleteOrAbsent(t *testing.T) {
	t.Parallel()

	valid := newBudgetResourceProtocol(t, 1, http.NotFoundHandler()).config
	for _, test := range []struct {
		name   string
		change func(*BudgetConfig)
	}{
		{name: "units", change: func(config *BudgetConfig) { config.Units = nil }},
		{name: "duplicate unit", change: func(config *BudgetConfig) { config.Units = append(config.Units, config.Units[0]) }},
		{name: "invalid declaration", change: func(config *BudgetConfig) { config.Units[0] = budgets.UnitDeclaration{} }},
		{name: "missing maximum", change: func(config *BudgetConfig) {
			unbounded, _ := budgets.NewUnitDeclaration(config.Units[0].Unit(), "")
			config.Units[0] = unbounded
		}},
		{name: "cost", change: func(config *BudgetConfig) { config.Cost = nil }},
		{name: "store", change: func(config *BudgetConfig) { config.Store = nil }},
		{name: "lineage retention", change: func(config *BudgetConfig) { config.RetainLineage = nil }},
		{name: "challenge", change: func(config *BudgetConfig) { config.Challenge = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			budgetCopy := *valid.Budget
			budgetCopy.Units = append([]budgets.UnitDeclaration(nil), valid.Budget.Units...)
			config.Budget = &budgetCopy
			test.change(config.Budget)
			if server, err := NewPSAuthorization(config); err == nil {
				t.Fatalf("NewPSAuthorization() = %#v, want error", server)
			}
		})
	}

}

func TestBudgetAuthorizationWithholdsTokenWhenLineageRetentionFails(t *testing.T) {
	t.Parallel()

	protocol := newBudgetResourceProtocol(t, 1, http.NotFoundHandler())
	protocol.config.Budget.RetainLineage = func(context.Context, BudgetLineage) error {
		return errors.New("lineage store unavailable")
	}
	server := protocol.server(t)
	personToken := mintPersonToken(
		t, protocol.personKey, protocol.agentKey.PublicJWK(), protocol.now,
		resourceIssuer, "budget-lineage-failure-person-token",
	)
	request := signedRequest(
		t, protocol.clock, protocol.agentKey, personToken,
		http.MethodPost, resourceIssuer+"/authorize",
		`{"scope":"records.read","budget":{"amount":1,"unit":"USD","decimals":6}}`,
	)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "resource_token") {
		t.Fatalf("lineage retention failure status=%d body=%s", response.Code, response.Body.String())
	}
}

type budgetResourceProtocol struct {
	now         time.Time
	clock       aauth.Clock
	personKey   joseSigningKeyAlias
	resourceKey joseSigningKeyAlias
	agentKey    joseSigningKeyAlias
	resolver    signaturekey.StaticKeyResolver
	unit        budgets.Unit
	store       *budgetMemoryStore
	config      PSAuthorizationConfig
}

// joseSigningKeyAlias keeps this test fixture declaration compact while using
// the same public signing-key type as the package helpers.
type joseSigningKeyAlias = jose.SigningKey

func newBudgetResourceProtocol(t *testing.T, cost int64, protected http.Handler) *budgetResourceProtocol {
	t.Helper()
	now := time.Date(2026, 8, 31, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "budget-person", 71)
	resourceKey := testSigningKey(t, "budget-resource", 72)
	agentKey := testSigningKey(t, "budget-agent", 73)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := budgets.NewBoundedUnitDeclaration(
		unit, 1_000_000, "US dollars at micro-dollar precision",
	)
	if err != nil {
		t.Fatal(err)
	}
	store := newBudgetMemoryStore()
	protocol := &budgetResourceProtocol{
		now: now, clock: clock, personKey: personKey, resourceKey: resourceKey,
		agentKey: agentKey, resolver: resolver, unit: unit, store: store,
	}
	protocol.config = PSAuthorizationConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "budget-resource-token" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected:         protected,
		Budget: &BudgetConfig{
			Units: []budgets.UnitDeclaration{declaration},
			RetainLineage: func(context.Context, BudgetLineage) error {
				return nil
			},
			Cost: func(_ context.Context, request BudgetCostRequest) (int64, error) {
				if request.Request == nil || !request.Grant.Unit().Equal(unit) {
					return 0, errors.New("unexpected Budget pricing input")
				}
				return cost, nil
			},
			Store: store,
			Challenge: func(context.Context, BudgetChallengeRequest) (string, error) {
				return "", nil
			},
		},
	}
	return protocol
}

func (protocol *budgetResourceProtocol) server(t *testing.T) *Server {
	t.Helper()
	server, err := NewPSAuthorization(protocol.config)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func (protocol *budgetResourceProtocol) authToken(t *testing.T, jti string, grant budgets.Value) string {
	t.Helper()
	return protocol.authTokenWith(t, jti, grant, nil)
}

func (protocol *budgetResourceProtocol) authTokenWith(
	t *testing.T,
	jti string,
	grant budgets.Value,
	mutate func(*aauth.AuthTokenClaims),
) string {
	t.Helper()
	claims := aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		JTI: jti, PersonServer: personIssuer, Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(time.Hour).Unix(),
		Scope: "records.read", Tenant: "tenant-1",
	}
	if mutate != nil {
		mutate(&claims)
	}
	compact, err := budgets.MintAuthToken(protocol.personKey, claims, grant)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (protocol *budgetResourceProtocol) coreAuthToken(t *testing.T, jti string) string {
	t.Helper()
	compact, err := aauth.MintAuthToken(protocol.personKey, aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		JTI: jti, PersonServer: personIssuer, Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		IssuedAt:     protocol.now.Unix(), ExpiresAt: protocol.now.Add(time.Hour).Unix(),
		Scope: "records.read", Tenant: "tenant-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (protocol *budgetResourceProtocol) call(t *testing.T, server *Server, authToken string) *httptest.ResponseRecorder {
	t.Helper()
	request := signedRequest(
		t, protocol.clock, protocol.agentKey, authToken,
		http.MethodGet, resourceIssuer+"/records", "",
	)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func (protocol *budgetResourceProtocol) challenge(
	t *testing.T,
	observe func(BudgetChallengeRequest),
) func(context.Context, BudgetChallengeRequest) (string, error) {
	t.Helper()
	return func(_ context.Context, request BudgetChallengeRequest) (string, error) {
		if observe != nil {
			observe(request)
		}
		return protocol.challengeToken(t, request, nil)
	}
}

func (protocol *budgetResourceProtocol) challengeToken(
	t *testing.T,
	request BudgetChallengeRequest,
	mutate func(*aauth.ResourceTokenClaims, *budgets.Value),
) (string, error) {
	t.Helper()
	thumbprint, err := request.Principal.Confirmation.Thumbprint()
	if err != nil {
		return "", err
	}
	claims := aauth.ResourceTokenClaims{
		Issuer: resourceIssuer, DWK: aauth.ResourceDiscoveryDocument,
		Audience: request.Principal.PersonServer, JTI: "replacement-" + request.Token.JTI,
		PersonServer: request.Principal.PersonServer, Subject: request.Principal.Subject,
		PresentedJTI: request.Token.JTI, AgentJKT: thumbprint,
		IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(),
		Scope:       strings.Join(request.Principal.Scope, " "),
		Account:     cloneBudgetAccount(request.Principal.Account),
		MissionS256: request.Principal.MissionS256, Tenant: request.Principal.Tenant,
	}
	offer := request.Grant
	if mutate != nil {
		mutate(&claims, &offer)
	}
	var consumed *budgets.ConsumptionRecord
	if offer.Unit().Equal(request.Grant.Unit()) {
		record, err := budgets.ConsumptionForPresentedGrant(request.Token.JTI, request.Grant, request.Remaining)
		if err != nil {
			return "", err
		}
		consumed = &record
	}
	return budgets.MintResourceToken(protocol.resourceKey, claims, offer, consumed)
}

func assertBudgetSuccess(t *testing.T, response *httptest.ResponseRecorder, cost, remaining int64, unit budgets.Unit) {
	t.Helper()
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", response.Code, response.Body.String())
	}
	feedback, err := budgets.ParseFeedback(response.Header().Values("AAuth-Budget"))
	if err != nil {
		t.Fatal(err)
	}
	gotCost, hasCost := feedback.Cost()
	gotUnit, hasUnit := feedback.Unit()
	if gotCost != cost || !hasCost || feedback.Remaining() != remaining || !hasUnit || !gotUnit.Equal(unit) {
		t.Fatalf("feedback = cost %d/%t remaining %d unit %q/%d/%t", gotCost, hasCost, feedback.Remaining(), gotUnit.Name(), gotUnit.Decimals(), hasUnit)
	}
}

func assertBudgetRefusal(
	t *testing.T,
	response *httptest.ResponseRecorder,
	reason budgets.Reason,
	remaining, required int64,
	hasRequired bool,
	unit budgets.Unit,
	resolver signaturekey.KeyResolver,
	clock aauth.Clock,
) {
	t.Helper()
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", response.Code, response.Body.String())
	}
	requirement, gotReason, err := budgets.ParseAuthTokenRequirement(response.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	if gotReason != reason {
		t.Fatalf("requirement reason = %q, want %q", gotReason, reason)
	}
	_, offer, _, err := budgets.VerifyResourceToken(context.Background(), requirement.ResourceToken, resolver, clock)
	if err != nil || !offer.Unit().Equal(unit) {
		t.Fatalf("challenge Resource token offer = %#v, %v", offer, err)
	}
	feedback, err := budgets.ParseFeedback(response.Header().Values("AAuth-Budget"))
	if err != nil {
		t.Fatal(err)
	}
	gotRequired, gotRequiredPresent := feedback.Required()
	gotUnit, gotUnitPresent := feedback.Unit()
	if feedback.Remaining() != remaining || gotRequired != required || gotRequiredPresent != hasRequired ||
		!gotUnitPresent || !gotUnit.Equal(unit) {
		t.Fatalf("refusal feedback = remaining %d required %d/%t unit %q/%d/%t", feedback.Remaining(), gotRequired, gotRequiredPresent, gotUnit.Name(), gotUnit.Decimals(), gotUnitPresent)
	}
}

func budgetValue(t *testing.T, amount int64, unit budgets.Unit) budgets.Value {
	t.Helper()
	value, err := budgets.NewValue(amount, unit)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

type budgetMemoryStore struct {
	mu      sync.Mutex
	tokens  map[aauth.TokenReference]budgetTokenState
	persons map[budgetPersonKey]int64
	failure error
	charges int
}

type budgetTokenState struct {
	charge   BudgetCharge
	consumed int64
}

type budgetPersonKey struct {
	personServer string
	subject      string
	audience     string
}

func newBudgetMemoryStore() *budgetMemoryStore {
	return &budgetMemoryStore{
		tokens:  make(map[aauth.TokenReference]budgetTokenState),
		persons: make(map[budgetPersonKey]int64),
	}
}

func (store *budgetMemoryStore) Charge(_ context.Context, charge BudgetCharge) (BudgetChargeResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.charges++
	if store.failure != nil {
		return BudgetChargeResult{}, store.failure
	}
	state, exists := store.tokens[charge.Token]
	if exists && !sameBudgetBinding(state.charge, charge) {
		return BudgetChargeResult{}, ErrBudgetConflict
	}
	remaining := charge.Grant.Amount() - state.consumed
	if remaining == 0 {
		return BudgetChargeResult{Remaining: 0}, ErrBudgetExhausted
	}
	if charge.Cost > remaining {
		return BudgetChargeResult{Remaining: remaining}, ErrBudgetInsufficient
	}
	state.charge = cloneBudgetCharge(charge)
	state.consumed += charge.Cost
	store.tokens[charge.Token] = state
	person := budgetPersonKey{charge.PersonServer, charge.Subject, charge.Audience}
	store.persons[person] += charge.Cost
	return BudgetChargeResult{Cost: charge.Cost, Remaining: remaining - charge.Cost}, nil
}

func (store *budgetMemoryStore) chargeCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.charges
}

func (store *budgetMemoryStore) personConsumed(personServer, subject, audience string) int64 {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.persons[budgetPersonKey{personServer, subject, audience}]
}

func sameBudgetBinding(left, right BudgetCharge) bool {
	return left.Token == right.Token && left.PersonServer == right.PersonServer &&
		left.Subject == right.Subject && left.Audience == right.Audience &&
		left.MissionS256 == right.MissionS256 && left.Tenant == right.Tenant &&
		equalBudgetAccount(left.Account, right.Account) &&
		left.Grant.Amount() == right.Grant.Amount() && left.Grant.Unit().Equal(right.Grant.Unit())
}

func equalBudgetAccount(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func cloneBudgetCharge(charge BudgetCharge) BudgetCharge {
	charge.Account = cloneBudgetAccount(charge.Account)
	return charge
}

type countingBudgetAuthTokenStore struct {
	mu       sync.Mutex
	observed int
}

func (store *countingBudgetAuthTokenStore) Observe(context.Context, ObservedAuthToken) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.observed++
	return nil
}

func (*countingBudgetAuthTokenStore) Revoke(context.Context, aauth.RevocationRequest) error {
	return nil
}

func (store *countingBudgetAuthTokenStore) observeCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.observed
}
