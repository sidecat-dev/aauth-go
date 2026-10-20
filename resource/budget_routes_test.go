package resource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Budgets at a99d353, Authorization Endpoint Extensions, permits operation-level
// metering. The host decides which routes require a grant.
func TestBudgetResourceSelectsMeteredRoutes(t *testing.T) {
	for _, test := range []struct {
		name                            string
		budgetToken, metered, exhausted bool
		status                          int
	}{
		{name: "free Core token", status: http.StatusNoContent},
		{name: "metered Core token", metered: true, status: http.StatusForbidden},
		{name: "free Budget token", budgetToken: true, status: http.StatusNoContent},
		{name: "free exhausted Budget token", budgetToken: true, exhausted: true, status: http.StatusNoContent},
		{name: "metered Budget token", budgetToken: true, metered: true, status: http.StatusNoContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			dispatched, priced := 0, 0
			protocol := newBudgetResourceProtocol(t, 2, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				dispatched++
				w.WriteHeader(http.StatusNoContent)
			}))
			protocol.config.Budget.Metered = func(r *http.Request) bool { return r.URL.Path == "/records" }
			cost := protocol.config.Budget.Cost
			protocol.config.Budget.Cost = func(ctx context.Context, req BudgetCostRequest) (int64, error) {
				priced++
				return cost(ctx, req)
			}
			server := protocol.server(t)
			grant := budgetValue(t, 2, protocol.unit)
			token := protocol.coreAuthToken(t, "route-token")
			if test.budgetToken {
				token = protocol.authToken(t, "route-token", grant)
			}
			if test.exhausted {
				if got := protocol.call(t, server, token); got.Code != http.StatusNoContent {
					t.Fatal(got.Body.String())
				}
				dispatched = 0
				priced = 0
			}
			path := "/free"
			if test.metered {
				path = "/records"
			}
			request := signedRequest(t, protocol.clock, protocol.agentKey, token, http.MethodGet, resourceIssuer+path, "")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			wantCalls := 0
			if test.status == http.StatusNoContent {
				wantCalls = 1
			}
			if dispatched != wantCalls {
				t.Fatalf("dispatches=%d want %d", dispatched, wantCalls)
			}
			wantPrices := 0
			if test.metered && test.budgetToken {
				wantPrices = 1
			}
			if priced != wantPrices {
				t.Fatalf("cost policy calls=%d want %d", priced, wantPrices)
			}
			if test.budgetToken {
				feedback, err := budgets.ParseFeedback(response.Header().Values("AAuth-Budget"))
				if err != nil {
					t.Fatal(err)
				}
				expectedCost, expectedRemaining := int64(0), int64(2)
				if test.metered {
					expectedCost = 2
				}
				if test.metered || test.exhausted {
					expectedRemaining = 0
				}
				if cost, ok := feedback.Cost(); !ok || cost != expectedCost || feedback.Remaining() != expectedRemaining {
					t.Fatalf("feedback=%#v", feedback)
				}
			} else if response.Header().Get("AAuth-Budget") != "" {
				t.Fatal("Core token received Budget feedback")
			}
		})
	}
}

// Budgets at a99d353, Sending Rules, requires feedback on Resource errors when the
// meter is available. Scope rejection precedes pricing and application dispatch.
func TestBudgetScopeRefusalReportsUnchargedBalance(t *testing.T) {
	for _, remaining := range []int64{3, 0} {
		t.Run(fmt.Sprintf("remaining=%d", remaining), func(t *testing.T) {
			dispatched := 0
			protocol := newBudgetResourceProtocol(t, 5-remaining, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { dispatched++; w.WriteHeader(http.StatusNoContent) }))
			protocol.config.ScopeDescriptions["records.write"] = "Write records"
			protocol.config.RequiredScopes = func(r *http.Request) []string {
				if r.URL.Path == "/write" {
					return []string{"records.write"}
				}
				return []string{"records.read"}
			}
			token := protocol.authToken(t, "scope-refusal", budgetValue(t, 5, protocol.unit))
			server := protocol.server(t)
			if got := protocol.call(t, server, token); got.Code != http.StatusNoContent {
				t.Fatal(got.Body.String())
			}
			request := signedRequest(t, protocol.clock, protocol.agentKey, token, http.MethodPost, resourceIssuer+"/write", "")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusForbidden || dispatched != 1 {
				t.Fatalf("status=%d dispatches=%d", response.Code, dispatched)
			}
			feedback, err := budgets.ParseFeedback(response.Header().Values("AAuth-Budget"))
			if err != nil {
				t.Fatal(err)
			}
			if cost, ok := feedback.Cost(); !ok || cost != 0 || feedback.Remaining() != remaining {
				t.Fatalf("feedback=%#v", feedback)
			}
			if got := protocol.store.personConsumed(personIssuer, "person-1", resourceIssuer); got != 5-remaining {
				t.Fatalf("consumed=%d", got)
			}
		})
	}
}

func TestBudgetRefusalOmitsFeedbackWhenMeterFails(t *testing.T) {
	protocol := newBudgetResourceProtocol(t, 1, http.NotFoundHandler())
	protocol.config.RequiredScopes = func(*http.Request) []string { return []string{"records.write"} }
	protocol.config.ScopeDescriptions["records.write"] = "Write records"
	protocol.store.failure = errors.New("meter unavailable")
	response := protocol.call(t, protocol.server(t), protocol.authToken(t, "failed-meter", budgetValue(t, 5, protocol.unit)))
	if response.Code != http.StatusForbidden || response.Header().Get("AAuth-Budget") != "" {
		t.Fatalf("status=%d header=%s", response.Code, response.Header())
	}
}

func TestFederatedBudgetStepUpRejectsWrongAudience(t *testing.T) {
	for _, audience := range []string{accessIssuer, personIssuer, "https://other.example"} {
		t.Run(audience, func(t *testing.T) {
			dispatched := 0
			protocol := newBudgetResourceProtocol(t, 2, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { dispatched++ }))
			protocol.resolver[signaturekey.StaticKeyReference{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: protocol.personKey.ID()}] = protocol.personKey.PublicJWK()
			protocol.config.Budget.Challenge = func(_ context.Context, challenge BudgetChallengeRequest) (string, error) {
				return protocol.challengeToken(t, challenge, func(claims *aauth.ResourceTokenClaims, _ *budgets.Value) { claims.Audience = audience })
			}
			config := protocol.config
			server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
				Issuer: config.Issuer, AccessServer: accessIssuer, SigningKey: config.SigningKey, KeyResolver: config.KeyResolver, Clock: config.Clock, NewID: config.NewID,
				ScopeDescriptions: config.ScopeDescriptions, RequiredScopes: config.RequiredScopes, ResolvePerson: config.ResolvePerson, Protected: config.Protected, Budget: config.Budget,
			})
			if err != nil {
				t.Fatal(err)
			}
			token := protocol.authTokenWith(t, "federated-refusal", budgetValue(t, 1, protocol.unit), func(claims *aauth.AuthTokenClaims) {
				claims.Issuer = accessIssuer
				claims.DWK = aauth.AccessDiscoveryDocument
			})
			response := protocol.call(t, server, token)
			expected := http.StatusInternalServerError
			if audience == accessIssuer {
				expected = http.StatusUnauthorized
			}
			if response.Code != expected || dispatched != 0 {
				t.Fatalf("status=%d dispatches=%d body=%s", response.Code, dispatched, response.Body.String())
			}
			if audience != accessIssuer && response.Header().Get("AAuth-Requirement") != "" {
				t.Fatal("wrong-audience challenge released")
			}
		})
	}
}

func TestBudgetRefusalDoesNotInventBalance(t *testing.T) {
	for _, test := range []struct {
		name   string
		result BudgetChargeResult
		err    error
	}{
		{name: "store error", err: errors.New("unavailable")},
		{name: "conflicting binding", err: ErrBudgetConflict},
		{name: "unexpected charge", result: BudgetChargeResult{Cost: 1, Remaining: 4}},
		{name: "negative remainder", result: BudgetChargeResult{Remaining: -1}},
		{name: "remainder exceeds grant", result: BudgetChargeResult{Remaining: 6}},
		{name: "exhaustion with remainder", result: BudgetChargeResult{Remaining: 1}, err: ErrBudgetExhausted},
		{name: "zero-cost insufficiency", result: BudgetChargeResult{Remaining: 1}, err: ErrBudgetInsufficient},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newBudgetResourceProtocol(t, 1, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("refusal dispatched") }))
			protocol.config.ScopeDescriptions["records.write"] = "Write records"
			protocol.config.RequiredScopes = func(*http.Request) []string { return []string{"records.write"} }
			observations := 0
			protocol.config.Budget.Store = budgetStoreFunc(func(_ context.Context, charge BudgetCharge) (BudgetChargeResult, error) {
				observations++
				if charge.Cost != 0 {
					t.Fatalf("refusal attempted charge=%d", charge.Cost)
				}
				return test.result, test.err
			})
			response := protocol.call(t, protocol.server(t), protocol.authToken(t, "balance-fault", budgetValue(t, 5, protocol.unit)))
			if response.Code != http.StatusForbidden || response.Header().Get("AAuth-Budget") != "" || observations != 1 {
				t.Fatalf("status=%d feedback=%q observations=%d", response.Code, response.Header().Get("AAuth-Budget"), observations)
			}
		})
	}
}

func TestBudgetFeedbackRequiresVerifiedRequestAndResourceContext(t *testing.T) {
	for _, kind := range []string{"wrong audience", "wrong issuer role", "changed signature", "foreign authority"} {
		t.Run(kind, func(t *testing.T) {
			protocol := newBudgetResourceProtocol(t, 1, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("invalid call dispatched") }))
			token := protocol.authTokenWith(t, "invalid-context", budgetValue(t, 5, protocol.unit), func(claims *aauth.AuthTokenClaims) {
				if kind == "wrong audience" {
					claims.Audience = "https://other.example"
				}
				if kind == "wrong issuer role" {
					claims.DWK = aauth.AccessDiscoveryDocument
				}
			})
			target := resourceIssuer + "/records"
			if kind == "foreign authority" {
				target = "https://other.example/records"
			}
			request := signedRequest(t, protocol.clock, protocol.agentKey, token, http.MethodGet, target, "")
			if kind == "changed signature" {
				request.Method = http.MethodPost
			}
			response := httptest.NewRecorder()
			protocol.server(t).Handler().ServeHTTP(response, request)
			if response.Code < 400 || response.Header().Get("AAuth-Budget") != "" || protocol.store.charges != 0 {
				t.Fatalf("status=%d feedback=%q meter calls=%d", response.Code, response.Header().Get("AAuth-Budget"), protocol.store.charges)
			}
		})
	}
}

type budgetStoreFunc func(context.Context, BudgetCharge) (BudgetChargeResult, error)

func (charge budgetStoreFunc) Charge(ctx context.Context, request BudgetCharge) (BudgetChargeResult, error) {
	return charge(ctx, request)
}
