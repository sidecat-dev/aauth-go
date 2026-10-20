package resource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
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

// Core at a99d353, Auth Token Verification and Token Revocation, precedes use of a
// credential's grant. Rejected credentials must not reach the Budget ledger.
func TestBudgetFeedbackRejectsInvalidCredentialBeforeMetering(t *testing.T) {
	for _, kind := range []string{"revoked", "conflicting token", "status unavailable", "unsupported account", "undeclared scope"} {
		t.Run(kind, func(t *testing.T) {
			protocol := newBudgetResourceProtocol(t, 1, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("invalid credential dispatched") }))
			statuses := newTestAuthTokenStatusStore()
			protocol.config.AuthTokenStatuses = statuses
			token := protocol.authTokenWith(t, "rejected-credential", budgetValue(t, 5, protocol.unit), func(claims *aauth.AuthTokenClaims) {
				switch kind {
				case "unsupported account":
					account := "account-1"
					claims.Account = &account
				case "undeclared scope":
					claims.Scope = "undeclared"
				}
			})
			reference := aauth.TokenReference{Issuer: personIssuer, JTI: "rejected-credential"}
			want := http.StatusForbidden
			switch kind {
			case "revoked":
				statuses.revoked[reference] = true
				want = http.StatusUnauthorized
			case "conflicting token":
				statuses.records[reference] = ObservedAuthToken{Reference: reference}
			case "status unavailable":
				statuses.observeError = errors.New("status unavailable")
				want = http.StatusInternalServerError
			}
			response := protocol.call(t, protocol.server(t), token)
			if response.Code != want {
				t.Errorf("status=%d want=%d body=%s", response.Code, want, response.Body.String())
			}
			if response.Header().Get("AAuth-Budget") != "" || protocol.store.chargeCount() != 0 || len(protocol.store.tokens) != 0 {
				t.Fatalf("rejected credential reached meter: feedback=%q calls=%d bindings=%d", response.Header().Get("AAuth-Budget"), protocol.store.chargeCount(), len(protocol.store.tokens))
			}
		})
	}
}

// Budgets at a99d353, Sending Rules, permits feedback omission for a meter fault.
// A route that requires no charge remains available when its balance is unknown.
func TestUnmeteredBudgetCallSurvivesMeterFailure(t *testing.T) {
	dispatched := 0
	protocol := newBudgetResourceProtocol(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { dispatched++; w.WriteHeader(http.StatusNoContent) }))
	protocol.config.Budget.Metered = func(*http.Request) bool { return false }
	protocol.config.Budget.Cost = func(context.Context, BudgetCostRequest) (int64, error) { t.Fatal("free route priced"); return 0, nil }
	protocol.store.failure = errors.New("meter unavailable")
	response := protocol.call(t, protocol.server(t), protocol.authToken(t, "free-meter-fault", budgetValue(t, 5, protocol.unit)))
	if response.Code != http.StatusNoContent || dispatched != 1 || response.Header().Get("AAuth-Budget") != "" || protocol.store.chargeCount() != 1 || len(protocol.store.tokens) != 0 {
		t.Fatalf("status=%d dispatched=%d feedback=%q observations=%d bindings=%d", response.Code, dispatched, response.Header().Get("AAuth-Budget"), protocol.store.chargeCount(), len(protocol.store.tokens))
	}
}

func TestBudgetCostPolicyFailureDoesNotObserveBalance(t *testing.T) {
	for _, kind := range []string{"policy error", "invalid cost"} {
		t.Run(kind, func(t *testing.T) {
			protocol := newBudgetResourceProtocol(t, 1, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("failed pricing dispatched") }))
			protocol.config.Budget.Cost = func(context.Context, BudgetCostRequest) (int64, error) {
				if kind == "policy error" {
					return 0, errors.New("price unavailable")
				}
				return -1, nil
			}
			response := protocol.call(t, protocol.server(t), protocol.authToken(t, "pricing-fault", budgetValue(t, 5, protocol.unit)))
			if response.Code != http.StatusInternalServerError || response.Header().Get("AAuth-Budget") != "" || protocol.store.chargeCount() != 0 {
				t.Fatalf("status=%d feedback=%q observations=%d", response.Code, response.Header().Get("AAuth-Budget"), protocol.store.chargeCount())
			}
		})
	}
}

// The implemented combined profile is class-R3 with a fixed Budget. Per-call
// composition remains a gap; it must not reach challenge creation or metering.
func TestR3BudgetPerCallClaimsRejectedBeforeMetering(t *testing.T) {
	protocol := newBudgetResourceProtocol(t, 1, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unsupported composition dispatched") }))
	documents := &r3TestDocumentStore{}
	r3Config := newResourceMCPConfig(t, documents, []string{"records.read"}, func(*http.Request) (string, bool, error) {
		t.Fatal("unsupported composition reached route policy")
		return "", false, nil
	})
	protocol.resolver[signaturekey.StaticKeyReference{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: protocol.personKey.ID()}] = protocol.personKey.PublicJWK()
	config := protocol.config
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: config.Issuer, AccessServer: accessIssuer, SigningKey: config.SigningKey, KeyResolver: config.KeyResolver, Clock: config.Clock, NewID: config.NewID,
		ScopeDescriptions: config.ScopeDescriptions, RequiredScopes: config.RequiredScopes, ResolvePerson: config.ResolvePerson, Protected: config.Protected, Budget: config.Budget, R3: r3Config,
	})
	if err != nil {
		t.Fatal(err)
	}
	base := protocol.authTokenWith(t, "unsupported-per-call", budgetValue(t, 5, protocol.unit), func(claims *aauth.AuthTokenClaims) {
		claims.Issuer = accessIssuer
		claims.DWK = aauth.AccessDiscoveryDocument
	})
	claims, err := aauth.VerifyAuthTokenCore(context.Background(), base, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := mcp.NewOperation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	typed, err := operation.ToR3()
	if err != nil {
		t.Fatal(err)
	}
	granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), typed)
	if err != nil {
		t.Fatal(err)
	}
	grantedJSON, err := json.Marshal(granted)
	if err != nil {
		t.Fatal(err)
	}
	uriJSON, _ := json.Marshal(resourceIssuer + "/r3/class")
	digestJSON, _ := json.Marshal(r3.Digest([]byte("class document")))
	claims.AdditionalClaims["r3_uri"] = uriJSON
	claims.AdditionalClaims["r3_s256"] = digestJSON
	claims.AdditionalClaims["r3_granted"] = grantedJSON
	classToken, err := aauth.MintAuthTokenCore(protocol.personKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	// The same independently signed claims are accepted by the combined verifier
	// before adding r3_per_call, so the negative case isolates that profile limit.
	if _, _, _, _, err := r3.VerifyBudgetAuthToken(context.Background(), r3Config.Registry, classToken, protocol.resolver, protocol.clock); err != nil {
		t.Fatal(err)
	}
	claims.AdditionalClaims["r3_per_call"] = grantedJSON
	token, err := aauth.MintAuthTokenCore(protocol.personKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := r3.VerifyBudgetAuthToken(context.Background(), r3Config.Registry, token, protocol.resolver, protocol.clock); err == nil || !strings.Contains(err.Error(), "the class-R3 Budget profile does not permit r3_per_call") {
		t.Fatalf("combined verifier error=%v", err)
	}
	response := protocol.call(t, server, token)
	if response.Code != http.StatusUnauthorized || response.Header().Get("AAuth-Requirement") != "" || response.Header().Get("AAuth-Budget") != "" || protocol.store.chargeCount() != 0 {
		t.Fatalf("status=%d headers=%v observations=%d", response.Code, response.Header(), protocol.store.chargeCount())
	}
}
