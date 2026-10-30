package resource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// TestHeldBudgetRefusalMetersOnlyTheCompletingToken follows Budgets Deferred
// Delivery through the Resource handler: the refused token is neither
// reserved against nor metered, a completing token that does not fit gets
// another 202 and the call stays held, the token that fits is metered once,
// and its replay is not metered again.
func TestHeldBudgetRefusalMetersOnlyTheCompletingToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "held-budget-resource", 161)
	accessKey := testSigningKey(t, "held-budget-access", 162)
	agentKey := testSigningKey(t, "held-budget-agent", 163)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := budgets.NewBoundedUnitDeclaration(unit, 1_000_000, "US dollars at micro-dollar precision")
	if err != nil {
		t.Fatal(err)
	}
	const cost = 7
	var runs atomic.Int32
	store := newBudgetMemoryStore()
	held := newHeldMemoryStore()
	config := validConfigWithKey(resourceKey, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		runs.Add(1)
		writeJSON(response, http.StatusOK, map[string]string{"report": "ready"})
	}))
	config.Clock = clock
	config.KeyResolver = resolver
	config.AdditionalSignatureComponents = nil
	config.ScopeDescriptions = map[string]string{"records.read": "Read records"}
	config.RequiredScopes = func(*http.Request) []string { return []string{"records.read"} }
	config.MaxRetainedRequestBodyBytes = 64 << 10
	config.MaxRetainedResponseBodyBytes = 64 << 10
	config.MaxRetainedHeaderBytes = 16 << 10
	identifiers := 0
	config.NewID = func() string {
		identifiers++
		return "held-budget-id-" + strings.Repeat("x", identifiers)
	}
	config.HeldInvocations = held
	config.HoldAuthTokenRequest = func(*http.Request) bool { return true }
	config.Budget = &BudgetConfig{
		Units:         []budgets.UnitDeclaration{declaration},
		RetainLineage: func(context.Context, BudgetLineage) error { return nil },
		Cost:          func(context.Context, BudgetCostRequest) (int64, error) { return cost, nil },
		Store:         store,
		Challenge: func(_ context.Context, request BudgetChallengeRequest) (string, error) {
			thumbprint, err := request.Principal.Confirmation.Thumbprint()
			if err != nil {
				return "", err
			}
			consumed, err := budgets.NewConsumptionRecord(request.Token.JTI, request.Consumed)
			if err != nil {
				return "", err
			}
			offer := budgetValue(t, 50, unit)
			return budgets.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
				Issuer: resourceIssuer, DWK: aauth.ResourceDiscoveryDocument, Audience: accessIssuer,
				JTI: "fresh-for-" + request.Token.JTI, PersonServer: request.Principal.PersonServer,
				Subject: request.Principal.Subject, PresentedJTI: request.Token.JTI, AgentJKT: thumbprint,
				IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
				Scope: strings.Join(request.Principal.Scope, " "), Tenant: request.Principal.Tenant,
			}, offer, &consumed)
		},
	}
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	token := func(jti string, amount int64) string {
		compact, err := budgets.MintAuthToken(accessKey, aauth.AuthTokenClaims{
			Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: resourceIssuer,
			JTI: jti, PersonServer: personIssuer, Subject: "person-1",
			Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
			Scope: "records.read", Tenant: "tenant-1",
		}, budgetValue(t, amount, unit))
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	send := func(compact, method, target string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, signedRequest(t, clock, agentKey, compact, method, target, ""))
		return response
	}
	feedback := func(response *httptest.ResponseRecorder) budgets.Feedback {
		t.Helper()
		parsed, err := budgets.ParseFeedback(response.Header().Values("AAuth-Budget"))
		if err != nil {
			t.Fatalf("AAuth-Budget %q: %v", response.Header().Values("AAuth-Budget"), err)
		}
		return parsed
	}
	requireHeldRefusal := func(response *httptest.ResponseRecorder, presented string, remaining int64) {
		t.Helper()
		if response.Code != http.StatusAccepted || response.Header().Get("Location") == "" ||
			response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("held refusal = %d %v %s", response.Code, response.Header(), response.Body.String())
		}
		requirement, reason, err := budgets.ParseAuthTokenRequirement(response.Header().Values("AAuth-Requirement"))
		if err != nil || reason != budgets.ReasonInsufficientBudget {
			t.Fatalf("held refusal requirement = %v, %q", err, reason)
		}
		claims, _, _, err := budgets.VerifyResourceToken(context.Background(), requirement.ResourceToken, resolver, clock)
		if err != nil || claims.PresentedJTI != presented {
			t.Fatalf("held refusal Resource token = %#v, %v; want presented_jti %q", claims, err, presented)
		}
		got := feedback(response)
		required, hasRequired := got.Required()
		_, hasCost := got.Cost()
		_, hasReserved := got.Reserved()
		if got.Remaining() != remaining || !hasRequired || required != cost || hasCost || hasReserved {
			t.Fatalf("held refusal AAuth-Budget = %q", response.Header().Values("AAuth-Budget"))
		}
	}

	refused := send(token("refused-token", 5), http.MethodGet, resourceIssuer+"/records")
	requireHeldRefusal(refused, "refused-token", 5)
	location := refused.Header().Get("Location")
	if runs.Load() != 0 || store.personConsumed(personIssuer, "person-1", resourceIssuer) != 0 {
		t.Fatalf("the refusal ran or metered the call: runs %d", runs.Load())
	}
	// Nothing was reserved against the refused token: its remainder is still
	// available to the agent's other requests.
	if observed, err := store.Charge(context.Background(), BudgetCharge{
		Token: aauth.TokenReference{Issuer: accessIssuer, JTI: "refused-token"}, PersonServer: personIssuer,
		Subject: "person-1", Audience: resourceIssuer, Tenant: "tenant-1", Grant: budgetValue(t, 5, unit),
	}); err != nil || observed.Remaining != 5 {
		t.Fatalf("refused token remainder = %#v, %v; want 5", observed, err)
	}

	short := send(token("short-token", 6), http.MethodGet, location)
	requireHeldRefusal(short, "short-token", 6)
	if short.Header().Get("Location") != location || runs.Load() != 0 || held.rechallenges != 1 {
		t.Fatalf("a completing token that did not fit ran the call or moved it: runs %d", runs.Load())
	}

	completing := token("completing-token", 20)
	completed := send(completing, http.MethodGet, location)
	if completed.Code != http.StatusOK || !strings.Contains(completed.Body.String(), `"ready"`) || runs.Load() != 1 {
		t.Fatalf("completing poll = %d %s, runs %d", completed.Code, completed.Body.String(), runs.Load())
	}
	if got := feedback(completed); got.Remaining() != 13 {
		t.Fatalf("completing AAuth-Budget = %q", completed.Header().Values("AAuth-Budget"))
	} else if paid, ok := got.Cost(); !ok || paid != cost {
		t.Fatalf("completing cost = %d, %t", paid, ok)
	}
	if consumed := store.personConsumed(personIssuer, "person-1", resourceIssuer); consumed != cost {
		t.Fatalf("person ledger = %d, want %d", consumed, cost)
	}

	replayed := send(completing, http.MethodGet, location)
	if replayed.Code != http.StatusOK || replayed.Body.String() != completed.Body.String() || runs.Load() != 1 {
		t.Fatalf("replay = %d %s, runs %d", replayed.Code, replayed.Body.String(), runs.Load())
	}
	got := feedback(replayed)
	paid, hasCost := got.Cost()
	_, hasReserved := got.Reserved()
	if got.Remaining() != 13 || !hasCost || paid != cost || hasReserved {
		t.Fatalf("replay AAuth-Budget = %q", replayed.Header().Values("AAuth-Budget"))
	}
	if consumed := store.personConsumed(personIssuer, "person-1", resourceIssuer); consumed != cost {
		t.Fatalf("person ledger after replay = %d, want %d: the replay was metered again", consumed, cost)
	}

	other := send(token("other-token", 30), http.MethodGet, location)
	if other.Code != http.StatusForbidden || runs.Load() != 1 {
		t.Fatalf("another token after completion = %d %s, runs %d", other.Code, other.Body.String(), runs.Load())
	}
	if consumed := store.personConsumed(personIssuer, "person-1", resourceIssuer); consumed != cost {
		t.Fatalf("person ledger after another token = %d, want %d", consumed, cost)
	}
}
