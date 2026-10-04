package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestDirectPSBudgetPolicyReceivesACopyAndIssuesTheNarrowedGrant(t *testing.T) {
	t.Parallel()

	protocol := newBudgetAuthorizationProtocol(t)
	offer := protocol.value(t, 5_000_000, "USD", 6)
	grant := protocol.value(t, 2_000_000, "USD", 6)
	mutatedPolicyInput := protocol.value(t, 1_000_000, "USD", 6)
	var observed budgets.Value
	server := protocol.server(t, func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
		if request.Budget == nil {
			t.Fatal("authorization policy received no verified Budget offer")
		}
		observed = *request.Budget
		*request.Budget = mutatedPolicyInput
		return AuthorizationDecision{
			Scopes: []string{"records.read"}, Lifetime: 30 * time.Minute, Budget: &grant,
		}, nil
	})

	response := protocol.exchange(t, server, protocol.resourceToken(t, "budget-resource-token", &offer))
	if response.Code != http.StatusOK {
		t.Fatalf("Budget exchange = %d %s", response.Code, response.Body.String())
	}
	if !sameBudgetValue(observed, offer) {
		t.Fatalf("policy Budget = %d %s/%d, want %d %s/%d",
			observed.Amount(), observed.Unit().Name(), observed.Unit().Decimals(),
			offer.Amount(), offer.Unit().Name(), offer.Unit().Decimals())
	}
	output := decodeBudgetAuthorizationOutput(t, response)
	claims, gotGrant, err := budgets.VerifyAuthToken(context.Background(), output.AuthToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if !sameBudgetValue(gotGrant, grant) {
		t.Fatalf("Auth-token Budget = %d %s/%d, want %d %s/%d",
			gotGrant.Amount(), gotGrant.Unit().Name(), gotGrant.Unit().Decimals(),
			grant.Amount(), grant.Unit().Name(), grant.Unit().Decimals())
	}
	if claims.Scope != "records.read" || output.ExpiresIn != int64((30*time.Minute)/time.Second) {
		t.Fatalf("Auth-token Core result = scope %q, expires_in %d", claims.Scope, output.ExpiresIn)
	}
}

func TestDirectPSBudgetDecisionMustPreserveTheVerifiedOffer(t *testing.T) {
	t.Parallel()

	protocol := newBudgetAuthorizationProtocol(t)
	offer := protocol.value(t, 5_000_000, "USD", 6)
	equal := protocol.value(t, 5_000_000, "USD", 6)
	lower := protocol.value(t, 2_000_000, "USD", 6)
	higher := protocol.value(t, 5_000_001, "USD", 6)
	changedUnit := protocol.value(t, 2_000_000, "tokens", 0)
	changedScale := protocol.value(t, 200, "USD", 2)

	for _, test := range []struct {
		name       string
		offer      *budgets.Value
		grant      *budgets.Value
		wantStatus int
	}{
		{name: "equal", offer: &offer, grant: &equal, wantStatus: http.StatusOK},
		{name: "lower", offer: &offer, grant: &lower, wantStatus: http.StatusOK},
		{name: "offered Budget omitted", offer: &offer, wantStatus: http.StatusInternalServerError},
		{name: "amount increased", offer: &offer, grant: &higher, wantStatus: http.StatusInternalServerError},
		{name: "unit changed", offer: &offer, grant: &changedUnit, wantStatus: http.StatusInternalServerError},
		{name: "scale changed", offer: &offer, grant: &changedScale, wantStatus: http.StatusInternalServerError},
		{name: "Budget invented", grant: &lower, wantStatus: http.StatusInternalServerError},
		{name: "ordinary Core unchanged", wantStatus: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			server := protocol.server(t, func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
				calls++
				if (request.Budget == nil) != (test.offer == nil) {
					t.Fatalf("policy Budget presence = %t, want %t", request.Budget != nil, test.offer != nil)
				}
				return AuthorizationDecision{
					Scopes: []string{"records.read"}, Lifetime: time.Minute, Budget: test.grant,
				}, nil
			})
			compact := protocol.resourceToken(t, "decision-"+test.name, test.offer)
			response := protocol.exchange(t, server, compact)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if calls != 1 {
				t.Fatalf("authorization policy calls = %d, want 1", calls)
			}
			if test.wantStatus != http.StatusOK && bytes.Contains(response.Body.Bytes(), []byte(`"auth_token"`)) {
				t.Fatalf("invalid Budget decision released an Auth token: %s", response.Body.String())
			}
		})
	}
}

func TestDirectPSRejectsMalformedBudgetBeforeAuthorizationPolicy(t *testing.T) {
	t.Parallel()

	protocol := newBudgetAuthorizationProtocol(t)
	claims := protocol.resourceClaims(t, "malformed-budget-resource-token")
	claims.AdditionalClaims = map[string]json.RawMessage{
		"budget": json.RawMessage(`{"amount":-1,"unit":"USD","decimals":6}`),
	}
	compact, err := aauth.MintResourceTokenCore(protocol.resourceKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	policyCalls := 0
	server := protocol.server(t, func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
		policyCalls++
		return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}, nil
	})

	response := protocol.exchange(t, server, compact)
	if response.Code != http.StatusBadRequest || policyCalls != 0 {
		t.Fatalf("malformed Budget = %d %s; policy calls=%d", response.Code, response.Body.String(), policyCalls)
	}
	var problem struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Error != "invalid_budget" {
		t.Fatalf("error = %q, want invalid_budget", problem.Error)
	}
}

func TestDirectPSRejectsBudgetHistoryWithoutRetainedGrantResolution(t *testing.T) {
	t.Parallel()

	protocol := newBudgetAuthorizationProtocol(t)
	offer := protocol.value(t, 5_000_000, "USD", 6)
	prior, err := budgets.NewConsumptionRecord("budget-person-token", 431_200)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := budgets.MintResourceToken(
		protocol.resourceKey,
		protocol.resourceClaims(t, "budget-history-resource-token"),
		offer,
		&prior,
	)
	if err != nil {
		t.Fatal(err)
	}
	policyCalls := 0
	server := protocol.server(t, func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
		policyCalls++
		return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute, Budget: &offer}, nil
	})

	response := protocol.exchange(t, server, compact)
	if response.Code != http.StatusBadRequest || policyCalls != 0 {
		t.Fatalf("Budget history = %d %s; policy calls=%d", response.Code, response.Body.String(), policyCalls)
	}
}

func TestDirectPSChecksBudgetAgainstTrustedResourceMetadataBeforePolicy(t *testing.T) {
	t.Parallel()

	protocol := newBudgetAuthorizationProtocol(t)
	offer := protocol.value(t, 5_000_000, "USD", 6)
	compact := protocol.resourceToken(t, "metadata-budget-resource-token", &offer)
	usd6, _ := budgets.NewUnit("USD", 6)
	usd2, _ := budgets.NewUnit("USD", 2)
	matching, _ := budgets.NewBoundedUnitDeclaration(usd6, 5_000_000, "")
	tooSmall, _ := budgets.NewBoundedUnitDeclaration(usd6, 4_999_999, "")
	wrongScale, _ := budgets.NewBoundedUnitDeclaration(usd2, 5_000_000, "")

	for _, test := range []struct {
		name       string
		resolve    func(context.Context, string) ([]budgets.UnitDeclaration, error)
		wantStatus int
		wantCode   string
	}{
		{name: "matching", wantStatus: http.StatusOK, resolve: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
			return []budgets.UnitDeclaration{matching}, nil
		}},
		{name: "not configured", wantStatus: http.StatusBadRequest, wantCode: "invalid_resource_token"},
		{name: "resolution failure", wantStatus: http.StatusInternalServerError, resolve: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
			return nil, errors.New("metadata unavailable")
		}, wantCode: "server_error"},
		{name: "unit undeclared", wantStatus: http.StatusBadRequest, resolve: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
			return nil, nil
		}, wantCode: "invalid_budget"},
		{name: "wrong scale", wantStatus: http.StatusBadRequest, resolve: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
			return []budgets.UnitDeclaration{wrongScale}, nil
		}, wantCode: "invalid_budget"},
		{name: "offer exceeds metadata maximum", wantStatus: http.StatusBadRequest, resolve: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
			return []budgets.UnitDeclaration{tooSmall}, nil
		}, wantCode: "invalid_budget"},
	} {
		t.Run(test.name, func(t *testing.T) {
			policyCalls := 0
			server := protocol.serverWithBudgetResolver(t, func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
				policyCalls++
				return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute, Budget: &offer}, nil
			}, test.resolve)
			response := protocol.exchange(t, server, compact)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if test.wantCode != "" {
				var problem struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
					t.Fatal(err)
				}
				if problem.Error != test.wantCode {
					t.Fatalf("error = %q, want %q", problem.Error, test.wantCode)
				}
			}
			wantCalls := 0
			if test.wantStatus == http.StatusOK {
				wantCalls = 1
			}
			if policyCalls != wantCalls {
				t.Fatalf("policy calls = %d, want %d", policyCalls, wantCalls)
			}
		})
	}
}

type budgetAuthorizationProtocol struct {
	now         time.Time
	clock       aauth.Clock
	providerKey jose.SigningKey
	personKey   jose.SigningKey
	resourceKey jose.SigningKey
	agentKey    jose.SigningKey
	resolver    signaturekey.StaticKeyResolver
	agentToken  string
	agentJKT    string
	store       *memoryTokenStore
}

func newBudgetAuthorizationProtocol(t *testing.T) *budgetAuthorizationProtocol {
	t.Helper()
	now := time.Date(2026, 8, 31, 18, 0, 0, 0, time.UTC)
	protocol := &budgetAuthorizationProtocol{
		now: now, clock: aauth.ClockFunc(func() time.Time { return now }),
		providerKey: personServerTestKey(t, "budget-provider"),
		personKey:   personServerTestKey(t, "budget-person"),
		resourceKey: personServerTestKey(t, "budget-resource"),
		agentKey:    personServerTestKey(t, "budget-agent"),
		store:       newMemoryTokenStore(),
	}
	protocol.resolver = signaturekey.StaticKeyResolver{
		{Issuer: "https://provider.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: protocol.providerKey.ID()}:    protocol.providerKey.PublicJWK(),
		{Issuer: "https://person.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: protocol.personKey.ID()}:       protocol.personKey.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: protocol.resourceKey.ID()}: protocol.resourceKey.PublicJWK(),
	}
	var err error
	protocol.agentToken, err = aauth.MintAgentToken(
		"https://provider.example", protocol.providerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:planner@provider.example", PersonServer: "https://person.example",
			PublicKey: protocol.agentKey.PublicJWK(), Lifetime: 30 * time.Minute,
		}, now, "budget-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	protocol.agentJKT, err = protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.store.Commit(context.Background(), directPersonTokenRecord(
		"budget-person-token", "https://person.example", "https://resource.example", "person-123", "tenant-1",
		"https://provider.example", "aauth:planner@provider.example", protocol.agentKey.PublicJWK(),
		now.Add(40*time.Minute), now.Add(45*time.Minute),
	)); err != nil {
		t.Fatal(err)
	}
	return protocol
}

func (protocol *budgetAuthorizationProtocol) value(t *testing.T, amount int64, name string, decimals int64) budgets.Value {
	t.Helper()
	unit, err := budgets.NewUnit(name, decimals)
	if err != nil {
		t.Fatal(err)
	}
	value, err := budgets.NewValue(amount, unit)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func (protocol *budgetAuthorizationProtocol) resourceClaims(t *testing.T, jti string) aauth.ResourceTokenClaims {
	t.Helper()
	return aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://person.example", JTI: jti, PersonServer: "https://person.example",
		Subject: "person-123", PresentedJTI: "budget-person-token", AgentJKT: protocol.agentJKT,
		IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read", Tenant: "tenant-1",
	}
}

func (protocol *budgetAuthorizationProtocol) resourceToken(t *testing.T, jti string, offer *budgets.Value) string {
	t.Helper()
	claims := protocol.resourceClaims(t, jti)
	if offer == nil {
		compact, err := aauth.MintResourceToken(protocol.resourceKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	compact, err := budgets.MintResourceToken(protocol.resourceKey, claims, *offer, nil)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (protocol *budgetAuthorizationProtocol) server(
	t *testing.T,
	authorize func(context.Context, AuthorizationRequest) (AuthorizationDecision, error),
) *Server {
	t.Helper()
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := budgets.NewBoundedUnitDeclaration(unit, 10_000_000, "")
	if err != nil {
		t.Fatal(err)
	}
	return protocol.serverWithBudgetResolver(t, authorize, func(_ context.Context, resource string) ([]budgets.UnitDeclaration, error) {
		if resource != "https://resource.example" {
			return nil, errors.New("unexpected Budget metadata Resource")
		}
		return []budgets.UnitDeclaration{declaration}, nil
	})
}

func (protocol *budgetAuthorizationProtocol) serverWithBudgetResolver(
	t *testing.T,
	authorize func(context.Context, AuthorizationRequest) (AuthorizationDecision, error),
	resolve func(context.Context, string) ([]budgets.UnitDeclaration, error),
) *Server {
	t.Helper()
	config := PSAuthorizationConfig{
		Issuer: "https://person.example", SigningKey: protocol.personKey,
		KeyResolver: protocol.resolver, Clock: protocol.clock,
		NewID: func() string { return "budget-auth-token" }, Tokens: protocol.store,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
		Authorize:  authorize,
	}
	if resolve != nil {
		config.Budget = &BudgetConfig{ResolveResourceUnits: resolve}
	}
	server, err := NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func (protocol *budgetAuthorizationProtocol) exchange(t *testing.T, server *Server, resourceToken string) *httptest.ResponseRecorder {
	t.Helper()
	presentedToken := testPresentedPersonToken(
		t, protocol.personKey, resourceToken, protocol.agentKey.PublicJWK(), protocol.now, protocol.now.Add(40*time.Minute),
	)
	body := testTokenRequestBody(t, resourceToken, presentedToken)
	request := httptest.NewRequest(http.MethodPost, "https://person.example/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

type budgetAuthorizationOutput struct {
	AuthToken string `json:"auth_token"`
	ExpiresIn int64  `json:"expires_in"`
}

func decodeBudgetAuthorizationOutput(t *testing.T, response *httptest.ResponseRecorder) budgetAuthorizationOutput {
	t.Helper()
	var output budgetAuthorizationOutput
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if output.AuthToken == "" {
		t.Fatalf("response contains no Auth token: %s", response.Body.String())
	}
	return output
}

func sameBudgetValue(left, right budgets.Value) bool {
	return left.Amount() == right.Amount() && left.Unit().Equal(right.Unit())
}
