package accessserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestBudgetDecisionCannotInventDropIncreaseOrChangeDenomination(t *testing.T) {
	t.Parallel()

	usd6, _ := budgets.NewUnit("USD", 6)
	usd2, _ := budgets.NewUnit("USD", 2)
	credits, _ := budgets.NewUnit("credits", 0)
	value := func(amount int64, unit budgets.Unit) *budgets.Value {
		result, err := budgets.NewValue(amount, unit)
		if err != nil {
			t.Fatal(err)
		}
		return &result
	}
	offer := value(450_000, usd6)

	for _, test := range []struct {
		name    string
		offer   *budgets.Value
		grant   *budgets.Value
		wantErr string
	}{
		{name: "ordinary Core", offer: nil, grant: nil},
		{name: "narrowed", offer: offer, grant: value(300_000, usd6)},
		{name: "invented", grant: value(1, usd6), wantErr: "invent"},
		{name: "dropped", offer: offer, wantErr: "preserve"},
		{name: "increased", offer: offer, grant: value(450_001, usd6), wantErr: "exceeds"},
		{name: "unit changed", offer: offer, grant: value(300_000, credits), wantErr: "unit and decimals"},
		{name: "decimals changed", offer: offer, grant: value(30, usd2), wantErr: "unit and decimals"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateBudgetDecision(test.offer, test.grant)
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestPersonServerBudgetCeilingFallsBackOrNarrowsWithoutInvention(t *testing.T) {
	t.Parallel()

	usd6, _ := budgets.NewUnit("USD", 6)
	usd2, _ := budgets.NewUnit("USD", 2)
	value := func(amount int64, unit budgets.Unit) *budgets.Value {
		result, err := budgets.NewValue(amount, unit)
		if err != nil {
			t.Fatal(err)
		}
		return &result
	}
	offer := value(600_000, usd6)
	lower := value(450_000, usd6)

	for _, test := range []struct {
		name      string
		offer     *budgets.Value
		requested *budgets.Value
		want      *budgets.Value
		wantErr   string
	}{
		{name: "ordinary Core"},
		{name: "omitted member is not a grant", offer: offer},
		{name: "narrowed member", offer: offer, requested: lower, want: lower},
		{name: "invented member", requested: lower, wantErr: "invent"},
		{name: "increased member", offer: offer, requested: value(600_001, usd6), wantErr: "exceeds"},
		{name: "changed decimals", offer: offer, requested: value(45, usd2), wantErr: "unit and decimals"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := selectBudgetCeiling(test.offer, test.requested)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (got == nil) != (test.want == nil) {
				t.Fatalf("ceiling = %#v, want %#v", got, test.want)
			}
			if got != nil && (got.Amount() != test.want.Amount() || !got.Unit().Equal(test.want.Unit())) {
				t.Fatalf("ceiling = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestDecodePersonServerBudgetCeilingDistinguishesOmissionFromNull(t *testing.T) {
	t.Parallel()

	valid := json.RawMessage(`{"amount":450000,"unit":"USD","decimals":6}`)
	for _, test := range []struct {
		name    string
		raw     json.RawMessage
		want    bool
		wantErr string
	}{
		{name: "omitted"},
		{name: "valid object", raw: valid, want: true},
		{name: "null", raw: json.RawMessage(`null`), wantErr: "requires amount"},
		{name: "partial", raw: json.RawMessage(`{"amount":1,"unit":"USD"}`), wantErr: "requires amount"},
		{name: "unknown member", raw: json.RawMessage(`{"amount":1,"unit":"USD","decimals":6,"extra":true}`), wantErr: "unknown field"},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := decodeBudgetCeiling(test.raw)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (value != nil) != test.want {
				t.Fatalf("value = %#v, want present %t", value, test.want)
			}
		})
	}
}

func TestAccessServerBudgetEndpointReturnsInvalidBudgetForMalformedPSCeiling(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := accessServerTestKey(t, "budget-provider")
	personKey := accessServerTestKey(t, "budget-person")
	resourceKey := accessServerTestKey(t, "budget-resource")
	accessKey := accessServerTestKey(t, "budget-access")
	agentKey := accessServerTestKey(t, "budget-agent")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:          providerKey.PublicJWK(),
		{Issuer: "https://ps.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:           personKey.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://as.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:           accessKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken(
		"https://ap.example", providerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:budget-agent@ap.example", PersonServer: "https://ps.example",
			PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		},
		now, "budget-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := budgets.NewValue(600_000, unit)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := budgets.NewBoundedUnitDeclaration(unit, 1_000_000, "")
	if err != nil {
		t.Fatal(err)
	}
	resourceToken, err := budgets.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://as.example", JTI: "budget-resource-token",
		AgentJKT: agentJKT, IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Scope: "records.read", PersonServer: "https://ps.example",
		Subject: "person-123", PresentedJTI: "person-token-1",
	}, offer, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		Issuer: "https://as.example", SigningKey: accessKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "budget-auth-token" },
		TrustPersonServer: func(context.Context, string) error { return nil },
		Authorize: func(context.Context, AuthorizationRequest) (Decision, error) {
			t.Fatal("authorization policy ran for malformed PS Budget ceiling")
			return Decision{}, nil
		},
		Budget: &BudgetConfig{ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
			return []budgets.UnitDeclaration{declaration}, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(struct {
		ResourceToken  string          `json:"resource_token"`
		AgentToken     string          `json:"agent_token"`
		PresentedToken string          `json:"presented_token"`
		Budget         json.RawMessage `json:"budget"`
	}{
		ResourceToken: resourceToken, AgentToken: agentToken, Budget: json.RawMessage(`null`),
		PresentedToken: accessServerPresentedToken(t, personKey, now, resourceToken, agentKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://as.example/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		request, personKey, "https://ps.example", aauth.PersonDiscoveryDocument, clock,
		signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
			MaxBodyBytes:         1 << 20,
		},
	); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
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

func TestAccessServerBudgetChecksTrustedResourceMetadata(t *testing.T) {
	t.Parallel()

	usd6, _ := budgets.NewUnit("USD", 6)
	usd2, _ := budgets.NewUnit("USD", 2)
	offer, _ := budgets.NewValue(450_000, usd6)
	matching, _ := budgets.NewBoundedUnitDeclaration(usd6, 600_000, "")
	tooSmall, _ := budgets.NewBoundedUnitDeclaration(usd6, 449_999, "")
	wrongScale, _ := budgets.NewBoundedUnitDeclaration(usd2, 600_000, "")

	for _, test := range []struct {
		name        string
		config      *budgetConfig
		wantErr     string
		operational bool
	}{
		{name: "matching", config: &budgetConfig{resolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
			return []budgets.UnitDeclaration{matching}, nil
		}}},
		{name: "not configured", wantErr: "not configured"},
		{name: "lookup failure", config: &budgetConfig{resolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
			return nil, errors.New("metadata unavailable")
		}}, wantErr: "metadata unavailable", operational: true},
		{name: "undeclared", config: &budgetConfig{resolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
			return nil, nil
		}}, wantErr: "not declared"},
		{name: "wrong decimals", config: &budgetConfig{resolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
			return []budgets.UnitDeclaration{wrongScale}, nil
		}}, wantErr: "different declared scale"},
		{name: "offer exceeds metadata maximum", config: &budgetConfig{resolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
			return []budgets.UnitDeclaration{tooSmall}, nil
		}}, wantErr: "metadata maximum"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.config.validateOffer(context.Background(), "https://resource.example", offer)
			var operational *budgetMetadataResolutionError
			if errors.As(err, &operational) != test.operational {
				t.Fatalf("operational metadata error = %t, want %t; error=%v", operational != nil, test.operational, err)
			}
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestAccessServerDeliversBudgetConsumptionToPolicy(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := accessServerTestKey(t, "budget-consumed-provider")
	personKey := accessServerTestKey(t, "budget-consumed-person")
	resourceKey := accessServerTestKey(t, "budget-consumed-resource")
	accessKey := accessServerTestKey(t, "budget-consumed-access")
	agentKey := accessServerTestKey(t, "budget-consumed-agent")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:          providerKey.PublicJWK(),
		{Issuer: "https://ps.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:           personKey.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://as.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:           accessKey.PublicJWK(),
	}
	agentToken, err := aauth.MintAgentToken(
		"https://ap.example", providerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:budget-agent@ap.example", PersonServer: "https://ps.example",
			PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		},
		now, "budget-consumed-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := budgets.NewValue(600_000, unit)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := budgets.NewValue(300_000, unit)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := budgets.NewConsumptionRecord("person-token-1", 125_000)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := budgets.NewBoundedUnitDeclaration(unit, 1_000_000, "")
	if err != nil {
		t.Fatal(err)
	}
	resourceToken, err := budgets.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://as.example", JTI: "budget-consumed-resource-token",
		AgentJKT: agentJKT, IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Scope: "records.read", PersonServer: "https://ps.example",
		Subject: "person-123", PresentedJTI: "person-token-1",
	}, offer, &prior)
	if err != nil {
		t.Fatal(err)
	}
	var seen *budgets.ConsumptionRecord
	server, err := New(Config{
		Issuer: "https://as.example", SigningKey: accessKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "budget-consumed-auth-token" },
		TrustPersonServer: func(context.Context, string) error { return nil },
		Authorize: func(_ context.Context, request AuthorizationRequest) (Decision, error) {
			seen = request.BudgetConsumed
			return Decision{Scopes: []string{"records.read"}, Lifetime: time.Minute, Budget: &grant}, nil
		},
		Budget: &BudgetConfig{ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
			return []budgets.UnitDeclaration{declaration}, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(struct {
		ResourceToken  string        `json:"resource_token"`
		AgentToken     string        `json:"agent_token"`
		PresentedToken string        `json:"presented_token"`
		Budget         budgets.Value `json:"budget"`
	}{
		ResourceToken: resourceToken, AgentToken: agentToken, Budget: offer,
		PresentedToken: accessServerPresentedToken(t, personKey, now, resourceToken, agentKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://as.example/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		request, personKey, "https://ps.example", aauth.PersonDiscoveryDocument, clock,
		signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
			MaxBodyBytes:         1 << 20,
		},
	); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", response.Code, response.Body.String())
	}
	if seen == nil || seen.JTI() != "person-token-1" || seen.Consumed() != 125_000 {
		t.Fatalf("policy consumption = %#v", seen)
	}
}
