package reference

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestResourceBudgetUnitsAreAdvertisedAndEnforced(t *testing.T) {
	resource := &Resource{
		identifier: "https://resource.example",
		accessMode: aauth.AccessModeAuthToken,
		budgetUnits: []budgets.BudgetUnit{
			{Unit: "USD", Decimals: 6, Max: budgets.OptionalInteger(5_000_000), Description: "US dollars"},
			{Unit: "tokens", Decimals: 0},
		},
	}
	response := httptest.NewRecorder()
	resource.handleMetadata(response, httptest.NewRequest(http.MethodGet, "https://resource.example/.well-known/aauth-resource.json", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("metadata status = %d", response.Code)
	}
	var metadata map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	units, ok := metadata["budget_units"].([]any)
	if !ok || len(units) != 2 {
		t.Fatalf("budget_units metadata = %#v", metadata["budget_units"])
	}
	first, ok := units[0].(map[string]any)
	if !ok || first["unit"] != "USD" {
		t.Fatalf("budget_units are not canonicalized: %#v", units)
	}
	if err := resource.validateBudgetOffer(budgets.Budget{Amount: 5_000_000, Unit: "USD", Decimals: 6}); err != nil {
		t.Fatalf("valid declared offer refused: %v", err)
	}
	for _, offer := range []budgets.Budget{
		{Amount: 1, Unit: "USD", Decimals: 0},
		{Amount: 5_000_001, Unit: "USD", Decimals: 6},
		{Amount: 1, Unit: "EUR", Decimals: 2},
	} {
		if err := resource.validateBudgetOffer(offer); err == nil {
			t.Fatalf("invalid declared offer accepted: %#v", offer)
		}
	}
	if !strings.Contains(response.Body.String(), `"description":"US dollars"`) {
		t.Fatalf("metadata omitted unit description: %s", response.Body.String())
	}
}

func TestNewResourceValidatesAndCanonicalizesBudgetUnits(t *testing.T) {
	now := time.Date(2026, 8, 29, 11, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := referenceTestSigningKey(t, "budget-units")
	replay, err := NewMemoryProofReplayStore(clock, 8)
	if err != nil {
		t.Fatal(err)
	}
	budgetStore, err := NewFileBudgetStore(t.TempDir() + "/budget.json")
	if err != nil {
		t.Fatal(err)
	}
	lineage, err := NewFileResourceTokenLineageStore(t.TempDir() + "/lineage.json")
	if err != nil {
		t.Fatal(err)
	}
	base := ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aauth.AccessModeAuthToken,
		PersonServer: "https://ps.example", SigningKey: key,
		KeyResolver: signaturekey.StaticKeyResolver{}, Clock: clock, NewID: func() string { return "id" },
		Scopes: []string{"operation.a"}, ScopeDescriptions: map[string]string{"operation.a": "Operation A"},
		RequiredScopesForRequest: func(context.Context, *http.Request) ([]string, error) {
			return []string{"operation.a"}, nil
		},
		ReplayStore: replay, ProtectedAuthorizationPolicy: testProtectedAuthorizationPolicy,
		Budget: &ResourceBudgetConfig{
			Offer: func(context.Context, *budgets.Budget) (budgets.Budget, error) {
				return budgets.Budget{Amount: 1, Unit: "USD", Decimals: 6}, nil
			},
			Store: budgetStore, ResourceTokenStore: lineage,
			MaximumCost: func(context.Context, aauth.AuthorizedRequest) (int64, error) { return 1, nil },
			CallKey:     func(context.Context, aauth.AuthorizedRequest) (string, error) { return "key", nil },
			Operation: func(context.Context, aauth.AuthorizedRequest, string) (BudgetOperationResult, error) {
				return BudgetOperationResult{}, nil
			},
			Units: []budgets.BudgetUnit{{Unit: "USD", Decimals: -1}},
		},
	}
	if _, err := NewResource(base); err == nil || !strings.Contains(err.Error(), "Budget unit declarations") {
		t.Fatalf("invalid Budget units error = %v", err)
	}
	base.Budget.Units = []budgets.BudgetUnit{
		{Unit: "tokens", Decimals: 0},
		{Unit: "USD", Decimals: 6, Max: budgets.OptionalInteger(1), Description: "US dollars"},
	}
	resource, err := NewResource(base)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	resource.handleMetadata(response, httptest.NewRequest(http.MethodGet, "https://resource.example/.well-known/aauth-resource.json", nil))
	var metadata map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	units, ok := metadata["budget_units"].([]any)
	if !ok || len(units) != 2 || units[0].(map[string]any)["unit"] != "USD" {
		t.Fatalf("canonical Budget units metadata = %#v", metadata["budget_units"])
	}
}

func TestAccessServerUsesResourceBudgetWhenPersonServerOmitsNarrowing(t *testing.T) {
	offer := budgets.Budget{Amount: 5_000_000, Unit: "USD", Decimals: 6}
	ceiling, err := accessServerBudgetCeiling(offer, nil)
	if err != nil || ceiling != offer {
		t.Fatalf("ceiling = %#v, %v", ceiling, err)
	}

	narrowed := budgets.Budget{Amount: 3_000_000, Unit: "USD", Decimals: 6}
	ceiling, err = accessServerBudgetCeiling(offer, &narrowed)
	if err != nil || ceiling != narrowed {
		t.Fatalf("narrowed ceiling = %#v, %v", ceiling, err)
	}

	changed := budgets.Budget{Amount: 3_000_000, Unit: "tokens", Decimals: 0}
	if _, err := accessServerBudgetCeiling(offer, &changed); err == nil {
		t.Fatal("person-server denomination change was admitted")
	}
}
