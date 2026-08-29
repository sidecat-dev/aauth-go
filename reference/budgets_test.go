package reference

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/budgets"
)

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
