package personserver

import (
	"strings"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/budgets"
)

func TestFederatedBudgetGrantMustFitResourceOfferAndPersonServerCeiling(t *testing.T) {
	t.Parallel()

	usd6, err := budgets.NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	usd2, err := budgets.NewUnit("USD", 2)
	if err != nil {
		t.Fatal(err)
	}
	credits, err := budgets.NewUnit("credits", 0)
	if err != nil {
		t.Fatal(err)
	}
	value := func(amount int64, unit budgets.Unit) budgets.Value {
		result, err := budgets.NewValue(amount, unit)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	offer := value(600_000, usd6)
	ceiling := value(450_000, usd6)

	for _, test := range []struct {
		name    string
		ceiling *budgets.Value
		grant   budgets.Value
		wantErr string
	}{
		{name: "within both ceilings", ceiling: &ceiling, grant: value(300_000, usd6)},
		{name: "equal explicit ceiling", ceiling: &ceiling, grant: ceiling},
		{name: "omitted ceiling rejects a Budget claim", grant: offer, wantErr: "omitted"},
		{name: "exceeds explicit ceiling", ceiling: &ceiling, grant: value(450_001, usd6), wantErr: "Person Server ceiling"},
		{name: "omitted ceiling rejects a broadened claim", grant: value(600_001, usd6), wantErr: "omitted"},
		{name: "changes unit", ceiling: &ceiling, grant: value(300_000, credits), wantErr: "Resource offer"},
		{name: "changes decimals", ceiling: &ceiling, grant: value(30, usd2), wantErr: "Resource offer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateFederatedBudgetGrant(offer, test.ceiling, test.grant)
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
