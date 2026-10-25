package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

// BudgetContract constructs a fresh empty fixed-price Budget store.
type BudgetContract struct {
	New func(testing.TB) resource.BudgetStore
}

// RunBudget checks atomic charging, context binding, input ownership,
// insufficiency without mutation, zero-cost observations, and concurrent caps.
func RunBudget(t *testing.T, contract BudgetContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: BudgetContract.New is required")
	}
	store := contract.New(t)
	ctx := context.Background()
	charge := budgetCharge(t, "https://person.example", "auth-token-1", 10, 3)

	result, err := store.Charge(ctx, charge)
	if err != nil || result != (resource.BudgetChargeResult{Cost: 3, Remaining: 7}) {
		t.Fatalf("first Charge = %#v, %v", result, err)
	}
	*charge.Account = "mutated-after-charge"
	charge = budgetCharge(t, "https://person.example", "auth-token-1", 10, 2)
	result, err = store.Charge(ctx, charge)
	if err != nil || result != (resource.BudgetChargeResult{Cost: 2, Remaining: 5}) {
		t.Fatalf("Charge after input mutation = %#v, %v", result, err)
	}

	conflicting := charge
	conflicting.Subject = "different-person"
	conflicting.Cost = 1
	if _, err := store.Charge(ctx, conflicting); !errors.Is(err, resource.ErrBudgetConflict) {
		t.Fatalf("conflicting Charge = %v", err)
	}
	charge.Cost = 5
	result, err = store.Charge(ctx, charge)
	if err != nil || result != (resource.BudgetChargeResult{Cost: 5, Remaining: 0}) {
		t.Fatalf("Charge after conflict = %#v, %v", result, err)
	}
	charge.Cost = 1
	result, err = store.Charge(ctx, charge)
	if !errors.Is(err, resource.ErrBudgetExhausted) || result.Remaining != 0 || result.Cost != 0 {
		t.Fatalf("exhausted Charge = %#v, %v", result, err)
	}

	insufficient := budgetCharge(t, "https://person.example", "auth-token-2", 10, 11)
	result, err = store.Charge(ctx, insufficient)
	if !budgetRefusal(err) || result.Remaining != 10 || result.Cost != 0 {
		t.Fatalf("insufficient Charge = %#v, %v", result, err)
	}
	insufficient.Cost = 10
	result, err = store.Charge(ctx, insufficient)
	if err != nil || result != (resource.BudgetChargeResult{Cost: 10, Remaining: 0}) {
		t.Fatalf("Charge after insufficiency = %#v, %v", result, err)
	}

	t.Run("person ledger is not a ceiling", func(t *testing.T) {
		store := contract.New(t)
		first := budgetCharge(t, "https://person.example", "token-a", 10, 10)
		second := budgetCharge(t, "https://person.example", "token-b", 10, 10)
		for _, charge := range []resource.BudgetCharge{first, second} {
			result, err := store.Charge(ctx, charge)
			if err != nil || result != (resource.BudgetChargeResult{Cost: 10, Remaining: 0}) {
				t.Fatalf("Charge %s = %#v, %v", charge.Token.JTI, result, err)
			}
		}
	})

	t.Run("zero-cost observations", func(t *testing.T) {
		store := contract.New(t)
		charge := budgetCharge(t, "https://person.example", "observed-token", 10, 0)
		for _, want := range []int64{10, 7, 0} {
			observed, err := store.Charge(ctx, charge)
			if (err != nil && !(want == 0 && errors.Is(err, resource.ErrBudgetExhausted))) || observed.Cost != 0 || observed.Remaining != want {
				t.Fatalf("zero-cost Charge=%#v, %v; want remaining %d", observed, err, want)
			}
			if want == 0 {
				break
			}
			cost := int64(3)
			if want == 7 {
				cost = 7
			}
			debit := charge
			debit.Cost = cost
			charged, err := store.Charge(ctx, debit)
			if err != nil || charged.Cost != cost || charged.Remaining != want-cost {
				t.Fatalf("Charge after observation=%#v, %v", charged, err)
			}
		}
	})
	runConcurrentBudgetCharges(t, contract)
}

func runConcurrentBudgetCharges(t *testing.T, contract BudgetContract) {
	t.Helper()
	store := contract.New(t)
	ctx := context.Background()
	charge := budgetCharge(t, "https://person.example", "auth-token-race", 16, 1)
	var wait sync.WaitGroup
	results := make([]resource.BudgetChargeResult, 32)
	errorsByCall := make([]error, len(results))
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index], errorsByCall[index] = store.Charge(ctx, charge)
		}(index)
	}
	wait.Wait()
	succeeded := 0
	refused := 0
	for index, err := range errorsByCall {
		switch {
		case err == nil:
			succeeded++
			if results[index].Cost != 1 {
				t.Fatalf("concurrent Charge %d = %#v", index, results[index])
			}
		case budgetRefusal(err):
			refused++
		default:
			t.Fatalf("concurrent Charge %d = %v", index, err)
		}
	}
	if succeeded != 16 || refused != 16 {
		t.Fatalf("concurrent Charges: succeeded = %d, refused = %d", succeeded, refused)
	}
	result, err := store.Charge(ctx, charge)
	if !errors.Is(err, resource.ErrBudgetExhausted) || result.Remaining != 0 {
		t.Fatalf("terminal Charge = %#v, %v", result, err)
	}
}

func budgetCharge(t *testing.T, issuer, jti string, amount, cost int64) resource.BudgetCharge {
	t.Helper()
	unit, err := budgets.NewUnit("credits", 0)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := budgets.NewValue(amount, unit)
	if err != nil {
		t.Fatal(err)
	}
	account := "account-1"
	return resource.BudgetCharge{
		Token:        aauth.TokenReference{Issuer: issuer, JTI: jti},
		PersonServer: "https://person.example", Subject: "person-1",
		Audience: "https://resource.example", Tenant: "tenant-1", Account: &account,
		Grant: grant, Cost: cost,
	}
}

func budgetRefusal(err error) bool {
	return errors.Is(err, resource.ErrBudgetInsufficient) || errors.Is(err, resource.ErrBudgetExhausted)
}
