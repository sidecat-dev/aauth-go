package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

// RunBudgetReserve checks that a hold is not spent twice, that settling
// releases the unused part, and that a fixed charge sees outstanding holds.
func RunBudgetReserve(t *testing.T, contract BudgetUsageContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: BudgetUsageContract.New is required")
	}
	ctx := context.Background()
	store := contract.New(t)
	reserver, ok := store.(resource.BudgetReserver)
	if !ok {
		t.Fatal("storetest: Budget store does not reserve")
	}
	usage, ok := store.(resource.BudgetUsageStore)
	if !ok {
		t.Fatal("storetest: Budget store does not answer usage")
	}

	first := budgetCharge(t, "https://person.example", "token-a", 10, 0)
	hold, err := reserver.Reserve(ctx, budgetReserve(first, "hold-a", 6))
	if err != nil || hold != (resource.BudgetReserveResult{Reserved: 6, Remaining: 4}) {
		t.Fatalf("Reserve = %#v, %v", hold, err)
	}
	if _, err := store.Charge(ctx, budgetCharge(t, "https://person.example", "token-a", 10, 5)); !errors.Is(err, resource.ErrBudgetInsufficient) {
		t.Fatalf("Charge through a hold = %v", err)
	}
	charged, err := store.Charge(ctx, budgetCharge(t, "https://person.example", "token-a", 10, 4))
	if err != nil || charged != (resource.BudgetChargeResult{Cost: 4, Remaining: 0}) {
		t.Fatalf("Charge beside a hold = %#v, %v", charged, err)
	}
	settled, err := reserver.Commit(ctx, resource.BudgetCommit{
		Token: first.Token, ID: "hold-a", Cost: 1, ChargedAt: time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC),
	})
	if err != nil || settled != (resource.BudgetChargeResult{Cost: 1, Remaining: 5}) {
		t.Fatalf("Commit = %#v, %v", settled, err)
	}
	if _, err := reserver.Commit(ctx, resource.BudgetCommit{Token: first.Token, ID: "hold-a", Cost: 1}); !errors.Is(err, resource.ErrBudgetReservation) {
		t.Fatalf("second Commit = %v", err)
	}

	second := budgetCharge(t, "https://person.example", "token-b", 10, 0)
	if _, err := reserver.Reserve(ctx, budgetReserve(second, "hold-b", 10)); err != nil {
		t.Fatal(err)
	}
	if err := reserver.Release(ctx, resource.BudgetRelease{Token: second.Token, ID: "hold-b"}); err != nil {
		t.Fatal(err)
	}
	released, err := store.Charge(ctx, budgetCharge(t, "https://person.example", "token-b", 10, 10))
	if err != nil || released.Cost != 10 {
		t.Fatalf("Charge after release = %#v, %v", released, err)
	}

	asOf := time.Date(2026, 9, 2, 16, 0, 0, 0, time.UTC)
	queried, err := usage.QueryUsage(ctx, resource.BudgetUsageQuery{
		Caller: resource.BudgetUsageCaller{
			Identifier: "https://person.example", Document: aauth.PersonDiscoveryDocument,
		},
		AsOf: asOf, Subject: "person-1",
	})
	if err != nil || !queried.ScopeRecognized || queried.AllTime != 15 {
		t.Fatalf("usage after settle = %+v, %v", queried, err)
	}

	t.Run("concurrent holds", func(t *testing.T) {
		store := contract.New(t)
		reserver := store.(resource.BudgetReserver)
		base := budgetCharge(t, "https://person.example", "token-race", 10, 0)
		var wait sync.WaitGroup
		errs := make([]error, 8)
		for index := range errs {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				_, errs[index] = reserver.Reserve(ctx, budgetReserve(base, "race-"+string(rune('a'+index)), 2))
			}(index)
		}
		wait.Wait()
		succeeded := 0
		for _, err := range errs {
			if err == nil {
				succeeded++
				continue
			}
			if !budgetRefusal(err) {
				t.Fatal(err)
			}
		}
		if succeeded != 5 {
			t.Fatalf("concurrent reserves = %d", succeeded)
		}
	})
}

func budgetReserve(charge resource.BudgetCharge, id string, hold int64) resource.BudgetReserve {
	return resource.BudgetReserve{
		ID: id, Token: charge.Token, PersonServer: charge.PersonServer, Subject: charge.Subject,
		Audience: charge.Audience, MissionS256: charge.MissionS256, Tenant: charge.Tenant,
		Account: charge.Account, Grant: charge.Grant, Hold: hold, AgentJKT: charge.AgentJKT,
		ReservedAt: charge.ChargedAt,
	}
}
