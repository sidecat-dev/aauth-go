package reference

import (
	"context"
	"errors"
	"os"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/budgets"
)

func TestFileBudgetStoreReservesCommitsAndRecoversExactResult(t *testing.T) {
	path := t.TempDir() + "/budgets.json"
	store, err := NewFileBudgetStore(path)
	if err != nil {
		t.Fatal(err)
	}
	grant := budgets.Budget{Amount: 1_000, Unit: "credits", Decimals: 0}
	first, err := NewBudgetExecution("https://as.example", "auth-1", "call-1", grant, 700, 1_800_000_000)
	if err != nil {
		t.Fatal(err)
	}
	record, acquired, remaining, err := store.Claim(context.Background(), first)
	if err != nil || !acquired || record.State != "reserved" || remaining != 300 {
		t.Fatalf("first claim = %#v acquired=%t remaining=%d err=%v", record, acquired, remaining, err)
	}
	if replay, acquired, remaining, err := store.Claim(context.Background(), first); err != nil || acquired || replay.State != "reserved" || remaining != 300 {
		t.Fatalf("concurrent claim = %#v acquired=%t remaining=%d err=%v", replay, acquired, remaining, err)
	}
	tooLarge, _ := NewBudgetExecution("https://as.example", "auth-1", "call-2", grant, 400, 1_800_000_000)
	if _, _, remaining, err := store.Claim(context.Background(), tooLarge); !errors.Is(err, ErrBudgetInsufficient) || remaining != 300 {
		t.Fatalf("overshoot claim remaining=%d err=%v", remaining, err)
	}
	result := BudgetResult{Status: 200, ContentType: "application/json", Body: []byte(`{"output":"done"}`), Cost: 500}
	complete, remaining, err := store.Complete(context.Background(), first.Key, result)
	if err != nil || complete.State != "complete" || remaining != 500 {
		t.Fatalf("complete = %#v remaining=%d err=%v", complete, remaining, err)
	}
	if replay, acquired, remaining, err := store.Claim(context.Background(), first); err != nil || acquired || replay.Result == nil || remaining != 500 {
		t.Fatalf("complete replay = %#v acquired=%t remaining=%d err=%v", replay, acquired, remaining, err)
	}

	reopened, err := NewFileBudgetStore(path)
	if err != nil {
		t.Fatal(err)
	}
	replayed, acquired, remaining, err := reopened.Claim(context.Background(), first)
	if err != nil || acquired || replayed.Result == nil || string(replayed.Result.Body) != string(result.Body) || remaining != 500 {
		t.Fatalf("reopened result = %#v acquired=%t remaining=%d err=%v", replayed, acquired, remaining, err)
	}
	second, _ := NewBudgetExecution("https://as.example", "auth-1", "call-2", grant, 500, 1_800_000_000)
	reserved, acquired, remaining, err := reopened.Claim(context.Background(), second)
	if err != nil || !acquired || reserved.State != "reserved" || remaining != 0 {
		t.Fatalf("second claim = %#v acquired=%t remaining=%d err=%v", reserved, acquired, remaining, err)
	}
	reopened.Release(second.Key)
	if recovered, acquired, remaining, err := reopened.Claim(context.Background(), second); err != nil || !acquired || recovered.State != "reserved" || remaining != 0 {
		t.Fatalf("pending recovery = %#v acquired=%t remaining=%d err=%v", recovered, acquired, remaining, err)
	}

	substituted, err := NewBudgetExecution("https://as.example", "auth-1", "call-1", grant, 600, 1_800_000_000)
	if err != nil || substituted.Key != first.Key {
		t.Fatalf("stable provider key = %q/%q, %v", first.Key, substituted.Key, err)
	}
	if _, _, _, err := reopened.Claim(context.Background(), substituted); !errors.Is(err, ErrBudgetConflict) {
		t.Fatalf("substituted reservation = %v", err)
	}
}

func TestFileBudgetStoreRefusesCorruptCustody(t *testing.T) {
	path := t.TempDir() + "/budgets.json"
	store, err := NewFileBudgetStore(path)
	if err != nil {
		t.Fatal(err)
	}
	execution, _ := NewBudgetExecution(
		"https://as.example", "auth-1", "call-1",
		budgets.Budget{Amount: 1_000, Unit: "credits", Decimals: 0}, 500, 1_800_000_000,
	)
	if _, acquired, _, err := store.Claim(context.Background(), execution); err != nil || !acquired {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 1
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := NewFileBudgetStore(path); err == nil || reopened != nil {
		t.Fatalf("corrupt custody reopened: %#v, %v", reopened, err)
	}
}
