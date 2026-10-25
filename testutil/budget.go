package testutil

import (
	"context"
	"sync"

	"gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

type budgetStore struct {
	mu       sync.Mutex
	tokens   map[aauth.TokenReference]budgetAccount
	persons  map[string]int64
	postings []usagePosting
}

type budgetAccount struct {
	charge   resource.BudgetCharge
	consumed int64
}

// NewBudgetStore returns an empty, concurrency-safe fixed-price Budget ledger.
// It atomically retains token consumption and person totals, including zero-cost
// observations. Entries are retained for the lifetime of the store.
func NewBudgetStore() resource.BudgetStore {
	return &budgetStore{
		tokens:  make(map[aauth.TokenReference]budgetAccount),
		persons: make(map[string]int64),
	}
}

func (store *budgetStore) Charge(
	_ context.Context,
	charge resource.BudgetCharge,
) (resource.BudgetChargeResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	account, found := store.tokens[charge.Token]
	if found && !sameBudgetCharge(account.charge, charge) {
		return resource.BudgetChargeResult{}, resource.ErrBudgetConflict
	}
	remaining := charge.Grant.Amount() - account.consumed
	if charge.Cost > remaining {
		result := resource.BudgetChargeResult{Remaining: remaining}
		if remaining == 0 {
			return result, resource.ErrBudgetExhausted
		}
		return result, resource.ErrBudgetInsufficient
	}

	account.charge = cloneBudgetCharge(charge)
	account.consumed += charge.Cost
	store.tokens[charge.Token] = account
	store.persons[budgetPersonKey(charge.PersonServer, charge.Subject, charge.Audience)] += charge.Cost
	store.postings = append(store.postings, usagePosting{
		issuer: charge.Token.Issuer, personServer: charge.PersonServer, subject: charge.Subject,
		audience: charge.Audience, tenant: charge.Tenant, mission: charge.MissionS256,
		agentJKT: charge.AgentJKT, unit: charge.Grant.Unit(), cost: charge.Cost, at: charge.ChargedAt,
	})
	return resource.BudgetChargeResult{Cost: charge.Cost, Remaining: remaining - charge.Cost}, nil
}

func cloneBudgetCharge(charge resource.BudgetCharge) resource.BudgetCharge {
	if charge.Account != nil {
		account := *charge.Account
		charge.Account = &account
	}
	return charge
}

func sameBudgetCharge(left, right resource.BudgetCharge) bool {
	return left.Token == right.Token && left.PersonServer == right.PersonServer &&
		left.Subject == right.Subject && left.Audience == right.Audience &&
		left.MissionS256 == right.MissionS256 && left.Tenant == right.Tenant &&
		sameOptionalString(left.Account, right.Account) && sameBudget(left.Grant, right.Grant)
}

func sameOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func sameBudget(left, right budgets.Value) bool {
	return left.Amount() == right.Amount() && left.Unit().Equal(right.Unit())
}

func budgetPersonKey(personServer, subject, resourceID string) string {
	return personServer + "\x00" + subject + "\x00" + resourceID
}
