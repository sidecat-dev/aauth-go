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
	holds    map[string]budgetHold
}

type budgetAccount struct {
	charge   resource.BudgetCharge
	consumed int64
	reserved int64
}

type budgetHold struct {
	token  aauth.TokenReference
	amount int64
}

// NewBudgetStore returns an empty, concurrency-safe fixed-price Budget ledger.
// It atomically retains token consumption and person totals, including zero-cost
// observations. Entries are retained for the lifetime of the store.
func NewBudgetStore() resource.BudgetStore {
	return &budgetStore{
		tokens:  make(map[aauth.TokenReference]budgetAccount),
		persons: make(map[string]int64),
		holds:   make(map[string]budgetHold),
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
	remaining := charge.Grant.Amount() - account.consumed - account.reserved
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

func (store *budgetStore) Reserve(_ context.Context, reserve resource.BudgetReserve) (resource.BudgetReserveResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if reserve.ID == "" || reserve.Hold <= 0 {
		return resource.BudgetReserveResult{}, resource.ErrBudgetReservation
	}
	if _, exists := store.holds[reserve.ID]; exists {
		return resource.BudgetReserveResult{}, resource.ErrBudgetReservation
	}
	account, found := store.tokens[reserve.Token]
	charge := resource.BudgetCharge{
		Token: reserve.Token, PersonServer: reserve.PersonServer, Subject: reserve.Subject,
		Audience: reserve.Audience, MissionS256: reserve.MissionS256, Tenant: reserve.Tenant,
		Account: reserve.Account, Grant: reserve.Grant, AgentJKT: reserve.AgentJKT,
		ChargedAt: reserve.ReservedAt,
	}
	if found && !sameBudgetCharge(account.charge, charge) {
		return resource.BudgetReserveResult{}, resource.ErrBudgetConflict
	}
	available := reserve.Grant.Amount() - account.consumed - account.reserved
	if reserve.Hold > available {
		result := resource.BudgetReserveResult{Remaining: available}
		if available == 0 {
			return result, resource.ErrBudgetExhausted
		}
		return result, resource.ErrBudgetInsufficient
	}
	account.charge = cloneBudgetCharge(charge)
	account.reserved += reserve.Hold
	store.tokens[reserve.Token] = account
	store.holds[reserve.ID] = budgetHold{token: reserve.Token, amount: reserve.Hold}
	return resource.BudgetReserveResult{Reserved: reserve.Hold, Remaining: available - reserve.Hold}, nil
}

func (store *budgetStore) Commit(_ context.Context, commit resource.BudgetCommit) (resource.BudgetChargeResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	hold, ok := store.holds[commit.ID]
	if !ok || hold.token != commit.Token || commit.Cost < 0 || commit.Cost > hold.amount {
		return resource.BudgetChargeResult{}, resource.ErrBudgetReservation
	}
	account, ok := store.tokens[hold.token]
	if !ok || account.reserved < hold.amount {
		return resource.BudgetChargeResult{}, resource.ErrBudgetReservation
	}
	delete(store.holds, commit.ID)
	account.reserved -= hold.amount
	account.consumed += commit.Cost
	store.tokens[hold.token] = account
	store.persons[budgetPersonKey(account.charge.PersonServer, account.charge.Subject, account.charge.Audience)] += commit.Cost
	chargedAt := commit.ChargedAt
	if chargedAt.IsZero() {
		chargedAt = account.charge.ChargedAt
	}
	store.postings = append(store.postings, usagePosting{
		issuer: account.charge.Token.Issuer, personServer: account.charge.PersonServer,
		subject: account.charge.Subject, audience: account.charge.Audience,
		tenant: account.charge.Tenant, mission: account.charge.MissionS256,
		agentJKT: account.charge.AgentJKT, unit: account.charge.Grant.Unit(),
		cost: commit.Cost, at: chargedAt.UTC(),
	})
	remaining := account.charge.Grant.Amount() - account.consumed - account.reserved
	return resource.BudgetChargeResult{Cost: commit.Cost, Remaining: remaining}, nil
}

func (store *budgetStore) Release(_ context.Context, release resource.BudgetRelease) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	hold, ok := store.holds[release.ID]
	if !ok || hold.token != release.Token {
		return resource.ErrBudgetReservation
	}
	account, ok := store.tokens[hold.token]
	if !ok || account.reserved < hold.amount {
		return resource.ErrBudgetReservation
	}
	delete(store.holds, release.ID)
	account.reserved -= hold.amount
	store.tokens[hold.token] = account
	return nil
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
