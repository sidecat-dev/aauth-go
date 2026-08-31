package main

import (
	"context"
	"errors"
	"sync"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

type personTokenStore struct {
	mu      sync.Mutex
	records map[string]personserver.PersonTokenRecord
}

func newPersonTokenStore() *personTokenStore {
	return &personTokenStore{records: make(map[string]personserver.PersonTokenRecord)}
}

func (store *personTokenStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if _, exists := store.records[key]; exists {
		return errors.New("budget example: person-token record already exists")
	}
	store.records[key] = record
	return nil
}

func (store *personTokenStore) Load(_ context.Context, issuer, tokenID string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[issuer+"\x00"+tokenID]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
}

type personLineage struct {
	ResourceToken aauth.TokenReference
	JTI           string
	Subject       string
	Tenant        string
}

type personLineageStore struct {
	mu       sync.RWMutex
	lineage  personLineage
	retained bool
}

func newPersonLineageStore() *personLineageStore { return &personLineageStore{} }

func (store *personLineageStore) Retain(_ context.Context, retained resource.BudgetLineage) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	lineage := personLineage{
		ResourceToken: retained.ResourceToken,
		JTI:           retained.PresentedJTI,
		Subject:       retained.Person.Subject,
		Tenant:        retained.PersonContext.Tenant,
	}
	if store.retained && store.lineage != lineage {
		return errors.New("budget example: Person-token lineage conflicts with retained state")
	}
	store.lineage = lineage
	store.retained = true
	return nil
}

func (store *personLineageStore) Load() (personLineage, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.lineage, store.retained
}

type memoryBudgetStore struct {
	mu      sync.Mutex
	tokens  map[aauth.TokenReference]budgetAccount
	persons map[string]int64
}

type budgetAccount struct {
	charge   resource.BudgetCharge
	consumed int64
}

func newMemoryBudgetStore() *memoryBudgetStore {
	return &memoryBudgetStore{
		tokens:  make(map[aauth.TokenReference]budgetAccount),
		persons: make(map[string]int64),
	}
}

func (store *memoryBudgetStore) Charge(
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

var _ personserver.TokenStore = (*personTokenStore)(nil)
var _ resource.BudgetStore = (*memoryBudgetStore)(nil)
