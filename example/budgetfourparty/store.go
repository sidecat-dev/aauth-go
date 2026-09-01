package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"

	aauth "gitlab.com/sidecat-dev/aauth-go"
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
		return errors.New("Budget four-party example: person-token record already exists")
	}
	store.records[key] = record
	return nil
}

func (store *personTokenStore) Load(_ context.Context, issuer, tokenID string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.records[issuer+"\x00"+tokenID]
	if !found {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
}

var _ personserver.TokenStore = (*personTokenStore)(nil)

type lineageStore struct {
	mu       sync.Mutex
	retained *resource.BudgetLineage
}

func newLineageStore() *lineageStore { return &lineageStore{} }

func (store *lineageStore) Retain(_ context.Context, lineage resource.BudgetLineage) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	owned := cloneLineage(lineage)
	if store.retained != nil && !reflect.DeepEqual(*store.retained, owned) {
		return errors.New("Budget four-party example: lineage conflicts with retained state")
	}
	store.retained = &owned
	return nil
}

func (store *lineageStore) Load() (resource.BudgetLineage, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.retained == nil {
		return resource.BudgetLineage{}, false
	}
	return cloneLineage(*store.retained), true
}

func cloneLineage(lineage resource.BudgetLineage) resource.BudgetLineage {
	lineage.Scope = append([]string(nil), lineage.Scope...)
	if lineage.Account != nil {
		account := *lineage.Account
		lineage.Account = &account
	}
	if lineage.PersonContext.AdditionalClaims != nil {
		claims := make(map[string]json.RawMessage, len(lineage.PersonContext.AdditionalClaims))
		for name, value := range lineage.PersonContext.AdditionalClaims {
			claims[name] = append(json.RawMessage(nil), value...)
		}
		lineage.PersonContext.AdditionalClaims = claims
	}
	return lineage
}

type budgetState struct {
	charge   resource.BudgetCharge
	consumed int64
}

type budgetStore struct {
	mu      sync.Mutex
	tokens  map[aauth.TokenReference]budgetState
	persons map[string]int64
}

func newBudgetStore() *budgetStore {
	return &budgetStore{
		tokens:  make(map[aauth.TokenReference]budgetState),
		persons: make(map[string]int64),
	}
}

func (store *budgetStore) Charge(
	_ context.Context,
	charge resource.BudgetCharge,
) (resource.BudgetChargeResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	state, found := store.tokens[charge.Token]
	if found && !sameCharge(state.charge, charge) {
		return resource.BudgetChargeResult{}, resource.ErrBudgetConflict
	}
	remaining := charge.Grant.Amount() - state.consumed
	if remaining == 0 {
		return resource.BudgetChargeResult{}, resource.ErrBudgetExhausted
	}
	if charge.Cost > remaining {
		return resource.BudgetChargeResult{Remaining: remaining}, resource.ErrBudgetInsufficient
	}
	state.charge = cloneCharge(charge)
	state.consumed += charge.Cost
	store.tokens[charge.Token] = state
	store.persons[charge.PersonServer+"\x00"+charge.Subject+"\x00"+charge.Audience] += charge.Cost
	return resource.BudgetChargeResult{Cost: charge.Cost, Remaining: remaining - charge.Cost}, nil
}

func sameCharge(left, right resource.BudgetCharge) bool {
	return left.Token == right.Token && left.PersonServer == right.PersonServer &&
		left.Subject == right.Subject && left.Audience == right.Audience &&
		left.MissionS256 == right.MissionS256 && left.Tenant == right.Tenant &&
		sameOptionalString(left.Account, right.Account) && sameBudget(left.Grant, right.Grant)
}

func cloneCharge(charge resource.BudgetCharge) resource.BudgetCharge {
	if charge.Account != nil {
		account := *charge.Account
		charge.Account = &account
	}
	return charge
}

func sameOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

var _ resource.BudgetStore = (*budgetStore)(nil)
