package main

import (
	"context"
	"errors"
	"reflect"
	"sync"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

type r3DocumentStore struct {
	mu      sync.Mutex
	records map[string]resource.R3DocumentRecord
}

func newR3DocumentStore() *r3DocumentStore {
	return &r3DocumentStore{records: make(map[string]resource.R3DocumentRecord)}
}

func (store *r3DocumentStore) Commit(_ context.Context, record resource.R3DocumentRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	owned := record.Clone()
	if retained, ok := store.records[record.Reference.URI()]; ok {
		if !reflect.DeepEqual(retained, owned) {
			return resource.ErrR3DocumentConflict
		}
		return nil
	}
	store.records[record.Reference.URI()] = owned
	return nil
}

func (store *r3DocumentStore) Load(_ context.Context, uri string) (resource.R3DocumentRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[uri]
	if !ok {
		return resource.R3DocumentRecord{}, resource.ErrR3DocumentNotFound
	}
	return record.Clone(), nil
}

type r3IssuanceStore struct {
	mu      sync.Mutex
	records map[aauth.TokenReference]r3.IssuanceRecord
}

func newR3IssuanceStore() *r3IssuanceStore {
	return &r3IssuanceStore{records: make(map[aauth.TokenReference]r3.IssuanceRecord)}
}

func (store *r3IssuanceStore) Commit(_ context.Context, record r3.IssuanceRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if retained, ok := store.records[record.AuthTokenReference]; ok {
		if !reflect.DeepEqual(retained, record) {
			return errors.New("budget example: R3 issuance conflicts with retained state")
		}
		return nil
	}
	store.records[record.AuthTokenReference] = record
	return nil
}

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
	mu      sync.RWMutex
	records map[aauth.TokenReference]personLineage
	latest  aauth.TokenReference
}

func newPersonLineageStore() *personLineageStore {
	return &personLineageStore{records: make(map[aauth.TokenReference]personLineage)}
}

func (store *personLineageStore) Retain(_ context.Context, retained resource.BudgetLineage) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	lineage := personLineage{
		ResourceToken: retained.ResourceToken,
		JTI:           retained.PresentedJTI,
		Subject:       retained.Person.Subject,
		Tenant:        retained.PersonContext.Tenant,
	}
	if prior, found := store.records[retained.ResourceToken]; found && prior != lineage {
		return errors.New("budget example: Person-token lineage conflicts with retained state")
	}
	store.records[retained.ResourceToken] = lineage
	store.latest = retained.ResourceToken
	return nil
}

func (store *personLineageStore) Load() (personLineage, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	lineage, found := store.records[store.latest]
	return lineage, found
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
var _ resource.R3DocumentStore = (*r3DocumentStore)(nil)
var _ r3.IssuanceStore = (*r3IssuanceStore)(nil)
