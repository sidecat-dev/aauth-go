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

var _ personserver.TokenStore = (*personTokenStore)(nil)

func sameBudget(left, right budgets.Value) bool {
	return left.Amount() == right.Amount() && left.Unit().Equal(right.Unit())
}
