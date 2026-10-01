package main

import (
	"context"
	"encoding/json"
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
	owned := record.Clone()
	if retained, ok := store.records[record.AuthTokenReference]; ok {
		if !reflect.DeepEqual(retained, owned) {
			return r3.ErrIssuanceConflict
		}
		return nil
	}
	store.records[record.AuthTokenReference] = owned
	return nil
}

type budgetStore struct {
	mu           sync.Mutex
	charges      map[aauth.TokenReference]resource.BudgetCharge
	consumed     map[aauth.TokenReference]int64
	observations *profileObservations
}

func newBudgetStore() *budgetStore {
	return &budgetStore{
		charges:  make(map[aauth.TokenReference]resource.BudgetCharge),
		consumed: make(map[aauth.TokenReference]int64),
	}
}

func (store *budgetStore) Charge(_ context.Context, charge resource.BudgetCharge) (resource.BudgetChargeResult, error) {
	if store.observations != nil {
		store.observations.budgetCharges.Add(1)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if retained, ok := store.charges[charge.Token]; ok && !sameCharge(retained, charge) {
		return resource.BudgetChargeResult{}, resource.ErrBudgetConflict
	}
	remaining := charge.Grant.Amount() - store.consumed[charge.Token]
	if charge.Cost > remaining {
		result := resource.BudgetChargeResult{Remaining: remaining}
		if remaining == 0 {
			return result, resource.ErrBudgetExhausted
		}
		return result, resource.ErrBudgetInsufficient
	}
	store.charges[charge.Token] = cloneCharge(charge)
	store.consumed[charge.Token] += charge.Cost
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

func cloneOptionalString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func sameBudget(left, right budgets.Value) bool {
	return left.Amount() == right.Amount() && left.Unit().Equal(right.Unit())
}

type lineageStore struct {
	mu       sync.Mutex
	retained *resource.BudgetLineage
}

func (store *lineageStore) Retain(_ context.Context, lineage resource.BudgetLineage) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	owned := lineage
	owned.Scope = append([]string(nil), lineage.Scope...)
	owned.Account = cloneOptionalString(lineage.Account)
	if store.retained != nil && !reflect.DeepEqual(*store.retained, owned) {
		return errors.New("hosted-service example: Budget lineage conflicts with retained state")
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
	owned := *store.retained
	owned.Scope = append([]string(nil), store.retained.Scope...)
	owned.Account = cloneOptionalString(store.retained.Account)
	if store.retained.PersonContext.AdditionalClaims != nil {
		owned.PersonContext.AdditionalClaims = make(map[string]json.RawMessage, len(store.retained.PersonContext.AdditionalClaims))
		for name, value := range store.retained.PersonContext.AdditionalClaims {
			owned.PersonContext.AdditionalClaims[name] = append(json.RawMessage(nil), value...)
		}
	}
	return owned, true
}

type agentTokenRevocationStore struct {
	mu      sync.Mutex
	revoked map[aauth.TokenReference]struct{}
}

func newAgentTokenRevocationStore() *agentTokenRevocationStore {
	return &agentTokenRevocationStore{revoked: make(map[aauth.TokenReference]struct{})}
}

func (store *agentTokenRevocationStore) Revoke(_ context.Context, request aauth.RevocationRequest) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revoked[request.Reference] = struct{}{}
	return nil
}

func (store *agentTokenRevocationStore) IsRevoked(_ context.Context, reference aauth.TokenReference) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, revoked := store.revoked[reference]
	return revoked, nil
}

var _ resource.R3DocumentStore = (*r3DocumentStore)(nil)
var _ r3.IssuanceStore = (*r3IssuanceStore)(nil)
var _ resource.BudgetStore = (*budgetStore)(nil)
var _ personserver.AgentTokenRevocationStore = (*agentTokenRevocationStore)(nil)
var _ resource.AgentTokenRevocationStore = (*agentTokenRevocationStore)(nil)
