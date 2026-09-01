package exampleutil

import (
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// NewPermissionStore returns a concurrency-safe in-memory Person Server
// permission store for examples.
func NewPermissionStore() personserver.PermissionStore {
	return &permissionStore{records: make(map[string]personserver.PermissionRecord)}
}

type permissionStore struct {
	mu      sync.Mutex
	records map[string]personserver.PermissionRecord
}

var _ personserver.PermissionStore = (*permissionStore)(nil)

func (store *permissionStore) CreatePermission(_ context.Context, record personserver.PermissionRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return createPermissionRecord(store.records, record)
}

func createPermissionRecord(records map[string]personserver.PermissionRecord, record personserver.PermissionRecord) error {
	if _, exists := records[record.ID]; exists {
		return personserver.ErrPermissionConflict
	}
	records[record.ID] = clonePermissionRecord(record)
	return nil
}

func (store *permissionStore) LoadPermission(
	_ context.Context,
	id string,
	now time.Time,
) (personserver.PermissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return loadPermissionRecord(store.records, id, now)
}

func loadPermissionRecord(
	records map[string]personserver.PermissionRecord,
	id string,
	now time.Time,
) (personserver.PermissionRecord, error) {
	record, ok := records[id]
	if !ok {
		return personserver.PermissionRecord{}, personserver.ErrPermissionNotFound
	}
	materializePermissionExpiry(&record, now)
	records[id] = clonePermissionRecord(record)
	return clonePermissionRecord(record), nil
}

func (store *permissionStore) DecidePermission(
	_ context.Context,
	id string,
	decision personserver.PermissionDecision,
	now time.Time,
) (personserver.PermissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return decidePermissionRecord(store.records, id, decision, now)
}

func decidePermissionRecord(
	records map[string]personserver.PermissionRecord,
	id string,
	decision personserver.PermissionDecision,
	now time.Time,
) (personserver.PermissionRecord, error) {
	record, ok := records[id]
	if !ok {
		return personserver.PermissionRecord{}, personserver.ErrPermissionNotFound
	}
	materializePermissionExpiry(&record, now)
	if record.State == personserver.PermissionStateExpired {
		records[id] = clonePermissionRecord(record)
		return personserver.PermissionRecord{}, personserver.ErrPermissionExpired
	}
	if record.State == personserver.PermissionStateGranted || record.State == personserver.PermissionStateDenied {
		if record.Decision == decision {
			return clonePermissionRecord(record), nil
		}
		return personserver.PermissionRecord{}, personserver.ErrPermissionConflict
	}
	if record.State != personserver.PermissionStatePending || !validPermissionDecision(decision) {
		return personserver.PermissionRecord{}, personserver.ErrPermissionConflict
	}
	if decision.Permission == aauth.PermissionGranted {
		record.State = personserver.PermissionStateGranted
	} else {
		record.State = personserver.PermissionStateDenied
	}
	record.Decision = decision
	record.DecidedAt = now
	records[id] = clonePermissionRecord(record)
	return clonePermissionRecord(record), nil
}

func (store *permissionStore) PollPermission(
	_ context.Context,
	id string,
	identity personserver.PermissionPollIdentity,
	now time.Time,
) (personserver.PermissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return pollPermissionRecord(store.records, id, identity, now)
}

func pollPermissionRecord(
	records map[string]personserver.PermissionRecord,
	id string,
	identity personserver.PermissionPollIdentity,
	now time.Time,
) (personserver.PermissionRecord, error) {
	record, ok := records[id]
	if !ok || !permissionIdentityMatches(record, identity) {
		return personserver.PermissionRecord{}, personserver.ErrPermissionNotFound
	}
	materializePermissionExpiry(&record, now)
	records[id] = clonePermissionRecord(record)
	if record.State == personserver.PermissionStateGone {
		return personserver.PermissionRecord{}, personserver.ErrPermissionGone
	}
	return clonePermissionRecord(record), nil
}

func (store *permissionStore) ConsumePermissionResult(
	_ context.Context,
	id string,
	expected personserver.PermissionRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return consumePermissionRecord(store.records, id, expected)
}

func consumePermissionRecord(
	records map[string]personserver.PermissionRecord,
	id string,
	expected personserver.PermissionRecord,
) error {
	record, ok := records[id]
	if !ok {
		return personserver.ErrPermissionNotFound
	}
	if record.State == personserver.PermissionStateGone {
		return personserver.ErrPermissionGone
	}
	if !reflect.DeepEqual(record, expected) || !terminalPermissionState(record.State) {
		return personserver.ErrPermissionConflict
	}
	record.State = personserver.PermissionStateGone
	records[id] = clonePermissionRecord(record)
	return nil
}

func validPermissionDecision(decision personserver.PermissionDecision) bool {
	permission, err := aauth.ParsePermission(string(decision.Permission))
	if err != nil || permission != decision.Permission {
		return false
	}
	return decision.Permission != aauth.PermissionGranted || decision.Reason == ""
}

func terminalPermissionState(state personserver.PermissionState) bool {
	return state == personserver.PermissionStateGranted ||
		state == personserver.PermissionStateDenied ||
		state == personserver.PermissionStateExpired
}

func permissionIdentityMatches(
	record personserver.PermissionRecord,
	identity personserver.PermissionPollIdentity,
) bool {
	return record.PersonServer == identity.PersonServer &&
		record.AgentProvider == identity.AgentProvider &&
		record.Agent == identity.Agent &&
		record.ConfirmationThumbprint == identity.ConfirmationThumbprint
}

func materializePermissionExpiry(record *personserver.PermissionRecord, now time.Time) {
	if record.State == personserver.PermissionStatePending && !now.Before(record.ExpiresAt) {
		record.State = personserver.PermissionStateExpired
	}
}

func clonePermissionRecord(record personserver.PermissionRecord) personserver.PermissionRecord {
	record.Parameters = append(json.RawMessage(nil), record.Parameters...)
	if record.AgentAdditionalClaims != nil {
		claims := make(map[string]json.RawMessage, len(record.AgentAdditionalClaims))
		for name, value := range record.AgentAdditionalClaims {
			claims[name] = append(json.RawMessage(nil), value...)
		}
		record.AgentAdditionalClaims = claims
	}
	return record
}
