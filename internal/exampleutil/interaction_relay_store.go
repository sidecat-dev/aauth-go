package exampleutil

import (
	"context"
	"reflect"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// NewInteractionRelayStore returns a process-local reference store. It is
// suitable for examples and contract tests, not multi-process deployment.
func NewInteractionRelayStore() personserver.InteractionRelayStore {
	return &interactionRelayStore{records: make(map[string]personserver.InteractionRelayRecord)}
}

type interactionRelayStore struct {
	mu      sync.Mutex
	records map[string]personserver.InteractionRelayRecord
}

func (store *interactionRelayStore) CreateInteractionRelay(_ context.Context, record personserver.InteractionRelayRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return createInteractionRelayRecord(store.records, record)
}

func createInteractionRelayRecord(records map[string]personserver.InteractionRelayRecord, record personserver.InteractionRelayRecord) error {
	if _, exists := records[record.ID]; exists {
		return personserver.ErrInteractionRelayConflict
	}
	records[record.ID] = cloneExampleRelayRecord(record)
	return nil
}

func (store *interactionRelayStore) LoadInteractionRelay(_ context.Context, id string, at time.Time) (personserver.InteractionRelayRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return loadInteractionRelayRecord(store.records, id, at)
}

func (store *interactionRelayStore) ResolveInteractionRelay(
	_ context.Context,
	id string,
	status aauth.InteractionRelayStatus,
	at time.Time,
) (personserver.InteractionRelayRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return resolveInteractionRelayRecord(store.records, id, status, at)
}

func resolveInteractionRelayRecord(
	records map[string]personserver.InteractionRelayRecord,
	id string,
	status aauth.InteractionRelayStatus,
	at time.Time,
) (personserver.InteractionRelayRecord, error) {
	record, err := loadInteractionRelayRecord(records, id, at)
	if err != nil {
		return personserver.InteractionRelayRecord{}, err
	}
	if record.State == personserver.InteractionRelayResolved {
		if record.Completion.Status == status {
			return cloneExampleRelayRecord(record), nil
		}
		return personserver.InteractionRelayRecord{}, personserver.ErrInteractionRelayConflict
	}
	if record.State != personserver.InteractionRelayPending {
		return personserver.InteractionRelayRecord{}, personserver.ErrInteractionRelayConflict
	}
	record.State = personserver.InteractionRelayResolved
	record.Completion = aauth.InteractionRelayCompletion{Status: status}
	record.ResolvedAt = at
	records[id] = cloneExampleRelayRecord(record)
	return cloneExampleRelayRecord(record), nil
}

func (store *interactionRelayStore) PollInteractionRelay(
	_ context.Context,
	id string,
	identity personserver.InteractionRelayPollIdentity,
	at time.Time,
) (personserver.InteractionRelayRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return pollInteractionRelayRecord(store.records, id, identity, at)
}

func pollInteractionRelayRecord(
	records map[string]personserver.InteractionRelayRecord,
	id string,
	identity personserver.InteractionRelayPollIdentity,
	at time.Time,
) (personserver.InteractionRelayRecord, error) {
	record, err := loadInteractionRelayRecord(records, id, at)
	if err != nil {
		return personserver.InteractionRelayRecord{}, err
	}
	if record.PersonServer != identity.PersonServer || record.AgentProvider != identity.AgentProvider ||
		record.Agent != identity.Agent || record.ConfirmationThumbprint != identity.ConfirmationThumbprint {
		return personserver.InteractionRelayRecord{}, personserver.ErrInteractionRelayNotFound
	}
	return cloneExampleRelayRecord(record), nil
}

func (store *interactionRelayStore) ConsumeInteractionRelay(
	_ context.Context,
	id string,
	expected personserver.InteractionRelayRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return consumeInteractionRelayRecord(store.records, id, expected)
}

func consumeInteractionRelayRecord(
	records map[string]personserver.InteractionRelayRecord,
	id string,
	expected personserver.InteractionRelayRecord,
) error {
	record, exists := records[id]
	if !exists {
		return personserver.ErrInteractionRelayNotFound
	}
	if record.State == personserver.InteractionRelayGone {
		return personserver.ErrInteractionRelayGone
	}
	if record.State != personserver.InteractionRelayResolved || !reflect.DeepEqual(record, expected) {
		return personserver.ErrInteractionRelayConflict
	}
	record.State = personserver.InteractionRelayGone
	records[id] = cloneExampleRelayRecord(record)
	return nil
}

func loadInteractionRelayRecord(
	records map[string]personserver.InteractionRelayRecord,
	id string,
	at time.Time,
) (personserver.InteractionRelayRecord, error) {
	record, exists := records[id]
	if !exists {
		return personserver.InteractionRelayRecord{}, personserver.ErrInteractionRelayNotFound
	}
	if record.State == personserver.InteractionRelayGone {
		return personserver.InteractionRelayRecord{}, personserver.ErrInteractionRelayGone
	}
	if record.State == personserver.InteractionRelayPending && !at.Before(record.ExpiresAt) {
		record.State = personserver.InteractionRelayResolved
		record.Completion = aauth.InteractionRelayCompletion{Status: aauth.InteractionRelayPending}
		record.ResolvedAt = record.ExpiresAt
		records[id] = cloneExampleRelayRecord(record)
	}
	return cloneExampleRelayRecord(record), nil
}

func cloneExampleRelayRecord(record personserver.InteractionRelayRecord) personserver.InteractionRelayRecord {
	record.Document.ExactJSON = append([]byte(nil), record.Document.ExactJSON...)
	return record
}

var _ personserver.InteractionRelayStore = (*interactionRelayStore)(nil)
