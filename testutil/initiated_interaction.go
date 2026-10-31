package testutil

import (
	"context"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/resource"
)

type initiatedInteractionStore struct {
	mu           sync.Mutex
	interactions map[string]*memoryInitiatedInteraction
}

type memoryInitiatedInteraction struct {
	record         resource.InitiatedInteractionRecord
	consumed       bool
	failedAttempts int
}

// NewInitiatedInteractionStore returns an empty, concurrency-safe Resource
// store for Resource-initiated interactions. Records are retained for the
// store lifetime.
func NewInitiatedInteractionStore() resource.InitiatedInteractionStore {
	return &initiatedInteractionStore{interactions: make(map[string]*memoryInitiatedInteraction)}
}

func (store *initiatedInteractionStore) CreateInitiatedInteraction(
	_ context.Context,
	record resource.InitiatedInteractionRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.Resource + "\x00" + record.ID
	if _, exists := store.interactions[key]; exists {
		return resource.ErrInitiatedInteractionConflict
	}
	record.Scopes = append([]string(nil), record.Scopes...)
	store.interactions[key] = &memoryInitiatedInteraction{record: record}
	return nil
}

func (store *initiatedInteractionStore) ConsumeInitiatedInteractionCode(
	_ context.Context,
	resourceIssuer string,
	reference string,
	presentation resource.InitiatedInteractionCodePresentation,
	now time.Time,
) (resource.InitiatedInteractionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	retained, ok := store.interactions[resourceIssuer+"\x00"+reference]
	if !ok || retained.failedAttempts >= resource.MaximumInitiatedInteractionCodeAttempts {
		return resource.InitiatedInteractionRecord{}, resource.ErrInitiatedInteractionCodeInvalid
	}
	if !now.Before(retained.record.ExpiresAt) {
		return resource.InitiatedInteractionRecord{}, resource.ErrInitiatedInteractionExpired
	}
	if retained.consumed {
		return resource.InitiatedInteractionRecord{}, resource.ErrInitiatedInteractionCodeUsed
	}
	if !presentation.SyntacticallyValid || presentation.CodeSHA256 != retained.record.CodeSHA256 {
		retained.failedAttempts++
		return resource.InitiatedInteractionRecord{}, resource.ErrInitiatedInteractionCodeInvalid
	}
	retained.consumed = true
	record := retained.record
	record.Scopes = append([]string(nil), record.Scopes...)
	return record, nil
}
