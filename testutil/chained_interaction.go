package testutil

import (
	"context"
	"reflect"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/resource"
)

type chainedInteractionStore struct {
	mu           sync.Mutex
	interactions map[string]*memoryChainedInteraction
}

type memoryChainedInteraction struct {
	snapshot       resource.ChainedInteractionSnapshot
	failedAttempts int
}

// NewChainedInteractionStore returns an empty, concurrency-safe Resource
// store for chained interactions and their results. Records are retained for
// the store lifetime.
func NewChainedInteractionStore() resource.ChainedInteractionStore {
	return &chainedInteractionStore{interactions: make(map[string]*memoryChainedInteraction)}
}

func (store *chainedInteractionStore) CreateChainedInteraction(_ context.Context, record resource.ChainedInteractionRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.Resource + "\x00" + record.ID
	if _, exists := store.interactions[key]; exists {
		return resource.ErrChainedInteractionConflict
	}
	store.interactions[key] = &memoryChainedInteraction{snapshot: resource.ChainedInteractionSnapshot{
		Record: record, State: resource.ChainedInteractionWaiting,
	}}
	return nil
}

func (store *chainedInteractionStore) ConsumeChainedInteractionCode(
	_ context.Context,
	resourceIssuer string,
	reference string,
	presentation resource.ChainedInteractionCodePresentation,
	now time.Time,
) (resource.ChainedInteractionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	retained, ok := store.interactions[resourceIssuer+"\x00"+reference]
	if !ok || retained.failedAttempts >= resource.MaximumChainedInteractionCodeAttempts {
		return resource.ChainedInteractionRecord{}, resource.ErrChainedInteractionCodeInvalid
	}
	materializeChainedExpiry(retained, now)
	switch retained.snapshot.State {
	case resource.ChainedInteractionWaiting:
	case resource.ChainedInteractionExpired:
		return resource.ChainedInteractionRecord{}, resource.ErrChainedInteractionExpired
	default:
		return resource.ChainedInteractionRecord{}, resource.ErrChainedInteractionCodeUsed
	}
	if !presentation.SyntacticallyValid || presentation.CodeSHA256 != retained.snapshot.Record.CodeSHA256 {
		retained.failedAttempts++
		return resource.ChainedInteractionRecord{}, resource.ErrChainedInteractionCodeInvalid
	}
	retained.snapshot.State = resource.ChainedInteractionInteracting
	retained.snapshot.Callback = presentation.Callback
	retained.snapshot.CallbackSHA256 = presentation.CallbackSHA256
	return retained.snapshot.Record, nil
}

func (store *chainedInteractionStore) LoadChainedInteraction(
	_ context.Context,
	resourceIssuer string,
	reference string,
	now time.Time,
) (resource.ChainedInteractionSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	retained, ok := store.interactions[resourceIssuer+"\x00"+reference]
	if !ok {
		return resource.ChainedInteractionSnapshot{}, resource.ErrChainedInteractionNotFound
	}
	materializeChainedExpiry(retained, now)
	return cloneChainedSnapshot(retained.snapshot), nil
}

func (store *chainedInteractionStore) FinishChainedInteraction(
	_ context.Context,
	resourceIssuer string,
	reference string,
	outcome resource.ChainedInteractionOutcome,
	now time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	retained, ok := store.interactions[resourceIssuer+"\x00"+reference]
	if !ok {
		return resource.ErrChainedInteractionNotFound
	}
	if (outcome.Result == nil) == (outcome.Failure == "") {
		return resource.ErrChainedInteractionConflict
	}
	materializeChainedExpiry(retained, now)
	snapshot := &retained.snapshot
	switch snapshot.State {
	case resource.ChainedInteractionWaiting, resource.ChainedInteractionInteracting:
	case resource.ChainedInteractionCompleted:
		if outcome.Result != nil && reflect.DeepEqual(*outcome.Result, snapshot.Result) {
			return nil
		}
		return resource.ErrChainedInteractionConflict
	case resource.ChainedInteractionFailed:
		if outcome.Failure == snapshot.Failure {
			return nil
		}
		return resource.ErrChainedInteractionConflict
	case resource.ChainedInteractionExpired:
		return resource.ErrChainedInteractionExpired
	case resource.ChainedInteractionGone:
		return resource.ErrChainedInteractionGone
	default:
		return resource.ErrChainedInteractionConflict
	}
	if outcome.Result != nil {
		snapshot.State = resource.ChainedInteractionCompleted
		snapshot.Result = *outcome.Result
		snapshot.Result.Body = append([]byte(nil), outcome.Result.Body...)
		return nil
	}
	snapshot.State = resource.ChainedInteractionFailed
	snapshot.Failure = outcome.Failure
	return nil
}

func (store *chainedInteractionStore) ConsumeChainedInteractionResult(
	_ context.Context,
	resourceIssuer string,
	reference string,
	now time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	retained, ok := store.interactions[resourceIssuer+"\x00"+reference]
	if !ok {
		return resource.ErrChainedInteractionNotFound
	}
	materializeChainedExpiry(retained, now)
	switch retained.snapshot.State {
	case resource.ChainedInteractionCompleted, resource.ChainedInteractionFailed, resource.ChainedInteractionExpired:
		retained.snapshot.State = resource.ChainedInteractionGone
		return nil
	case resource.ChainedInteractionGone:
		return resource.ErrChainedInteractionGone
	default:
		return resource.ErrChainedInteractionConflict
	}
}

func materializeChainedExpiry(retained *memoryChainedInteraction, now time.Time) {
	state := retained.snapshot.State
	if (state == resource.ChainedInteractionWaiting || state == resource.ChainedInteractionInteracting) &&
		!now.Before(retained.snapshot.Record.ExpiresAt) {
		retained.snapshot.State = resource.ChainedInteractionExpired
	}
}

func cloneChainedSnapshot(snapshot resource.ChainedInteractionSnapshot) resource.ChainedInteractionSnapshot {
	snapshot.Result.Body = append([]byte(nil), snapshot.Result.Body...)
	return snapshot
}
