package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/resource"
)

// memorySessionStore illustrates the storage transitions used by the example.
// Applications should implement the same contract with their durable store.
type memorySessionStore struct {
	mu       sync.Mutex
	next     int
	sessions map[string]resource.SessionRecord
	pending  map[string]*pendingSession
}

type pendingSession struct {
	record   resource.PendingSessionRecord
	state    resource.SessionPollState
	attempts int
	approval resource.SessionApproval
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{
		sessions: make(map[string]resource.SessionRecord),
		pending:  make(map[string]*pendingSession),
	}
}

func (store *memorySessionStore) Create(_ context.Context, record resource.SessionRecord) (resource.SessionApproval, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.create(record), nil
}

func (store *memorySessionStore) create(record resource.SessionRecord) resource.SessionApproval {
	store.next++
	token := fmt.Sprintf("example-session-%d", store.next)
	record = cloneSessionRecord(record)
	store.sessions[token] = record
	return resource.SessionApproval{Token: token, Record: cloneSessionRecord(record)}
}

func (store *memorySessionStore) Load(_ context.Context, token string, now time.Time) (resource.SessionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.sessions[token]
	if !ok {
		return resource.SessionRecord{}, resource.ErrSessionNotFound
	}
	if !now.Before(record.ExpiresAt) {
		return resource.SessionRecord{}, resource.ErrSessionExpired
	}
	return cloneSessionRecord(record), nil
}

func (store *memorySessionStore) CreatePending(_ context.Context, record resource.PendingSessionRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.pending[record.ID]; exists {
		return resource.ErrPendingSessionConflict
	}
	store.pending[record.ID] = &pendingSession{record: clonePendingRecord(record), state: resource.SessionPollPending}
	return nil
}

func (store *memorySessionStore) ConsumeInteractionCode(
	_ context.Context,
	issuer string,
	reference string,
	digest [32]byte,
	now time.Time,
) (resource.PendingSessionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return resource.PendingSessionRecord{}, resource.ErrSessionInteractionCodeInvalid
	}
	if pending.state == resource.SessionPollGone {
		return resource.PendingSessionRecord{}, resource.ErrPendingSessionGone
	}
	if pending.state != resource.SessionPollPending {
		return resource.PendingSessionRecord{}, resource.ErrSessionInteractionCodeUsed
	}
	if !now.Before(pending.record.ExpiresAt) {
		pending.state = resource.SessionPollExpired
		return resource.PendingSessionRecord{}, resource.ErrPendingSessionExpired
	}
	if pending.record.Resource != issuer || pending.record.CodeSHA256 != digest {
		pending.attempts++
		if pending.attempts >= pending.record.MaximumCodeAttempts {
			pending.state = resource.SessionPollGone
			return resource.PendingSessionRecord{}, resource.ErrPendingSessionGone
		}
		return resource.PendingSessionRecord{}, resource.ErrSessionInteractionCodeInvalid
	}
	pending.state = resource.SessionPollInteracting
	return clonePendingRecord(pending.record), nil
}

func (store *memorySessionStore) LoadPending(_ context.Context, reference string) (resource.PendingSessionSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return resource.PendingSessionSnapshot{}, resource.ErrPendingSessionNotFound
	}
	return resource.PendingSessionSnapshot{
		Record: clonePendingRecord(pending.record), State: pending.state,
		Approval: cloneSessionApproval(pending.approval),
	}, nil
}

func (store *memorySessionStore) Approve(
	_ context.Context,
	reference string,
	record resource.SessionRecord,
	now time.Time,
) (resource.SessionApproval, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return resource.SessionApproval{}, resource.ErrPendingSessionNotFound
	}
	if pending.state == resource.SessionPollApproved {
		if reflect.DeepEqual(pending.approval.Record, record) {
			return cloneSessionApproval(pending.approval), nil
		}
		return resource.SessionApproval{}, resource.ErrPendingSessionConflict
	}
	if pending.state != resource.SessionPollInteracting {
		return resource.SessionApproval{}, resource.ErrPendingSessionConflict
	}
	if !now.Before(pending.record.ExpiresAt) {
		pending.state = resource.SessionPollExpired
		return resource.SessionApproval{}, resource.ErrPendingSessionExpired
	}
	pending.approval = store.create(record)
	pending.state = resource.SessionPollApproved
	return cloneSessionApproval(pending.approval), nil
}

func (store *memorySessionStore) Deny(_ context.Context, reference string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return resource.ErrPendingSessionNotFound
	}
	if pending.state != resource.SessionPollInteracting {
		return resource.ErrPendingSessionConflict
	}
	pending.state = resource.SessionPollDenied
	return nil
}

func (store *memorySessionStore) Invalidate(_ context.Context, reference string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return resource.ErrPendingSessionNotFound
	}
	pending.state = resource.SessionPollGone
	return nil
}

func (store *memorySessionStore) Poll(
	_ context.Context,
	reference string,
	identity resource.SessionPollIdentity,
	now time.Time,
) (resource.SessionPollRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return resource.SessionPollRecord{}, resource.ErrPendingSessionNotFound
	}
	principal := pending.record.Request.AgentPrincipal
	if identity.Resource != pending.record.Resource || identity.AgentProvider != principal.AgentProvider ||
		identity.Agent != principal.Agent || identity.ParentAgent != principal.ParentAgent {
		return resource.SessionPollRecord{}, resource.ErrPendingSessionNotFound
	}
	if pending.state == resource.SessionPollGone {
		return resource.SessionPollRecord{}, resource.ErrPendingSessionGone
	}
	if !now.Before(pending.record.ExpiresAt) &&
		(pending.state == resource.SessionPollPending || pending.state == resource.SessionPollInteracting) {
		pending.state = resource.SessionPollExpired
	}
	return resource.SessionPollRecord{
		State: pending.state, Approval: cloneSessionApproval(pending.approval), RetryAfter: pending.record.RetryAfter,
	}, nil
}

func (store *memorySessionStore) ConsumeResult(
	_ context.Context,
	reference string,
	result resource.SessionPollRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return resource.ErrPendingSessionNotFound
	}
	want := resource.SessionPollRecord{
		State: pending.state, Approval: cloneSessionApproval(pending.approval), RetryAfter: pending.record.RetryAfter,
	}
	if !reflect.DeepEqual(result, want) ||
		(result.State != resource.SessionPollApproved && result.State != resource.SessionPollDenied && result.State != resource.SessionPollExpired) {
		return resource.ErrPendingSessionConflict
	}
	pending.state = resource.SessionPollGone
	return nil
}

func cloneSessionRecord(record resource.SessionRecord) resource.SessionRecord {
	record.Scope = append([]string(nil), record.Scope...)
	return record
}

func cloneSessionApproval(approval resource.SessionApproval) resource.SessionApproval {
	approval.Record = cloneSessionRecord(approval.Record)
	return approval
}

func clonePendingRecord(record resource.PendingSessionRecord) resource.PendingSessionRecord {
	record.Request.RequiredScopes = append([]string(nil), record.Request.RequiredScopes...)
	claims := record.Request.AgentPrincipal.AdditionalClaims
	if claims != nil {
		record.Request.AgentPrincipal.AdditionalClaims = make(map[string]json.RawMessage, len(claims))
		for name, value := range claims {
			record.Request.AgentPrincipal.AdditionalClaims[name] = append(json.RawMessage(nil), value...)
		}
	}
	return record
}

var _ resource.DeferredSessionStore = (*memorySessionStore)(nil)
