package agentprovider_test

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
)

func TestTransitionEnrollmentRecord(t *testing.T) {
	key := testSigningKey(t, "transition-key", 0x72).PublicJWK()
	active := agentprovider.EnrollmentRecord{
		Identity: "urn:jkt:sha-256:transition", IdentityKey: key,
		Agent: "aauth:transition@ap.example", State: agentprovider.EnrollmentActive, Revision: 1,
	}
	disabled, err := agentprovider.TransitionEnrollmentRecord(active, 1, agentprovider.EnrollmentDisabled)
	if err != nil || disabled.State != agentprovider.EnrollmentDisabled || disabled.Revision != 2 ||
		disabled.Identity != active.Identity || disabled.Agent != active.Agent || !disabled.IdentityKey.Equal(key) {
		t.Fatalf("disable = %#v, %v", disabled, err)
	}
	replayed, err := agentprovider.TransitionEnrollmentRecord(disabled, 1, agentprovider.EnrollmentDisabled)
	if err != nil || !replayed.Equal(disabled) {
		t.Fatalf("disable replay = %#v, %v", replayed, err)
	}

	tests := []struct {
		name     string
		current  agentprovider.EnrollmentRecord
		expected uint64
		next     agentprovider.EnrollmentState
		want     error
	}{
		{name: "missing current", next: agentprovider.EnrollmentDisabled, want: agentprovider.ErrEnrollmentConflict},
		{name: "revision conflict", current: active, expected: 2, next: agentprovider.EnrollmentDisabled, want: agentprovider.ErrEnrollmentConflict},
		{name: "revision overflow", current: agentprovider.EnrollmentRecord{Identity: active.Identity, IdentityKey: key, Agent: active.Agent, State: agentprovider.EnrollmentActive, Revision: math.MaxUint64}, expected: math.MaxUint64, next: agentprovider.EnrollmentDisabled, want: agentprovider.ErrEnrollmentConflict},
		{name: "same state", current: active, expected: 1, next: agentprovider.EnrollmentActive, want: agentprovider.ErrInvalidEnrollmentTransition},
		{name: "unknown state", current: active, expected: 1, next: agentprovider.EnrollmentState("unknown"), want: agentprovider.ErrInvalidEnrollmentTransition},
		{name: "revoked is terminal", current: agentprovider.EnrollmentRecord{Identity: active.Identity, IdentityKey: key, Agent: active.Agent, State: agentprovider.EnrollmentRevoked, Revision: 2}, expected: 2, next: agentprovider.EnrollmentActive, want: agentprovider.ErrEnrollmentInactive},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := agentprovider.TransitionEnrollmentRecord(test.current, test.expected, test.next); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestEnrollmentStoreCommitRefreshExpiryOrdering(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 6, 10, 0, 0, time.UTC)
	current := now
	store := newMemoryEnrollmentStore()
	store.now = func() time.Time { return current }
	key := testSigningKey(t, "store-expiry-key", 0x71).PublicJWK()
	enrollment := agentprovider.EnrollmentRecord{
		Identity: "urn:jkt:sha-256:store-expiry", IdentityKey: key,
		Agent: "aauth:reference@ap.example", State: agentprovider.EnrollmentActive, Revision: 1,
	}
	if _, err := store.CommitEnrollment(ctx, enrollment); err != nil {
		t.Fatal(err)
	}
	record := agentprovider.RefreshRecord{
		Identity: enrollment.Identity, Profile: agentprovider.RefreshProfileTwoKey,
		RequestJTI:    "refresh-retained",
		RequestSHA256: [32]byte{1}, Agent: enrollment.Agent,
		Confirmation: key, RequestExpiresAt: now.Add(time.Minute), AgentToken: "agent-token",
	}
	retained, err := store.CommitRefresh(ctx, enrollment, record)
	if err != nil || retained.AgentToken != record.AgentToken {
		t.Fatalf("first CommitRefresh = %#v, %v", retained, err)
	}
	current = record.RequestExpiresAt
	retained, err = store.CommitRefresh(ctx, enrollment, record)
	if err != nil || retained.AgentToken != record.AgentToken {
		t.Fatalf("existing CommitRefresh at expiry = %#v, %v", retained, err)
	}
	changed := record
	changed.RequestSHA256 = [32]byte{2}
	if _, err := store.CommitRefresh(ctx, enrollment, changed); !errors.Is(err, agentprovider.ErrRefreshConflict) {
		t.Fatalf("changed CommitRefresh at expiry error = %v", err)
	}
	newRecord := record
	newRecord.RequestJTI = "refresh-first-at-expiry"
	if _, err := store.CommitRefresh(ctx, enrollment, newRecord); !errors.Is(err, agentprovider.ErrRefreshExpired) {
		t.Fatalf("first CommitRefresh at expiry error = %v", err)
	}
}

type memoryEnrollmentStore struct {
	mu             sync.Mutex
	enrollments    map[string]agentprovider.EnrollmentRecord
	agents         map[string]string
	refreshes      map[string]agentprovider.RefreshRecord
	refreshCommits int
	now            func() time.Time
}

func newMemoryEnrollmentStore() *memoryEnrollmentStore {
	return &memoryEnrollmentStore{
		enrollments: make(map[string]agentprovider.EnrollmentRecord),
		agents:      make(map[string]string),
		refreshes:   make(map[string]agentprovider.RefreshRecord),
		now:         func() time.Time { return time.Time{} },
	}
}

func (store *memoryEnrollmentStore) CommitEnrollment(
	_ context.Context,
	record agentprovider.EnrollmentRecord,
) (agentprovider.EnrollmentRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if current, ok := store.enrollments[record.Identity]; ok {
		if !current.Equal(record) {
			return agentprovider.EnrollmentRecord{}, agentprovider.ErrEnrollmentConflict
		}
		return current, nil
	}
	if identity, ok := store.agents[record.Agent]; ok && identity != record.Identity {
		return agentprovider.EnrollmentRecord{}, agentprovider.ErrEnrollmentConflict
	}
	store.enrollments[record.Identity] = record
	store.agents[record.Agent] = record.Identity
	return record, nil
}

func (store *memoryEnrollmentStore) LoadEnrollment(
	_ context.Context,
	identity string,
) (agentprovider.EnrollmentRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.enrollments[identity]
	if !ok {
		return agentprovider.EnrollmentRecord{}, agentprovider.ErrEnrollmentNotFound
	}
	return record, nil
}

func (store *memoryEnrollmentStore) TransitionEnrollment(
	_ context.Context,
	identity string,
	expectedRevision uint64,
	next agentprovider.EnrollmentState,
) (agentprovider.EnrollmentRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	current, ok := store.enrollments[identity]
	if !ok {
		return agentprovider.EnrollmentRecord{}, agentprovider.ErrEnrollmentNotFound
	}
	updated, err := agentprovider.TransitionEnrollmentRecord(current, expectedRevision, next)
	if err != nil {
		return agentprovider.EnrollmentRecord{}, err
	}
	store.enrollments[identity] = updated
	return updated, nil
}

func (store *memoryEnrollmentStore) LoadRefresh(
	_ context.Context,
	identity, requestJTI string,
) (agentprovider.RefreshRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.refreshes[identity+"\x00"+requestJTI]
	if !ok {
		return agentprovider.RefreshRecord{}, agentprovider.ErrRefreshNotFound
	}
	return record, nil
}

func (store *memoryEnrollmentStore) CommitRefresh(
	_ context.Context,
	expected agentprovider.EnrollmentRecord,
	record agentprovider.RefreshRecord,
) (agentprovider.RefreshRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.refreshCommits++
	current, ok := store.enrollments[expected.Identity]
	if !ok {
		return agentprovider.RefreshRecord{}, agentprovider.ErrEnrollmentNotFound
	}
	if !current.Equal(expected) {
		return agentprovider.RefreshRecord{}, agentprovider.ErrEnrollmentConflict
	}
	key := record.Identity + "\x00" + record.RequestJTI
	if retained, ok := store.refreshes[key]; ok {
		if !retained.SameRequest(record) {
			return agentprovider.RefreshRecord{}, agentprovider.ErrRefreshConflict
		}
		return retained, nil
	}
	if !record.RequestExpiresAt.After(store.now().UTC()) {
		return agentprovider.RefreshRecord{}, agentprovider.ErrRefreshExpired
	}
	store.refreshes[key] = record
	return record, nil
}

var _ agentprovider.EnrollmentStore = (*memoryEnrollmentStore)(nil)

type failEnrollmentCommitStore struct {
	*memoryEnrollmentStore
	err error
}

func (store *failEnrollmentCommitStore) CommitEnrollment(
	context.Context,
	agentprovider.EnrollmentRecord,
) (agentprovider.EnrollmentRecord, error) {
	return agentprovider.EnrollmentRecord{}, store.err
}

var _ agentprovider.EnrollmentStore = (*failEnrollmentCommitStore)(nil)

type ambiguousEnrollmentCommitStore struct {
	*memoryEnrollmentStore
	returnedFailure bool
}

func (store *ambiguousEnrollmentCommitStore) CommitEnrollment(
	ctx context.Context,
	record agentprovider.EnrollmentRecord,
) (agentprovider.EnrollmentRecord, error) {
	retained, err := store.memoryEnrollmentStore.CommitEnrollment(ctx, record)
	if err != nil {
		return agentprovider.EnrollmentRecord{}, err
	}
	if !store.returnedFailure {
		store.returnedFailure = true
		return agentprovider.EnrollmentRecord{}, errors.New("commit result unavailable")
	}
	return retained, nil
}

var _ agentprovider.EnrollmentStore = (*ambiguousEnrollmentCommitStore)(nil)
