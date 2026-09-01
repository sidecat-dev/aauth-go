package exampleutil

import (
	"context"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
)

// NewEnrollmentStore returns a concurrency-safe in-memory Agent Provider
// enrollment store for examples.
func NewEnrollmentStore(clock aauth.Clock) agentprovider.EnrollmentStore {
	if clock == nil {
		clock = aauth.ClockFunc(time.Now)
	}
	return &enrollmentStore{
		enrollments: make(map[string]agentprovider.EnrollmentRecord),
		agents:      make(map[string]string),
		refreshes:   make(map[string]agentprovider.RefreshRecord),
		clock:       clock,
	}
}

type enrollmentStore struct {
	mu          sync.Mutex
	enrollments map[string]agentprovider.EnrollmentRecord
	agents      map[string]string
	refreshes   map[string]agentprovider.RefreshRecord
	clock       aauth.Clock
}

func (store *enrollmentStore) CommitEnrollment(
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

func (store *enrollmentStore) LoadEnrollment(
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

func (store *enrollmentStore) LoadRefresh(
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

func (store *enrollmentStore) CommitRefresh(
	_ context.Context,
	expected agentprovider.EnrollmentRecord,
	record agentprovider.RefreshRecord,
) (agentprovider.RefreshRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
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
	if !record.RequestExpiresAt.After(store.clock.Now().UTC()) {
		return agentprovider.RefreshRecord{}, agentprovider.ErrRefreshExpired
	}
	store.refreshes[key] = record
	return record, nil
}

var _ agentprovider.EnrollmentStore = (*enrollmentStore)(nil)
