package integration_test

import (
	"context"
	"sync"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
)

type integrationEnrollmentStore struct {
	mu          sync.Mutex
	enrollments map[string]agentprovider.EnrollmentRecord
	agents      map[string]string
	refreshes   map[string]agentprovider.RefreshRecord
	clock       aauth.Clock
}

func newIntegrationEnrollmentStore(clock aauth.Clock) *integrationEnrollmentStore {
	return &integrationEnrollmentStore{
		enrollments: make(map[string]agentprovider.EnrollmentRecord),
		agents:      make(map[string]string),
		refreshes:   make(map[string]agentprovider.RefreshRecord),
		clock:       clock,
	}
}

func (store *integrationEnrollmentStore) CommitEnrollment(
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

func (store *integrationEnrollmentStore) LoadEnrollment(
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

func (store *integrationEnrollmentStore) LoadRefresh(
	_ context.Context,
	identity, delegationJTI string,
) (agentprovider.RefreshRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.refreshes[identity+"\x00"+delegationJTI]
	if !ok {
		return agentprovider.RefreshRecord{}, agentprovider.ErrRefreshNotFound
	}
	return record, nil
}

func (store *integrationEnrollmentStore) CommitRefresh(
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
	key := record.Identity + "\x00" + record.DelegationJTI
	if retained, ok := store.refreshes[key]; ok {
		if !retained.SameRequest(record) {
			return agentprovider.RefreshRecord{}, agentprovider.ErrRefreshConflict
		}
		return retained, nil
	}
	if !record.DelegationExpiresAt.After(store.clock.Now().UTC()) {
		return agentprovider.RefreshRecord{}, agentprovider.ErrRefreshExpired
	}
	store.refreshes[key] = record
	return record, nil
}

var _ agentprovider.EnrollmentStore = (*integrationEnrollmentStore)(nil)
