package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
)

type enrollmentStoreState struct {
	Enrollments map[string]agentprovider.EnrollmentRecord `json:"enrollments"`
	Refreshes   map[string]agentprovider.RefreshRecord    `json:"refreshes"`
}

type enrollmentFileStore struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
}

func newEnrollmentFileStore(path string, now func() time.Time) *enrollmentFileStore {
	return &enrollmentFileStore{path: path, now: now}
}

func (store *enrollmentFileStore) CommitEnrollment(_ context.Context, candidate agentprovider.EnrollmentRecord) (agentprovider.EnrollmentRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return agentprovider.EnrollmentRecord{}, err
	}
	if retained, ok := state.Enrollments[candidate.Identity]; ok {
		if !retained.Equal(candidate) {
			return agentprovider.EnrollmentRecord{}, agentprovider.ErrEnrollmentConflict
		}
		return retained, nil
	}
	for identity, retained := range state.Enrollments {
		if identity != candidate.Identity && retained.Agent == candidate.Agent {
			return agentprovider.EnrollmentRecord{}, agentprovider.ErrEnrollmentConflict
		}
	}
	state.Enrollments[candidate.Identity] = candidate
	if err := store.save(state); err != nil {
		return agentprovider.EnrollmentRecord{}, err
	}
	return candidate, nil
}

func (store *enrollmentFileStore) LoadEnrollment(_ context.Context, identity string) (agentprovider.EnrollmentRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return agentprovider.EnrollmentRecord{}, err
	}
	record, ok := state.Enrollments[identity]
	if !ok {
		return agentprovider.EnrollmentRecord{}, agentprovider.ErrEnrollmentNotFound
	}
	return record, nil
}

func (store *enrollmentFileStore) TransitionEnrollment(_ context.Context, identity string, expected uint64, next agentprovider.EnrollmentState) (agentprovider.EnrollmentRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return agentprovider.EnrollmentRecord{}, err
	}
	current, ok := state.Enrollments[identity]
	if !ok {
		return agentprovider.EnrollmentRecord{}, agentprovider.ErrEnrollmentNotFound
	}
	transitioned, err := agentprovider.TransitionEnrollmentRecord(current, expected, next)
	if err != nil {
		return agentprovider.EnrollmentRecord{}, err
	}
	if transitioned.Equal(current) {
		return current, nil
	}
	state.Enrollments[identity] = transitioned
	if err := store.save(state); err != nil {
		return agentprovider.EnrollmentRecord{}, err
	}
	return transitioned, nil
}

func (store *enrollmentFileStore) LoadRefresh(_ context.Context, identity, jti string) (agentprovider.RefreshRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return agentprovider.RefreshRecord{}, err
	}
	record, ok := state.Refreshes[refreshKey(identity, jti)]
	if !ok {
		return agentprovider.RefreshRecord{}, agentprovider.ErrRefreshNotFound
	}
	return record, nil
}

func (store *enrollmentFileStore) CommitRefresh(_ context.Context, expected agentprovider.EnrollmentRecord, candidate agentprovider.RefreshRecord) (agentprovider.RefreshRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return agentprovider.RefreshRecord{}, err
	}
	current, ok := state.Enrollments[expected.Identity]
	if !ok {
		return agentprovider.RefreshRecord{}, agentprovider.ErrEnrollmentNotFound
	}
	if !current.Equal(expected) || current.State != agentprovider.EnrollmentActive {
		return agentprovider.RefreshRecord{}, agentprovider.ErrEnrollmentInactive
	}
	key := refreshKey(candidate.Identity, candidate.RequestJTI)
	if retained, ok := state.Refreshes[key]; ok {
		if !retained.SameRequest(candidate) {
			return agentprovider.RefreshRecord{}, agentprovider.ErrRefreshConflict
		}
		return retained, nil
	}
	if !store.now().UTC().Before(candidate.RequestExpiresAt.UTC()) {
		return agentprovider.RefreshRecord{}, agentprovider.ErrRefreshExpired
	}
	state.Refreshes[key] = candidate
	if err := store.save(state); err != nil {
		return agentprovider.RefreshRecord{}, err
	}
	return candidate, nil
}

func (store *enrollmentFileStore) counts() (int, int, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return 0, 0, err
	}
	return len(state.Enrollments), len(state.Refreshes), nil
}

func (store *enrollmentFileStore) revokeOnlyEnrollment() (agentprovider.RefreshRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return agentprovider.RefreshRecord{}, err
	}
	if len(state.Enrollments) != 1 || len(state.Refreshes) == 0 {
		return agentprovider.RefreshRecord{}, errors.New("hosted walkthrough: exact enrollment or refresh is unavailable")
	}
	for identity, current := range state.Enrollments {
		if current.State != agentprovider.EnrollmentRevoked {
			transitioned, err := agentprovider.TransitionEnrollmentRecord(current, current.Revision, agentprovider.EnrollmentRevoked)
			if err != nil {
				return agentprovider.RefreshRecord{}, err
			}
			state.Enrollments[identity] = transitioned
			if err := store.save(state); err != nil {
				return agentprovider.RefreshRecord{}, err
			}
		}
		for _, refresh := range state.Refreshes {
			if refresh.Identity == identity {
				return refresh, nil
			}
		}
	}
	return agentprovider.RefreshRecord{}, errors.New("hosted walkthrough: enrollment has no refresh result")
}

func (store *enrollmentFileStore) load() (enrollmentStoreState, error) {
	var state enrollmentStoreState
	if err := readJSON(store.path, &state); err != nil {
		return state, err
	}
	if state.Enrollments == nil || state.Refreshes == nil {
		return state, errors.New("enrollment store is incomplete")
	}
	return state, nil
}

func (store *enrollmentFileStore) save(state enrollmentStoreState) error {
	return writeJSONFile(store.path, 0o600, state)
}

func refreshKey(identity, jti string) string { return identity + "\x1f" + jti }

var _ agentprovider.EnrollmentStore = (*enrollmentFileStore)(nil)
