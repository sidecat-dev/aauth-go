package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

type jsonFile[T any] struct {
	mu   sync.Mutex
	path string
	zero func() T
}

func (file *jsonFile[T]) update(change func(*T) error) error {
	file.mu.Lock()
	defer file.mu.Unlock()
	value, err := file.readUnlocked()
	if err != nil {
		return err
	}
	if err := change(&value); err != nil {
		return err
	}
	return writeJSONAtomic(file.path, value)
}

func (file *jsonFile[T]) read() (T, error) {
	file.mu.Lock()
	defer file.mu.Unlock()
	return file.readUnlocked()
}

func (file *jsonFile[T]) readUnlocked() (T, error) {
	value := file.zero()
	encoded, err := os.ReadFile(file.path)
	if os.IsNotExist(err) {
		return value, nil
	}
	if err != nil {
		return value, err
	}
	if err := json.Unmarshal(encoded, &value); err != nil {
		return value, fmt.Errorf("decode %s: %w", filepath.Base(file.path), err)
	}
	return value, nil
}

func writeJSONAtomic(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

type tokenState struct {
	Records map[string]personserver.PersonTokenRecord `json:"records"`
}

type tokenStore struct{ file jsonFile[tokenState] }

func newTokenStore(path string) *tokenStore {
	return &tokenStore{file: jsonFile[tokenState]{path: path, zero: func() tokenState {
		return tokenState{Records: make(map[string]personserver.PersonTokenRecord)}
	}}}
}

func (store *tokenStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	return store.file.update(func(state *tokenState) error {
		key := record.PersonServer + "\x00" + record.JTI
		if _, exists := state.Records[key]; exists {
			return errors.New("person token already exists")
		}
		state.Records[key] = clone(record)
		return nil
	})
}

func (store *tokenStore) Load(_ context.Context, issuer, tokenID string) (personserver.PersonTokenRecord, error) {
	state, err := store.file.read()
	if err != nil {
		return personserver.PersonTokenRecord{}, err
	}
	record, ok := state.Records[issuer+"\x00"+tokenID]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return clone(record), nil
}

type permissionState struct {
	Records map[string]personserver.PermissionRecord `json:"records"`
}

type permissionStore struct{ file jsonFile[permissionState] }

func newPermissionStore(path string) *permissionStore {
	return &permissionStore{file: jsonFile[permissionState]{path: path, zero: func() permissionState {
		return permissionState{Records: make(map[string]personserver.PermissionRecord)}
	}}}
}

func (store *permissionStore) CreatePermission(_ context.Context, record personserver.PermissionRecord) error {
	return store.file.update(func(state *permissionState) error {
		if _, exists := state.Records[record.ID]; exists {
			return personserver.ErrPermissionConflict
		}
		state.Records[record.ID] = clone(record)
		return nil
	})
}

func (store *permissionStore) LoadPermission(_ context.Context, id string, now time.Time) (personserver.PermissionRecord, error) {
	var output personserver.PermissionRecord
	err := store.file.update(func(state *permissionState) error {
		record, ok := state.Records[id]
		if !ok {
			return personserver.ErrPermissionNotFound
		}
		materializePermissionExpiry(&record, now)
		state.Records[id] = record
		output = clone(record)
		return nil
	})
	return output, err
}

func (store *permissionStore) DecidePermission(_ context.Context, id string, decision personserver.PermissionDecision, now time.Time) (personserver.PermissionRecord, error) {
	var output personserver.PermissionRecord
	err := store.file.update(func(state *permissionState) error {
		record, ok := state.Records[id]
		if !ok {
			return personserver.ErrPermissionNotFound
		}
		materializePermissionExpiry(&record, now)
		switch record.State {
		case personserver.PermissionStatePending:
			record.Decision = decision
			record.DecidedAt = now
			if decision.Permission == aauth.PermissionGranted {
				record.State = personserver.PermissionStateGranted
			} else {
				record.State = personserver.PermissionStateDenied
			}
		case personserver.PermissionStateExpired:
			state.Records[id] = record
			return personserver.ErrPermissionExpired
		case personserver.PermissionStateGranted, personserver.PermissionStateDenied:
			if record.Decision != decision {
				return personserver.ErrPermissionConflict
			}
		default:
			return personserver.ErrPermissionConflict
		}
		state.Records[id] = record
		output = clone(record)
		return nil
	})
	return output, err
}

func (store *permissionStore) PollPermission(_ context.Context, id string, identity personserver.PermissionPollIdentity, now time.Time) (personserver.PermissionRecord, error) {
	var output personserver.PermissionRecord
	err := store.file.update(func(state *permissionState) error {
		record, ok := state.Records[id]
		if !ok || record.PersonServer != identity.PersonServer || record.AgentProvider != identity.AgentProvider ||
			record.Agent != identity.Agent || record.ConfirmationThumbprint != identity.ConfirmationThumbprint {
			return personserver.ErrPermissionNotFound
		}
		if record.State == personserver.PermissionStateGone {
			return personserver.ErrPermissionGone
		}
		materializePermissionExpiry(&record, now)
		state.Records[id] = record
		output = clone(record)
		return nil
	})
	return output, err
}

func (store *permissionStore) ConsumePermissionResult(_ context.Context, id string, expected personserver.PermissionRecord) error {
	return store.file.update(func(state *permissionState) error {
		record, ok := state.Records[id]
		if !ok {
			return personserver.ErrPermissionNotFound
		}
		if record.State == personserver.PermissionStateGone {
			return personserver.ErrPermissionGone
		}
		if !equalJSON(record, expected) {
			return personserver.ErrPermissionConflict
		}
		switch record.State {
		case personserver.PermissionStateGranted, personserver.PermissionStateDenied, personserver.PermissionStateExpired:
			record.State = personserver.PermissionStateGone
			state.Records[id] = record
			return nil
		default:
			return personserver.ErrPermissionConflict
		}
	})
}

func materializePermissionExpiry(record *personserver.PermissionRecord, now time.Time) {
	if record.State == personserver.PermissionStatePending && !record.ExpiresAt.IsZero() && !now.Before(record.ExpiresAt) {
		record.State = personserver.PermissionStateExpired
	}
}

type revocationState struct {
	References map[string]aauth.TokenReference `json:"references"`
}

type revocationStore struct{ file jsonFile[revocationState] }

func newRevocationStore(path string) *revocationStore {
	return &revocationStore{file: jsonFile[revocationState]{path: path, zero: func() revocationState {
		return revocationState{References: make(map[string]aauth.TokenReference)}
	}}}
}

func (store *revocationStore) Revoke(_ context.Context, reference aauth.TokenReference) error {
	return store.file.update(func(state *revocationState) error {
		state.References[reference.Issuer+"\x00"+reference.JTI] = reference
		return nil
	})
}

func (store *revocationStore) IsRevoked(_ context.Context, reference aauth.TokenReference) (bool, error) {
	state, err := store.file.read()
	if err != nil {
		return false, err
	}
	_, ok := state.References[reference.Issuer+"\x00"+reference.JTI]
	return ok, nil
}

type consequenceState struct {
	Results map[string]string `json:"results"`
	Count   int               `json:"count"`
}

type consequenceStore struct{ file jsonFile[consequenceState] }

func newConsequenceStore(path string) *consequenceStore {
	return &consequenceStore{file: jsonFile[consequenceState]{path: path, zero: func() consequenceState {
		return consequenceState{Results: make(map[string]string)}
	}}}
}

func (store *consequenceStore) apply(requestKey string) (string, bool, int, error) {
	var result string
	var replayed bool
	var count int
	err := store.file.update(func(state *consequenceState) error {
		if existing, ok := state.Results[requestKey]; ok {
			result, replayed, count = existing, true, state.Count
			return nil
		}
		state.Count++
		result = fmt.Sprintf("note-%d", state.Count)
		state.Results[requestKey] = result
		count = state.Count
		return nil
	})
	return result, replayed, count, err
}

func (store *consequenceStore) count() (int, error) {
	state, err := store.file.read()
	return state.Count, err
}

type actionOutput struct {
	Status           string `json:"status"`
	Agent            string `json:"agent,omitempty"`
	RequestKey       string `json:"request_key,omitempty"`
	Result           string `json:"result,omitempty"`
	Replayed         bool   `json:"replayed"`
	ConsequenceCount int    `json:"consequence_count"`
}

type resultState struct {
	Results map[string]actionOutput `json:"results"`
}

type resultStore struct{ file jsonFile[resultState] }

func newResultStore(path string) *resultStore {
	return &resultStore{file: jsonFile[resultState]{path: path, zero: func() resultState {
		return resultState{Results: make(map[string]actionOutput)}
	}}}
}

func (store *resultStore) load(requestKey string) (actionOutput, bool, error) {
	state, err := store.file.read()
	if err != nil {
		return actionOutput{}, false, err
	}
	result, ok := state.Results[requestKey]
	return result, ok, nil
}

func (store *resultStore) save(requestKey string, result actionOutput) error {
	return store.file.update(func(state *resultState) error {
		if existing, ok := state.Results[requestKey]; ok && !equalJSON(existing, result) {
			return errors.New("request key conflicts with retained result")
		}
		state.Results[requestKey] = result
		return nil
	})
}

func clone[T any](input T) T {
	encoded, err := json.Marshal(input)
	if err != nil {
		panic(err)
	}
	var output T
	if err := json.Unmarshal(encoded, &output); err != nil {
		panic(err)
	}
	return output
}

func equalJSON(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}
