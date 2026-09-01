package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	errLoginRequired   = errors.New("login_required")
	errLoginDenied     = errors.New("login_denied")
	errAccountConflict = errors.New("account_conflict")
)

type linkedConnector struct {
	Account    string `json:"account"`
	Credential string `json:"credential"`
}

type accountStoreState struct {
	Email           string               `json:"email"`
	PasswordSHA256  string               `json:"password_sha256"`
	Sessions        map[string]time.Time `json:"sessions"`
	Connector       *linkedConnector     `json:"connector,omitempty"`
	MissionApproved bool                 `json:"mission_approved"`
}

type accountFileStore struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
}

func initializeAccountStore(path, email, password string) error {
	digest := sha256.Sum256([]byte(password))
	return writeJSONFile(path, 0o600, accountStoreState{
		Email: email, PasswordSHA256: fmt.Sprintf("%x", digest[:]), Sessions: map[string]time.Time{},
	})
}

func newAccountFileStore(path string, now func() time.Time) *accountFileStore {
	return &accountFileStore{path: path, now: now}
}

func (store *accountFileStore) login(email, password string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(password))
	encoded := fmt.Sprintf("%x", digest[:])
	if email != state.Email || len(encoded) != len(state.PasswordSHA256) || subtle.ConstantTimeCompare([]byte(encoded), []byte(state.PasswordSHA256)) != 1 {
		return "", errLoginDenied
	}
	token, err := randomSecret()
	if err != nil {
		return "", err
	}
	state.Sessions[token] = store.now().UTC().Add(time.Hour)
	if err := store.save(state); err != nil {
		return "", err
	}
	return token, nil
}

func (store *accountFileStore) link(token, account string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return err
	}
	if !sessionActive(state, token, store.now()) {
		return errLoginRequired
	}
	if state.Connector != nil {
		if state.Connector.Account != account {
			return errAccountConflict
		}
		return nil
	}
	credential, err := randomSecret()
	if err != nil {
		return err
	}
	state.Connector = &linkedConnector{Account: account, Credential: credential}
	return store.save(state)
}

func (store *accountFileStore) status(token string) (string, string, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return "", "", false, err
	}
	if !sessionActive(state, token, store.now()) {
		return "", "", false, errLoginRequired
	}
	if state.Connector == nil {
		return state.Email, "", false, nil
	}
	return state.Email, state.Connector.Account, true, nil
}

func (store *accountFileStore) approveMission(token string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return err
	}
	if !sessionActive(state, token, store.now()) {
		return errLoginRequired
	}
	if state.Connector == nil {
		return errors.New("connector account is not linked")
	}
	state.MissionApproved = true
	return store.save(state)
}

func (store *accountFileStore) approvedMissionAccount() (string, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return "", false, err
	}
	if !state.MissionApproved || state.Connector == nil {
		return "", false, nil
	}
	return state.Connector.Account, true, nil
}

func (store *accountFileStore) connectorCredential(account string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, err := store.load()
	if err != nil {
		return "", err
	}
	if state.Connector == nil || state.Connector.Account != account {
		return "", errors.New("connector account is unavailable")
	}
	return state.Connector.Credential, nil
}

func (store *accountFileStore) load() (accountStoreState, error) {
	var state accountStoreState
	if err := readJSON(store.path, &state); err != nil {
		return state, err
	}
	if state.Email == "" || state.PasswordSHA256 == "" || state.Sessions == nil {
		return state, errors.New("account store is incomplete")
	}
	return state, nil
}

func (store *accountFileStore) save(state accountStoreState) error {
	return writeJSONFile(store.path, 0o600, state)
}

func sessionActive(state accountStoreState, token string, now time.Time) bool {
	expiresAt, ok := state.Sessions[token]
	return ok && expiresAt.After(now.UTC())
}
