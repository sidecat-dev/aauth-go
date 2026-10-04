package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// Token bindings belong to this one Person Server process. Restart loses them.
type tokenStore struct {
	mu      sync.Mutex
	records map[string][]byte
}

func (store *tokenStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if _, exists := store.records[key]; exists {
		return errors.New("person-token binding already exists")
	}
	store.records[key] = encoded
	return nil
}

func (store *tokenStore) Load(_ context.Context, issuer, jti string) (personserver.PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	encoded, ok := store.records[issuer+"\x00"+jti]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	var record personserver.PersonTokenRecord
	err := json.Unmarshal(encoded, &record)
	return record, err
}

// Issuance records belong to this one Person Server process as well. They
// name the Agent each auth token was issued to, which is how the Person Server
// identifies the caller when that token comes back as an upstream token.
type issuedTokenStore struct {
	mu      sync.Mutex
	records map[aauth.TokenReference]personserver.IssuedAuthTokenRecord
}

func (store *issuedTokenStore) CommitIssuedAuthToken(_ context.Context, record personserver.IssuedAuthTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if retained, exists := store.records[record.Reference]; exists && retained != record {
		return personserver.ErrIssuedAuthTokenConflict
	}
	store.records[record.Reference] = record
	return nil
}

func (store *issuedTokenStore) LoadIssuedAuthToken(_ context.Context, reference aauth.TokenReference) (personserver.IssuedAuthTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[reference]
	if !ok {
		return personserver.IssuedAuthTokenRecord{}, personserver.ErrIssuedAuthTokenNotFound
	}
	return record, nil
}
