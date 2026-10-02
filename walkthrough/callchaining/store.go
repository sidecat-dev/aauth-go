package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

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
