package testutil

import (
	"context"
	"sync"

	"gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

type issuedAuthTokenStore struct {
	mu      sync.Mutex
	records map[aauth.TokenReference]personserver.IssuedAuthTokenRecord
}

// NewIssuedAuthTokenStore returns an empty, concurrency-safe Person Server
// issuance store for targeted Auth-token revocation. Records are retained for
// the store lifetime.
func NewIssuedAuthTokenStore() personserver.IssuedAuthTokenStore {
	return &issuedAuthTokenStore{records: make(map[aauth.TokenReference]personserver.IssuedAuthTokenRecord)}
}

func (store *issuedAuthTokenStore) CommitIssuedAuthToken(_ context.Context, record personserver.IssuedAuthTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if retained, ok := store.records[record.Reference]; ok && retained != record {
		return personserver.ErrIssuedAuthTokenConflict
	}
	store.records[record.Reference] = record
	return nil
}

func (store *issuedAuthTokenStore) LoadIssuedAuthToken(_ context.Context, reference aauth.TokenReference) (personserver.IssuedAuthTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[reference]
	if !ok {
		return personserver.IssuedAuthTokenRecord{}, personserver.ErrIssuedAuthTokenNotFound
	}
	return record, nil
}

type authTokenStatusStore struct {
	mu      sync.Mutex
	records map[aauth.TokenReference]resource.ObservedAuthToken
	revoked map[aauth.TokenReference]bool
}

// NewAuthTokenStatusStore returns an empty, concurrency-safe Resource store
// for observed Auth tokens and revocations. Revocation markers are retained for
// the store lifetime, including tokens revoked before their first use.
func NewAuthTokenStatusStore() resource.AuthTokenStatusStore {
	return &authTokenStatusStore{
		records: make(map[aauth.TokenReference]resource.ObservedAuthToken),
		revoked: make(map[aauth.TokenReference]bool),
	}
}

func (store *authTokenStatusStore) Observe(_ context.Context, record resource.ObservedAuthToken) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	reference := record.Reference
	if _, ok := store.records[reference]; !ok && store.revoked[reference] {
		return resource.ErrAuthTokenRevoked
	}
	if retained, ok := store.records[reference]; ok {
		if retained != record {
			return resource.ErrAuthTokenConflict
		}
		if store.revoked[reference] {
			return resource.ErrAuthTokenRevoked
		}
		return nil
	}
	store.records[reference] = record
	return nil
}

func (store *authTokenStatusStore) Revoke(_ context.Context, request aauth.RevocationRequest) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revoked[request.Reference] = true
	return nil
}
