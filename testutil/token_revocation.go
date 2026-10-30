package testutil

import (
	"context"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
)

// TokenRevocationStore is an (iss, jti) revocation store. It satisfies the
// revocation store of every role: personserver.TokenRevocationStore,
// accessserver.TokenRevocationStore, resource.PersonTokenRevocationStore and
// both AgentTokenRevocationStore interfaces.
type TokenRevocationStore interface {
	Revoke(context.Context, aauth.RevocationRequest) error
	IsRevoked(context.Context, aauth.TokenReference) (bool, error)
}

// NewTokenRevocationStore returns an empty, concurrency-safe in-memory
// revocation store. Markers are kept until the store is discarded; it provides
// neither expiry cleanup, entry limits nor restart persistence.
func NewTokenRevocationStore() TokenRevocationStore {
	return &tokenRevocationStore{revoked: make(map[aauth.TokenReference]time.Time)}
}

type tokenRevocationStore struct {
	mu      sync.RWMutex
	revoked map[aauth.TokenReference]time.Time
}

func (store *tokenRevocationStore) Revoke(_ context.Context, request aauth.RevocationRequest) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if retained, ok := store.revoked[request.Reference]; !ok || request.ExpiresAt.After(retained) {
		store.revoked[request.Reference] = request.ExpiresAt
	}
	return nil
}

func (store *tokenRevocationStore) IsRevoked(_ context.Context, reference aauth.TokenReference) (bool, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	_, revoked := store.revoked[reference]
	return revoked, nil
}

// NewAccessIssuedAuthTokenStore returns an empty, concurrency-safe in-memory
// store of the auth tokens an Access Server issued. Records are kept for the
// store lifetime.
func NewAccessIssuedAuthTokenStore() accessserver.IssuedAuthTokenStore {
	return &accessIssuedAuthTokenStore{byPresented: make(map[aauth.TokenReference][]accessserver.IssuedAuthToken)}
}

type accessIssuedAuthTokenStore struct {
	mu          sync.RWMutex
	byPresented map[aauth.TokenReference][]accessserver.IssuedAuthToken
}

func (store *accessIssuedAuthTokenStore) CommitIssuedAuthToken(_ context.Context, record accessserver.IssuedAuthToken) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, retained := range store.byPresented[record.Presented] {
		if retained == record {
			return nil
		}
	}
	store.byPresented[record.Presented] = append(store.byPresented[record.Presented], record)
	return nil
}

func (store *accessIssuedAuthTokenStore) LoadIssuedAuthTokens(_ context.Context, presented aauth.TokenReference) ([]accessserver.IssuedAuthToken, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return append([]accessserver.IssuedAuthToken(nil), store.byPresented[presented]...), nil
}
