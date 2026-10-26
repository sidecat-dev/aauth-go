package testutil

import (
	"context"
	"sync"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

// NewAgentTokenRevocationStore returns an empty, concurrency-safe in-memory
// store for a Resource's AgentTokenRevocations. Markers remain until the store
// is discarded; it provides neither expiry cleanup nor restart persistence.
func NewAgentTokenRevocationStore() resource.AgentTokenRevocationStore {
	return &agentTokenRevocationStore{revoked: make(map[aauth.TokenReference]struct{})}
}

type agentTokenRevocationStore struct {
	mu      sync.RWMutex
	revoked map[aauth.TokenReference]struct{}
}

func (store *agentTokenRevocationStore) Revoke(_ context.Context, request aauth.RevocationRequest) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revoked[request.Reference] = struct{}{}
	return nil
}

func (store *agentTokenRevocationStore) IsRevoked(_ context.Context, reference aauth.TokenReference) (bool, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	_, revoked := store.revoked[reference]
	return revoked, nil
}
