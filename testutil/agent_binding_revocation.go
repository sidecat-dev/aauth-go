package testutil

import (
	"context"
	"sync"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// NewAgentBindingRevocationStore returns an empty, concurrency-safe in-memory
// store for a Person Server's AgentBindingRevocations. Revocations remain until
// the store is discarded; it provides neither removal nor restart persistence.
func NewAgentBindingRevocationStore() personserver.AgentBindingRevocationStore {
	return &agentBindingRevocationStore{revoked: make(map[personserver.AgentBinding]struct{})}
}

type agentBindingRevocationStore struct {
	mu      sync.RWMutex
	revoked map[personserver.AgentBinding]struct{}
}

func (store *agentBindingRevocationStore) RevokeAgentBinding(ctx context.Context, binding personserver.AgentBinding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revoked[binding] = struct{}{}
	return nil
}

func (store *agentBindingRevocationStore) IsAgentBindingRevoked(ctx context.Context, binding personserver.AgentBinding) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	_, revoked := store.revoked[binding]
	return revoked, nil
}
