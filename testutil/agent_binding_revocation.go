package testutil

import (
	"context"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// NewAgentBindingRevocationStore returns an empty, concurrency-safe in-memory
// store for a Person Server's AgentBindingRevocations. Entries remain until the
// store is discarded; it provides no restart persistence.
func NewAgentBindingRevocationStore() personserver.AgentBindingRevocationStore {
	return &agentBindingRevocationStore{states: make(map[personserver.AgentBinding]personserver.AgentBindingRevocation)}
}

type agentBindingRevocationStore struct {
	mu     sync.RWMutex
	states map[personserver.AgentBinding]personserver.AgentBindingRevocation
}

func (store *agentBindingRevocationStore) RevokeAgentBinding(ctx context.Context, binding personserver.AgentBinding, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	state := store.states[binding]
	if at.After(state.RevokedAt) {
		state.RevokedAt = at
	}
	state.ReestablishedAt = time.Time{}
	store.states[binding] = state
	return nil
}

func (store *agentBindingRevocationStore) ReestablishAgentBinding(ctx context.Context, binding personserver.AgentBinding, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	state, ok := store.states[binding]
	if !ok {
		return personserver.ErrAgentBindingNotRevoked
	}
	if !state.ReestablishedAt.IsZero() {
		return nil
	}
	state.ReestablishedAt = at
	if at.Before(state.RevokedAt) {
		state.ReestablishedAt = state.RevokedAt
	}
	store.states[binding] = state
	return nil
}

func (store *agentBindingRevocationStore) LoadAgentBindingRevocation(ctx context.Context, binding personserver.AgentBinding) (personserver.AgentBindingRevocation, error) {
	if err := ctx.Err(); err != nil {
		return personserver.AgentBindingRevocation{}, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.states[binding], nil
}
