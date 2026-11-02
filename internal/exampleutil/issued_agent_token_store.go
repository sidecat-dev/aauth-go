package exampleutil

import (
	"context"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
)

// NewIssuedAgentTokenStore returns an empty, concurrency-safe in-memory
// record of the Agent tokens a provider issued.
func NewIssuedAgentTokenStore() agentprovider.IssuedAgentTokenStore {
	return &issuedAgentTokenStore{tokens: make(map[string]agentprovider.IssuedAgentToken)}
}

type issuedAgentTokenStore struct {
	mu     sync.Mutex
	tokens map[string]agentprovider.IssuedAgentToken
}

func (store *issuedAgentTokenStore) RecordIssuedAgentToken(_ context.Context, token agentprovider.IssuedAgentToken) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if current, ok := store.tokens[token.JTI]; ok {
		if current != token {
			return agentprovider.ErrIssuedAgentTokenConflict
		}
		return nil
	}
	store.tokens[token.JTI] = token
	return nil
}

func (store *issuedAgentTokenStore) LoadIssuedAgentTokens(
	_ context.Context,
	agent string,
	at time.Time,
) ([]agentprovider.IssuedAgentToken, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var found []agentprovider.IssuedAgentToken
	for _, token := range store.tokens {
		if token.Agent == agent && token.ExpiresAt.After(at) {
			found = append(found, token)
		}
	}
	return found, nil
}
