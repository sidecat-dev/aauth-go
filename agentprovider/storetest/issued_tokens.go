package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
)

// IssuedAgentTokensContract constructs a fresh empty store.
type IssuedAgentTokensContract struct {
	New func(testing.TB) agentprovider.IssuedAgentTokenStore
}

// RunIssuedAgentTokens checks the record an Agent Provider keeps of the
// Agent tokens it issued: an identical repeat is accepted, a different record
// under a retained JTI conflicts, and a load returns exactly one Agent's
// unexpired records.
func RunIssuedAgentTokens(t *testing.T, contract IssuedAgentTokensContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: IssuedAgentTokensContract.New is required")
	}
	ctx := context.Background()
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	store := contract.New(t)
	first := agentprovider.IssuedAgentToken{
		JTI: "token-1", Agent: "aauth:assistant@ap.example", PersonServer: "https://ps.example",
		ExpiresAt: now.Add(time.Hour),
	}
	second := agentprovider.IssuedAgentToken{
		JTI: "token-2", Agent: first.Agent, PersonServer: "https://other-ps.example",
		ExpiresAt: now.Add(2 * time.Hour),
	}
	expired := agentprovider.IssuedAgentToken{
		JTI: "token-3", Agent: first.Agent, PersonServer: first.PersonServer, ExpiresAt: now,
	}
	child := agentprovider.IssuedAgentToken{
		JTI: "token-4", Agent: "aauth:assistant+helper@ap.example", ParentAgent: first.Agent,
		PersonServer: first.PersonServer, ExpiresAt: now.Add(time.Hour),
	}
	for _, token := range []agentprovider.IssuedAgentToken{first, second, expired, child} {
		if err := store.RecordIssuedAgentToken(ctx, token); err != nil {
			t.Fatalf("RecordIssuedAgentToken(%s) = %v", token.JTI, err)
		}
	}
	if err := store.RecordIssuedAgentToken(ctx, first); err != nil {
		t.Fatalf("identical repeat = %v", err)
	}
	changed := first
	changed.PersonServer = "https://elsewhere.example"
	if err := store.RecordIssuedAgentToken(ctx, changed); !errors.Is(err, agentprovider.ErrIssuedAgentTokenConflict) {
		t.Fatalf("changed record under a retained JTI = %v, want ErrIssuedAgentTokenConflict", err)
	}
	loaded, err := store.LoadIssuedAgentTokens(ctx, first.Agent, now)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]agentprovider.IssuedAgentToken{}
	for _, token := range loaded {
		found[token.JTI] = token
	}
	if len(loaded) != 2 || found[first.JTI] != first || found[second.JTI] != second {
		t.Fatalf("LoadIssuedAgentTokens = %+v, want the two unexpired records of the Agent", loaded)
	}
	children, err := store.LoadIssuedAgentTokens(ctx, child.Agent, now)
	if err != nil || len(children) != 1 || children[0] != child {
		t.Fatalf("sub-agent records = %+v, %v", children, err)
	}
}
