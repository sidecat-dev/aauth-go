package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// AgentBindingRevocationContract constructs a fresh Person Server binding
// revocation store for each contract run.
type AgentBindingRevocationContract struct {
	New func(testing.TB) personserver.AgentBindingRevocationStore
}

// RunAgentBindingRevocation checks the public Agent-person binding revocation
// store contract: a binding starts unrevoked; revocation is idempotent, keeps
// the later instant, clears a replacement, and is isolated to one provider and
// Agent; a replacement requires a revocation, keeps its first instant, never
// precedes the revocation, and does not erase it; and concurrent revocations
// and lookups settle on revoked. Passing it complements, but does not replace,
// backend transaction, restart, and failure-injection tests.
func RunAgentBindingRevocation(t *testing.T, contract AgentBindingRevocationContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: AgentBindingRevocationContract.New is required")
	}
	store := contract.New(t)
	ctx := context.Background()
	binding := personserver.AgentBinding{AgentProvider: "https://provider.example", Agent: "aauth:planner@provider.example"}
	otherAgent := personserver.AgentBinding{AgentProvider: binding.AgentProvider, Agent: "aauth:other@provider.example"}
	otherProvider := personserver.AgentBinding{AgentProvider: "https://other.example", Agent: binding.Agent}
	revokedAt := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	expect := func(t *testing.T, binding personserver.AgentBinding, revoked, reestablished time.Time) {
		t.Helper()
		state, err := store.LoadAgentBindingRevocation(ctx, binding)
		if err != nil || !state.RevokedAt.Equal(revoked) || !state.ReestablishedAt.Equal(reestablished) {
			t.Fatalf("LoadAgentBindingRevocation(%#v) = %#v, %v; want revoked %v, reestablished %v", binding, state, err, revoked, reestablished)
		}
	}

	expect(t, binding, time.Time{}, time.Time{})
	if err := store.ReestablishAgentBinding(ctx, binding, revokedAt); !errors.Is(err, personserver.ErrAgentBindingNotRevoked) {
		t.Fatalf("ReestablishAgentBinding before revocation = %v", err)
	}
	expect(t, binding, time.Time{}, time.Time{})
	if err := store.RevokeAgentBinding(ctx, binding, revokedAt); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeAgentBinding(ctx, binding, revokedAt); err != nil {
		t.Fatalf("exact RevokeAgentBinding replay = %v", err)
	}
	if err := store.RevokeAgentBinding(ctx, binding, revokedAt.Add(-time.Minute)); err != nil {
		t.Fatalf("earlier RevokeAgentBinding = %v", err)
	}
	expect(t, binding, revokedAt, time.Time{})
	for _, unrelated := range []personserver.AgentBinding{otherAgent, otherProvider} {
		expect(t, unrelated, time.Time{}, time.Time{})
	}

	reestablishedAt := revokedAt.Add(time.Minute)
	if err := store.ReestablishAgentBinding(ctx, binding, reestablishedAt); err != nil {
		t.Fatal(err)
	}
	if err := store.ReestablishAgentBinding(ctx, binding, reestablishedAt.Add(time.Minute)); err != nil {
		t.Fatalf("repeated ReestablishAgentBinding = %v", err)
	}
	expect(t, binding, revokedAt, reestablishedAt)

	again := reestablishedAt.Add(time.Hour)
	if err := store.RevokeAgentBinding(ctx, binding, again); err != nil {
		t.Fatal(err)
	}
	expect(t, binding, again, time.Time{})
	if err := store.ReestablishAgentBinding(ctx, binding, again.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	expect(t, binding, again, again)

	raceStore := contract.New(t)
	var wait sync.WaitGroup
	errorsByCall := make([]error, 16)
	for index := range errorsByCall {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			if index%2 == 0 {
				errorsByCall[index] = raceStore.RevokeAgentBinding(ctx, binding, revokedAt)
				return
			}
			_, errorsByCall[index] = raceStore.LoadAgentBindingRevocation(ctx, binding)
		}(index)
	}
	wait.Wait()
	for index, err := range errorsByCall {
		if err != nil {
			t.Fatalf("concurrent call %d = %v", index, err)
		}
	}
	if state, err := raceStore.LoadAgentBindingRevocation(ctx, binding); err != nil ||
		!state.RevokedAt.Equal(revokedAt) || !state.ReestablishedAt.IsZero() {
		t.Fatalf("terminal LoadAgentBindingRevocation = %#v, %v", state, err)
	}
}
