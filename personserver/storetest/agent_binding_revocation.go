package storetest

import (
	"context"
	"sync"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// AgentBindingRevocationContract constructs a fresh Person Server binding
// revocation store for each contract run.
type AgentBindingRevocationContract struct {
	New func(testing.TB) personserver.AgentBindingRevocationStore
}

// RunAgentBindingRevocation checks the public Agent-person binding revocation
// store contract: initially no binding is revoked, revocation is idempotent and
// isolated to one provider and Agent, and concurrent revocations and lookups
// settle on revoked. Passing it complements, but does not replace, backend
// transaction, restart, and failure-injection tests.
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

	if revoked, err := store.IsAgentBindingRevoked(ctx, binding); err != nil || revoked {
		t.Fatalf("initial IsAgentBindingRevoked = %t, %v", revoked, err)
	}
	if err := store.RevokeAgentBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeAgentBinding(ctx, binding); err != nil {
		t.Fatalf("exact RevokeAgentBinding replay = %v", err)
	}
	if revoked, err := store.IsAgentBindingRevoked(ctx, binding); err != nil || !revoked {
		t.Fatalf("retained IsAgentBindingRevoked = %t, %v", revoked, err)
	}
	for _, unrelated := range []personserver.AgentBinding{otherAgent, otherProvider} {
		if revoked, err := store.IsAgentBindingRevoked(ctx, unrelated); err != nil || revoked {
			t.Fatalf("unrelated binding %#v revoked = %t, %v", unrelated, revoked, err)
		}
	}

	raceStore := contract.New(t)
	var wait sync.WaitGroup
	errorsByCall := make([]error, 16)
	for index := range errorsByCall {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			if index%2 == 0 {
				errorsByCall[index] = raceStore.RevokeAgentBinding(ctx, binding)
				return
			}
			_, errorsByCall[index] = raceStore.IsAgentBindingRevoked(ctx, binding)
		}(index)
	}
	wait.Wait()
	for index, err := range errorsByCall {
		if err != nil {
			t.Fatalf("concurrent call %d = %v", index, err)
		}
	}
	if revoked, err := raceStore.IsAgentBindingRevoked(ctx, binding); err != nil || !revoked {
		t.Fatalf("terminal IsAgentBindingRevoked = %t, %v", revoked, err)
	}
}
