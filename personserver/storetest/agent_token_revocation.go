package storetest

import (
	"context"
	"sync"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// AgentTokenRevocationContract constructs a fresh Person Server revocation
// store for each contract run.
type AgentTokenRevocationContract struct {
	New func(testing.TB) personserver.AgentTokenRevocationStore
}

// RunAgentTokenRevocation checks the public Person Server Agent-token
// revocation store contract. Passing it complements, but does not replace,
// backend transaction, restart, and failure-injection tests.
func RunAgentTokenRevocation(t *testing.T, contract AgentTokenRevocationContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: AgentTokenRevocationContract.New is required")
	}
	store := contract.New(t)
	ctx := context.Background()
	reference := aauth.TokenReference{Issuer: "https://provider.example", JTI: "agent-token-1"}
	otherIssuer := aauth.TokenReference{Issuer: "https://other.example", JTI: reference.JTI}

	if revoked, err := store.IsRevoked(ctx, reference); err != nil || revoked {
		t.Fatalf("initial IsRevoked = %t, %v", revoked, err)
	}
	if err := store.Revoke(ctx, reference); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, reference); err != nil {
		t.Fatalf("exact Revoke replay = %v", err)
	}
	if revoked, err := store.IsRevoked(ctx, reference); err != nil || !revoked {
		t.Fatalf("retained IsRevoked = %t, %v", revoked, err)
	}
	if revoked, err := store.IsRevoked(ctx, otherIssuer); err != nil || revoked {
		t.Fatalf("same JTI under another issuer = %t, %v", revoked, err)
	}

	raceStore := contract.New(t)
	raceReference := aauth.TokenReference{Issuer: reference.Issuer, JTI: "agent-token-race"}
	var wait sync.WaitGroup
	errorsByCall := make([]error, 16)
	for index := range errorsByCall {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			if index%2 == 0 {
				errorsByCall[index] = raceStore.Revoke(ctx, raceReference)
				return
			}
			_, errorsByCall[index] = raceStore.IsRevoked(ctx, raceReference)
		}(index)
	}
	wait.Wait()
	for index, err := range errorsByCall {
		if err != nil {
			t.Fatalf("concurrent call %d = %v", index, err)
		}
	}
	if revoked, err := raceStore.IsRevoked(ctx, raceReference); err != nil || !revoked {
		t.Fatalf("terminal IsRevoked = %t, %v", revoked, err)
	}
}
