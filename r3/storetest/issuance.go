package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

// IssuanceContract constructs a fresh empty R3 issuance store.
type IssuanceContract struct {
	New func(testing.TB) r3.IssuanceStore
}

// RunIssuance checks exact replay, input ownership, token-reference
// namespacing, conflict refusal, and concurrent linearization.
func RunIssuance(t *testing.T, contract IssuanceContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: IssuanceContract.New is required")
	}
	store := contract.New(t)
	ctx := context.Background()
	record := issuanceRecord(t, "https://person.example", "auth-token-1")
	pristine := record.Clone()

	if err := store.Commit(ctx, record); err != nil {
		t.Fatalf("first Commit = %v", err)
	}
	*record.Account = "mutated-after-commit"
	if err := store.Commit(ctx, pristine); err != nil {
		t.Fatalf("exact Commit after input mutation = %v", err)
	}

	var wait sync.WaitGroup
	errorsByCall := make([]error, 16)
	for index := range errorsByCall {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			errorsByCall[index] = store.Commit(ctx, pristine)
		}(index)
	}
	wait.Wait()
	for index, err := range errorsByCall {
		if err != nil {
			t.Fatalf("concurrent exact Commit %d = %v", index, err)
		}
	}

	conflicting := pristine.Clone()
	conflicting.Subject = "different-person"
	if err := store.Commit(ctx, conflicting); !errors.Is(err, r3.ErrIssuanceConflict) {
		t.Fatalf("conflicting Commit = %v", err)
	}
	if err := store.Commit(ctx, pristine); err != nil {
		t.Fatalf("exact Commit after conflict = %v", err)
	}

	otherIssuer := pristine.Clone()
	otherIssuer.AuthTokenReference.Issuer = "https://access.example"
	if err := store.Commit(ctx, otherIssuer); err != nil {
		t.Fatalf("same JTI under another issuer = %v", err)
	}
}

func issuanceRecord(t *testing.T, issuer, jti string) r3.IssuanceRecord {
	t.Helper()
	reference, err := r3.NewReference(
		"https://resource.example/r3/document-1",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	)
	if err != nil {
		t.Fatal(err)
	}
	account := "account-1"
	return r3.IssuanceRecord{
		AuthTokenReference: aauth.TokenReference{Issuer: issuer, JTI: jti},
		Resource:           "https://resource.example",
		R3Reference:        reference,
		Vocabulary:         r3.VocabularyURI("https://modelcontextprotocol.io/schema/2025-11-25"),
		IssuedAt:           time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
		PersonServer:       "https://person.example",
		Subject:            "person-1",
		Account:            &account,
		PresentedJTI:       "person-token-1",
		AgentJKT:           "agent-thumbprint",
		Agent:              "aauth:worker@agents.example",
	}
}
