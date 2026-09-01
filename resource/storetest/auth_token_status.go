package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

// AuthTokenStatusContract constructs a fresh empty Resource auth-token status
// store.
type AuthTokenStatusContract struct {
	New func(testing.TB) resource.AuthTokenStatusStore
}

// RunAuthTokenStatus checks issuer/JTI namespacing, exact observation,
// conflict refusal, idempotent revocation, no resurrection, and concurrent
// Observe/Revoke linearization.
func RunAuthTokenStatus(t *testing.T, contract AuthTokenStatusContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: AuthTokenStatusContract.New is required")
	}
	store := newAuthTokenStatusStore(t, contract)
	ctx := context.Background()
	record := observedAuthToken("https://person.example", "auth-token-1", 1)

	if err := store.Revoke(ctx, record.Reference); !errors.Is(err, resource.ErrAuthTokenNotFound) {
		t.Fatalf("initial Revoke = %v", err)
	}
	if err := store.Observe(ctx, record); err != nil {
		t.Fatalf("first Observe = %v", err)
	}
	if err := store.Observe(ctx, record); err != nil {
		t.Fatalf("exact Observe replay = %v", err)
	}
	conflicting := record
	conflicting.CompactSHA256[0]++
	if err := store.Observe(ctx, conflicting); !errors.Is(err, resource.ErrAuthTokenConflict) {
		t.Fatalf("conflicting Observe = %v", err)
	}
	if err := store.Observe(ctx, record); err != nil {
		t.Fatalf("exact Observe after conflict = %v", err)
	}

	otherIssuer := observedAuthToken("https://access.example", record.Reference.JTI, 2)
	if err := store.Observe(ctx, otherIssuer); err != nil {
		t.Fatalf("same JTI under another issuer = %v", err)
	}
	if err := store.Revoke(ctx, record.Reference); err != nil {
		t.Fatalf("Revoke = %v", err)
	}
	if err := store.Revoke(ctx, record.Reference); err != nil {
		t.Fatalf("exact Revoke replay = %v", err)
	}
	if err := store.Observe(ctx, record); !errors.Is(err, resource.ErrAuthTokenRevoked) {
		t.Fatalf("Observe after Revoke = %v", err)
	}
	if err := store.Observe(ctx, conflicting); !errors.Is(err, resource.ErrAuthTokenConflict) {
		t.Fatalf("changed Observe after Revoke = %v", err)
	}
	if err := store.Observe(ctx, otherIssuer); err != nil {
		t.Fatalf("other issuer changed by Revoke = %v", err)
	}

	runConcurrentAuthTokenStatus(t, contract)
}

func runConcurrentAuthTokenStatus(t *testing.T, contract AuthTokenStatusContract) {
	t.Helper()
	store := newAuthTokenStatusStore(t, contract)
	ctx := context.Background()
	record := observedAuthToken("https://person.example", "auth-token-race", 3)
	if err := store.Observe(ctx, record); err != nil {
		t.Fatal(err)
	}
	errorsByCall := make([]error, 32)
	var wait sync.WaitGroup
	for index := range errorsByCall {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			if index%2 == 0 {
				errorsByCall[index] = store.Observe(ctx, record)
				return
			}
			errorsByCall[index] = store.Revoke(ctx, record.Reference)
		}(index)
	}
	wait.Wait()
	for index, err := range errorsByCall {
		if index%2 == 0 {
			if err != nil && !errors.Is(err, resource.ErrAuthTokenRevoked) {
				t.Fatalf("concurrent Observe %d = %v", index, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("concurrent Revoke %d = %v", index, err)
		}
	}
	if err := store.Observe(ctx, record); !errors.Is(err, resource.ErrAuthTokenRevoked) {
		t.Fatalf("terminal Observe = %v", err)
	}
	if err := store.Revoke(ctx, record.Reference); err != nil {
		t.Fatalf("terminal Revoke replay = %v", err)
	}
}

func newAuthTokenStatusStore(t *testing.T, contract AuthTokenStatusContract) resource.AuthTokenStatusStore {
	t.Helper()
	store := contract.New(t)
	if store == nil {
		t.Fatal("storetest: AuthTokenStatusContract.New returned nil")
	}
	return store
}

func observedAuthToken(issuer, jti string, marker byte) resource.ObservedAuthToken {
	return resource.ObservedAuthToken{
		Reference:     aauth.TokenReference{Issuer: issuer, JTI: jti},
		CompactSHA256: [32]byte{marker},
		ExpiresAt:     time.Date(2026, 9, 1, 19, 0, 0, 0, time.UTC),
	}
}
