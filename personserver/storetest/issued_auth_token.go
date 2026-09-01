package storetest

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// IssuedAuthTokenContract constructs a fresh empty Person Server issued-token
// store.
type IssuedAuthTokenContract struct {
	New func(testing.TB) personserver.IssuedAuthTokenStore
}

// RunIssuedAuthToken checks issuer/JTI namespacing, exact replay, conflict
// refusal, retained-state preservation, and concurrent linearization.
func RunIssuedAuthToken(t *testing.T, contract IssuedAuthTokenContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: IssuedAuthTokenContract.New is required")
	}
	store := newIssuedAuthTokenStore(t, contract)
	ctx := context.Background()
	record := issuedAuthTokenRecord("https://person.example", "auth-token-1", "https://resource.example", 1)

	if _, err := store.LoadIssuedAuthToken(ctx, record.Reference); !errors.Is(err, personserver.ErrIssuedAuthTokenNotFound) {
		t.Fatalf("initial LoadIssuedAuthToken = %v", err)
	}
	if err := store.CommitIssuedAuthToken(ctx, record); err != nil {
		t.Fatalf("first CommitIssuedAuthToken = %v", err)
	}
	if err := store.CommitIssuedAuthToken(ctx, record); err != nil {
		t.Fatalf("exact CommitIssuedAuthToken replay = %v", err)
	}
	loaded, err := store.LoadIssuedAuthToken(ctx, record.Reference)
	if err != nil || !reflect.DeepEqual(loaded, record) {
		t.Fatalf("LoadIssuedAuthToken = %#v, %v", loaded, err)
	}
	conflicting := record
	conflicting.Resource = "https://other-resource.example"
	if err := store.CommitIssuedAuthToken(ctx, conflicting); !errors.Is(err, personserver.ErrIssuedAuthTokenConflict) {
		t.Fatalf("conflicting CommitIssuedAuthToken = %v", err)
	}
	loaded, err = store.LoadIssuedAuthToken(ctx, record.Reference)
	if err != nil || !reflect.DeepEqual(loaded, record) {
		t.Fatalf("LoadIssuedAuthToken after conflict = %#v, %v", loaded, err)
	}

	otherIssuer := issuedAuthTokenRecord("https://access.example", record.Reference.JTI, record.Resource, 2)
	if err := store.CommitIssuedAuthToken(ctx, otherIssuer); err != nil {
		t.Fatalf("same JTI under another issuer = %v", err)
	}
	loadedOther, err := store.LoadIssuedAuthToken(ctx, otherIssuer.Reference)
	if err != nil || !reflect.DeepEqual(loadedOther, otherIssuer) {
		t.Fatalf("LoadIssuedAuthToken for other issuer = %#v, %v", loadedOther, err)
	}

	runConcurrentIssuedAuthTokenCommit(t, contract)
}

func runConcurrentIssuedAuthTokenCommit(t *testing.T, contract IssuedAuthTokenContract) {
	t.Helper()
	store := newIssuedAuthTokenStore(t, contract)
	ctx := context.Background()
	left := issuedAuthTokenRecord("https://person.example", "auth-token-race", "https://left.example", 3)
	right := left
	right.Resource = "https://right.example"
	records := make([]personserver.IssuedAuthTokenRecord, 32)
	errorsByCall := make([]error, len(records))
	var wait sync.WaitGroup
	for index := range records {
		if index%2 == 0 {
			records[index] = left
		} else {
			records[index] = right
		}
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			errorsByCall[index] = store.CommitIssuedAuthToken(ctx, records[index])
		}(index)
	}
	wait.Wait()
	winner, err := store.LoadIssuedAuthToken(ctx, left.Reference)
	if err != nil || (!reflect.DeepEqual(winner, left) && !reflect.DeepEqual(winner, right)) {
		t.Fatalf("concurrent winner = %#v, %v", winner, err)
	}
	for index, callErr := range errorsByCall {
		if reflect.DeepEqual(records[index], winner) {
			if callErr != nil {
				t.Fatalf("winning concurrent CommitIssuedAuthToken %d = %v", index, callErr)
			}
			continue
		}
		if !errors.Is(callErr, personserver.ErrIssuedAuthTokenConflict) {
			t.Fatalf("losing concurrent CommitIssuedAuthToken %d = %v", index, callErr)
		}
	}
}

func newIssuedAuthTokenStore(t *testing.T, contract IssuedAuthTokenContract) personserver.IssuedAuthTokenStore {
	t.Helper()
	store := contract.New(t)
	if store == nil {
		t.Fatal("storetest: IssuedAuthTokenContract.New returned nil")
	}
	return store
}

func issuedAuthTokenRecord(issuer, jti, resourceID string, marker byte) personserver.IssuedAuthTokenRecord {
	now := time.Date(2026, 9, 1, 18, 0, 0, 0, time.UTC)
	return personserver.IssuedAuthTokenRecord{
		Reference: aauth.TokenReference{Issuer: issuer, JTI: jti},
		Resource:  resourceID, MissionS256: "mission-digest",
		CompactSHA256: [32]byte{marker}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}
