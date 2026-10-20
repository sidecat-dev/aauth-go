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

// RunIssuedAuthToken checks issuer/JTI namespacing, exact round-trip and
// replay of a record with every field set, conflict refusal for a change to
// any one field, retained-state preservation, and concurrent linearization.
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
	// Every retained field takes part in the conflict comparison, including
	// the recipient Agent and the upstream token of a chained issuance.
	for _, conflict := range []struct {
		name   string
		change func(*personserver.IssuedAuthTokenRecord)
	}{
		{"resource", func(record *personserver.IssuedAuthTokenRecord) { record.Resource = "https://other-resource.example" }},
		{"mission", func(record *personserver.IssuedAuthTokenRecord) { record.MissionS256 = "other-mission-digest" }},
		{"compact digest", func(record *personserver.IssuedAuthTokenRecord) { record.CompactSHA256[31] ^= 1 }},
		{"issued at", func(record *personserver.IssuedAuthTokenRecord) { record.IssuedAt = record.IssuedAt.Add(time.Second) }},
		{"expires at", func(record *personserver.IssuedAuthTokenRecord) { record.ExpiresAt = record.ExpiresAt.Add(time.Second) }},
		{"agent provider", func(record *personserver.IssuedAuthTokenRecord) { record.AgentProvider = "https://other-agent.example" }},
		{"agent", func(record *personserver.IssuedAuthTokenRecord) { record.Agent = "aauth:other@agent.example" }},
		{"parent agent", func(record *personserver.IssuedAuthTokenRecord) { record.ParentAgent = "aauth:parent@agent.example" }},
		{"agent token jti", func(record *personserver.IssuedAuthTokenRecord) { record.AgentTokenJTI = "other-agent-token" }},
		{"agent key thumbprint", func(record *personserver.IssuedAuthTokenRecord) { record.AgentJKT = "other-agent-key-thumbprint" }},
		{"upstream issuer", func(record *personserver.IssuedAuthTokenRecord) {
			record.UpstreamTokenReference.Issuer = "https://other-person.example"
		}},
		{"upstream jti", func(record *personserver.IssuedAuthTokenRecord) {
			record.UpstreamTokenReference.JTI = "other-upstream-token"
		}},
		{"upstream digest", func(record *personserver.IssuedAuthTokenRecord) { record.UpstreamTokenSHA256[31] ^= 1 }},
	} {
		conflicting := record
		conflict.change(&conflicting)
		if reflect.DeepEqual(conflicting, record) {
			t.Fatalf("%s conflict case leaves the record unchanged", conflict.name)
		}
		if err := store.CommitIssuedAuthToken(ctx, conflicting); !errors.Is(err, personserver.ErrIssuedAuthTokenConflict) {
			t.Fatalf("CommitIssuedAuthToken with changed %s = %v", conflict.name, err)
		}
		loaded, err = store.LoadIssuedAuthToken(ctx, record.Reference)
		if err != nil || !reflect.DeepEqual(loaded, record) {
			t.Fatalf("LoadIssuedAuthToken after changed %s = %#v, %v", conflict.name, loaded, err)
		}
	}
	if err := store.CommitIssuedAuthToken(ctx, record); err != nil {
		t.Fatalf("exact CommitIssuedAuthToken replay after conflicts = %v", err)
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
		AgentProvider: "https://agent.example", Agent: "aauth:assistant@agent.example",
		AgentTokenJTI: "agent-token-" + jti, AgentJKT: "agent-key-thumbprint",
		UpstreamTokenReference: aauth.TokenReference{Issuer: issuer, JTI: "upstream-" + jti},
		UpstreamTokenSHA256:    [32]byte{marker, 1},
	}
}
