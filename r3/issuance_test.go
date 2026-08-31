package r3_test

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func TestIssuanceStoreContractIsUsableOutsideRolePackages(t *testing.T) {
	t.Parallel()

	account := "account-1"
	reference, err := r3.NewReference(
		"https://resource.example/r3/document",
		r3.Digest([]byte(`{"operations":[{"tool":"records.read"}]}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	record := r3.IssuanceRecord{
		AuthTokenReference: aauth.TokenReference{Issuer: "https://access.example", JTI: "auth-token-1"},
		Resource:           "https://resource.example",
		R3Reference:        reference,
		Vocabulary:         r3.VocabularyURI("https://spec.modelcontextprotocol.io/r3"),
		IssuedAt:           time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC),
		PersonServer:       "https://person.example",
		Subject:            "person-1",
		Account:            &account,
		PresentedJTI:       "person-token-1",
		AgentJKT:           "agent-thumbprint",
		Agent:              "aauth:planner@provider.example",
	}
	store := &contractIssuanceStore{}
	if err := store.Commit(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	account = "mutated-by-caller"
	retained := store.recordsCopy()
	if len(retained) != 1 || retained[0].Vocabulary != record.Vocabulary ||
		retained[0].Account == nil || *retained[0].Account != "account-1" {
		t.Fatalf("retained record aliases caller state: %#v", retained)
	}
	if err := store.Commit(context.Background(), retained[0]); err != nil {
		t.Fatalf("exact repeat: %v", err)
	}
	if got := len(store.recordsCopy()); got != 1 {
		t.Fatalf("exact repeat retained %d records, want 1", got)
	}

	changed := retained[0]
	changed.Resource = "https://other-resource.example"
	if err := store.Commit(context.Background(), changed); !errors.Is(err, r3.ErrIssuanceConflict) {
		t.Fatalf("changed repeat error = %v, want %v", err, r3.ErrIssuanceConflict)
	}

	concurrent := &contractIssuanceStore{}
	const repeatCount = 16
	start := make(chan struct{})
	errorsSeen := make(chan error, repeatCount)
	var wait sync.WaitGroup
	for range repeatCount {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errorsSeen <- concurrent.Commit(context.Background(), retained[0])
		}()
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent exact repeat: %v", err)
		}
	}
	if got := len(concurrent.recordsCopy()); got != 1 {
		t.Fatalf("concurrent exact repeats retained %d records, want 1", got)
	}

	competing := &contractIssuanceStore{}
	start = make(chan struct{})
	errorsSeen = make(chan error, repeatCount)
	wait = sync.WaitGroup{}
	for index := range repeatCount {
		candidate := retained[0]
		if index%2 != 0 {
			candidate = changed
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errorsSeen <- competing.Commit(context.Background(), candidate)
		}()
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	conflicts := 0
	for err := range errorsSeen {
		switch {
		case err == nil:
		case errors.Is(err, r3.ErrIssuanceConflict):
			conflicts++
		default:
			t.Fatalf("competing commit: %v", err)
		}
	}
	winner := competing.recordsCopy()
	if len(winner) != 1 || conflicts == 0 ||
		!reflect.DeepEqual(winner[0], retained[0]) && !reflect.DeepEqual(winner[0], changed) {
		t.Fatalf("competing commits retained %#v with %d conflicts", winner, conflicts)
	}
}

var _ r3.IssuanceStore = (*contractIssuanceStore)(nil)

type contractIssuanceStore struct {
	mu      sync.Mutex
	records []r3.IssuanceRecord
}

func (store *contractIssuanceStore) Commit(_ context.Context, record r3.IssuanceRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	copy := cloneIssuanceRecord(record)
	for _, retained := range store.records {
		if retained.AuthTokenReference != copy.AuthTokenReference {
			continue
		}
		if !reflect.DeepEqual(retained, copy) {
			return r3.ErrIssuanceConflict
		}
		return nil
	}
	store.records = append(store.records, copy)
	return nil
}

func (store *contractIssuanceStore) recordsCopy() []r3.IssuanceRecord {
	store.mu.Lock()
	defer store.mu.Unlock()
	records := make([]r3.IssuanceRecord, len(store.records))
	for index, record := range store.records {
		records[index] = cloneIssuanceRecord(record)
	}
	return records
}

func cloneIssuanceRecord(record r3.IssuanceRecord) r3.IssuanceRecord {
	copy := record
	if record.Account != nil {
		account := *record.Account
		copy.Account = &account
	}
	return copy
}
