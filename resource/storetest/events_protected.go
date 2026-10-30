package storetest

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/resource"
)

// ProtectedEventsContract constructs a fresh empty protected Events store.
type ProtectedEventsContract struct {
	New func(testing.TB) resource.ProtectedSubscriptionStore
}

// RunProtectedEvents checks ticket retention, cloaking of a ticket presented
// by another key, expiry, single-use registration under concurrency, and
// exact-result recovery.
func RunProtectedEvents(t *testing.T, contract ProtectedEventsContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: ProtectedEventsContract.New is required")
	}
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 1, 30, 0, 0, time.UTC)
	store := contract.New(t)
	const (
		keyThumbprint   = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
		otherThumbprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	)
	ticket := resource.ProtectedSubscriptionTicket{
		ID: "ticket-1", Resource: "https://resource.example", KeyThumbprint: keyThumbprint,
		Context:   []byte(`{"operation":"appointments.create"}`),
		CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	if err := store.CreateProtectedSubscriptionTicket(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	ticket.Context[0] = 'x'
	loaded, err := store.LoadProtectedSubscriptionTicket(ctx, ticket.ID, ticket.KeyThumbprint, now)
	if err != nil || loaded.Context[0] != '{' {
		t.Fatalf("loaded ticket = %#v, %v", loaded, err)
	}
	if _, err := store.LoadProtectedSubscriptionTicket(ctx, ticket.ID, otherThumbprint, now); !errors.Is(err, resource.ErrProtectedSubscriptionNotFound) {
		t.Fatalf("load with another key thumbprint = %v", err)
	}
	if _, err := store.LoadProtectedSubscriptionTicket(ctx, ticket.ID, ticket.KeyThumbprint, loaded.ExpiresAt); !errors.Is(err, resource.ErrProtectedSubscriptionExpired) {
		t.Fatalf("expired load = %v", err)
	}

	candidate := resource.EventSubscription{
		EventID: "event-1", AgentProvider: "https://ap.example", Agent: "aauth:agent@ap.example",
		RegistrationSHA256: sha256.Sum256([]byte("registration")),
		RegisteredAt:       now.Add(time.Second), ExpiresAt: now.Add(time.Hour),
	}
	retained, err := store.CommitProtectedSubscription(ctx, loaded, candidate)
	if err != nil || retained.RegistrationSHA256 != candidate.RegistrationSHA256 {
		t.Fatalf("first commit = %#v, %v", retained, err)
	}
	used, err := store.LoadProtectedSubscriptionTicket(ctx, ticket.ID, ticket.KeyThumbprint, now.Add(2*time.Second))
	if err != nil || used.UsedAt.IsZero() || used.RegistrationSHA256 != candidate.RegistrationSHA256 {
		t.Fatalf("used ticket = %#v, %v", used, err)
	}
	usedAfterExpiry, err := store.LoadProtectedSubscriptionTicket(ctx, ticket.ID, ticket.KeyThumbprint, loaded.ExpiresAt)
	if err != nil || usedAfterExpiry.RegistrationSHA256 != candidate.RegistrationSHA256 {
		t.Fatalf("used ticket after expiry = %#v, %v", usedAfterExpiry, err)
	}
	replayed, err := store.CommitProtectedSubscription(ctx, usedAfterExpiry, candidate)
	if err != nil || replayed.RegistrationSHA256 != candidate.RegistrationSHA256 {
		t.Fatalf("exact replay = %#v, %v", replayed, err)
	}
	changed := candidate
	changed.RegistrationSHA256 = sha256.Sum256([]byte("changed"))
	if _, err := store.CommitProtectedSubscription(ctx, used, changed); !errors.Is(err, resource.ErrProtectedSubscriptionConflict) {
		t.Fatalf("changed replay = %v", err)
	}
	loadedSubscription, err := store.Load(ctx, resource.EventSubscriptionRef{
		AgentProvider: candidate.AgentProvider, EventID: candidate.EventID,
	})
	if err != nil || loadedSubscription.RegistrationSHA256 != candidate.RegistrationSHA256 {
		t.Fatalf("Load subscription = %#v, %v", loadedSubscription, err)
	}

	concurrentStore := contract.New(t)
	concurrentTicket := ticket
	concurrentTicket.ID = "ticket-concurrent"
	concurrentTicket.Context = []byte("concurrent")
	if err := concurrentStore.CreateProtectedSubscriptionTicket(ctx, concurrentTicket); err != nil {
		t.Fatal(err)
	}
	concurrentTicket, err = concurrentStore.LoadProtectedSubscriptionTicket(
		ctx, concurrentTicket.ID, concurrentTicket.KeyThumbprint, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	first := candidate
	first.EventID = "event-concurrent-first"
	first.RegistrationSHA256 = sha256.Sum256([]byte("concurrent-first"))
	second := first
	second.EventID = "event-concurrent-second"
	second.RegistrationSHA256 = sha256.Sum256([]byte("concurrent-second"))
	results := make(chan error, 2)
	for _, contender := range []resource.EventSubscription{first, second} {
		contender := contender
		go func() {
			_, commitErr := concurrentStore.CommitProtectedSubscription(ctx, concurrentTicket, contender)
			results <- commitErr
		}()
	}
	var successes, conflicts int
	for range 2 {
		result := <-results
		switch {
		case result == nil:
			successes++
		case errors.Is(result, resource.ErrProtectedSubscriptionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent commit = %v", result)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent results: successes=%d conflicts=%d", successes, conflicts)
	}
}
