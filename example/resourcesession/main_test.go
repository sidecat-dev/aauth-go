package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/resource"
)

func TestRunCompletesResourceManagedSession(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	const want = "AAuth Resource-managed session complete: person-123 has records.read\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}

func TestExampleStoreBoundsInvalidInteractionCodes(t *testing.T) {
	t.Parallel()

	store := newMemorySessionStore()
	now := time.Date(2026, 8, 30, 23, 45, 0, 0, time.UTC)
	record := resource.PendingSessionRecord{
		ID: "pending-1", Resource: resourceID, CodeSHA256: [32]byte{1},
		CreatedAt: now, ExpiresAt: now.Add(time.Minute), MaximumCodeAttempts: 2,
	}
	if err := store.CreatePending(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeInteractionCode(
		context.Background(), resourceID, record.ID, [32]byte{2}, now,
	); !errors.Is(err, resource.ErrSessionInteractionCodeInvalid) {
		t.Fatalf("first invalid code error = %v", err)
	}
	if _, err := store.ConsumeInteractionCode(
		context.Background(), resourceID, record.ID, [32]byte{3}, now,
	); !errors.Is(err, resource.ErrPendingSessionGone) {
		t.Fatalf("bounded invalid code error = %v", err)
	}
	if _, err := store.ConsumeInteractionCode(
		context.Background(), resourceID, record.ID, record.CodeSHA256, now,
	); !errors.Is(err, resource.ErrPendingSessionGone) {
		t.Fatalf("correct code after invalidation error = %v", err)
	}
}

func TestExampleStorePreservesTerminalStateAgainstLateApproval(t *testing.T) {
	t.Parallel()

	store := newMemorySessionStore()
	now := time.Date(2026, 8, 30, 23, 50, 0, 0, time.UTC)
	pending := resource.PendingSessionRecord{
		ID: "pending-terminal", Resource: resourceID, CodeSHA256: [32]byte{1},
		CreatedAt: now, ExpiresAt: now.Add(time.Minute), MaximumCodeAttempts: 2,
	}
	if err := store.CreatePending(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeInteractionCode(
		context.Background(), resourceID, pending.ID, pending.CodeSHA256, now,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Deny(context.Background(), pending.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(
		context.Background(), pending.ID, resource.SessionRecord{}, pending.ExpiresAt,
	); !errors.Is(err, resource.ErrPendingSessionConflict) {
		t.Fatalf("late approval after denial error = %v", err)
	}
	snapshot, err := store.LoadPending(context.Background(), pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != resource.SessionPollDenied {
		t.Fatalf("late approval changed denied state to %v", snapshot.State)
	}
	result, err := store.Poll(context.Background(), pending.ID, resource.SessionPollIdentity{Resource: resourceID}, pending.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeResult(context.Background(), pending.ID, result); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(
		context.Background(), pending.ID, resource.SessionRecord{}, pending.ExpiresAt,
	); !errors.Is(err, resource.ErrPendingSessionConflict) {
		t.Fatalf("late approval after terminal consumption error = %v", err)
	}
	if _, err := store.Poll(
		context.Background(), pending.ID, resource.SessionPollIdentity{Resource: resourceID}, pending.ExpiresAt,
	); !errors.Is(err, resource.ErrPendingSessionGone) {
		t.Fatalf("late approval resurrected consumed result: %v", err)
	}
}
