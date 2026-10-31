package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/resource"
)

// SessionContract constructs a fresh empty Resource-managed session store.
type SessionContract struct {
	New func(testing.TB) resource.SessionStore
}

// RunSession checks opaque-token retention, independent ownership, expiry,
// not-found behavior, and coexistence of distinct sessions.
func RunSession(t *testing.T, contract SessionContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: SessionContract.New is required")
	}
	store := contract.New(t)
	if store == nil {
		t.Fatal("storetest: SessionContract.New returned nil")
	}
	ctx := context.Background()
	now := sessionTestTime()
	record := sessionRecord("person-1", now)
	pristine := cloneSessionRecord(record)

	approval, err := store.Create(ctx, record)
	if err != nil || approval.Token == "" || !reflect.DeepEqual(approval.Record, pristine) {
		t.Fatalf("Create = %#v, %v", approval, err)
	}
	record.Scope[0] = "mutated-input"
	approval.Record.Scope[0] = "mutated-output"
	loaded, err := store.Load(ctx, approval.Token, now)
	if err != nil || !reflect.DeepEqual(loaded, pristine) {
		t.Fatalf("Load after mutations = %#v, %v", loaded, err)
	}
	loaded.Scope[0] = "mutated-load"
	loadedAgain, err := store.Load(ctx, approval.Token, now)
	if err != nil || !reflect.DeepEqual(loadedAgain, pristine) {
		t.Fatalf("second Load = %#v, %v", loadedAgain, err)
	}
	if _, err := store.Load(ctx, "unknown-session", now); !errors.Is(err, resource.ErrSessionNotFound) {
		t.Fatalf("unknown Load = %v", err)
	}
	if _, err := store.Load(ctx, approval.Token, pristine.ExpiresAt); !errors.Is(err, resource.ErrSessionExpired) {
		t.Fatalf("Load at expiry = %v", err)
	}

	other := sessionRecord("person-2", now)
	otherApproval, err := store.Create(ctx, other)
	if err != nil || otherApproval.Token == "" || otherApproval.Token == approval.Token {
		t.Fatalf("second Create = %#v, %v", otherApproval, err)
	}
	firstAgain, firstErr := store.Load(ctx, approval.Token, now)
	secondAgain, secondErr := store.Load(ctx, otherApproval.Token, now)
	if firstErr != nil || secondErr != nil || !reflect.DeepEqual(firstAgain, pristine) ||
		!reflect.DeepEqual(secondAgain, other) {
		t.Fatalf("coexisting sessions = first %#v/%v, second %#v/%v", firstAgain, firstErr, secondAgain, secondErr)
	}
}

// DeferredSessionContract constructs a fresh empty Resource-managed deferred
// session store.
type DeferredSessionContract struct {
	New func(testing.TB) resource.DeferredSessionStore
}

// RunDeferredSession checks the interaction lifecycle, including copy
// isolation, code-attempt bounds, identity cloaking, approval replay, denial,
// expiry, terminal consumption, invalidation, and concurrent unique creation.
func RunDeferredSession(t *testing.T, contract DeferredSessionContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: DeferredSessionContract.New is required")
	}
	t.Run("approval", func(t *testing.T) { runDeferredApproval(t, contract) })
	t.Run("denial and invalidation", func(t *testing.T) { runDeferredDenial(t, contract) })
	t.Run("expiry", func(t *testing.T) { runDeferredExpiry(t, contract) })
	t.Run("interaction attempt bound", func(t *testing.T) { runDeferredAttemptBound(t, contract) })
	t.Run("concurrent unique creation", func(t *testing.T) { runDeferredConcurrentCreate(t, contract) })
}

func runDeferredApproval(t *testing.T, contract DeferredSessionContract) {
	store := newDeferredStore(t, contract)
	ctx := context.Background()
	now := sessionTestTime()
	record := pendingSessionRecord("pending-approval", now, 3)
	pristine := clonePendingSessionRecord(record)
	if _, err := store.LoadPending(ctx, record.ID); !errors.Is(err, resource.ErrPendingSessionNotFound) {
		t.Fatalf("initial LoadPending = %v", err)
	}
	if err := store.CreatePending(ctx, record); err != nil {
		t.Fatalf("CreatePending = %v", err)
	}
	record.Request.RequiredScopes[0] = "mutated-input"
	record.Request.AgentPrincipal.AdditionalClaims["profile"] = json.RawMessage(`"mutated"`)
	snapshot := loadPending(t, store, pristine.ID)
	if snapshot.State != resource.SessionPollPending || !reflect.DeepEqual(snapshot.Record, pristine) ||
		snapshot.Approval.Token != "" {
		t.Fatalf("pending snapshot = %#v", snapshot)
	}
	snapshot.Record.Request.RequiredScopes[0] = "mutated-output"
	if again := loadPending(t, store, pristine.ID); !reflect.DeepEqual(again.Record, pristine) {
		t.Fatalf("LoadPending aliases output = %#v", again)
	}
	if err := store.CreatePending(ctx, pristine); !errors.Is(err, resource.ErrPendingSessionConflict) {
		t.Fatalf("duplicate CreatePending = %v", err)
	}
	wrongDigest := pristine.CodeSHA256
	wrongDigest[0]++
	if _, err := store.ConsumeInteractionCode(ctx, pristine.Resource, pristine.ID, resource.SessionCodePresentation{
		CodeSHA256: wrongDigest, Callback: "https://agent.example/wrong",
	}, now); !errors.Is(err, resource.ErrSessionInteractionCodeInvalid) {
		t.Fatalf("wrong interaction code = %v", err)
	}
	if snapshot := loadPending(t, store, pristine.ID); snapshot.Callback != "" {
		t.Fatalf("a failed attempt retained callback %q", snapshot.Callback)
	}
	interacting, err := store.ConsumeInteractionCode(ctx, pristine.Resource, pristine.ID, resource.SessionCodePresentation{
		CodeSHA256: pristine.CodeSHA256, Callback: "https://agent.example/callback",
	}, now)
	if err != nil || !reflect.DeepEqual(interacting, pristine) {
		t.Fatalf("ConsumeInteractionCode = %#v, %v", interacting, err)
	}
	interacting.Request.RequiredScopes[0] = "mutated-interaction"
	if snapshot := loadPending(t, store, pristine.ID); snapshot.State != resource.SessionPollInteracting ||
		!reflect.DeepEqual(snapshot.Record, pristine) || snapshot.Callback != "https://agent.example/callback" {
		t.Fatalf("interacting snapshot = %#v", snapshot)
	}
	if _, err := store.ConsumeInteractionCode(ctx, pristine.Resource, pristine.ID, resource.SessionCodePresentation{
		CodeSHA256: pristine.CodeSHA256, Callback: "https://agent.example/other",
	}, now); !errors.Is(err, resource.ErrSessionInteractionCodeUsed) {
		t.Fatalf("reused interaction code = %v", err)
	}
	if snapshot := loadPending(t, store, pristine.ID); snapshot.Callback != "https://agent.example/callback" {
		t.Fatalf("a reused code replaced callback with %q", snapshot.Callback)
	}

	session := sessionRecord("person-approved", now)
	pristineSession := cloneSessionRecord(session)
	approval, err := store.Approve(ctx, pristine.ID, session, now)
	if err != nil || approval.Token == "" || !reflect.DeepEqual(approval.Record, pristineSession) {
		t.Fatalf("Approve = %#v, %v", approval, err)
	}
	pristineApproval := cloneSessionApproval(approval)
	session.Scope[0] = "mutated-approval-input"
	approval.Record.Scope[0] = "mutated-approval-output"
	replayed, err := store.Approve(ctx, pristine.ID, pristineSession, now)
	if err != nil || !reflect.DeepEqual(replayed, pristineApproval) {
		t.Fatalf("exact Approve replay = %#v, %v", replayed, err)
	}
	changed := cloneSessionRecord(pristineSession)
	changed.Subject = "different-person"
	if _, err := store.Approve(ctx, pristine.ID, changed, now); !errors.Is(err, resource.ErrPendingSessionConflict) {
		t.Fatalf("changed Approve = %v", err)
	}
	if err := store.Invalidate(ctx, pristine.ID, now); !errors.Is(err, resource.ErrPendingSessionConflict) {
		t.Fatalf("Invalidate approved session = %v", err)
	}

	identity := sessionPollIdentity(pristine)
	wrongIdentity := identity
	wrongIdentity.Agent = "aauth:other@agents.example"
	if _, err := store.Poll(ctx, pristine.ID, wrongIdentity, now); !errors.Is(err, resource.ErrPendingSessionNotFound) {
		t.Fatalf("wrong-identity Poll = %v", err)
	}
	result, err := store.Poll(ctx, pristine.ID, identity, now)
	wantResult := resource.SessionPollRecord{
		State: resource.SessionPollApproved, Approval: pristineApproval, RetryAfter: pristine.RetryAfter,
	}
	if err != nil || !reflect.DeepEqual(result, wantResult) {
		t.Fatalf("approved Poll = %#v, %v", result, err)
	}
	result.Approval.Record.Scope[0] = "mutated-poll"
	result, err = store.Poll(ctx, pristine.ID, identity, now)
	if err != nil || !reflect.DeepEqual(result, wantResult) {
		t.Fatalf("second approved Poll = %#v, %v", result, err)
	}
	changedResult := result
	changedResult.RetryAfter++
	if err := store.ConsumeResult(ctx, pristine.ID, changedResult); !errors.Is(err, resource.ErrPendingSessionConflict) {
		t.Fatalf("changed ConsumeResult = %v", err)
	}
	if err := store.ConsumeResult(ctx, pristine.ID, result); err != nil {
		t.Fatalf("ConsumeResult = %v", err)
	}
	if _, err := store.Poll(ctx, pristine.ID, identity, now); !errors.Is(err, resource.ErrPendingSessionGone) {
		t.Fatalf("Poll after consume = %v", err)
	}
	loaded, err := store.Load(ctx, approval.Token, now)
	if err != nil || !reflect.DeepEqual(loaded, pristineSession) {
		t.Fatalf("Load approved session = %#v, %v", loaded, err)
	}
}

func runDeferredDenial(t *testing.T, contract DeferredSessionContract) {
	store := newDeferredStore(t, contract)
	ctx := context.Background()
	now := sessionTestTime()
	denied := pendingSessionRecord("pending-denied", now, 3)
	if err := store.CreatePending(ctx, denied); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeInteractionCode(ctx, denied.Resource, denied.ID, resource.SessionCodePresentation{CodeSHA256: denied.CodeSHA256}, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Deny(ctx, denied.ID, now); err != nil {
		t.Fatalf("Deny = %v", err)
	}
	if err := store.Deny(ctx, denied.ID, now); err != nil {
		t.Fatalf("exact Deny replay = %v", err)
	}
	if err := store.Invalidate(ctx, denied.ID, now); !errors.Is(err, resource.ErrPendingSessionConflict) {
		t.Fatalf("Invalidate denied session = %v", err)
	}
	result, err := store.Poll(ctx, denied.ID, sessionPollIdentity(denied), now)
	if err != nil || result.State != resource.SessionPollDenied || result.Approval.Token != "" {
		t.Fatalf("denied Poll = %#v, %v", result, err)
	}
	if err := store.ConsumeResult(ctx, denied.ID, result); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Poll(ctx, denied.ID, sessionPollIdentity(denied), now); !errors.Is(err, resource.ErrPendingSessionGone) {
		t.Fatalf("denied Poll after consume = %v", err)
	}

	invalidated := pendingSessionRecord("pending-invalidated", now, 3)
	if err := store.CreatePending(ctx, invalidated); err != nil {
		t.Fatal(err)
	}
	if err := store.Invalidate(ctx, invalidated.ID, now); err != nil {
		t.Fatalf("Invalidate = %v", err)
	}
	if err := store.Invalidate(ctx, invalidated.ID, now); err != nil {
		t.Fatalf("exact Invalidate replay = %v", err)
	}
	if _, err := store.Poll(ctx, invalidated.ID, sessionPollIdentity(invalidated), now); !errors.Is(err, resource.ErrPendingSessionGone) {
		t.Fatalf("invalidated Poll = %v", err)
	}
}

func runDeferredExpiry(t *testing.T, contract DeferredSessionContract) {
	store := newDeferredStore(t, contract)
	ctx := context.Background()
	now := sessionTestTime()
	expired := pendingSessionRecord("pending-expired", now, 3)
	if err := store.CreatePending(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeInteractionCode(ctx, expired.Resource, expired.ID, resource.SessionCodePresentation{CodeSHA256: expired.CodeSHA256}, expired.ExpiresAt); !errors.Is(err, resource.ErrPendingSessionExpired) {
		t.Fatalf("ConsumeInteractionCode at expiry = %v", err)
	}
	result, err := store.Poll(ctx, expired.ID, sessionPollIdentity(expired), expired.ExpiresAt)
	if err != nil || result.State != resource.SessionPollExpired {
		t.Fatalf("expired Poll = %#v, %v", result, err)
	}
	if err := store.ConsumeResult(ctx, expired.ID, result); err != nil {
		t.Fatalf("Consume expired result = %v", err)
	}

	lateApproval := pendingSessionRecord("pending-late-approval", now, 3)
	if err := store.CreatePending(ctx, lateApproval); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeInteractionCode(ctx, lateApproval.Resource, lateApproval.ID, resource.SessionCodePresentation{CodeSHA256: lateApproval.CodeSHA256}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(ctx, lateApproval.ID, sessionRecord("person-late", now), lateApproval.ExpiresAt); !errors.Is(err, resource.ErrPendingSessionExpired) {
		t.Fatalf("Approve at expiry = %v", err)
	}
	result, err = store.Poll(ctx, lateApproval.ID, sessionPollIdentity(lateApproval), lateApproval.ExpiresAt)
	if err != nil || result.State != resource.SessionPollExpired || result.Approval.Token != "" {
		t.Fatalf("late-approval Poll = %#v, %v", result, err)
	}
}

func runDeferredAttemptBound(t *testing.T, contract DeferredSessionContract) {
	store := newDeferredStore(t, contract)
	ctx := context.Background()
	now := sessionTestTime()
	record := pendingSessionRecord("pending-attempts", now, 2)
	if err := store.CreatePending(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeInteractionCode(ctx, "https://wrong.example", record.ID, resource.SessionCodePresentation{CodeSHA256: record.CodeSHA256}, now); !errors.Is(err, resource.ErrSessionInteractionCodeInvalid) {
		t.Fatalf("first invalid attempt = %v", err)
	}
	wrongDigest := record.CodeSHA256
	wrongDigest[0]++
	if _, err := store.ConsumeInteractionCode(ctx, record.Resource, record.ID, resource.SessionCodePresentation{CodeSHA256: wrongDigest}, now); !errors.Is(err, resource.ErrPendingSessionGone) {
		t.Fatalf("bounded invalid attempt = %v", err)
	}
	if _, err := store.ConsumeInteractionCode(ctx, record.Resource, record.ID, resource.SessionCodePresentation{CodeSHA256: record.CodeSHA256}, now); !errors.Is(err, resource.ErrPendingSessionGone) {
		t.Fatalf("correct code after invalidation = %v", err)
	}
}

func runDeferredConcurrentCreate(t *testing.T, contract DeferredSessionContract) {
	store := newDeferredStore(t, contract)
	ctx := context.Background()
	record := pendingSessionRecord("pending-concurrent", sessionTestTime(), 3)
	errorsByCall := make([]error, 16)
	var wait sync.WaitGroup
	for index := range errorsByCall {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			errorsByCall[index] = store.CreatePending(ctx, clonePendingSessionRecord(record))
		}(index)
	}
	wait.Wait()
	succeeded := 0
	conflicted := 0
	for index, err := range errorsByCall {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, resource.ErrPendingSessionConflict):
			conflicted++
		default:
			t.Fatalf("concurrent CreatePending %d = %v", index, err)
		}
	}
	if succeeded != 1 || conflicted != len(errorsByCall)-1 {
		t.Fatalf("concurrent CreatePending: succeeded=%d conflicted=%d", succeeded, conflicted)
	}
}

func newDeferredStore(t *testing.T, contract DeferredSessionContract) resource.DeferredSessionStore {
	t.Helper()
	store := contract.New(t)
	if store == nil {
		t.Fatal("storetest: DeferredSessionContract.New returned nil")
	}
	return store
}

func sessionTestTime() time.Time {
	return time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)
}

func sessionRecord(subject string, now time.Time) resource.SessionRecord {
	return resource.SessionRecord{
		Resource: "https://resource.example", AgentProvider: "https://agents.example",
		Agent: "aauth:worker@agents.example", ParentAgent: "aauth:parent@agents.example",
		Subject: subject, Scope: []string{"records.read"},
		CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}
}

func pendingSessionRecord(id string, now time.Time, maximumAttempts int) resource.PendingSessionRecord {
	return resource.PendingSessionRecord{
		ID: id, CodeSHA256: [32]byte{1, 2, 3}, Resource: "https://resource.example",
		Request: resource.SessionAuthorizationRequest{
			AgentPrincipal: resource.AgentPrincipal{
				AgentProvider: "https://agents.example", Agent: "aauth:worker@agents.example",
				ParentAgent:      "aauth:parent@agents.example",
				AdditionalClaims: map[string]json.RawMessage{"profile": json.RawMessage(`"managed"`)},
			},
			Method: "GET", Path: "/records", RequiredScopes: []string{"records.read"},
		},
		CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), RetryAfter: 3 * time.Second,
		MaximumCodeAttempts: maximumAttempts,
	}
}

func sessionPollIdentity(record resource.PendingSessionRecord) resource.SessionPollIdentity {
	return resource.SessionPollIdentity{
		Resource: record.Resource, AgentProvider: record.Request.AgentPrincipal.AgentProvider,
		Agent: record.Request.AgentPrincipal.Agent, ParentAgent: record.Request.AgentPrincipal.ParentAgent,
	}
}

func loadPending(t *testing.T, store resource.DeferredSessionStore, id string) resource.PendingSessionSnapshot {
	t.Helper()
	snapshot, err := store.LoadPending(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func cloneSessionRecord(record resource.SessionRecord) resource.SessionRecord {
	record.Scope = append([]string(nil), record.Scope...)
	return record
}

func cloneSessionApproval(approval resource.SessionApproval) resource.SessionApproval {
	approval.Record = cloneSessionRecord(approval.Record)
	return approval
}

func clonePendingSessionRecord(record resource.PendingSessionRecord) resource.PendingSessionRecord {
	record.Request.RequiredScopes = append([]string(nil), record.Request.RequiredScopes...)
	claims := record.Request.AgentPrincipal.AdditionalClaims
	if claims != nil {
		record.Request.AgentPrincipal.AdditionalClaims = make(map[string]json.RawMessage, len(claims))
		for name, value := range claims {
			record.Request.AgentPrincipal.AdditionalClaims[name] = append(json.RawMessage(nil), value...)
		}
	}
	return record
}
