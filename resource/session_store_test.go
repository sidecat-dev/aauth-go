package resource

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

var _ DeferredSessionStore = (*memorySessionStore)(nil)

func TestSessionStoreCreatesOpaqueCopySafeSessions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
	store := newMemorySessionStore()
	record := SessionRecord{
		Resource: "https://resource.example", AgentProvider: "https://provider.example",
		Agent: "aauth:reader@provider.example", Subject: "person-123",
		Scope: []string{"records.read"}, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	approval, err := store.Create(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if approval.Token == "" || approval.Record.Resource != record.Resource ||
		approval.Record.AgentProvider != record.AgentProvider || approval.Record.Agent != record.Agent ||
		approval.Record.Subject != record.Subject || !reflect.DeepEqual(approval.Record.Scope, record.Scope) {
		t.Fatalf("approval = %#v", approval)
	}
	if _, err := formatSessionTokenForTest(approval.Token); err != nil {
		t.Fatalf("store returned a non-token68 credential %q: %v", approval.Token, err)
	}

	record.Scope[0] = "records.write"
	approval.Record.Scope[0] = "records.delete"
	loaded, err := store.Load(context.Background(), approval.Token, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.Scope, []string{"records.read"}) {
		t.Fatalf("stored scope changed through caller alias: %q", loaded.Scope)
	}
	loaded.Scope[0] = "records.write"
	again, err := store.Load(context.Background(), approval.Token, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again.Scope, []string{"records.read"}) {
		t.Fatalf("loaded scope aliases retained state: %q", again.Scope)
	}
	if _, err := store.Load(context.Background(), approval.Token, record.ExpiresAt); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expiry error = %v", err)
	}
	if _, err := store.Load(context.Background(), "unknown", now); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("unknown-token error = %v", err)
	}
}

func TestDeferredSessionStoreRetainsCanonicalApprovalBeforePollExposure(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 20, 30, 0, 0, time.UTC)
	store := newMemorySessionStore()
	pending := pendingSessionRecordForStoreTest(now)
	if err := store.CreatePending(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	pending.Request.RequiredScopes[0] = "records.write"
	pending.Request.AgentPrincipal.AdditionalClaims["platform"] = json.RawMessage(`{"changed":true}`)

	entered := sessionCodeDigestForTest("abco-1234")
	correlated, err := store.ConsumeInteractionCode(
		context.Background(), "https://resource.example", "pending-1", SessionCodePresentation{CodeSHA256: entered}, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(correlated.Request.RequiredScopes, []string{"records.read"}) ||
		string(correlated.Request.AgentPrincipal.AdditionalClaims["platform"]) != `{"level":"example"}` {
		t.Fatalf("pending record was not defensively copied: %#v", correlated)
	}
	correlated.Request.RequiredScopes[0] = "records.delete"
	correlated.Request.AgentPrincipal.AdditionalClaims["platform"][2] = 'X'

	if _, err := store.ConsumeInteractionCode(
		context.Background(), "https://resource.example", "pending-1", SessionCodePresentation{CodeSHA256: entered}, now,
	); !errors.Is(err, ErrSessionInteractionCodeUsed) {
		t.Fatalf("second code use error = %v", err)
	}

	record := SessionRecord{
		Resource: "https://resource.example", AgentProvider: "https://provider.example",
		Agent: "aauth:reader@provider.example", Subject: "person-123",
		Scope: []string{"records.read"}, CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}
	const workers = 16
	approvals := make(chan SessionApproval, workers)
	errorsSeen := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			approval, err := store.Approve(context.Background(), "pending-1", record, now)
			if err != nil {
				errorsSeen <- err
				return
			}
			approvals <- approval
		}()
	}
	group.Wait()
	close(approvals)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatalf("concurrent approval: %v", err)
	}
	canonical := ""
	for approval := range approvals {
		if canonical == "" {
			canonical = approval.Token
		}
		if approval.Token != canonical {
			t.Fatalf("approval token = %q, want canonical %q", approval.Token, canonical)
		}
	}
	if canonical == "" || store.sessionCount() != 1 {
		t.Fatalf("canonical token = %q, retained sessions = %d", canonical, store.sessionCount())
	}

	identity := SessionPollIdentity{
		Resource: "https://resource.example", AgentProvider: "https://provider.example",
		Agent: "aauth:reader@provider.example",
	}
	result, err := store.Poll(context.Background(), "pending-1", identity, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != SessionPollApproved || result.Approval.Token != canonical {
		t.Fatalf("approved poll = %#v", result)
	}
	if _, err := store.Load(context.Background(), canonical, now); err != nil {
		t.Fatalf("approval became pollable before retaining its session: %v", err)
	}
	if err := store.ConsumeResult(context.Background(), "pending-1", result); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Poll(context.Background(), "pending-1", identity, now); !errors.Is(err, ErrPendingSessionGone) {
		t.Fatalf("poll after terminal consumption error = %v", err)
	}
}

func TestDeferredSessionStoreBoundsCodeFailuresAndExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 0, 0, 0, time.UTC)
	store := newMemorySessionStore()
	pending := pendingSessionRecordForStoreTest(now)
	if err := store.CreatePending(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= pending.MaximumCodeAttempts; attempt++ {
		_, err := store.ConsumeInteractionCode(
			context.Background(), pending.Resource, pending.ID,
			SessionCodePresentation{CodeSHA256: sessionCodeDigestForTest(fmt.Sprintf("ZZZZ-000%d", attempt))}, now,
		)
		if attempt < pending.MaximumCodeAttempts && !errors.Is(err, ErrSessionInteractionCodeInvalid) {
			t.Fatalf("invalid attempt %d error = %v", attempt, err)
		}
		if attempt == pending.MaximumCodeAttempts && !errors.Is(err, ErrPendingSessionGone) {
			t.Fatalf("bounded attempt %d error = %v", attempt, err)
		}
	}
	if _, err := store.ConsumeInteractionCode(
		context.Background(), pending.Resource, pending.ID, SessionCodePresentation{CodeSHA256: pending.CodeSHA256}, now,
	); !errors.Is(err, ErrPendingSessionGone) {
		t.Fatalf("correct code after invalidation error = %v", err)
	}

	expiring := pendingSessionRecordForStoreTest(now)
	expiring.ID = "pending-expiring"
	expiring.ExpiresAt = now.Add(time.Second)
	if err := store.CreatePending(context.Background(), expiring); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeInteractionCode(
		context.Background(), expiring.Resource, expiring.ID, SessionCodePresentation{CodeSHA256: expiring.CodeSHA256}, expiring.ExpiresAt,
	); !errors.Is(err, ErrPendingSessionExpired) {
		t.Fatalf("expired code error = %v", err)
	}
	identity := SessionPollIdentity{
		Resource: expiring.Resource, AgentProvider: "https://provider.example", Agent: "aauth:reader@provider.example",
	}
	result, err := store.Poll(context.Background(), expiring.ID, identity, expiring.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != SessionPollExpired {
		t.Fatalf("expired poll = %#v", result)
	}
	if err := store.ConsumeResult(context.Background(), expiring.ID, result); err != nil {
		t.Fatal(err)
	}
}

func TestDeferredSessionStoreRefusesApprovalAtOrAfterPendingExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 15, 0, 0, time.UTC)
	store := newMemorySessionStore()
	pending := pendingSessionRecordForStoreTest(now)
	if err := store.CreatePending(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeInteractionCode(
		context.Background(), pending.Resource, pending.ID, SessionCodePresentation{CodeSHA256: pending.CodeSHA256}, now,
	); err != nil {
		t.Fatal(err)
	}
	record := SessionRecord{
		Resource: pending.Resource, AgentProvider: "https://provider.example",
		Agent: "aauth:reader@provider.example", Subject: "person-123",
		Scope: []string{"records.read"}, CreatedAt: pending.ExpiresAt,
		ExpiresAt: pending.ExpiresAt.Add(time.Hour),
	}
	if _, err := store.Approve(
		context.Background(), pending.ID, record, pending.ExpiresAt,
	); !errors.Is(err, ErrPendingSessionExpired) {
		t.Fatalf("approval at pending expiry error = %v", err)
	}
	if store.sessionCount() != 0 {
		t.Fatalf("approval at pending expiry retained %d sessions", store.sessionCount())
	}
	result, err := store.Poll(context.Background(), pending.ID, SessionPollIdentity{
		Resource: pending.Resource, AgentProvider: "https://provider.example", Agent: "aauth:reader@provider.example",
	}, pending.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != SessionPollExpired {
		t.Fatalf("poll after refused approval = %#v", result)
	}
	if _, err := store.Approve(
		context.Background(), pending.ID, record, pending.ExpiresAt.Add(time.Second),
	); !errors.Is(err, ErrPendingSessionConflict) {
		t.Fatalf("approval after expired transition error = %v", err)
	}
	again, err := store.Poll(context.Background(), pending.ID, SessionPollIdentity{
		Resource: pending.Resource, AgentProvider: "https://provider.example", Agent: "aauth:reader@provider.example",
	}, pending.ExpiresAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if again.State != SessionPollExpired {
		t.Fatalf("late approval changed expired state to %#v", again)
	}
}

func TestDeferredSessionStoreDoesNotRewriteTerminalStateOnLateApproval(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 30, 0, 0, time.UTC)
	store := newMemorySessionStore()
	pending := pendingSessionRecordForStoreTest(now)
	if err := store.CreatePending(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeInteractionCode(
		context.Background(), pending.Resource, pending.ID, SessionCodePresentation{CodeSHA256: pending.CodeSHA256}, now,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Deny(context.Background(), pending.ID, now); err != nil {
		t.Fatal(err)
	}
	record := SessionRecord{
		Resource: pending.Resource, AgentProvider: "https://provider.example",
		Agent: "aauth:reader@provider.example", Subject: "person-123",
		Scope: []string{"records.read"}, CreatedAt: pending.ExpiresAt,
		ExpiresAt: pending.ExpiresAt.Add(time.Hour),
	}
	if _, err := store.Approve(
		context.Background(), pending.ID, record, pending.ExpiresAt,
	); !errors.Is(err, ErrPendingSessionConflict) {
		t.Fatalf("late approval after denial error = %v", err)
	}
	identity := SessionPollIdentity{
		Resource: pending.Resource, AgentProvider: "https://provider.example", Agent: "aauth:reader@provider.example",
	}
	denied, err := store.Poll(context.Background(), pending.ID, identity, pending.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if denied.State != SessionPollDenied {
		t.Fatalf("late approval changed denied state to %v", denied.State)
	}
	if err := store.ConsumeResult(context.Background(), pending.ID, denied); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(
		context.Background(), pending.ID, record, pending.ExpiresAt,
	); !errors.Is(err, ErrPendingSessionConflict) {
		t.Fatalf("late approval after terminal consumption error = %v", err)
	}
	if _, err := store.Poll(context.Background(), pending.ID, identity, pending.ExpiresAt); !errors.Is(err, ErrPendingSessionGone) {
		t.Fatalf("late approval resurrected consumed result: %v", err)
	}
}

func pendingSessionRecordForStoreTest(now time.Time) PendingSessionRecord {
	return PendingSessionRecord{
		ID: "pending-1", CodeSHA256: sessionCodeDigestForTest("ABC0-1234"),
		Resource: "https://resource.example",
		Request: SessionAuthorizationRequest{
			AgentPrincipal: AgentPrincipal{
				AgentProvider: "https://provider.example", Agent: "aauth:reader@provider.example",
				AdditionalClaims: map[string]json.RawMessage{"platform": json.RawMessage(`{"level":"example"}`)},
			},
			Method: httpMethodGetForStoreTest, Path: "/records", RequiredScopes: []string{"records.read"},
		},
		CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), RetryAfter: 3 * time.Second,
		MaximumCodeAttempts: 3,
	}
}

const httpMethodGetForStoreTest = "GET"

type memorySessionStore struct {
	mu               sync.Mutex
	next             int
	sessions         map[string]SessionRecord
	pending          map[string]*memoryPendingSession
	loads            int
	createErr        error
	loadErr          error
	createPendingErr error
	pollErr          error
	pollOverride     *SessionPollRecord
	consumeResultErr error
}

type memoryPendingSession struct {
	record   PendingSessionRecord
	state    SessionPollState
	attempts int
	approval SessionApproval
	deniedAt time.Time
	callback string
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{
		sessions: make(map[string]SessionRecord), pending: make(map[string]*memoryPendingSession),
	}
}

func (store *memorySessionStore) Create(_ context.Context, record SessionRecord) (SessionApproval, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.createErr != nil {
		return SessionApproval{}, store.createErr
	}
	return store.createLocked(record)
}

func (store *memorySessionStore) createLocked(record SessionRecord) (SessionApproval, error) {
	store.next++
	token := fmt.Sprintf("session-%d", store.next)
	record = cloneSessionRecordForTest(record)
	store.sessions[token] = record
	return SessionApproval{Token: token, Record: cloneSessionRecordForTest(record)}, nil
}

func (store *memorySessionStore) Load(_ context.Context, token string, now time.Time) (SessionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.loads++
	if store.loadErr != nil {
		return SessionRecord{}, store.loadErr
	}
	record, ok := store.sessions[token]
	if !ok {
		return SessionRecord{}, ErrSessionNotFound
	}
	if !now.Before(record.ExpiresAt) {
		return SessionRecord{}, ErrSessionExpired
	}
	return cloneSessionRecordForTest(record), nil
}

func (store *memorySessionStore) CreatePending(_ context.Context, record PendingSessionRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.createPendingErr != nil {
		return store.createPendingErr
	}
	if _, exists := store.pending[record.ID]; exists {
		return ErrPendingSessionConflict
	}
	store.pending[record.ID] = &memoryPendingSession{
		record: clonePendingSessionRecordForTest(record), state: SessionPollPending,
	}
	return nil
}

func (store *memorySessionStore) ConsumeInteractionCode(
	_ context.Context, resource, reference string, presentation SessionCodePresentation, now time.Time,
) (PendingSessionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[reference]
	if !ok {
		return PendingSessionRecord{}, ErrSessionInteractionCodeInvalid
	}
	if pending.state == SessionPollGone {
		return PendingSessionRecord{}, ErrPendingSessionGone
	}
	if pending.state != SessionPollPending {
		return PendingSessionRecord{}, ErrSessionInteractionCodeUsed
	}
	if !now.Before(pending.record.ExpiresAt) {
		pending.state = SessionPollExpired
		return PendingSessionRecord{}, ErrPendingSessionExpired
	}
	if pending.record.Resource != resource || pending.record.CodeSHA256 != presentation.CodeSHA256 {
		pending.attempts++
		if pending.attempts >= pending.record.MaximumCodeAttempts {
			pending.state = SessionPollGone
			return PendingSessionRecord{}, ErrPendingSessionGone
		}
		return PendingSessionRecord{}, ErrSessionInteractionCodeInvalid
	}
	pending.state = SessionPollInteracting
	pending.callback = presentation.Callback
	return clonePendingSessionRecordForTest(pending.record), nil
}

func (store *memorySessionStore) LoadPending(_ context.Context, id string) (PendingSessionSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return PendingSessionSnapshot{}, ErrPendingSessionNotFound
	}
	return PendingSessionSnapshot{
		Record: clonePendingSessionRecordForTest(pending.record), State: pending.state,
		Approval: cloneSessionApprovalForTest(pending.approval), Callback: pending.callback,
	}, nil
}

func (store *memorySessionStore) Approve(
	_ context.Context, id string, record SessionRecord, now time.Time,
) (SessionApproval, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return SessionApproval{}, ErrPendingSessionNotFound
	}
	if pending.state == SessionPollApproved {
		if reflect.DeepEqual(pending.approval.Record, record) {
			return cloneSessionApprovalForTest(pending.approval), nil
		}
		return SessionApproval{}, ErrPendingSessionConflict
	}
	if pending.state != SessionPollInteracting {
		return SessionApproval{}, ErrPendingSessionConflict
	}
	if !now.Before(pending.record.ExpiresAt) {
		pending.state = SessionPollExpired
		return SessionApproval{}, ErrPendingSessionExpired
	}
	approval, err := store.createLocked(record)
	if err != nil {
		return SessionApproval{}, err
	}
	pending.approval = cloneSessionApprovalForTest(approval)
	pending.state = SessionPollApproved
	return cloneSessionApprovalForTest(approval), nil
}

func (store *memorySessionStore) Deny(_ context.Context, id string, decidedAt time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return ErrPendingSessionNotFound
	}
	if pending.state == SessionPollDenied {
		return nil
	}
	if pending.state != SessionPollInteracting {
		return ErrPendingSessionConflict
	}
	pending.deniedAt = decidedAt
	pending.state = SessionPollDenied
	return nil
}

func (store *memorySessionStore) Invalidate(_ context.Context, id string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, ok := store.pending[id]
	if !ok {
		return ErrPendingSessionNotFound
	}
	if pending.state == SessionPollGone {
		return nil
	}
	if pending.state != SessionPollPending && pending.state != SessionPollInteracting {
		return ErrPendingSessionConflict
	}
	pending.state = SessionPollGone
	return nil
}

func (store *memorySessionStore) Poll(
	_ context.Context, id string, identity SessionPollIdentity, now time.Time,
) (SessionPollRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.pollErr != nil {
		return SessionPollRecord{}, store.pollErr
	}
	pending, ok := store.pending[id]
	if !ok {
		return SessionPollRecord{}, ErrPendingSessionNotFound
	}
	principal := pending.record.Request.AgentPrincipal
	if identity.Resource != pending.record.Resource || identity.AgentProvider != principal.AgentProvider ||
		identity.Agent != principal.Agent || identity.ParentAgent != principal.ParentAgent {
		return SessionPollRecord{}, ErrPendingSessionNotFound
	}
	if pending.state == SessionPollGone {
		return SessionPollRecord{}, ErrPendingSessionGone
	}
	if store.pollOverride != nil {
		return cloneSessionPollRecordForTest(*store.pollOverride), nil
	}
	if !now.Before(pending.record.ExpiresAt) &&
		(pending.state == SessionPollPending || pending.state == SessionPollInteracting) {
		pending.state = SessionPollExpired
	}
	return SessionPollRecord{
		State: pending.state, Approval: cloneSessionApprovalForTest(pending.approval),
		RetryAfter: pending.record.RetryAfter,
	}, nil
}

func (store *memorySessionStore) ConsumeResult(_ context.Context, id string, result SessionPollRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.consumeResultErr != nil {
		return store.consumeResultErr
	}
	pending, ok := store.pending[id]
	if !ok {
		return ErrPendingSessionNotFound
	}
	if pending.state == SessionPollGone {
		return ErrPendingSessionGone
	}
	want := SessionPollRecord{
		State: pending.state, Approval: cloneSessionApprovalForTest(pending.approval),
		RetryAfter: pending.record.RetryAfter,
	}
	if !reflect.DeepEqual(result, want) ||
		(result.State != SessionPollApproved && result.State != SessionPollDenied && result.State != SessionPollExpired) {
		return ErrPendingSessionConflict
	}
	pending.state = SessionPollGone
	return nil
}

func (store *memorySessionStore) onlyPending(t *testing.T) PendingSessionRecord {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.pending) != 1 {
		t.Fatalf("pending records = %d, want 1", len(store.pending))
	}
	for _, pending := range store.pending {
		return clonePendingSessionRecordForTest(pending.record)
	}
	panic("unreachable")
}

func (store *memorySessionStore) sessionCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.sessions)
}

func (store *memorySessionStore) loadCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loads
}

func cloneSessionRecordForTest(record SessionRecord) SessionRecord {
	record.Scope = append([]string(nil), record.Scope...)
	return record
}

func cloneSessionApprovalForTest(approval SessionApproval) SessionApproval {
	approval.Record = cloneSessionRecordForTest(approval.Record)
	return approval
}

func cloneSessionPollRecordForTest(result SessionPollRecord) SessionPollRecord {
	result.Approval = cloneSessionApprovalForTest(result.Approval)
	return result
}

func clonePendingSessionRecordForTest(record PendingSessionRecord) PendingSessionRecord {
	record.Request.RequiredScopes = append([]string(nil), record.Request.RequiredScopes...)
	record.Request.AgentPrincipal.AdditionalClaims = cloneJSONMapForSessionTest(record.Request.AgentPrincipal.AdditionalClaims)
	return record
}

func cloneJSONMapForSessionTest(values map[string]json.RawMessage) map[string]json.RawMessage {
	if values == nil {
		return nil
	}
	cloned := make(map[string]json.RawMessage, len(values))
	for name, value := range values {
		cloned[name] = append(json.RawMessage(nil), value...)
	}
	return cloned
}

func sessionCodeDigestForTest(code string) [32]byte {
	normalized := normalizeSessionCodeForTest(code)
	return sha256.Sum256([]byte(normalized))
}

func normalizeSessionCodeForTest(code string) string {
	code = stringsToUpperForSessionTest(code)
	result := make([]byte, 0, len(code))
	for index := 0; index < len(code); index++ {
		switch code[index] {
		case '-':
			continue
		case 'I', 'L':
			result = append(result, '1')
		case 'O':
			result = append(result, '0')
		default:
			result = append(result, code[index])
		}
	}
	return string(result)
}

func stringsToUpperForSessionTest(value string) string {
	data := []byte(value)
	for index, character := range data {
		if character >= 'a' && character <= 'z' {
			data[index] = character - ('a' - 'A')
		}
	}
	return string(data)
}

func formatSessionTokenForTest(token string) (string, error) {
	if token == "" {
		return "", errors.New("empty token")
	}
	for index := 0; index < len(token); index++ {
		character := token[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '.' || character == '_' ||
			character == '~' || character == '+' || character == '/' || character == '=' {
			continue
		}
		return "", errors.New("not token68")
	}
	return token, nil
}
