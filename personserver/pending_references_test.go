package personserver

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// These are host APIs, not additional protocol endpoints. Retained queue
// snapshots are validated before any reference is exposed to the host.
func TestPendingPermissionReferencesValidateStoreResults(t *testing.T) {
	p := newPermissionProtocol(t)
	backing := newMemoryPermissionStore()
	p.policyResult = PermissionPolicyResult{Deferred: &PermissionPendingPolicy{Lifetime: time.Minute}}
	issuer := p.newServer(t, "direct", p.config("direct", &PermissionConfig{Policy: p.policy, Store: backing}))
	response := permissionRequest(t, p, issuer, p.agentKey, p.agentToken, `{"action":"SendEmail"}`)
	if response.Code != 202 {
		t.Fatalf("defer: %d %s", response.Code, response.Body.String())
	}
	valid := backing.onlyRecord(t)
	for _, tc := range []struct {
		name  string
		alter func(*PermissionRecord)
	}{
		{"valid", nil},
		{"foreign issuer", func(r *PermissionRecord) { r.PersonServer = "https://other.example" }},
		{"expired", func(r *PermissionRecord) { r.ExpiresAt = p.now }},
		{"terminal", func(r *PermissionRecord) { r.State = PermissionStateGone }},
		{"missing id", func(r *PermissionRecord) { r.ID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := cloneRetainedPermissionRecord(valid)
			if tc.alter != nil {
				tc.alter(&record)
			}
			queue := &permissionQueueProbe{PermissionStore: backing, records: []PermissionRecord{record}}
			server := p.newServer(t, "direct", p.config("direct", &PermissionConfig{Policy: p.policy, Store: queue}))
			refs, err := server.PendingPermissionReferences(context.Background(), 1)
			if tc.alter != nil {
				if !errors.Is(err, ErrPermissionConflict) || len(refs) != 0 {
					t.Fatalf("corrupt queue: %v %v", refs, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(refs, []string{valid.ID}) {
				t.Fatalf("queue: %v %v", refs, err)
			}
			if queue.issuer != p.personServerID || !queue.at.Equal(p.now) || queue.limit != 1 {
				t.Fatal("queue did not receive host identity, clock and bound")
			}
			// A replacement server uses retained state, without the Agent's poll URL.
			handle, err := server.ResumePermission(context.Background(), refs[0])
			if err != nil {
				t.Fatal(err)
			}
			if err = server.GrantPermission(context.Background(), handle); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPendingReferenceQueuesRejectInvalidCallsAndBackendFailures(t *testing.T) {
	p := newPermissionProtocol(t)
	backendError := errors.New("queue unavailable")
	permission := &permissionQueueProbe{err: backendError}
	question := &questionQueueProbe{err: backendError}
	federation := &federatedQueueProbe{err: backendError}
	server := &Server{issuer: p.personServerID, clock: p.clock, permissions: permission, interactionQuestionStore: question, federatedDeferred: &FederatedDeferredConfig{Store: federation}}
	for name, list := range map[string]func(context.Context, int) ([]string, error){"permission": server.PendingPermissionReferences, "question": server.PendingInteractionQuestionReferences, "federation": server.PendingFederatedAuthorizationReferences} {
		t.Run(name, func(t *testing.T) {
			for _, limit := range []int{-1, 0, 1001} {
				if _, err := list(context.Background(), limit); err == nil || errors.Is(err, backendError) {
					t.Fatalf("limit %d: %v", limit, err)
				}
			}
			if _, err := list(nil, 1); err == nil {
				t.Fatal("nil context accepted")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := list(ctx, 1); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled: %v", err)
			}
			if _, err := list(context.Background(), 1); !errors.Is(err, backendError) {
				t.Fatalf("backend error lost: %v", err)
			}
		})
	}
	if permission.calls != 1 || question.calls != 1 || federation.calls != 1 {
		t.Fatalf("invalid calls reached backend: %d %d", permission.calls, question.calls)
	}
	empty := &Server{}
	for _, list := range []func(context.Context, int) ([]string, error){empty.PendingPermissionReferences, empty.PendingInteractionQuestionReferences, empty.PendingFederatedAuthorizationReferences} {
		if _, err := list(context.Background(), 1); err == nil {
			t.Fatal("unconfigured queue accepted")
		}
	}
	server.permissions = newMemoryPermissionStore()
	if _, err := server.PendingPermissionReferences(context.Background(), 1); err == nil {
		t.Fatal("store without queue accepted")
	}
}

func TestPendingInteractionQuestionReferencesValidateStoreResults(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	document, err := aauth.EncodeInteractionQuestion(aauth.InteractionQuestion{Question: "Proceed?"})
	if err != nil {
		t.Fatal(err)
	}
	valid := InteractionQuestionRecord{ID: "question-1", PersonServer: "https://person.example", AgentProvider: "https://ap.example", Agent: "aauth:agent@ap.example", ConfirmationThumbprint: "thumbprint", AgentExpiresAt: now.Add(time.Hour), Document: document, State: InteractionQuestionPending, CreatedAt: now, ExpiresAt: now.Add(time.Minute), RetryAfter: time.Second}
	for _, tc := range []struct {
		name  string
		alter func(*InteractionQuestionRecord)
	}{
		{"valid", nil}, {"foreign issuer", func(r *InteractionQuestionRecord) { r.PersonServer = "https://other.example" }}, {"expired", func(r *InteractionQuestionRecord) { r.ExpiresAt = now }}, {"terminal", func(r *InteractionQuestionRecord) { r.State = InteractionQuestionGone }}, {"missing id", func(r *InteractionQuestionRecord) { r.ID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := cloneInteractionQuestionRecord(valid)
			if tc.alter != nil {
				tc.alter(&record)
			}
			queue := &questionQueueProbe{records: []InteractionQuestionRecord{record}}
			server := &Server{issuer: valid.PersonServer, clock: aauth.ClockFunc(func() time.Time { return now }), interactionQuestionStore: queue}
			refs, err := server.PendingInteractionQuestionReferences(context.Background(), 1)
			if tc.alter != nil {
				if !errors.Is(err, ErrInteractionQuestionConflict) || len(refs) != 0 {
					t.Fatalf("corrupt queue: %v %v", refs, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(refs, []string{valid.ID}) {
				t.Fatalf("queue: %v %v", refs, err)
			}
			if queue.issuer != valid.PersonServer || !queue.at.Equal(now) || queue.limit != 1 {
				t.Fatal("queue did not receive host identity, clock and bound")
			}
			for _, records := range [][]InteractionQuestionRecord{{valid, valid}, {{}}} {
				queue.records = records
				if _, err = server.PendingInteractionQuestionReferences(context.Background(), 2); !errors.Is(err, ErrInteractionQuestionConflict) {
					t.Fatalf("invalid queue: %v", err)
				}
			}
			queue.records = []InteractionQuestionRecord{valid, valid}
			if _, err = server.PendingInteractionQuestionReferences(context.Background(), 1); !errors.Is(err, ErrInteractionQuestionConflict) {
				t.Fatalf("oversized queue: %v", err)
			}
		})
	}
}

type permissionQueueProbe struct {
	PermissionStore
	records      []PermissionRecord
	err          error
	issuer       string
	at           time.Time
	limit, calls int
}

func (s *permissionQueueProbe) ListPendingPermissions(_ context.Context, issuer string, at time.Time, limit int) ([]PermissionRecord, error) {
	s.issuer, s.at, s.limit = issuer, at, limit
	s.calls++
	return s.records, s.err
}

type questionQueueProbe struct {
	InteractionQuestionStore
	records      []InteractionQuestionRecord
	err          error
	issuer       string
	at           time.Time
	limit, calls int
}

func (s *questionQueueProbe) ListPendingInteractionQuestions(_ context.Context, issuer string, at time.Time, limit int) ([]InteractionQuestionRecord, error) {
	s.issuer, s.at, s.limit = issuer, at, limit
	s.calls++
	return s.records, s.err
}
