package storetest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// ClarificationStore is the combined store contract required by a Person
// Server that supports deferred authorization and Agent clarification.
type ClarificationStore interface {
	personserver.DeferredAuthorizationStore
	personserver.AuthorizationClarificationStore
}

// Contract constructs a fresh store for each clarification scenario.
type Contract struct {
	New func(testing.TB) ClarificationStore
}

// RunClarification checks the public clarification store contract. Passing the
// suite complements, but does not replace, backend transaction, restart, and
// failure-injection tests.
func RunClarification(t *testing.T, contract Contract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: Contract.New is required")
	}

	t.Run("question answer retry and copy safety", func(t *testing.T) {
		fixture := newClarificationFixture(t, contract, "dialogue")
		request := personserver.AuthorizationClarificationRequest{
			Question: "Which workspace?", Options: []string{"personal", "shared"}, Lifetime: 5 * time.Minute,
		}
		requestedAt := fixture.now.Add(time.Minute)
		round, err := fixture.store.RequestPendingAuthorizationClarification(
			fixture.ctx, fixture.record.ID, request, requestedAt,
		)
		if err != nil {
			t.Fatal(err)
		}
		request.Options[0] = "mutated input"
		round.Options[1] = "mutated return"

		retry, err := fixture.store.RequestPendingAuthorizationClarification(
			fixture.ctx,
			fixture.record.ID,
			personserver.AuthorizationClarificationRequest{
				Question: "Which workspace?", Options: []string{"personal", "shared"}, Lifetime: 5 * time.Minute,
			},
			fixture.now.Add(2*time.Minute),
		)
		if err != nil {
			t.Fatalf("exact active-question retry: %v", err)
		}
		if retry.Question != "Which workspace?" || !slices.Equal(retry.Options, []string{"personal", "shared"}) ||
			!retry.RequestedAt.Equal(requestedAt) || !retry.ExpiresAt.Equal(requestedAt.Add(5*time.Minute)) {
			t.Fatalf("canonical question retry = %#v", retry)
		}
		if _, err := fixture.store.RequestPendingAuthorizationClarification(
			fixture.ctx,
			fixture.record.ID,
			personserver.AuthorizationClarificationRequest{
				Question: "Which project?", Options: []string{"personal", "shared"}, Lifetime: 5 * time.Minute,
			},
			fixture.now.Add(2*time.Minute),
		); !errors.Is(err, personserver.ErrPendingAuthorizationConflict) {
			t.Fatalf("changed active question = %v", err)
		}
		requireActiveQuestion(t, fixture, requestedAt, fixture.now.Add(2*time.Minute))

		wrongIdentity := fixture.identity
		wrongIdentity.Agent = "aauth:other@agents.example"
		if _, err := fixture.store.PollPendingAuthorization(
			fixture.ctx, fixture.record.ID, wrongIdentity, fixture.now.Add(2*time.Minute),
		); !errors.Is(err, personserver.ErrPendingAuthorizationNotFound) {
			t.Fatalf("wrong-identity poll = %v", err)
		}
		poll, err := fixture.store.PollPendingAuthorization(
			fixture.ctx, fixture.record.ID, fixture.identity, fixture.now.Add(2*time.Minute),
		)
		if err != nil {
			t.Fatal(err)
		}
		if poll.State != personserver.AuthorizationPollClarifying || poll.Clarification == nil ||
			poll.Clarification.Question != "Which workspace?" ||
			!slices.Equal(poll.Clarification.Options, []string{"personal", "shared"}) {
			t.Fatalf("clarifying poll = %#v", poll)
		}
		poll.Clarification.Options[0] = "mutated poll"
		again, err := fixture.store.PollPendingAuthorization(
			fixture.ctx, fixture.record.ID, fixture.identity, fixture.now.Add(2*time.Minute),
		)
		if err != nil || again.Clarification == nil || again.Clarification.Options[0] != "personal" {
			t.Fatalf("poll copy isolation = %#v, %v", again, err)
		}

		if err := fixture.store.AnswerPendingAuthorizationClarification(
			fixture.ctx, fixture.record.ID, wrongIdentity, "shared", fixture.now.Add(3*time.Minute),
		); !errors.Is(err, personserver.ErrPendingAuthorizationNotFound) {
			t.Fatalf("wrong-identity answer = %v", err)
		}
		requireActiveQuestion(t, fixture, requestedAt, fixture.now.Add(3*time.Minute))

		respondedAt := fixture.now.Add(3 * time.Minute)
		if err := fixture.store.AnswerPendingAuthorizationClarification(
			fixture.ctx, fixture.record.ID, fixture.identity, "shared", respondedAt,
		); err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.AnswerPendingAuthorizationClarification(
			fixture.ctx, fixture.record.ID, fixture.identity, "shared", fixture.now.Add(4*time.Minute),
		); err != nil {
			t.Fatalf("exact answer replay: %v", err)
		}
		if err := fixture.store.AnswerPendingAuthorizationClarification(
			fixture.ctx, fixture.record.ID, fixture.identity, "personal", fixture.now.Add(4*time.Minute),
		); !errors.Is(err, personserver.ErrPendingAuthorizationConflict) {
			t.Fatalf("changed answer replay = %v", err)
		}
		snapshot := fixture.load(t, fixture.now.Add(4*time.Minute))
		if snapshot.State != personserver.AuthorizationPollInteracting || len(snapshot.Clarifications) != 1 ||
			snapshot.Clarifications[0].Response != "shared" ||
			!snapshot.Clarifications[0].RespondedAt.Equal(respondedAt) {
			t.Fatalf("answered snapshot = %#v", snapshot)
		}
		snapshot.Clarifications[0].Options[0] = "mutated snapshot"
		if got := fixture.load(t, fixture.now.Add(4*time.Minute)); got.Clarifications[0].Options[0] != "personal" {
			t.Fatalf("snapshot options aliased retained history: %#v", got.Clarifications[0])
		}
		poll, err = fixture.store.PollPendingAuthorization(
			fixture.ctx, fixture.record.ID, fixture.identity, fixture.now.Add(4*time.Minute),
		)
		if err != nil || poll.State != personserver.AuthorizationPollInteracting || poll.Clarification != nil {
			t.Fatalf("answered poll = %#v, %v", poll, err)
		}
	})

	t.Run("round bound and failed request atomicity", func(t *testing.T) {
		fixture := newClarificationFixture(t, contract, "round-bound")
		if _, err := fixture.store.RequestPendingAuthorizationClarification(
			fixture.ctx,
			fixture.record.ID,
			personserver.AuthorizationClarificationRequest{Question: "", Lifetime: time.Minute},
			fixture.now,
		); err == nil {
			t.Fatal("empty clarification question was accepted")
		}
		snapshot := fixture.load(t, fixture.now)
		if snapshot.State != personserver.AuthorizationPollInteracting || len(snapshot.Clarifications) != 0 {
			t.Fatalf("invalid question partially mutated store = %#v", snapshot)
		}

		for number := 1; number <= personserver.MaximumAuthorizationClarificationRounds; number++ {
			askedAt := fixture.now.Add(time.Duration(number) * time.Minute)
			if _, err := fixture.store.RequestPendingAuthorizationClarification(
				fixture.ctx,
				fixture.record.ID,
				personserver.AuthorizationClarificationRequest{
					Question: fmt.Sprintf("Question %d", number), Lifetime: 30 * time.Second,
				},
				askedAt,
			); err != nil {
				t.Fatalf("question %d: %v", number, err)
			}
			if err := fixture.store.AnswerPendingAuthorizationClarification(
				fixture.ctx, fixture.record.ID, fixture.identity, "answer", askedAt.Add(10*time.Second),
			); err != nil {
				t.Fatalf("answer %d: %v", number, err)
			}
		}
		if _, err := fixture.store.RequestPendingAuthorizationClarification(
			fixture.ctx,
			fixture.record.ID,
			personserver.AuthorizationClarificationRequest{
				Question: fmt.Sprintf("Question %d", personserver.MaximumAuthorizationClarificationRounds+1),
				Lifetime: 30 * time.Second,
			},
			fixture.now.Add(10*time.Minute),
		); !errors.Is(err, personserver.ErrPendingAuthorizationConflict) {
			t.Fatalf("question beyond round bound = %v", err)
		}
		snapshot = fixture.load(t, fixture.now.Add(10*time.Minute))
		if snapshot.State != personserver.AuthorizationPollInteracting ||
			len(snapshot.Clarifications) != personserver.MaximumAuthorizationClarificationRounds {
			t.Fatalf("round-bound snapshot = %#v", snapshot)
		}
	})

	t.Run("active deadline expires pending authorization", func(t *testing.T) {
		fixture := newClarificationFixture(t, contract, "deadline")
		if _, err := fixture.store.RequestPendingAuthorizationClarification(
			fixture.ctx,
			fixture.record.ID,
			personserver.AuthorizationClarificationRequest{Question: "Still needed?", Lifetime: time.Minute},
			fixture.now,
		); err != nil {
			t.Fatal(err)
		}
		deadline := fixture.now.Add(time.Minute)
		poll, err := fixture.store.PollPendingAuthorization(
			fixture.ctx, fixture.record.ID, fixture.identity, deadline,
		)
		if err != nil || poll.State != personserver.AuthorizationPollExpired || poll.Clarification != nil {
			t.Fatalf("expired poll = %#v, %v", poll, err)
		}
		if err := fixture.store.AnswerPendingAuthorizationClarification(
			fixture.ctx, fixture.record.ID, fixture.identity, "yes", deadline,
		); !errors.Is(err, personserver.ErrPendingAuthorizationExpired) {
			t.Fatalf("late answer = %v", err)
		}
		if err := fixture.store.CancelPendingAuthorizationClarification(
			fixture.ctx, fixture.record.ID, fixture.identity, deadline,
		); !errors.Is(err, personserver.ErrPendingAuthorizationExpired) {
			t.Fatalf("late cancellation = %v", err)
		}
		snapshot := fixture.load(t, deadline)
		if snapshot.State != personserver.AuthorizationPollExpired || len(snapshot.Clarifications) != 1 ||
			snapshot.Clarifications[0].Response != "" || !snapshot.CancelledAt.IsZero() {
			t.Fatalf("expired snapshot = %#v", snapshot)
		}
	})

	t.Run("cancellation remains host visible and agent gone", func(t *testing.T) {
		fixture := newClarificationFixture(t, contract, "cancel")
		if _, err := fixture.store.RequestPendingAuthorizationClarification(
			fixture.ctx,
			fixture.record.ID,
			personserver.AuthorizationClarificationRequest{Question: "Continue?", Lifetime: 5 * time.Minute},
			fixture.now,
		); err != nil {
			t.Fatal(err)
		}
		wrongIdentity := fixture.identity
		wrongIdentity.ConfirmationThumbprint = "wrong"
		if err := fixture.store.CancelPendingAuthorizationClarification(
			fixture.ctx, fixture.record.ID, wrongIdentity, fixture.now.Add(10*time.Second),
		); !errors.Is(err, personserver.ErrPendingAuthorizationNotFound) {
			t.Fatalf("wrong-identity cancellation = %v", err)
		}
		before := fixture.load(t, fixture.now.Add(10*time.Second))
		if before.State != personserver.AuthorizationPollClarifying || !before.CancelledAt.IsZero() {
			t.Fatalf("wrong-identity cancellation partially mutated store = %#v", before)
		}

		cancelledAt := fixture.now.Add(20 * time.Second)
		if err := fixture.store.CancelPendingAuthorizationClarification(
			fixture.ctx, fixture.record.ID, fixture.identity, cancelledAt,
		); err != nil {
			t.Fatal(err)
		}
		if err := fixture.store.CancelPendingAuthorizationClarification(
			fixture.ctx, fixture.record.ID, fixture.identity, fixture.now.Add(30*time.Second),
		); !errors.Is(err, personserver.ErrPendingAuthorizationGone) {
			t.Fatalf("request after cancellation = %v", err)
		}
		snapshot := fixture.load(t, fixture.now.Add(30*time.Second))
		if snapshot.State != personserver.AuthorizationPollCancelled || !snapshot.CancelledAt.Equal(cancelledAt) ||
			len(snapshot.Clarifications) != 1 || snapshot.Clarifications[0].Question != "Continue?" {
			t.Fatalf("cancelled snapshot = %#v", snapshot)
		}
		if _, err := fixture.store.PollPendingAuthorization(
			fixture.ctx, fixture.record.ID, fixture.identity, fixture.now.Add(30*time.Second),
		); !errors.Is(err, personserver.ErrPendingAuthorizationGone) {
			t.Fatalf("cancelled poll = %v", err)
		}
		if _, err := fixture.store.RequestPendingAuthorizationClarification(
			fixture.ctx,
			fixture.record.ID,
			personserver.AuthorizationClarificationRequest{Question: "Another?", Lifetime: time.Minute},
			fixture.now.Add(30*time.Second),
		); !errors.Is(err, personserver.ErrPendingAuthorizationGone) {
			t.Fatalf("question after cancellation = %v", err)
		}
		if err := fixture.store.AnswerPendingAuthorizationClarification(
			fixture.ctx, fixture.record.ID, fixture.identity, "yes", fixture.now.Add(30*time.Second),
		); !errors.Is(err, personserver.ErrPendingAuthorizationGone) {
			t.Fatalf("answer after cancellation = %v", err)
		}
		if _, err := fixture.store.ConsumeAuthorizationInteractionCode(
			fixture.ctx,
			fixture.record.PersonServer,
			fixture.record.ID,
			personserver.AuthorizationCodePresentation{
				CodeSHA256: fixture.record.CodeSHA256, SyntacticallyValid: true,
			},
			fixture.now.Add(30*time.Second),
		); !errors.Is(err, personserver.ErrPendingAuthorizationGone) {
			t.Fatalf("interaction code after cancellation = %v", err)
		}
		after := fixture.load(t, fixture.now.Add(30*time.Second))
		if after.State != personserver.AuthorizationPollCancelled || !after.CancelledAt.Equal(cancelledAt) ||
			len(after.Clarifications) != 1 {
			t.Fatalf("cancelled state changed after refusals = %#v", after)
		}
	})
}

type clarificationFixture struct {
	ctx      context.Context
	store    ClarificationStore
	record   personserver.PendingAuthorizationRecord
	identity personserver.AuthorizationPollIdentity
	now      time.Time
}

func newClarificationFixture(t *testing.T, contract Contract, name string) clarificationFixture {
	t.Helper()
	store := contract.New(t)
	if store == nil {
		t.Fatal("storetest: Contract.New returned nil")
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := jose.NewEd25519SigningKey("storetest-"+name, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	confirmation := signingKey.PublicJWK()
	thumbprint, err := confirmation.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 31, 20, 0, 0, 0, time.UTC)
	record := personserver.PendingAuthorizationRecord{
		ID:                     "storetest-" + name,
		CodeSHA256:             sha256.Sum256([]byte("storetest-code-" + name)),
		PersonServer:           "https://person.example",
		AgentProvider:          "https://agents.example",
		Agent:                  "aauth:storetest@agents.example",
		Resource:               "https://resource.example",
		Subject:                "person-123",
		Tenant:                 "tenant-1",
		Scopes:                 []string{"records.read"},
		Confirmation:           confirmation,
		AgentExpiresAt:         now.Add(2 * time.Hour),
		ResourceTokenExpiresAt: now.Add(2 * time.Hour),
		Capabilities:           []string{"clarification"},
		CreatedAt:              now,
		ExpiresAt:              now.Add(time.Hour),
		RetryAfter:             time.Second,
	}
	ctx := context.Background()
	if err := store.CreatePendingAuthorization(ctx, record); err != nil {
		t.Fatalf("storetest: create pending authorization: %v", err)
	}
	if _, err := store.ConsumeAuthorizationInteractionCode(
		ctx,
		record.PersonServer,
		record.ID,
		personserver.AuthorizationCodePresentation{CodeSHA256: record.CodeSHA256, SyntacticallyValid: true},
		now,
	); err != nil {
		t.Fatalf("storetest: consume interaction code: %v", err)
	}
	return clarificationFixture{
		ctx: ctx, store: store, record: record, now: now,
		identity: personserver.AuthorizationPollIdentity{
			PersonServer: record.PersonServer, AgentProvider: record.AgentProvider,
			Agent: record.Agent, ConfirmationThumbprint: thumbprint,
		},
	}
}

func (fixture clarificationFixture) load(t *testing.T, now time.Time) personserver.PendingAuthorizationSnapshot {
	t.Helper()
	snapshot, err := fixture.store.LoadPendingAuthorization(fixture.ctx, fixture.record.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func requireActiveQuestion(t *testing.T, fixture clarificationFixture, requestedAt, observedAt time.Time) {
	t.Helper()
	snapshot := fixture.load(t, observedAt)
	if snapshot.State != personserver.AuthorizationPollClarifying || len(snapshot.Clarifications) != 1 ||
		snapshot.Clarifications[0].Question != "Which workspace?" ||
		!slices.Equal(snapshot.Clarifications[0].Options, []string{"personal", "shared"}) ||
		!snapshot.Clarifications[0].RequestedAt.Equal(requestedAt) || snapshot.Clarifications[0].Response != "" {
		t.Fatalf("active clarification changed = %#v", snapshot)
	}
}
