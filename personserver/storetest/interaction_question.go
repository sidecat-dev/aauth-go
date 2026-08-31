package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// InteractionQuestionContract constructs a fresh empty store.
type InteractionQuestionContract struct {
	New func(testing.TB) personserver.InteractionQuestionStore
}

// RunInteractionQuestion checks the reusable deferred-question store contract.
func RunInteractionQuestion(t *testing.T, contract InteractionQuestionContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: InteractionQuestionContract.New is required")
	}

	t.Run("create load copies identity and answer", func(t *testing.T) {
		store := contract.New(t)
		record := questionRecord(t, "question-1")
		if err := store.CreateInteractionQuestion(context.Background(), cloneQuestionRecord(record)); err != nil {
			t.Fatal(err)
		}
		loaded, err := store.LoadInteractionQuestion(context.Background(), record.ID, record.CreatedAt)
		if err != nil {
			t.Fatal(err)
		}
		loaded.Document.ExactJSON[0] = '['
		reloaded, err := store.LoadInteractionQuestion(context.Background(), record.ID, record.CreatedAt)
		if err != nil || reloaded.Document.ExactJSON[0] != '{' {
			t.Fatalf("reloaded = %#v, %v", reloaded, err)
		}
		wrong := questionIdentity(record)
		wrong.Agent = "aauth:other@ap.example"
		if _, err := store.PollInteractionQuestion(context.Background(), record.ID, wrong, record.CreatedAt); !errors.Is(err, personserver.ErrInteractionQuestionNotFound) {
			t.Fatalf("wrong identity = %v", err)
		}
		answer, _ := aauth.EncodeInteractionAnswer(aauth.InteractionAnswer{Answer: "Yes."})
		resolved, err := store.ResolveInteractionQuestion(context.Background(), record.ID, personserver.InteractionQuestionAnswered, answer, record.CreatedAt.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		answer.ExactJSON[0] = '['
		if resolved.Answer.ExactJSON[0] != '{' {
			t.Fatal("resolved answer aliases caller")
		}
		if _, err := store.ResolveInteractionQuestion(context.Background(), record.ID, personserver.InteractionQuestionUnreachable, aauth.InteractionAnswerDocument{}, record.CreatedAt.Add(time.Second)); !errors.Is(err, personserver.ErrInteractionQuestionConflict) {
			t.Fatalf("changed resolution = %v", err)
		}
	})

	t.Run("expiry and one terminal consumer", func(t *testing.T) {
		store := contract.New(t)
		expired := questionRecord(t, "question-expired")
		if err := store.CreateInteractionQuestion(context.Background(), expired); err != nil {
			t.Fatal(err)
		}
		polled, err := store.PollInteractionQuestion(context.Background(), expired.ID, questionIdentity(expired), expired.ExpiresAt)
		if err != nil || polled.State != personserver.InteractionQuestionExpired {
			t.Fatalf("expired poll = %#v, %v", polled, err)
		}
		if err := store.ConsumeInteractionQuestion(context.Background(), expired.ID, polled); err != nil {
			t.Fatal(err)
		}

		answered := questionRecord(t, "question-answered")
		if err := store.CreateInteractionQuestion(context.Background(), answered); err != nil {
			t.Fatal(err)
		}
		answer, _ := aauth.EncodeInteractionAnswer(aauth.InteractionAnswer{Answer: "Yes."})
		terminal, err := store.ResolveInteractionQuestion(context.Background(), answered.ID, personserver.InteractionQuestionAnswered, answer, answered.CreatedAt.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errorsOut := make(chan error, 2)
		var wait sync.WaitGroup
		for range 2 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				errorsOut <- store.ConsumeInteractionQuestion(context.Background(), answered.ID, cloneQuestionRecord(terminal))
			}()
		}
		close(start)
		wait.Wait()
		close(errorsOut)
		success, gone := 0, 0
		for err := range errorsOut {
			if err == nil {
				success++
			} else if errors.Is(err, personserver.ErrInteractionQuestionGone) {
				gone++
			}
		}
		if success != 1 || gone != 1 {
			t.Fatalf("consume results = success %d gone %d", success, gone)
		}
	})
}

func questionRecord(t *testing.T, id string) personserver.InteractionQuestionRecord {
	t.Helper()
	created := time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC)
	document, err := aauth.EncodeInteractionQuestion(aauth.InteractionQuestion{Question: "Proceed?"})
	if err != nil {
		t.Fatal(err)
	}
	return personserver.InteractionQuestionRecord{ID: id, PersonServer: "https://ps.example", AgentProvider: "https://ap.example", Agent: "aauth:operator@ap.example", ConfirmationThumbprint: "thumbprint", AgentExpiresAt: created.Add(time.Hour), Document: document, State: personserver.InteractionQuestionPending, CreatedAt: created, ExpiresAt: created.Add(time.Minute), RetryAfter: time.Second}
}
func questionIdentity(record personserver.InteractionQuestionRecord) personserver.InteractionQuestionPollIdentity {
	return personserver.InteractionQuestionPollIdentity{PersonServer: record.PersonServer, AgentProvider: record.AgentProvider, Agent: record.Agent, ConfirmationThumbprint: record.ConfirmationThumbprint}
}
func cloneQuestionRecord(record personserver.InteractionQuestionRecord) personserver.InteractionQuestionRecord {
	record.Document.ExactJSON = append([]byte(nil), record.Document.ExactJSON...)
	record.Answer.ExactJSON = append([]byte(nil), record.Answer.ExactJSON...)
	return record
}
