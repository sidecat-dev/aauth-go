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

// InteractionRelayContract constructs a fresh empty relay store.
type InteractionRelayContract struct {
	New func(testing.TB) personserver.InteractionRelayStore
}

// RunInteractionRelay checks the reusable deferred-relay store contract.
func RunInteractionRelay(t *testing.T, contract InteractionRelayContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: InteractionRelayContract.New is required")
	}

	t.Run("exact state and identity", func(t *testing.T) {
		store := contract.New(t)
		record := relayRecord(t, "relay-1")
		if err := store.CreateInteractionRelay(context.Background(), cloneRelayRecord(record)); err != nil {
			t.Fatal(err)
		}
		loaded, err := store.LoadInteractionRelay(context.Background(), record.ID, record.CreatedAt)
		if err != nil {
			t.Fatal(err)
		}
		loaded.Document.ExactJSON[0] = '['
		reloaded, err := store.LoadInteractionRelay(context.Background(), record.ID, record.CreatedAt)
		if err != nil || reloaded.Document.ExactJSON[0] != '{' {
			t.Fatalf("reloaded = %#v, %v", reloaded, err)
		}
		wrong := relayIdentity(record)
		wrong.Agent = "aauth:other@ap.example"
		if _, err := store.PollInteractionRelay(context.Background(), record.ID, wrong, record.CreatedAt); !errors.Is(err, personserver.ErrInteractionRelayNotFound) {
			t.Fatalf("wrong identity = %v", err)
		}
		resolved, err := store.ResolveInteractionRelay(
			context.Background(), record.ID, aauth.InteractionRelayInteracting, record.CreatedAt.Add(time.Second),
		)
		if err != nil || resolved.Completion.Status != aauth.InteractionRelayInteracting {
			t.Fatalf("resolved = %#v, %v", resolved, err)
		}
		if _, err := store.ResolveInteractionRelay(
			context.Background(), record.ID, aauth.InteractionRelayPending, record.CreatedAt.Add(time.Second),
		); !errors.Is(err, personserver.ErrInteractionRelayConflict) {
			t.Fatalf("changed resolution = %v", err)
		}
	})

	t.Run("deadline and one terminal consumer", func(t *testing.T) {
		store := contract.New(t)
		record := relayRecord(t, "relay-deadline")
		if err := store.CreateInteractionRelay(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		terminal, err := store.PollInteractionRelay(
			context.Background(), record.ID, relayIdentity(record), record.ExpiresAt,
		)
		if err != nil || terminal.State != personserver.InteractionRelayResolved ||
			terminal.Completion.Status != aauth.InteractionRelayPending || !terminal.ResolvedAt.Equal(record.ExpiresAt) {
			t.Fatalf("deadline result = %#v, %v", terminal, err)
		}

		start := make(chan struct{})
		errorsOut := make(chan error, 2)
		var wait sync.WaitGroup
		for range 2 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				errorsOut <- store.ConsumeInteractionRelay(context.Background(), record.ID, cloneRelayRecord(terminal))
			}()
		}
		close(start)
		wait.Wait()
		close(errorsOut)
		success, gone := 0, 0
		for err := range errorsOut {
			if err == nil {
				success++
			} else if errors.Is(err, personserver.ErrInteractionRelayGone) {
				gone++
			}
		}
		if success != 1 || gone != 1 {
			t.Fatalf("consume results = success %d gone %d", success, gone)
		}
	})
}

func relayRecord(t *testing.T, id string) personserver.InteractionRelayRecord {
	t.Helper()
	created := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	document, err := aauth.EncodeInteractionRelay(aauth.InteractionRelay{
		Type: aauth.InteractionRelayInteraction,
		URL:  "https://resource.example/confirm",
		Code: "ABCD-EFGH",
	})
	if err != nil {
		t.Fatal(err)
	}
	return personserver.InteractionRelayRecord{
		ID:                     id,
		PersonServer:           "https://ps.example",
		AgentProvider:          "https://ap.example",
		Agent:                  "aauth:operator@ap.example",
		ConfirmationThumbprint: "thumbprint",
		AgentExpiresAt:         created.Add(time.Hour),
		Document:               document,
		State:                  personserver.InteractionRelayPending,
		CreatedAt:              created,
		ExpiresAt:              created.Add(time.Minute),
		RetryAfter:             time.Second,
	}
}

func relayIdentity(record personserver.InteractionRelayRecord) personserver.InteractionRelayPollIdentity {
	return personserver.InteractionRelayPollIdentity{
		PersonServer:           record.PersonServer,
		AgentProvider:          record.AgentProvider,
		Agent:                  record.Agent,
		ConfirmationThumbprint: record.ConfirmationThumbprint,
	}
}

func cloneRelayRecord(record personserver.InteractionRelayRecord) personserver.InteractionRelayRecord {
	record.Document.ExactJSON = append([]byte(nil), record.Document.ExactJSON...)
	return record
}
