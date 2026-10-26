package storetest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// DeferredTokenContract constructs a fresh empty DeferredTokenStore for each
// scenario.
type DeferredTokenContract struct {
	New func(testing.TB) personserver.DeferredTokenStore
}

// RunDeferredToken checks the store boundary behind a Person Server-hosted
// account-link interaction, including distinct parent poll authority and child
// credential authority. Passing the suite complements, but does not replace,
// backend transaction, restart, and failure-injection tests.
func RunDeferredToken(t *testing.T, contract DeferredTokenContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: DeferredTokenContract.New is required")
	}

	t.Run("create retains independent request and unique code", func(t *testing.T) {
		store := contract.New(t)
		record := deferredTokenRecord(t, "create", "code-create")
		if err := store.CreatePendingPersonToken(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		record.AgentAdditionalClaims["attestation"][0] = '['
		snapshot, err := store.LoadPendingPersonToken(context.Background(), "create")
		if err != nil {
			t.Fatal(err)
		}
		if string(snapshot.Record.AgentAdditionalClaims["attestation"]) != `{"level":"example"}` ||
			snapshot.State != personserver.PersonTokenPollWaiting {
			t.Fatalf("retained snapshot = %#v", snapshot)
		}
		snapshot.Record.AgentAdditionalClaims["attestation"][0] = '['
		reloaded, err := store.LoadPendingPersonToken(context.Background(), "create")
		if err != nil || string(reloaded.Record.AgentAdditionalClaims["attestation"]) != `{"level":"example"}` {
			t.Fatalf("reloaded snapshot = %#v, %v", reloaded, err)
		}

		duplicateID := deferredTokenRecord(t, "create", "other-code")
		if err := store.CreatePendingPersonToken(context.Background(), duplicateID); !errors.Is(err, personserver.ErrPendingPersonTokenConflict) {
			t.Fatalf("duplicate id = %v", err)
		}
		duplicateCode := deferredTokenRecord(t, "other-id", "code-create")
		if err := store.CreatePendingPersonToken(context.Background(), duplicateCode); !errors.Is(err, personserver.ErrPendingPersonTokenConflict) {
			t.Fatalf("duplicate code = %v", err)
		}
	})

	t.Run("code correlation is exact and one shot", func(t *testing.T) {
		store := contract.New(t)
		record := deferredTokenRecord(t, "correlate", "code-correlate")
		if err := store.CreatePendingPersonToken(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		wrong := sha256.Sum256([]byte("wrong-code"))
		if _, err := store.ConsumePersonTokenInteractionCode(
			context.Background(), record.PersonServer, record.ID, wrong, deferredTokenNow,
		); !errors.Is(err, personserver.ErrInteractionCodeInvalid) {
			t.Fatalf("wrong code = %v", err)
		}
		consumed, err := store.ConsumePersonTokenInteractionCode(
			context.Background(), record.PersonServer, record.ID, record.CodeSHA256, deferredTokenNow,
		)
		if err != nil || consumed.ID != record.ID || consumed.Agent != record.Agent {
			t.Fatalf("consumed = %#v, %v", consumed, err)
		}
		if _, err := store.ConsumePersonTokenInteractionCode(
			context.Background(), record.PersonServer, record.ID, record.CodeSHA256, deferredTokenNow,
		); !errors.Is(err, personserver.ErrInteractionCodeUsed) {
			t.Fatalf("reused code = %v", err)
		}
	})

	t.Run("delegated request separates parent poller from child recipient", func(t *testing.T) {
		store := contract.New(t)
		record := deferredTokenRecord(t, "delegated", "code-delegated")
		record.Agent = "aauth:local+worker@agent.example"
		record.AgentTokenJTI = "child-token"
		record.ParentAgent = record.RequestingAgent
		record.Confirmation = deferredTokenJWKFor(t, "storetest-child-key", 1)
		record.AgentAdditionalClaims = map[string]json.RawMessage{
			"workload": json.RawMessage(`"records-worker"`),
		}
		if err := store.CreatePendingPersonToken(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		record.AgentAdditionalClaims["workload"][0] = '['
		record.RequestingAgentAdditionalClaims["attestation"][0] = '['
		retained, err := store.LoadPendingPersonToken(context.Background(), record.ID)
		if err != nil || retained.Record.Agent != "aauth:local+worker@agent.example" ||
			retained.Record.RequestingAgent != "aauth:local@agent.example" ||
			retained.Record.AgentTokenJTI != "child-token" || retained.Record.RequestingAgentTokenJTI != "agent-token" ||
			string(retained.Record.AgentAdditionalClaims["workload"]) != `"records-worker"` ||
			string(retained.Record.RequestingAgentAdditionalClaims["attestation"]) != `{"level":"example"}` {
			t.Fatalf("delegated retained request = %#v, %v", retained, err)
		}
		childJKT, err := retained.Record.Confirmation.Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PollPendingPersonToken(context.Background(), record.ID, personserver.PersonTokenPollIdentity{
			PersonServer: record.PersonServer, Agent: record.Agent, ConfirmationThumbprint: childJKT,
		}, deferredTokenNow); !errors.Is(err, personserver.ErrPendingPersonTokenNotFound) {
			t.Fatalf("child poll = %v", err)
		}
		consumed, err := store.ConsumePersonTokenInteractionCode(
			context.Background(), record.PersonServer, record.ID, record.CodeSHA256, deferredTokenNow,
		)
		if err != nil {
			t.Fatal(err)
		}
		approval := deferredTokenApproval(consumed, "account-123", "delegated-token")
		if err := store.ApprovePendingPersonToken(context.Background(), record.ID, approval); err != nil {
			t.Fatal(err)
		}
		result, err := store.PollPendingPersonToken(
			context.Background(), record.ID, deferredTokenIdentity(t, consumed), deferredTokenNow,
		)
		if err != nil || result.State != personserver.PersonTokenPollApproved ||
			result.Record.Agent != consumed.Agent || result.Record.ParentAgent != consumed.ParentAgent ||
			!result.Record.Confirmation.Equal(consumed.Confirmation) {
			t.Fatalf("delegated approved result = %#v, %v", result, err)
		}
	})

	t.Run("approval is canonical identity bound and delivered once", func(t *testing.T) {
		store := contract.New(t)
		record := createAndConsumeDeferredToken(t, store, "approve")
		approval := deferredTokenApproval(record, "account-123", "token-first")
		if err := store.ApprovePendingPersonToken(context.Background(), record.ID, approval); err != nil {
			t.Fatal(err)
		}
		replay := deferredTokenApproval(record, "account-123", "token-retry")
		if err := store.ApprovePendingPersonToken(context.Background(), record.ID, replay); err != nil {
			t.Fatalf("exact person replay = %v", err)
		}
		changed := deferredTokenApproval(record, "other-account", "token-changed")
		if err := store.ApprovePendingPersonToken(context.Background(), record.ID, changed); !errors.Is(err, personserver.ErrPendingPersonTokenConflict) {
			t.Fatalf("changed approval = %v", err)
		}

		for _, identity := range wrongDeferredTokenIdentities(t, record) {
			if _, err := store.PollPendingPersonToken(
				context.Background(), record.ID, identity, deferredTokenNow,
			); !errors.Is(err, personserver.ErrPendingPersonTokenNotFound) {
				t.Fatalf("wrong identity poll = %v", err)
			}
		}
		canonical, err := store.PollPendingPersonToken(
			context.Background(), record.ID, deferredTokenIdentity(t, record), deferredTokenNow,
		)
		if err != nil || canonical.State != personserver.PersonTokenPollApproved ||
			canonical.Token != approval.Token || canonical.Record.JTI != approval.Record.JTI {
			t.Fatalf("canonical approval = %#v, %v", canonical, err)
		}
		retained, err := store.Load(context.Background(), approval.Record.PersonServer, approval.Record.JTI)
		if err != nil || retained.JTI != approval.Record.JTI || retained.Subject != "account-123" {
			t.Fatalf("retained person token = %#v, %v", retained, err)
		}
		altered := canonical
		altered.Token = "substituted"
		if err := store.ConsumePendingPersonTokenResult(context.Background(), record.ID, altered); !errors.Is(err, personserver.ErrPendingPersonTokenConflict) {
			t.Fatalf("changed consume = %v", err)
		}

		results := make(chan error, 2)
		start := make(chan struct{})
		var wait sync.WaitGroup
		for range 2 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				results <- store.ConsumePendingPersonTokenResult(context.Background(), record.ID, canonical)
			}()
		}
		close(start)
		wait.Wait()
		close(results)
		succeeded, gone := 0, 0
		for err := range results {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, personserver.ErrPendingPersonTokenGone):
				gone++
			default:
				t.Fatalf("concurrent consume = %v", err)
			}
		}
		if succeeded != 1 || gone != 1 {
			t.Fatalf("concurrent consumers: succeeded=%d gone=%d", succeeded, gone)
		}
	})

	t.Run("denial expiry and invalidation remain terminal", func(t *testing.T) {
		t.Run("denied", func(t *testing.T) {
			store := contract.New(t)
			record := createAndConsumeDeferredToken(t, store, "denied")
			if err := store.DenyPendingPersonToken(context.Background(), record.ID, deferredTokenNow); err != nil {
				t.Fatal(err)
			}
			if err := store.DenyPendingPersonToken(context.Background(), record.ID, deferredTokenNow.Add(time.Second)); err != nil {
				t.Fatalf("denial replay = %v", err)
			}
			if err := store.ApprovePendingPersonToken(
				context.Background(), record.ID, deferredTokenApproval(record, "account-123", "late-token"),
			); !errors.Is(err, personserver.ErrPendingPersonTokenConflict) {
				t.Fatalf("approval after denial = %v", err)
			}
			consumeTerminalDeferredToken(t, store, record, personserver.PersonTokenPollDenied, deferredTokenNow)
		})

		t.Run("expired", func(t *testing.T) {
			store := contract.New(t)
			record := deferredTokenRecord(t, "expired", "code-expired")
			record.ExpiresAt = deferredTokenNow.Add(time.Minute)
			if err := store.CreatePendingPersonToken(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ConsumePersonTokenInteractionCode(
				context.Background(), record.PersonServer, record.ID, record.CodeSHA256, record.ExpiresAt,
			); !errors.Is(err, personserver.ErrPendingPersonTokenExpired) {
				t.Fatalf("consume at deadline = %v", err)
			}
			consumeTerminalDeferredToken(t, store, record, personserver.PersonTokenPollExpired, record.ExpiresAt)
		})

		t.Run("invalidated", func(t *testing.T) {
			store := contract.New(t)
			record := deferredTokenRecord(t, "invalidated", "code-invalidated")
			if err := store.CreatePendingPersonToken(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			if err := store.InvalidatePendingPersonToken(context.Background(), record.ID, deferredTokenNow); err != nil {
				t.Fatal(err)
			}
			if err := store.InvalidatePendingPersonToken(context.Background(), record.ID, deferredTokenNow); err != nil {
				t.Fatalf("invalidation replay = %v", err)
			}
			if _, err := store.PollPendingPersonToken(
				context.Background(), record.ID, deferredTokenIdentity(t, record), deferredTokenNow,
			); !errors.Is(err, personserver.ErrPendingPersonTokenGone) {
				t.Fatalf("poll invalidated = %v", err)
			}
		})
	})

	t.Run("competing host decisions have one winner", func(t *testing.T) {
		store := contract.New(t)
		record := createAndConsumeDeferredToken(t, store, "decision-race")
		results := make(chan error, 2)
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			results <- store.ApprovePendingPersonToken(
				context.Background(), record.ID, deferredTokenApproval(record, "account-123", "race-token"),
			)
		}()
		go func() {
			defer wait.Done()
			<-start
			results <- store.DenyPendingPersonToken(context.Background(), record.ID, deferredTokenNow)
		}()
		close(start)
		wait.Wait()
		close(results)
		succeeded, conflicted := 0, 0
		for err := range results {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, personserver.ErrPendingPersonTokenConflict):
				conflicted++
			default:
				t.Fatalf("decision result = %v", err)
			}
		}
		if succeeded != 1 || conflicted != 1 {
			t.Fatalf("competing decisions: succeeded=%d conflicted=%d", succeeded, conflicted)
		}
	})
}

var deferredTokenNow = time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)

func deferredTokenRecord(t testing.TB, id, code string) personserver.PendingPersonTokenRecord {
	t.Helper()
	return personserver.PendingPersonTokenRecord{
		ID: id, CodeSHA256: sha256.Sum256([]byte(code)),
		PersonServer: "https://person.example", AgentProvider: "https://agent.example",
		Agent: "aauth:local@agent.example", AgentTokenJTI: "agent-token", Resource: "https://resource.example",
		Confirmation: deferredTokenJWK(t), AgentExpiresAt: deferredTokenNow.Add(time.Hour),
		AgentAdditionalClaims: map[string]json.RawMessage{
			"attestation": json.RawMessage(`{"level":"example"}`),
		},
		RequestingAgent:                 "aauth:local@agent.example",
		RequestingAgentTokenJTI:         "agent-token",
		RequestingConfirmation:          deferredTokenJWK(t),
		RequestingAgentExpiresAt:        deferredTokenNow.Add(time.Hour),
		RequestingAgentAdditionalClaims: map[string]json.RawMessage{"attestation": json.RawMessage(`{"level":"example"}`)},
		CreatedAt:                       deferredTokenNow, ExpiresAt: deferredTokenNow.Add(5 * time.Minute),
		RetryAfter: time.Second,
	}
}

func createAndConsumeDeferredToken(
	t testing.TB,
	store personserver.DeferredTokenStore,
	id string,
) personserver.PendingPersonTokenRecord {
	t.Helper()
	record := deferredTokenRecord(t, id, "code-"+id)
	if err := store.CreatePendingPersonToken(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	consumed, err := store.ConsumePersonTokenInteractionCode(
		context.Background(), record.PersonServer, record.ID, record.CodeSHA256, deferredTokenNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	return consumed
}

func deferredTokenApproval(
	record personserver.PendingPersonTokenRecord,
	subject string,
	token string,
) personserver.PersonTokenApproval {
	return personserver.PersonTokenApproval{
		Person: personserver.Person{Subject: subject, Lifetime: 20 * time.Minute},
		Token:  token,
		Record: personserver.PersonTokenRecord{
			JTI: "person-token-" + subject, PersonServer: record.PersonServer,
			Resource: record.Resource, Subject: subject, AgentProvider: record.AgentProvider,
			Agent: record.Agent, ParentAgent: record.ParentAgent, Confirmation: record.Confirmation,
			ExpiresAt: deferredTokenNow.Add(20 * time.Minute), RetainUntil: deferredTokenNow.Add(time.Hour),
		},
		ExpiresIn: 1200, DecidedAt: deferredTokenNow,
	}
}

func deferredTokenIdentity(t testing.TB, record personserver.PendingPersonTokenRecord) personserver.PersonTokenPollIdentity {
	t.Helper()
	thumbprint, err := record.RequestingConfirmation.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	return personserver.PersonTokenPollIdentity{
		PersonServer: record.PersonServer, Agent: record.RequestingAgent, ConfirmationThumbprint: thumbprint,
	}
}

func wrongDeferredTokenIdentities(t testing.TB, record personserver.PendingPersonTokenRecord) []personserver.PersonTokenPollIdentity {
	t.Helper()
	base := deferredTokenIdentity(t, record)
	wrongServer := base
	wrongServer.PersonServer = "https://other-person.example"
	wrongAgent := base
	wrongAgent.Agent = "aauth:other@agent.example"
	wrongKey := base
	wrongKey.ConfirmationThumbprint = "other-thumbprint"
	return []personserver.PersonTokenPollIdentity{wrongServer, wrongAgent, wrongKey}
}

func consumeTerminalDeferredToken(
	t testing.TB,
	store personserver.DeferredTokenStore,
	record personserver.PendingPersonTokenRecord,
	state personserver.PersonTokenPollState,
	now time.Time,
) {
	t.Helper()
	result, err := store.PollPendingPersonToken(
		context.Background(), record.ID, deferredTokenIdentity(t, record), now,
	)
	if err != nil || result.State != state {
		t.Fatalf("terminal poll = %#v, %v", result, err)
	}
	if err := store.ConsumePendingPersonTokenResult(context.Background(), record.ID, result); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PollPendingPersonToken(
		context.Background(), record.ID, deferredTokenIdentity(t, record), now,
	); !errors.Is(err, personserver.ErrPendingPersonTokenGone) {
		t.Fatalf("poll after consume = %v", err)
	}
}

func deferredTokenJWK(t testing.TB) jose.JWK {
	return deferredTokenJWKFor(t, "storetest-key", 0)
}

func deferredTokenJWKFor(t testing.TB, id string, firstSeedByte byte) jose.JWK {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = firstSeedByte
	privateKey := ed25519.NewKeyFromSeed(seed)
	signingKey, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signingKey.PublicJWK()
}
