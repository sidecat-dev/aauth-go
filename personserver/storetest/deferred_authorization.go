package storetest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// DeferredAuthorizationContract constructs a fresh empty authorization store
// for each scenario.
type DeferredAuthorizationContract struct {
	New func(testing.TB) personserver.DeferredAuthorizationStore
}

// RunDeferredAuthorization checks the base store behind Person Server-hosted
// Auth-token consent. It does not require the optional clarification store.
// Passing the suite complements, but does not replace, backend transaction,
// restart, and failure-injection tests.
func RunDeferredAuthorization(t *testing.T, contract DeferredAuthorizationContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: DeferredAuthorizationContract.New is required")
	}

	t.Run("create retains an independent request and unique code", func(t *testing.T) {
		store := contract.New(t)
		record := deferredAuthorizationRecord(t, "create", "code-create")
		if err := store.CreatePendingAuthorization(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		mutateDeferredAuthorizationRecord(&record)
		snapshot, err := store.LoadPendingAuthorization(context.Background(), "create", deferredAuthorizationNow)
		if err != nil {
			t.Fatal(err)
		}
		requireDeferredAuthorizationRecord(t, snapshot.Record, "create")
		if snapshot.State != personserver.AuthorizationPollWaiting {
			t.Fatalf("created state = %v", snapshot.State)
		}
		mutateDeferredAuthorizationRecord(&snapshot.Record)
		reloaded, err := store.LoadPendingAuthorization(context.Background(), "create", deferredAuthorizationNow)
		if err != nil {
			t.Fatal(err)
		}
		requireDeferredAuthorizationRecord(t, reloaded.Record, "create")
		waiting, err := store.PollPendingAuthorization(
			context.Background(), "create", deferredAuthorizationIdentity(t, reloaded.Record), deferredAuthorizationNow,
		)
		if err != nil || waiting.State != personserver.AuthorizationPollWaiting {
			t.Fatalf("waiting poll = %#v, %v", waiting, err)
		}

		duplicateID := deferredAuthorizationRecord(t, "create", "other-code")
		if err := store.CreatePendingAuthorization(context.Background(), duplicateID); !errors.Is(err, personserver.ErrPendingAuthorizationConflict) {
			t.Fatalf("duplicate id = %v", err)
		}
		duplicateCode := deferredAuthorizationRecord(t, "other-id", "code-create")
		if err := store.CreatePendingAuthorization(context.Background(), duplicateCode); !errors.Is(err, personserver.ErrPendingAuthorizationConflict) {
			t.Fatalf("duplicate code = %v", err)
		}
	})

	t.Run("code correlation is exact bounded and one shot", func(t *testing.T) {
		store := contract.New(t)
		record := deferredAuthorizationRecord(t, "correlate", "code-correlate")
		if err := store.CreatePendingAuthorization(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		wrong := sha256.Sum256([]byte("wrong-code"))
		if _, err := store.ConsumeAuthorizationInteractionCode(
			context.Background(), record.PersonServer, record.ID,
			personserver.AuthorizationCodePresentation{
				CodeSHA256: wrong, SyntacticallyValid: true, Callback: "https://agent.example/wrong",
			}, deferredAuthorizationNow,
		); !errors.Is(err, personserver.ErrAuthorizationInteractionCodeInvalid) {
			t.Fatalf("wrong code = %v", err)
		}
		consumed, err := store.ConsumeAuthorizationInteractionCode(
			context.Background(), record.PersonServer, record.ID,
			personserver.AuthorizationCodePresentation{
				CodeSHA256: record.CodeSHA256, SyntacticallyValid: true, Callback: "https://agent.example/callback",
			}, deferredAuthorizationNow,
		)
		if err != nil {
			t.Fatal(err)
		}
		requireDeferredAuthorizationRecord(t, consumed, record.ID)
		mutateDeferredAuthorizationRecord(&consumed)
		retained, err := store.LoadPendingAuthorization(context.Background(), record.ID, deferredAuthorizationNow)
		if err != nil {
			t.Fatal(err)
		}
		requireDeferredAuthorizationRecord(t, retained.Record, record.ID)
		if retained.Callback != "https://agent.example/callback" {
			t.Fatalf("retained callback = %q", retained.Callback)
		}
		if _, err := store.ConsumeAuthorizationInteractionCode(
			context.Background(), record.PersonServer, record.ID,
			personserver.AuthorizationCodePresentation{
				CodeSHA256: record.CodeSHA256, SyntacticallyValid: true, Callback: "https://agent.example/other",
			}, deferredAuthorizationNow,
		); !errors.Is(err, personserver.ErrAuthorizationInteractionCodeUsed) {
			t.Fatalf("reused code = %v", err)
		}
		if again, err := store.LoadPendingAuthorization(context.Background(), record.ID, deferredAuthorizationNow); err != nil ||
			again.Callback != "https://agent.example/callback" {
			t.Fatalf("callback after a reused code = %q, %v", again.Callback, err)
		}

		bounded := deferredAuthorizationRecord(t, "bounded", "code-bounded")
		if err := store.CreatePendingAuthorization(context.Background(), bounded); err != nil {
			t.Fatal(err)
		}
		for attempt := 1; attempt <= personserver.MaximumAuthorizationCodeAttempts; attempt++ {
			_, err := store.ConsumeAuthorizationInteractionCode(
				context.Background(), bounded.PersonServer, bounded.ID,
				personserver.AuthorizationCodePresentation{SyntacticallyValid: false}, deferredAuthorizationNow,
			)
			if attempt < personserver.MaximumAuthorizationCodeAttempts && !errors.Is(err, personserver.ErrAuthorizationInteractionCodeInvalid) {
				t.Fatalf("invalid attempt %d = %v", attempt, err)
			}
			if attempt == personserver.MaximumAuthorizationCodeAttempts && !errors.Is(err, personserver.ErrPendingAuthorizationGone) {
				t.Fatalf("terminal invalid attempt = %v", err)
			}
		}
	})

	t.Run("parent polls the delegated canonical approval", func(t *testing.T) {
		store := contract.New(t)
		record := createAndConsumeDeferredAuthorization(t, store, "delegated")
		childJKT, err := record.SubagentConfirmation.Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PollPendingAuthorization(context.Background(), record.ID, personserver.AuthorizationPollIdentity{
			PersonServer: record.PersonServer, AgentProvider: record.AgentProvider,
			Agent: record.Subagent, ConfirmationThumbprint: childJKT,
		}, deferredAuthorizationNow); !errors.Is(err, personserver.ErrPendingAuthorizationNotFound) {
			t.Fatalf("child poll = %v", err)
		}

		approval := deferredAuthorizationApproval(record, "token-first")
		canonical, err := store.ApprovePendingAuthorization(context.Background(), record.ID, approval)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(canonical, approval) {
			t.Fatalf("canonical approval = %#v, want %#v", canonical, approval)
		}
		approval.Decision.Scopes[0] = "mutated.input"
		replay := deferredAuthorizationApproval(record, "token-retry")
		replay.Decision.Scopes = []string{"records.list", "records.read"}
		replay.DecidedAt = replay.DecidedAt.Add(time.Second)
		canonical, err = store.ApprovePendingAuthorization(context.Background(), record.ID, replay)
		if err != nil || canonical.Token != approval.Token || !canonical.DecidedAt.Equal(approval.DecidedAt) {
			t.Fatalf("approval replay = %#v, %v", canonical, err)
		}
		canonical.Decision.Scopes[0] = "mutated.return"
		changed := deferredAuthorizationApproval(record, "token-changed")
		changed.Decision.Lifetime += time.Second
		if _, err := store.ApprovePendingAuthorization(context.Background(), record.ID, changed); !errors.Is(err, personserver.ErrPendingAuthorizationConflict) {
			t.Fatalf("changed approval = %v", err)
		}

		for _, identity := range wrongDeferredAuthorizationIdentities(t, record) {
			if _, err := store.PollPendingAuthorization(
				context.Background(), record.ID, identity, deferredAuthorizationNow,
			); !errors.Is(err, personserver.ErrPendingAuthorizationNotFound) {
				t.Fatalf("wrong identity poll = %v", err)
			}
		}
		result, err := store.PollPendingAuthorization(
			context.Background(), record.ID, deferredAuthorizationIdentity(t, record), deferredAuthorizationNow,
		)
		if err != nil || result.State != personserver.AuthorizationPollApproved || result.Token != approval.Token ||
			result.Pending.Subagent != record.Subagent || !result.Pending.SubagentConfirmation.Equal(record.SubagentConfirmation) {
			t.Fatalf("approved poll = %#v, %v", result, err)
		}
		result.Pending.SubagentAdditionalClaims["workload"][0] = '['
		result.Decision.Scopes[0] = "mutated.scope"
		result, err = store.PollPendingAuthorization(
			context.Background(), record.ID, deferredAuthorizationIdentity(t, record), deferredAuthorizationNow,
		)
		if err != nil || string(result.Pending.SubagentAdditionalClaims["workload"]) != `"worker"` ||
			!reflect.DeepEqual(result.Decision.Scopes, record.Scopes) {
			t.Fatalf("approved poll copy isolation = %#v, %v", result, err)
		}
		mutated := result
		mutated.Token = "substituted"
		if err := store.ConsumePendingAuthorizationResult(context.Background(), record.ID, mutated); !errors.Is(err, personserver.ErrPendingAuthorizationConflict) {
			t.Fatalf("changed consume = %v", err)
		}
		consumeDeferredAuthorizationConcurrently(t, store, record.ID, result)
	})

	t.Run("explicit terminal outcomes and expiry remain terminal", func(t *testing.T) {
		for _, test := range []struct {
			name  string
			state personserver.AuthorizationPollState
			apply func(personserver.DeferredAuthorizationStore, string) error
		}{
			{name: "denied", state: personserver.AuthorizationPollDenied, apply: func(store personserver.DeferredAuthorizationStore, id string) error {
				return store.DenyPendingAuthorization(context.Background(), id, deferredAuthorizationNow)
			}},
			{name: "abandoned", state: personserver.AuthorizationPollAbandoned, apply: func(store personserver.DeferredAuthorizationStore, id string) error {
				return store.AbandonPendingAuthorization(context.Background(), id, deferredAuthorizationNow)
			}},
			{name: "server error", state: personserver.AuthorizationPollServerError, apply: func(store personserver.DeferredAuthorizationStore, id string) error {
				return store.FailPendingAuthorization(context.Background(), id, deferredAuthorizationNow)
			}},
		} {
			t.Run(test.name, func(t *testing.T) {
				store := contract.New(t)
				record := createAndConsumeDeferredAuthorization(t, store, test.name)
				if err := test.apply(store, record.ID); err != nil {
					t.Fatal(err)
				}
				if err := test.apply(store, record.ID); err != nil {
					t.Fatalf("terminal replay = %v", err)
				}
				if _, err := store.ApprovePendingAuthorization(
					context.Background(), record.ID, deferredAuthorizationApproval(record, "late-token"),
				); !errors.Is(err, personserver.ErrPendingAuthorizationConflict) {
					t.Fatalf("approval after terminal outcome = %v", err)
				}
				consumeTerminalDeferredAuthorization(t, store, record, test.state, deferredAuthorizationNow)
			})
		}

		t.Run("expired", func(t *testing.T) {
			store := contract.New(t)
			record := deferredAuthorizationRecord(t, "expired", "code-expired")
			record.ExpiresAt = deferredAuthorizationNow.Add(time.Minute)
			if err := store.CreatePendingAuthorization(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ConsumeAuthorizationInteractionCode(
				context.Background(), record.PersonServer, record.ID,
				personserver.AuthorizationCodePresentation{CodeSHA256: record.CodeSHA256, SyntacticallyValid: true}, record.ExpiresAt,
			); !errors.Is(err, personserver.ErrPendingAuthorizationExpired) {
				t.Fatalf("consume at deadline = %v", err)
			}
			consumeTerminalDeferredAuthorization(t, store, record, personserver.AuthorizationPollExpired, record.ExpiresAt)
		})
	})

	t.Run("competing host decisions have one winner", func(t *testing.T) {
		store := contract.New(t)
		record := createAndConsumeDeferredAuthorization(t, store, "decision-race")
		results := make(chan error, 2)
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, err := store.ApprovePendingAuthorization(
				context.Background(), record.ID, deferredAuthorizationApproval(record, "race-token"),
			)
			results <- err
		}()
		go func() {
			defer wait.Done()
			<-start
			results <- store.DenyPendingAuthorization(context.Background(), record.ID, deferredAuthorizationNow)
		}()
		close(start)
		wait.Wait()
		close(results)
		succeeded, conflicted := 0, 0
		for err := range results {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, personserver.ErrPendingAuthorizationConflict):
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

var deferredAuthorizationNow = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

func deferredAuthorizationRecord(t testing.TB, id, code string) personserver.PendingAuthorizationRecord {
	t.Helper()
	return personserver.PendingAuthorizationRecord{
		ID: id, CodeSHA256: sha256.Sum256([]byte(code)),
		PersonServer: "https://person.example", AgentProvider: "https://agent.example",
		Agent: "aauth:local@agent.example", AgentTokenJTI: "parent-token",
		Subagent: "aauth:local+worker@agent.example", SubagentTokenJTI: "child-token",
		Resource: "https://resource.example", Subject: "person-123", Tenant: "tenant-1",
		Scopes:                   []string{"records.read", "records.list"},
		Confirmation:             deferredAuthorizationJWKFor(t, "parent", 1),
		AgentExpiresAt:           deferredAuthorizationNow.Add(2 * time.Hour),
		SubagentConfirmation:     deferredAuthorizationJWKFor(t, "child", 2),
		SubagentExpiresAt:        deferredAuthorizationNow.Add(90 * time.Minute),
		ResourceTokenExpiresAt:   deferredAuthorizationNow.Add(2 * time.Hour),
		PersonTokenExpiresAt:     deferredAuthorizationNow.Add(2 * time.Hour),
		AgentAdditionalClaims:    map[string]json.RawMessage{"platform": json.RawMessage(`"orchestrator"`)},
		SubagentAdditionalClaims: map[string]json.RawMessage{"workload": json.RawMessage(`"worker"`)},
		Capabilities:             []string{"interaction"}, CreatedAt: deferredAuthorizationNow,
		ExpiresAt: deferredAuthorizationNow.Add(time.Hour), RetryAfter: time.Second,
	}
}

func deferredAuthorizationJWKFor(t testing.TB, name string, marker byte) jose.JWK {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[len(seed)-1] = marker
	key, err := jose.NewEd25519SigningKey("storetest-deferred-authorization-"+name, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicJWK()
}

func createAndConsumeDeferredAuthorization(
	t *testing.T,
	store personserver.DeferredAuthorizationStore,
	id string,
) personserver.PendingAuthorizationRecord {
	t.Helper()
	record := deferredAuthorizationRecord(t, id, "code-"+id)
	if err := store.CreatePendingAuthorization(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	consumed, err := store.ConsumeAuthorizationInteractionCode(
		context.Background(), record.PersonServer, record.ID,
		personserver.AuthorizationCodePresentation{CodeSHA256: record.CodeSHA256, SyntacticallyValid: true}, deferredAuthorizationNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	return consumed
}

func deferredAuthorizationApproval(record personserver.PendingAuthorizationRecord, token string) personserver.AuthorizationApproval {
	return personserver.AuthorizationApproval{
		Decision: personserver.AuthorizationDecision{
			Scopes: append([]string(nil), record.Scopes...), Lifetime: 10 * time.Minute,
		},
		Token: token, ExpiresIn: int64((10 * time.Minute) / time.Second), DecidedAt: deferredAuthorizationNow,
	}
}

func deferredAuthorizationIdentity(t testing.TB, record personserver.PendingAuthorizationRecord) personserver.AuthorizationPollIdentity {
	t.Helper()
	thumbprint, err := record.Confirmation.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	return personserver.AuthorizationPollIdentity{
		PersonServer: record.PersonServer, AgentProvider: record.AgentProvider,
		Agent: record.Agent, ConfirmationThumbprint: thumbprint,
	}
}

func wrongDeferredAuthorizationIdentities(t testing.TB, record personserver.PendingAuthorizationRecord) []personserver.AuthorizationPollIdentity {
	t.Helper()
	valid := deferredAuthorizationIdentity(t, record)
	wrongIssuer := valid
	wrongIssuer.PersonServer = "https://other-person.example"
	wrongProvider := valid
	wrongProvider.AgentProvider = "https://other-agent.example"
	wrongAgent := valid
	wrongAgent.Agent = "aauth:other@agent.example"
	wrongKey := valid
	wrongKey.ConfirmationThumbprint = deferredAuthorizationThumbprint(t, deferredAuthorizationJWKFor(t, "wrong", 3))
	return []personserver.AuthorizationPollIdentity{wrongIssuer, wrongProvider, wrongAgent, wrongKey}
}

func deferredAuthorizationThumbprint(t testing.TB, key jose.JWK) string {
	t.Helper()
	thumbprint, err := key.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	return thumbprint
}

func consumeTerminalDeferredAuthorization(
	t *testing.T,
	store personserver.DeferredAuthorizationStore,
	record personserver.PendingAuthorizationRecord,
	state personserver.AuthorizationPollState,
	now time.Time,
) {
	t.Helper()
	result, err := store.PollPendingAuthorization(
		context.Background(), record.ID, deferredAuthorizationIdentity(t, record), now,
	)
	if err != nil || result.State != state {
		t.Fatalf("terminal poll = %#v, %v; want %v", result, err, state)
	}
	if err := store.ConsumePendingAuthorizationResult(context.Background(), record.ID, result); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PollPendingAuthorization(
		context.Background(), record.ID, deferredAuthorizationIdentity(t, record), now,
	); !errors.Is(err, personserver.ErrPendingAuthorizationGone) {
		t.Fatalf("poll after terminal consume = %v", err)
	}
}

func consumeDeferredAuthorizationConcurrently(
	t *testing.T,
	store personserver.DeferredAuthorizationStore,
	id string,
	result personserver.AuthorizationPollRecord,
) {
	t.Helper()
	results := make(chan error, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			results <- store.ConsumePendingAuthorizationResult(context.Background(), id, result)
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
		case errors.Is(err, personserver.ErrPendingAuthorizationGone):
			gone++
		default:
			t.Fatalf("concurrent consume = %v", err)
		}
	}
	if succeeded != 1 || gone != 1 {
		t.Fatalf("concurrent consumers: succeeded=%d gone=%d", succeeded, gone)
	}
}

func mutateDeferredAuthorizationRecord(record *personserver.PendingAuthorizationRecord) {
	record.Scopes[0] = "mutated.scope"
	record.Capabilities[0] = "mutated-capability"
	record.AgentAdditionalClaims["platform"][0] = '['
	record.SubagentAdditionalClaims["workload"][0] = '['
}

func requireDeferredAuthorizationRecord(t testing.TB, record personserver.PendingAuthorizationRecord, id string) {
	t.Helper()
	if record.ID != id || !reflect.DeepEqual(record.Scopes, []string{"records.read", "records.list"}) ||
		!reflect.DeepEqual(record.Capabilities, []string{"interaction"}) ||
		string(record.AgentAdditionalClaims["platform"]) != `"orchestrator"` ||
		string(record.SubagentAdditionalClaims["workload"]) != `"worker"` ||
		record.Agent != "aauth:local@agent.example" || record.Subagent != "aauth:local+worker@agent.example" ||
		record.AgentTokenJTI != "parent-token" || record.SubagentTokenJTI != "child-token" {
		t.Fatalf("retained authorization record = %#v", record)
	}
}
