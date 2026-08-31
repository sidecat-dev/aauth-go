package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// PermissionContract constructs a fresh PermissionStore for each scenario.
type PermissionContract struct {
	New func(testing.TB) personserver.PermissionStore
}

// RunPermission checks the public permission store contract. Passing the suite
// complements, but does not replace, backend transaction, restart, and
// failure-injection tests.
func RunPermission(t *testing.T, contract PermissionContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: PermissionContract.New is required")
	}

	t.Run("immediate decision is retained and consumed exactly once", func(t *testing.T) {
		store := contract.New(t)
		record := permissionRecord("immediate", personserver.PermissionStateDenied)
		record.Decision = personserver.PermissionDecision{
			Permission: aauth.PermissionDenied,
			Reason:     "**Policy** denied this action.",
		}
		record.DecidedAt = record.CreatedAt
		if err := store.CreatePermission(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		mutatePermissionRecord(&record)

		loaded, err := store.LoadPermission(context.Background(), "immediate", permissionNow)
		if err != nil {
			t.Fatal(err)
		}
		requirePermissionRecord(t, loaded, "immediate", personserver.PermissionStateDenied)
		if loaded.Decision.Permission != aauth.PermissionDenied || loaded.Decision.Reason != "**Policy** denied this action." {
			t.Fatalf("decision = %#v", loaded.Decision)
		}
		mutatePermissionRecord(&loaded)
		polled, err := store.PollPermission(
			context.Background(), "immediate", permissionIdentity(), permissionNow,
		)
		if err != nil {
			t.Fatal(err)
		}
		requirePermissionRecord(t, polled, "immediate", personserver.PermissionStateDenied)

		changed := polled
		changed.Decision.Reason = "changed"
		if err := store.ConsumePermissionResult(context.Background(), "immediate", changed); !errors.Is(err, personserver.ErrPermissionConflict) {
			t.Fatalf("changed consume = %v", err)
		}
		if err := store.ConsumePermissionResult(context.Background(), "immediate", polled); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PollPermission(context.Background(), "immediate", permissionIdentity(), permissionNow); !errors.Is(err, personserver.ErrPermissionGone) {
			t.Fatalf("poll after consume = %v", err)
		}
	})

	t.Run("deferred decision is identity bound and first result is canonical", func(t *testing.T) {
		store := contract.New(t)
		record := permissionRecord("deferred", personserver.PermissionStatePending)
		record.ExpiresAt = permissionNow.Add(10 * time.Minute)
		record.RetryAfter = 3 * time.Second
		if err := store.CreatePermission(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		if err := store.CreatePermission(context.Background(), record); !errors.Is(err, personserver.ErrPermissionConflict) {
			t.Fatalf("duplicate create = %v", err)
		}

		for _, test := range []struct {
			name   string
			mutate func(*personserver.PermissionPollIdentity)
		}{
			{name: "person server", mutate: func(value *personserver.PermissionPollIdentity) { value.PersonServer = "https://other-person.example" }},
			{name: "agent provider", mutate: func(value *personserver.PermissionPollIdentity) {
				value.AgentProvider = "https://other-provider.example"
			}},
			{name: "agent", mutate: func(value *personserver.PermissionPollIdentity) { value.Agent = "aauth:other@provider.example" }},
			{name: "proof key", mutate: func(value *personserver.PermissionPollIdentity) { value.ConfirmationThumbprint = "other-thumbprint" }},
		} {
			t.Run("wrong "+test.name, func(t *testing.T) {
				wrong := permissionIdentity()
				test.mutate(&wrong)
				if _, err := store.PollPermission(context.Background(), "deferred", wrong, permissionNow); !errors.Is(err, personserver.ErrPermissionNotFound) {
					t.Fatalf("wrong identity poll = %v", err)
				}
			})
		}
		pending, err := store.PollPermission(context.Background(), "deferred", permissionIdentity(), permissionNow)
		if err != nil {
			t.Fatal(err)
		}
		requirePermissionRecord(t, pending, "deferred", personserver.PermissionStatePending)
		mutatePermissionRecord(&pending)

		decidedAt := permissionNow.Add(time.Minute)
		decision := personserver.PermissionDecision{Permission: aauth.PermissionGranted}
		decided, err := store.DecidePermission(context.Background(), "deferred", decision, decidedAt)
		if err != nil {
			t.Fatal(err)
		}
		requirePermissionRecord(t, decided, "deferred", personserver.PermissionStateGranted)
		if decided.Decision != decision || !decided.DecidedAt.Equal(decidedAt) {
			t.Fatalf("canonical decision = %#v", decided)
		}
		replay, err := store.DecidePermission(context.Background(), "deferred", decision, permissionNow.Add(2*time.Minute))
		if err != nil {
			t.Fatalf("exact decision replay = %v", err)
		}
		if replay.Decision != decision || !replay.DecidedAt.Equal(decidedAt) {
			t.Fatalf("decision replay changed canonical record = %#v", replay)
		}
		if _, err := store.DecidePermission(
			context.Background(), "deferred",
			personserver.PermissionDecision{Permission: aauth.PermissionDenied, Reason: "changed"},
			permissionNow.Add(2*time.Minute),
		); !errors.Is(err, personserver.ErrPermissionConflict) {
			t.Fatalf("changed decision replay = %v", err)
		}
	})

	t.Run("expiry is atomic and remains consumable", func(t *testing.T) {
		store := contract.New(t)
		record := permissionRecord("expiry", personserver.PermissionStatePending)
		record.ExpiresAt = permissionNow.Add(time.Minute)
		if err := store.CreatePermission(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		if _, err := store.DecidePermission(
			context.Background(), "expiry",
			personserver.PermissionDecision{Permission: aauth.PermissionGranted},
			record.ExpiresAt,
		); !errors.Is(err, personserver.ErrPermissionExpired) {
			t.Fatalf("decision at deadline = %v", err)
		}
		expired, err := store.PollPermission(
			context.Background(), "expiry", permissionIdentity(), record.ExpiresAt,
		)
		if err != nil {
			t.Fatal(err)
		}
		requirePermissionRecord(t, expired, "expiry", personserver.PermissionStateExpired)
		if err := store.ConsumePermissionResult(context.Background(), "expiry", expired); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadPermission(context.Background(), "expiry", record.ExpiresAt); err != nil {
			t.Fatalf("load consumed record: %v", err)
		}
		if _, err := store.PollPermission(context.Background(), "expiry", permissionIdentity(), record.ExpiresAt); !errors.Is(err, personserver.ErrPermissionGone) {
			t.Fatalf("poll consumed expiry = %v", err)
		}
	})

	t.Run("concurrent different decisions have one winner", func(t *testing.T) {
		store := contract.New(t)
		record := permissionRecord("race", personserver.PermissionStatePending)
		record.ExpiresAt = permissionNow.Add(10 * time.Minute)
		if err := store.CreatePermission(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		decisions := []personserver.PermissionDecision{
			{Permission: aauth.PermissionGranted},
			{Permission: aauth.PermissionDenied, Reason: "person declined"},
		}
		errorsByIndex := make([]error, len(decisions))
		var wait sync.WaitGroup
		for index := range decisions {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				_, errorsByIndex[index] = store.DecidePermission(
					context.Background(), "race", decisions[index], permissionNow.Add(time.Minute),
				)
			}(index)
		}
		wait.Wait()
		successes := 0
		conflicts := 0
		for _, err := range errorsByIndex {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, personserver.ErrPermissionConflict):
				conflicts++
			default:
				t.Fatalf("concurrent decision = %v", err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("concurrent results: successes=%d conflicts=%d errors=%v", successes, conflicts, errorsByIndex)
		}
	})

	t.Run("concurrent exact consumers release one terminal result", func(t *testing.T) {
		store := contract.New(t)
		record := permissionRecord("consume-race", personserver.PermissionStateGranted)
		record.Decision = personserver.PermissionDecision{Permission: aauth.PermissionGranted}
		record.DecidedAt = permissionNow
		if err := store.CreatePermission(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		canonical, err := store.PollPermission(
			context.Background(), "consume-race", permissionIdentity(), permissionNow,
		)
		if err != nil {
			t.Fatal(err)
		}

		errorsByIndex := make([]error, 2)
		start := make(chan struct{})
		var wait sync.WaitGroup
		for index := range errorsByIndex {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				<-start
				errorsByIndex[index] = store.ConsumePermissionResult(
					context.Background(), "consume-race", canonical,
				)
			}(index)
		}
		close(start)
		wait.Wait()
		successes := 0
		gone := 0
		for _, err := range errorsByIndex {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, personserver.ErrPermissionGone):
				gone++
			default:
				t.Fatalf("concurrent consume = %v", err)
			}
		}
		if successes != 1 || gone != 1 {
			t.Fatalf("concurrent consume: successes=%d gone=%d errors=%v", successes, gone, errorsByIndex)
		}
		if _, err := store.PollPermission(
			context.Background(), "consume-race", permissionIdentity(), permissionNow,
		); !errors.Is(err, personserver.ErrPermissionGone) {
			t.Fatalf("poll after concurrent consume = %v", err)
		}
	})
}

var permissionNow = time.Date(2026, 8, 31, 23, 0, 0, 0, time.UTC)

func permissionRecord(id string, state personserver.PermissionState) personserver.PermissionRecord {
	return personserver.PermissionRecord{
		ID:                     id,
		PersonServer:           "https://person.example",
		AgentProvider:          "https://provider.example",
		Agent:                  "aauth:operator@provider.example",
		ConfirmationThumbprint: "agent-key-thumbprint",
		AgentExpiresAt:         permissionNow.Add(time.Hour),
		AgentAdditionalClaims: map[string]json.RawMessage{
			"platform_attestation": json.RawMessage(`{"level":"example"}`),
		},
		Action:      "files.write",
		Description: "Write the generated report.",
		Parameters:  json.RawMessage(`{"path":"report.md"}`),
		State:       state,
		CreatedAt:   permissionNow,
	}
}

func permissionIdentity() personserver.PermissionPollIdentity {
	return personserver.PermissionPollIdentity{
		PersonServer:           "https://person.example",
		AgentProvider:          "https://provider.example",
		Agent:                  "aauth:operator@provider.example",
		ConfirmationThumbprint: "agent-key-thumbprint",
	}
}

func requirePermissionRecord(t *testing.T, record personserver.PermissionRecord, id string, state personserver.PermissionState) {
	t.Helper()
	if record.ID != id || record.State != state || record.Action != "files.write" ||
		record.Description != "Write the generated report." ||
		string(record.Parameters) != `{"path":"report.md"}` ||
		string(record.AgentAdditionalClaims["platform_attestation"]) != `{"level":"example"}` {
		t.Fatalf("permission record = %#v", record)
	}
}

func mutatePermissionRecord(record *personserver.PermissionRecord) {
	if len(record.Parameters) > 0 {
		record.Parameters[0] = '['
	}
	if claim := record.AgentAdditionalClaims["platform_attestation"]; len(claim) > 0 {
		claim[0] = '['
	}
}
