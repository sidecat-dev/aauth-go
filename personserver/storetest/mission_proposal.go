package storetest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// MissionProposalContract constructs a fresh MissionProposalStore for each
// scenario.
type MissionProposalContract struct {
	New func(testing.TB) personserver.MissionProposalStore
}

// RunMissionProposal checks the public deferred mission-proposal store
// contract. Passing the suite complements, but does not replace, backend
// transaction, restart, and failure-injection tests.
func RunMissionProposal(t *testing.T, contract MissionProposalContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: MissionProposalContract.New is required")
	}

	t.Run("exact create load list and copy isolation", func(t *testing.T) {
		store := newMissionProposalStore(t, contract)
		record, _ := missionProposalRecord(t, "exact", missionProposalNow)
		want := record.Clone()
		if err := store.CreateMissionProposal(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		mutateMissionProposalRecord(&record)

		snapshot, err := store.LoadMissionProposal(context.Background(), want.ID, missionProposalNow)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.State != personserver.MissionProposalPending ||
			!missionProposalRecordsExact(snapshot.Record, want) ||
			!snapshot.DecidedAt.IsZero() || !snapshot.DeliveredAt.IsZero() {
			t.Fatalf("created mission proposal = %#v", snapshot)
		}
		canonical := snapshot.Clone()
		mutateMissionProposalRecord(&snapshot.Record)
		reloaded, err := store.LoadMissionProposal(context.Background(), want.ID, missionProposalNow)
		if err != nil {
			t.Fatal(err)
		}
		if reloaded.State != canonical.State || !missionProposalRecordsExact(reloaded.Record, canonical.Record) {
			t.Fatalf("mission proposal load aliases retained state = %#v", reloaded)
		}

		listed, err := store.ListPendingMissionProposals(context.Background(), missionProposalNow, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(listed) != 1 || !missionProposalRecordsExact(listed[0], want) {
			t.Fatalf("pending mission proposals = %#v", listed)
		}
		mutateMissionProposalRecord(&listed[0])
		again, err := store.ListPendingMissionProposals(context.Background(), missionProposalNow, 10)
		if err != nil || len(again) != 1 || !missionProposalRecordsExact(again[0], want) {
			t.Fatalf("mission proposal list aliases retained state = %#v, %v", again, err)
		}
		if err := store.CreateMissionProposal(context.Background(), want.Clone()); !errors.Is(err, personserver.ErrMissionProposalConflict) {
			t.Fatalf("duplicate mission proposal create = %v", err)
		}
		if _, err := store.LoadMissionProposal(context.Background(), "absent-proposal", missionProposalNow); !errors.Is(err, personserver.ErrMissionProposalNotFound) {
			t.Fatalf("absent mission proposal load = %v", err)
		}
	})

	t.Run("stable pending order and limit", func(t *testing.T) {
		store := newMissionProposalStore(t, contract)
		first, _ := missionProposalRecord(t, "z-first", missionProposalNow)
		second, _ := missionProposalRecord(t, "m-second", missionProposalNow.Add(time.Second))
		third, _ := missionProposalRecord(t, "a-third", missionProposalNow.Add(2*time.Second))
		for _, record := range []personserver.MissionProposalRecord{third, first, second} {
			if err := store.CreateMissionProposal(context.Background(), record.Clone()); err != nil {
				t.Fatal(err)
			}
		}
		at := missionProposalNow.Add(3 * time.Second)
		for attempt := 0; attempt < 2; attempt++ {
			listed, err := store.ListPendingMissionProposals(context.Background(), at, 2)
			if err != nil {
				t.Fatal(err)
			}
			if len(listed) != 2 || listed[0].ID != first.ID || listed[1].ID != second.ID {
				t.Fatalf("bounded pending order = %#v", listed)
			}
		}
		listed, err := store.ListPendingMissionProposals(context.Background(), at, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(listed) != 3 || listed[0].ID != first.ID || listed[1].ID != second.ID || listed[2].ID != third.ID {
			t.Fatalf("complete pending order = %#v", listed)
		}
	})

	t.Run("wrong person server agent provider agent or key is cloaked", func(t *testing.T) {
		store := newMissionProposalStore(t, contract)
		record, identity := missionProposalRecord(t, "cloaking", missionProposalNow)
		if err := store.CreateMissionProposal(context.Background(), record.Clone()); err != nil {
			t.Fatal(err)
		}
		_, otherKey := missionProposalRecord(t, "other-key", missionProposalNow)
		for _, test := range []struct {
			name   string
			mutate func(*personserver.MissionProposalPollIdentity)
		}{
			{name: "person server", mutate: func(value *personserver.MissionProposalPollIdentity) {
				value.PersonServer = "https://other-person.example"
			}},
			{name: "agent provider", mutate: func(value *personserver.MissionProposalPollIdentity) {
				value.AgentProvider = "https://other-agents.example"
			}},
			{name: "agent", mutate: func(value *personserver.MissionProposalPollIdentity) {
				value.Agent = "aauth:other@agents.example"
			}},
			{name: "proof key", mutate: func(value *personserver.MissionProposalPollIdentity) {
				value.ConfirmationThumbprint = otherKey.ConfirmationThumbprint
			}},
		} {
			t.Run(test.name, func(t *testing.T) {
				wrong := identity
				test.mutate(&wrong)
				if _, err := store.PollMissionProposal(context.Background(), record.ID, wrong, missionProposalNow); !errors.Is(err, personserver.ErrMissionProposalNotFound) {
					t.Fatalf("wrong-identity mission proposal poll = %v", err)
				}
				snapshot, err := store.LoadMissionProposal(context.Background(), record.ID, missionProposalNow)
				if err != nil || snapshot.State != personserver.MissionProposalPending || !snapshot.DeliveredAt.IsZero() {
					t.Fatalf("wrong identity changed mission proposal = %#v, %v", snapshot, err)
				}
			})
		}
	})

	t.Run("pending expiry is materialized", func(t *testing.T) {
		store := newMissionProposalStore(t, contract)
		record, identity := missionProposalRecord(t, "pending-expiry", missionProposalNow)
		if err := store.CreateMissionProposal(context.Background(), record.Clone()); err != nil {
			t.Fatal(err)
		}
		listed, err := store.ListPendingMissionProposals(context.Background(), record.ExpiresAt, 10)
		if err != nil || len(listed) != 0 {
			t.Fatalf("expired proposal remains pending = %#v, %v", listed, err)
		}
		snapshot, err := store.LoadMissionProposal(context.Background(), record.ID, record.ExpiresAt)
		if err != nil || snapshot.State != personserver.MissionProposalExpired ||
			!snapshot.DecidedAt.Equal(record.ExpiresAt) || !snapshot.DeliveredAt.IsZero() ||
			snapshot.Approval.Mission.S256 != "" {
			t.Fatalf("materialized pending expiry = %#v, %v", snapshot, err)
		}
		terminal, err := store.PollMissionProposal(
			context.Background(), record.ID, identity, record.ExpiresAt,
		)
		if err != nil || terminal.State != personserver.MissionProposalExpired ||
			!terminal.DeliveredAt.Equal(record.ExpiresAt) {
			t.Fatalf("expired terminal poll = %#v, %v", terminal, err)
		}
		if _, err := store.PollMissionProposal(context.Background(), record.ID, identity, record.ExpiresAt); !errors.Is(err, personserver.ErrMissionProposalGone) {
			t.Fatalf("poll after expired delivery = %v", err)
		}
	})

	t.Run("approval commits mission and person token atomically", func(t *testing.T) {
		store := newMissionProposalStore(t, contract)
		record, _ := missionProposalRecord(t, "approval", missionProposalNow)
		if err := store.CreateMissionProposal(context.Background(), record.Clone()); err != nil {
			t.Fatal(err)
		}
		decidedAt := missionProposalNow.Add(time.Minute)
		approval := missionProposalApproval(
			t, record, "approval", "Read approved records.", decidedAt,
			missionProposalNow.Add(20*time.Minute), missionProposalNow.Add(15*time.Minute),
		)
		want := approval.Clone()
		canonical, err := store.ApproveMissionProposal(
			context.Background(), record.Clone(), approval, decidedAt,
		)
		if err != nil || !missionProposalApprovalsExact(canonical, want) {
			t.Fatalf("canonical mission proposal approval = %#v, %v", canonical, err)
		}
		mutateMissionProposalApproval(&approval)
		mutateMissionProposalApproval(&canonical)

		snapshot, err := store.LoadMissionProposal(context.Background(), record.ID, decidedAt)
		if err != nil || snapshot.State != personserver.MissionProposalApproved ||
			!snapshot.DecidedAt.Equal(decidedAt) || !snapshot.DeliveredAt.IsZero() ||
			!missionProposalApprovalsExact(snapshot.Approval, want) {
			t.Fatalf("retained mission proposal approval = %#v, %v", snapshot, err)
		}
		retained := snapshot.Clone()
		mutateMissionProposalRecord(&snapshot.Record)
		mutateMissionProposalApproval(&snapshot.Approval)
		reloaded, err := store.LoadMissionProposal(context.Background(), record.ID, decidedAt)
		if err != nil || !missionProposalRecordsExact(reloaded.Record, retained.Record) ||
			!missionProposalApprovalsExact(reloaded.Approval, retained.Approval) {
			t.Fatalf("approved snapshot aliases retained state = %#v, %v", reloaded, err)
		}

		mission, err := store.LoadMissionForAgent(
			context.Background(), want.Mission.Agent, want.Mission.S256, decidedAt,
		)
		if err != nil || !mission.Equal(want.Mission) {
			t.Fatalf("approved mission store consequence = %#v, %v", mission, err)
		}
		token := want.PersonTokenRecords[0]
		retainedToken, err := store.Load(context.Background(), token.PersonServer, token.JTI)
		if err != nil || retainedToken != token {
			t.Fatalf("approved person-token store consequence = %#v, %v", retainedToken, err)
		}
	})

	t.Run("exact decision replay is canonical and changed decision conflicts", func(t *testing.T) {
		store := newMissionProposalStore(t, contract)
		record, _ := missionProposalRecord(t, "replay", missionProposalNow)
		if err := store.CreateMissionProposal(context.Background(), record.Clone()); err != nil {
			t.Fatal(err)
		}
		decidedAt := missionProposalNow.Add(time.Minute)
		approval := missionProposalApproval(
			t, record, "replay", "Read approved records.", decidedAt,
			missionProposalNow.Add(20*time.Minute), missionProposalNow.Add(15*time.Minute),
		)
		canonical, err := store.ApproveMissionProposal(
			context.Background(), record.Clone(), approval.Clone(), decidedAt,
		)
		if err != nil {
			t.Fatal(err)
		}
		replayed, err := store.ApproveMissionProposal(
			context.Background(), record.Clone(), approval.Clone(), decidedAt.Add(time.Minute),
		)
		if err != nil || !missionProposalApprovalsExact(replayed, canonical) || !replayed.Equivalent(approval) {
			t.Fatalf("exact mission proposal decision replay = %#v, %v", replayed, err)
		}
		changed := missionProposalApproval(
			t, record, "changed", "Publish approved records.", decidedAt,
			missionProposalNow.Add(20*time.Minute), missionProposalNow.Add(15*time.Minute),
		)
		if changed.Equivalent(approval) {
			t.Fatal("changed fixture is equivalent to the canonical decision")
		}
		if _, err := store.ApproveMissionProposal(
			context.Background(), record.Clone(), changed.Clone(), decidedAt.Add(time.Minute),
		); !errors.Is(err, personserver.ErrMissionProposalConflict) {
			t.Fatalf("changed mission proposal decision = %v", err)
		}
		snapshot, err := store.LoadMissionProposal(context.Background(), record.ID, decidedAt.Add(time.Minute))
		if err != nil || !missionProposalApprovalsExact(snapshot.Approval, canonical) ||
			!snapshot.DecidedAt.Equal(decidedAt) {
			t.Fatalf("changed decision replaced canonical approval = %#v, %v", snapshot, err)
		}
	})

	t.Run("denial releases no mission or person token", func(t *testing.T) {
		store := newMissionProposalStore(t, contract)
		record, _ := missionProposalRecord(t, "denial", missionProposalNow)
		if err := store.CreateMissionProposal(context.Background(), record.Clone()); err != nil {
			t.Fatal(err)
		}
		decidedAt := missionProposalNow.Add(time.Minute)
		unreleased := missionProposalApproval(
			t, record, "denial", "Do not approve this mission.", decidedAt,
			missionProposalNow.Add(20*time.Minute), missionProposalNow.Add(15*time.Minute),
		)
		if err := store.DenyMissionProposal(context.Background(), record.Clone(), decidedAt); err != nil {
			t.Fatal(err)
		}
		if err := store.DenyMissionProposal(context.Background(), record.Clone(), decidedAt.Add(time.Minute)); err != nil {
			t.Fatalf("exact mission proposal denial replay = %v", err)
		}
		if _, err := store.ApproveMissionProposal(
			context.Background(), record.Clone(), unreleased.Clone(), decidedAt.Add(time.Minute),
		); !errors.Is(err, personserver.ErrMissionProposalConflict) {
			t.Fatalf("approval after mission proposal denial = %v", err)
		}
		snapshot, err := store.LoadMissionProposal(context.Background(), record.ID, decidedAt.Add(time.Minute))
		if err != nil || snapshot.State != personserver.MissionProposalDenied ||
			!snapshot.DecidedAt.Equal(decidedAt) || snapshot.Approval.Mission.S256 != "" {
			t.Fatalf("retained mission proposal denial = %#v, %v", snapshot, err)
		}
		if _, err := store.LoadMissionForAgent(
			context.Background(), unreleased.Mission.Agent, unreleased.Mission.S256, decidedAt,
		); !errors.Is(err, personserver.ErrMissionNotFound) {
			t.Fatalf("denied proposal released mission = %v", err)
		}
		token := unreleased.PersonTokenRecords[0]
		if _, err := store.Load(context.Background(), token.PersonServer, token.JTI); !errors.Is(err, personserver.ErrPersonTokenNotFound) {
			t.Fatalf("denied proposal released person token = %v", err)
		}
	})

	t.Run("approved credential expiry wins before delivery", func(t *testing.T) {
		store := newMissionProposalStore(t, contract)
		record, identity := missionProposalRecord(t, "approved-expiry", missionProposalNow)
		if err := store.CreateMissionProposal(context.Background(), record.Clone()); err != nil {
			t.Fatal(err)
		}
		decidedAt := missionProposalNow.Add(time.Minute)
		tokenExpiresAt := missionProposalNow.Add(3 * time.Minute)
		approval := missionProposalApproval(
			t, record, "approved-expiry", "Read approved records.", decidedAt,
			missionProposalNow.Add(20*time.Minute), tokenExpiresAt,
		)
		if approval.Expired(tokenExpiresAt.Add(-time.Nanosecond)) || !approval.Expired(tokenExpiresAt) {
			t.Fatal("approved credential expiry fixture does not cross its delivery deadline")
		}
		if _, err := store.ApproveMissionProposal(
			context.Background(), record.Clone(), approval.Clone(), decidedAt,
		); err != nil {
			t.Fatal(err)
		}
		terminal, err := store.PollMissionProposal(
			context.Background(), record.ID, identity, tokenExpiresAt,
		)
		if err != nil || terminal.State != personserver.MissionProposalExpired ||
			terminal.Approval.Mission.S256 != "" || !terminal.DecidedAt.Equal(decidedAt) ||
			!terminal.DeliveredAt.Equal(tokenExpiresAt) {
			t.Fatalf("approved credential expiry poll = %#v, %v", terminal, err)
		}
		if _, err := store.PollMissionProposal(context.Background(), record.ID, identity, tokenExpiresAt); !errors.Is(err, personserver.ErrMissionProposalGone) {
			t.Fatalf("poll after expired approval delivery = %v", err)
		}
	})

	t.Run("one terminal poll wins and later polls are gone", func(t *testing.T) {
		store := newMissionProposalStore(t, contract)
		record, identity := missionProposalRecord(t, "poll-winner", missionProposalNow)
		if err := store.CreateMissionProposal(context.Background(), record.Clone()); err != nil {
			t.Fatal(err)
		}
		decidedAt := missionProposalNow.Add(time.Minute)
		approval := missionProposalApproval(
			t, record, "poll-winner", "Read approved records.", decidedAt,
			missionProposalNow.Add(20*time.Minute), missionProposalNow.Add(15*time.Minute),
		)
		canonical, err := store.ApproveMissionProposal(
			context.Background(), record.Clone(), approval.Clone(), decidedAt,
		)
		if err != nil {
			t.Fatal(err)
		}

		type pollResult struct {
			snapshot personserver.MissionProposalSnapshot
			err      error
		}
		results := make([]pollResult, 2)
		start := make(chan struct{})
		var wait sync.WaitGroup
		for index := range results {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				<-start
				results[index].snapshot, results[index].err = store.PollMissionProposal(
					context.Background(), record.ID, identity, decidedAt.Add(time.Minute),
				)
			}(index)
		}
		close(start)
		wait.Wait()
		winners, gone := 0, 0
		for _, result := range results {
			switch {
			case result.err == nil:
				winners++
				if result.snapshot.State != personserver.MissionProposalApproved ||
					!result.snapshot.DeliveredAt.Equal(decidedAt.Add(time.Minute)) ||
					!missionProposalApprovalsExact(result.snapshot.Approval, canonical) {
					t.Fatalf("terminal mission proposal winner = %#v", result.snapshot)
				}
			case errors.Is(result.err, personserver.ErrMissionProposalGone):
				gone++
			default:
				t.Fatalf("concurrent mission proposal poll = %v", result.err)
			}
		}
		if winners != 1 || gone != 1 {
			t.Fatalf("terminal mission proposal polls: winners=%d gone=%d results=%#v", winners, gone, results)
		}
		if _, err := store.PollMissionProposal(
			context.Background(), record.ID, identity, decidedAt.Add(2*time.Minute),
		); !errors.Is(err, personserver.ErrMissionProposalGone) {
			t.Fatalf("later terminal mission proposal poll = %v", err)
		}
	})

	t.Run("concurrent different decisions have one winner", func(t *testing.T) {
		store := newMissionProposalStore(t, contract)
		record, _ := missionProposalRecord(t, "decision-race", missionProposalNow)
		if err := store.CreateMissionProposal(context.Background(), record.Clone()); err != nil {
			t.Fatal(err)
		}
		decidedAt := missionProposalNow.Add(time.Minute)
		approvals := []personserver.MissionProposalApproval{
			missionProposalApproval(
				t, record, "decision-a", "Read approved records A.", decidedAt,
				missionProposalNow.Add(20*time.Minute), missionProposalNow.Add(15*time.Minute),
			),
			missionProposalApproval(
				t, record, "decision-b", "Read approved records B.", decidedAt,
				missionProposalNow.Add(20*time.Minute), missionProposalNow.Add(15*time.Minute),
			),
		}
		results := make([]struct {
			approval personserver.MissionProposalApproval
			err      error
		}, len(approvals))
		start := make(chan struct{})
		var wait sync.WaitGroup
		for index := range approvals {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				<-start
				results[index].approval, results[index].err = store.ApproveMissionProposal(
					context.Background(), record.Clone(), approvals[index].Clone(), decidedAt,
				)
			}(index)
		}
		close(start)
		wait.Wait()
		winners, conflicts := 0, 0
		winner := -1
		for index, result := range results {
			switch {
			case result.err == nil:
				winners++
				winner = index
				if !missionProposalApprovalsExact(result.approval, approvals[index]) {
					t.Fatalf("concurrent canonical decision = %#v", result.approval)
				}
			case errors.Is(result.err, personserver.ErrMissionProposalConflict):
				conflicts++
			default:
				t.Fatalf("concurrent mission proposal decision = %v", result.err)
			}
		}
		if winners != 1 || conflicts != 1 {
			t.Fatalf("concurrent mission proposal decisions: winners=%d conflicts=%d results=%#v", winners, conflicts, results)
		}
		snapshot, err := store.LoadMissionProposal(context.Background(), record.ID, decidedAt)
		if err != nil || snapshot.State != personserver.MissionProposalApproved || winner < 0 ||
			!snapshot.Approval.Equivalent(approvals[winner]) ||
			snapshot.Approval.Equivalent(approvals[1-winner]) {
			t.Fatalf("retained concurrent mission proposal decision = %#v, %v", snapshot, err)
		}
		loserToken := approvals[1-winner].PersonTokenRecords[0]
		if _, err := store.Load(context.Background(), loserToken.PersonServer, loserToken.JTI); !errors.Is(err, personserver.ErrPersonTokenNotFound) {
			t.Fatalf("losing mission proposal decision released person token = %v", err)
		}
	})
}

var missionProposalNow = time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC)

const missionProposalResource = "https://resource.example"

func newMissionProposalStore(t *testing.T, contract MissionProposalContract) personserver.MissionProposalStore {
	t.Helper()
	store := contract.New(t)
	if store == nil {
		t.Fatal("storetest: MissionProposalContract.New returned nil")
	}
	return store
}

func missionProposalRecord(
	t *testing.T,
	name string,
	createdAt time.Time,
) (personserver.MissionProposalRecord, personserver.MissionProposalPollIdentity) {
	t.Helper()
	seed := sha256.Sum256([]byte("storetest mission proposal key " + name))
	key, err := jose.NewEd25519SigningKey("storetest-"+name, ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	confirmation := key.PublicJWK()
	thumbprint, err := confirmation.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	record := personserver.MissionProposalRecord{
		ID:             "storetest-mission-proposal-" + name,
		PersonServer:   "https://person.example",
		AgentProvider:  "https://agents.example",
		Agent:          "aauth:storetest@agents.example",
		Confirmation:   confirmation,
		AgentExpiresAt: createdAt.Add(time.Hour),
		AgentAdditionalClaims: map[string]json.RawMessage{
			"platform_attestation": json.RawMessage(`{"level":"example"}`),
		},
		ExactJSON:  []byte(`{"description":"Read approved records","resources":["https://resource.example"]}`),
		CreatedAt:  createdAt,
		ExpiresAt:  createdAt.Add(30 * time.Minute),
		RetryAfter: 3 * time.Second,
	}
	return record, personserver.MissionProposalPollIdentity{
		PersonServer: record.PersonServer, AgentProvider: record.AgentProvider,
		Agent: record.Agent, ConfirmationThumbprint: thumbprint,
	}
}

func missionProposalApproval(
	t *testing.T,
	record personserver.MissionProposalRecord,
	suffix, description string,
	approvedAt, missionExpiresAt, tokenExpiresAt time.Time,
) personserver.MissionProposalApproval {
	t.Helper()
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: record.PersonServer, Agent: record.Agent, ApprovedAt: approvedAt,
		ExpiresAt: &missionExpiresAt, Description: description,
		ApprovedResources: []string{missionProposalResource},
	})
	if err != nil {
		t.Fatal(err)
	}
	missionRecord := personserver.MissionRecord{
		S256: mission.S256, Agent: record.Agent, ExactJSON: append([]byte(nil), mission.ExactJSON...),
		ApprovedAt: approvedAt, ExpiresAt: missionExpiresAt,
		Capabilities: []string{"interaction"}, State: personserver.MissionActive,
	}
	tokenRecord := personserver.PersonTokenRecord{
		JTI: "storetest-person-token-" + suffix, PersonServer: record.PersonServer,
		Resource: missionProposalResource, Subject: "person-123", MissionS256: mission.S256,
		Tenant: "tenant-1", AgentProvider: record.AgentProvider, Agent: record.Agent,
		Confirmation: record.Confirmation, ExpiresAt: tokenExpiresAt,
		RetainUntil: tokenExpiresAt.Add(time.Hour),
	}
	return personserver.MissionProposalApproval{
		Mission: missionRecord,
		PersonTokens: map[string]string{
			missionProposalResource: "storetest-person-token-credential-" + suffix,
		},
		PersonTokenRecords: []personserver.PersonTokenRecord{tokenRecord},
	}
}

func missionProposalRecordsExact(left, right personserver.MissionProposalRecord) bool {
	return left.Equal(right) && left.Confirmation == right.Confirmation
}

func missionProposalApprovalsExact(left, right personserver.MissionProposalApproval) bool {
	return left.Mission.Equal(right.Mission) && maps.Equal(left.PersonTokens, right.PersonTokens) &&
		slices.Equal(left.PersonTokenRecords, right.PersonTokenRecords)
}

func mutateMissionProposalRecord(record *personserver.MissionProposalRecord) {
	if len(record.ExactJSON) > 0 {
		record.ExactJSON[0] = '['
	}
	if claim := record.AgentAdditionalClaims["platform_attestation"]; len(claim) > 0 {
		claim[0] = '['
	}
	record.AgentAdditionalClaims["added"] = json.RawMessage(`true`)
	record.Confirmation.Kid = "mutated"
}

func mutateMissionProposalApproval(approval *personserver.MissionProposalApproval) {
	if len(approval.Mission.ExactJSON) > 0 {
		approval.Mission.ExactJSON[0] = '['
	}
	if len(approval.Mission.Capabilities) > 0 {
		approval.Mission.Capabilities[0] = "mutated"
	}
	if approval.PersonTokens != nil {
		approval.PersonTokens[missionProposalResource] = "mutated"
	}
	if len(approval.PersonTokenRecords) > 0 {
		approval.PersonTokenRecords[0].JTI = "mutated"
	}
}
