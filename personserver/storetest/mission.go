package storetest

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// MissionContract constructs a fresh empty mission store and exposes a
// test-only read of mission-bound Auth-token records. The observation function
// is deliberately not part of the production MissionStore interface.
type MissionContract struct {
	New func(testing.TB) MissionFixture
}

// MissionFixture connects one production store adapter to the reusable
// MissionStore contract.
type MissionFixture struct {
	Store         personserver.MissionStore
	LoadAuthToken func(aauth.TokenReference) (personserver.IssuedAuthTokenRecord, bool)
}

// RunMission checks mission creation, owner-scoped lookup, copy isolation,
// lifecycle transitions, exact-state comparisons, conflict-safe token
// retention, concurrent completion, host termination, and the list of tokens
// retained under a mission that termination revokes. Backend restart and
// injected-failure tests remain the application's responsibility.
func RunMission(t *testing.T, contract MissionContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: MissionContract.New is required")
	}

	t.Run("commit is atomic and owns its values", func(t *testing.T) {
		fixture := newMissionFixture(t, contract)
		mission := missionRecord(t, "mission-commit")
		wantMission := cloneMission(mission)
		first := missionPersonToken(mission, "https://person.example", "person-token-1")
		second := missionPersonToken(mission, "https://other-person.example", first.JTI)
		if err := fixture.Store.CommitMission(context.Background(), mission, []personserver.PersonTokenRecord{first, second}); err != nil {
			t.Fatal(err)
		}
		mission.ExactJSON[0] = '['
		mission.Capabilities[0] = "mutated"
		loaded, err := fixture.Store.LoadMissionForAgent(
			context.Background(), wantMission.Agent, wantMission.S256, wantMission.ApprovedAt,
		)
		if err != nil || !loaded.Equal(wantMission) {
			t.Fatalf("loaded mission = %#v, %v; want %#v", loaded, err, wantMission)
		}
		loaded.ExactJSON[0] = '['
		loaded.Capabilities[0] = "mutated"
		reloaded, err := fixture.Store.LoadMissionForAgent(
			context.Background(), wantMission.Agent, wantMission.S256, wantMission.ApprovedAt,
		)
		if err != nil || !reloaded.Equal(wantMission) {
			t.Fatalf("mission load aliases retained state = %#v, %v", reloaded, err)
		}
		for _, want := range []personserver.PersonTokenRecord{first, second} {
			got, err := fixture.Store.Load(context.Background(), want.PersonServer, want.JTI)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("mission Person token = %#v, %v; want %#v", got, err, want)
			}
		}
	})

	t.Run("duplicate token batch leaves no partial state", func(t *testing.T) {
		fixture := newMissionFixture(t, contract)
		mission := missionRecord(t, "mission-duplicate-batch")
		token := missionPersonToken(mission, "https://person.example", "duplicate-token")
		changed := token
		changed.Resource = "https://other-resource.example"
		if err := fixture.Store.CommitMission(
			context.Background(), mission, []personserver.PersonTokenRecord{token, changed},
		); !errors.Is(err, personserver.ErrMissionConflict) {
			t.Fatalf("duplicate token batch = %v", err)
		}
		assertMissionAbsent(t, fixture.Store, mission)
		if _, err := fixture.Store.Load(context.Background(), token.PersonServer, token.JTI); !errors.Is(err, personserver.ErrPersonTokenNotFound) {
			t.Fatalf("failed mission retained Person token = %v", err)
		}
	})

	t.Run("existing token conflict leaves mission absent", func(t *testing.T) {
		fixture := newMissionFixture(t, contract)
		mission := missionRecord(t, "mission-existing-token")
		token := missionPersonToken(mission, "https://person.example", "existing-token")
		if err := fixture.Store.Commit(context.Background(), token); err != nil {
			t.Fatal(err)
		}
		if err := fixture.Store.CommitMission(
			context.Background(), mission, []personserver.PersonTokenRecord{token},
		); !errors.Is(err, personserver.ErrMissionConflict) {
			t.Fatalf("existing Person-token binding = %v", err)
		}
		assertMissionAbsent(t, fixture.Store, mission)
		retained, err := fixture.Store.Load(context.Background(), token.PersonServer, token.JTI)
		if err != nil || !reflect.DeepEqual(retained, token) {
			t.Fatalf("existing Person token changed after conflict = %#v, %v", retained, err)
		}
	})

	t.Run("existing mission conflict preserves first record", func(t *testing.T) {
		fixture, mission := committedMissionFixture(t, contract, "mission-existing")
		changed := cloneMission(mission)
		changed.Capabilities[0] = "different"
		if err := fixture.Store.CommitMission(context.Background(), changed, nil); !errors.Is(err, personserver.ErrMissionConflict) {
			t.Fatalf("existing mission = %v", err)
		}
		retained, err := fixture.Store.LoadMissionForAgent(
			context.Background(), mission.Agent, mission.S256, mission.ApprovedAt,
		)
		if err != nil || !retained.Equal(mission) {
			t.Fatalf("existing mission changed after conflict = %#v, %v", retained, err)
		}
	})

	t.Run("owner lookup is cloaked and expiry is permanent", func(t *testing.T) {
		fixture, mission := committedMissionFixture(t, contract, "mission-expiry")
		if _, err := fixture.Store.LoadMissionForAgent(
			context.Background(), "aauth:other@provider.example", mission.S256, mission.ApprovedAt,
		); !errors.Is(err, personserver.ErrMissionNotFound) {
			t.Fatalf("wrong-owner mission lookup = %v", err)
		}
		expired, err := fixture.Store.LoadMissionForAgent(
			context.Background(), mission.Agent, mission.S256, mission.ExpiresAt,
		)
		if err != nil || expired.State != personserver.MissionTerminated || expired.TerminationReason != "expired" {
			t.Fatalf("mission at expiry = %#v, %v", expired, err)
		}
		later, err := fixture.Store.LoadMissionForAgent(
			context.Background(), mission.Agent, mission.S256, mission.ApprovedAt,
		)
		if err != nil || !later.Equal(expired) {
			t.Fatalf("expired mission returned to active = %#v, %v", later, err)
		}
	})

	t.Run("updates are ordered and compare complete state", func(t *testing.T) {
		fixture, original := committedMissionFixture(t, contract, "mission-updates")
		first := missionUpdate(t, "first update")
		firstAt := original.ApprovedAt.Add(time.Minute)
		current, err := fixture.Store.AppendMissionUpdate(context.Background(), cloneMission(original), firstAt, first)
		if err != nil || len(current.AcceptedUpdates) != 1 || !current.AcceptedUpdates[0].AcceptedAt.Equal(firstAt) ||
			!reflect.DeepEqual(current.AcceptedUpdates[0].Document, first) {
			t.Fatalf("first mission update = %#v, %v", current, err)
		}
		wantCurrent := cloneMission(current)
		first.ExactJSON[0] = '['
		current.ExactJSON[0] = '['
		current.Capabilities[0] = "mutated"
		current.AcceptedUpdates[0].Document.ExactJSON[0] = '['
		current, err = fixture.Store.LoadMissionForAgent(
			context.Background(), original.Agent, original.S256, firstAt,
		)
		if err != nil || !current.Equal(wantCurrent) {
			t.Fatalf("mission update result aliases retained state = %#v, %v", current, err)
		}
		second := missionUpdate(t, "second update")
		secondAt := firstAt.Add(time.Minute)
		updated, err := fixture.Store.AppendMissionUpdate(context.Background(), cloneMission(current), secondAt, second)
		if err != nil || len(updated.AcceptedUpdates) != 2 ||
			updated.AcceptedUpdates[0].Document.Update.Description != "first update" ||
			updated.AcceptedUpdates[1].Document.Update.Description != "second update" {
			t.Fatalf("ordered mission updates = %#v, %v", updated, err)
		}
		if _, err := fixture.Store.AppendMissionUpdate(
			context.Background(), original, secondAt.Add(time.Minute), missionUpdate(t, "stale update"),
		); !errors.Is(err, personserver.ErrMissionConflict) {
			t.Fatalf("stale mission update = %v", err)
		}
		if _, err := fixture.Store.AppendMissionUpdate(
			context.Background(), updated, time.Time{}, missionUpdate(t, "missing time"),
		); err == nil {
			t.Fatal("mission update without acceptance time succeeded")
		}
		reloaded, err := fixture.Store.LoadMissionForAgent(
			context.Background(), original.Agent, original.S256, secondAt,
		)
		if err != nil || !reloaded.Equal(updated) {
			t.Fatalf("mission after refused updates = %#v, %v", reloaded, err)
		}
	})

	t.Run("every expected mission field participates in comparison", func(t *testing.T) {
		operations := missionComparisonOperations()
		for _, change := range missionComparisonChanges(t) {
			for _, operation := range operations {
				t.Run(change.name+"/"+operation.name, func(t *testing.T) {
					fixture, mission := committedMissionFixture(t, contract, "mission-compare-"+change.name+"-"+operation.name)
					changed := cloneMission(mission)
					change.apply(&changed)
					err := operation.apply(t, fixture, changed, mission.ApprovedAt.Add(time.Minute))
					if !errors.Is(err, change.wantErr) {
						t.Fatalf("changed %s during %s = %v; want %v", change.name, operation.name, err, change.wantErr)
					}
					retained, loadErr := fixture.Store.LoadMissionForAgent(
						context.Background(), mission.Agent, mission.S256, mission.ApprovedAt,
					)
					if loadErr != nil || !retained.Equal(mission) {
						t.Fatalf("changed %s during %s mutated mission = %#v, %v", change.name, operation.name, retained, loadErr)
					}
				})
			}
		}
	})

	t.Run("completion is exact and terminal", func(t *testing.T) {
		fixture, mission := committedMissionFixture(t, contract, "mission-complete")
		document := missionCompletion(t, "The work is complete.")
		wantDocument := document
		wantDocument.ExactJSON = append([]byte(nil), document.ExactJSON...)
		acceptedAt := mission.ApprovedAt.Add(time.Minute)
		if _, err := fixture.Store.CompleteMission(
			context.Background(), cloneMission(mission), time.Time{}, document,
		); err == nil {
			t.Fatal("mission completion without acceptance time succeeded")
		}
		completed, err := fixture.Store.CompleteMission(
			context.Background(), cloneMission(mission), acceptedAt, document,
		)
		if err != nil || completed.State != personserver.MissionTerminated ||
			completed.TerminationReason != "completed" || completed.Completion == nil ||
			!completed.Completion.AcceptedAt.Equal(acceptedAt) ||
			!reflect.DeepEqual(completed.Completion.Document, document) {
			t.Fatalf("completed mission = %#v, %v", completed, err)
		}
		wantCompleted := cloneMission(completed)
		document.ExactJSON[0] = '['
		completed.ExactJSON[0] = '['
		completed.Capabilities[0] = "mutated"
		completed.Completion.Document.ExactJSON[0] = '['
		reloaded, err := fixture.Store.LoadMissionForAgent(
			context.Background(), mission.Agent, mission.S256, acceptedAt,
		)
		if err != nil || !reloaded.Equal(wantCompleted) || reloaded.Completion == nil ||
			!reflect.DeepEqual(reloaded.Completion.Document, wantDocument) {
			t.Fatalf("completion aliases caller input = %#v, %v", reloaded, err)
		}
		_, err = fixture.Store.AppendMissionUpdate(
			context.Background(), reloaded, acceptedAt.Add(time.Minute), missionUpdate(t, "too late"),
		)
		assertMissionTerminated(t, err, "completed")
	})

	t.Run("mission-bound token commits are all or nothing", func(t *testing.T) {
		fixture, mission := committedMissionFixture(t, contract, "mission-tokens")
		personToken := missionPersonToken(mission, "https://person.example", "mission-person-token")
		if err := fixture.Store.CommitMissionPersonToken(
			context.Background(), cloneMission(mission), mission.ApprovedAt.Add(time.Minute), personToken,
		); err != nil {
			t.Fatal(err)
		}
		loadedPerson, err := fixture.Store.Load(context.Background(), personToken.PersonServer, personToken.JTI)
		if err != nil || !reflect.DeepEqual(loadedPerson, personToken) {
			t.Fatalf("mission Person token = %#v, %v", loadedPerson, err)
		}

		authToken := missionAuthToken(mission, "mission-auth-token", 1)
		if err := fixture.Store.CommitMissionAuthToken(
			context.Background(), cloneMission(mission), mission.ApprovedAt.Add(time.Minute), authToken,
		); err != nil {
			t.Fatal(err)
		}
		if loadedAuth, ok := fixture.LoadAuthToken(authToken.Reference); !ok || !reflect.DeepEqual(loadedAuth, authToken) {
			t.Fatalf("mission Auth token = %#v, %t", loadedAuth, ok)
		}

		wrongMission := authToken
		wrongMission.Reference.JTI = "wrong-mission-auth-token"
		wrongMission.MissionS256 = "different-mission"
		if err := fixture.Store.CommitMissionAuthToken(
			context.Background(), cloneMission(mission), mission.ApprovedAt.Add(time.Minute), wrongMission,
		); !errors.Is(err, personserver.ErrMissionConflict) {
			t.Fatalf("wrong-mission Auth token = %v", err)
		}
		if _, ok := fixture.LoadAuthToken(wrongMission.Reference); ok {
			t.Fatal("wrong-mission Auth token was retained")
		}

		_, err = fixture.Store.AppendMissionUpdate(
			context.Background(), cloneMission(mission), mission.ApprovedAt.Add(2*time.Minute), missionUpdate(t, "state advanced"),
		)
		if err != nil {
			t.Fatal(err)
		}
		stalePerson := missionPersonToken(mission, "https://person.example", "stale-person-token")
		if err := fixture.Store.CommitMissionPersonToken(
			context.Background(), mission, mission.ApprovedAt.Add(3*time.Minute), stalePerson,
		); !errors.Is(err, personserver.ErrMissionConflict) {
			t.Fatalf("stale mission Person token = %v", err)
		}
		if _, err := fixture.Store.Load(context.Background(), stalePerson.PersonServer, stalePerson.JTI); !errors.Is(err, personserver.ErrPersonTokenNotFound) {
			t.Fatalf("stale mission retained Person token = %v", err)
		}
		staleAuth := missionAuthToken(mission, "stale-auth-token", 2)
		if err := fixture.Store.CommitMissionAuthToken(
			context.Background(), mission, mission.ApprovedAt.Add(3*time.Minute), staleAuth,
		); !errors.Is(err, personserver.ErrMissionConflict) {
			t.Fatalf("stale mission Auth token = %v", err)
		}
		if _, ok := fixture.LoadAuthToken(staleAuth.Reference); ok {
			t.Fatal("stale mission retained Auth token")
		}
	})

	t.Run("termination is owner-scoped, keeps its first reason and ends issuance", func(t *testing.T) {
		fixture, mission := committedMissionFixture(t, contract, "mission-terminate")
		at := mission.ApprovedAt.Add(time.Minute)
		if _, err := fixture.Store.TerminateMission(
			context.Background(), "aauth:other@provider.example", mission.S256, at, "revoked",
		); !errors.Is(err, personserver.ErrMissionNotFound) {
			t.Fatalf("wrong-owner termination = %v", err)
		}
		if retained, err := fixture.Store.LoadMissionForAgent(context.Background(), mission.Agent, mission.S256, at); err != nil || !retained.Equal(mission) {
			t.Fatalf("wrong-owner termination changed the mission = %#v, %v", retained, err)
		}
		want := cloneMission(mission)
		want.State = personserver.MissionTerminated
		want.TerminationReason = "revoked"
		terminated, err := fixture.Store.TerminateMission(context.Background(), mission.Agent, mission.S256, at, "revoked")
		if err != nil || !terminated.Equal(want) {
			t.Fatalf("terminated mission = %#v, %v; want %#v", terminated, err, want)
		}
		terminated.ExactJSON[0] = '['
		terminated.Capabilities[0] = "mutated"
		again, err := fixture.Store.TerminateMission(context.Background(), mission.Agent, mission.S256, at.Add(time.Minute), "superseded")
		if err != nil || !again.Equal(want) {
			t.Fatalf("repeated termination = %#v, %v; want the first reason kept", again, err)
		}
		reloaded, err := fixture.Store.LoadMissionForAgent(context.Background(), mission.Agent, mission.S256, at)
		if err != nil || !reloaded.Equal(want) {
			t.Fatalf("terminated mission reloaded = %#v, %v", reloaded, err)
		}
		later := at.Add(2 * time.Minute)
		assertMissionTerminated(t, fixture.Store.CommitMissionPersonToken(
			context.Background(), cloneMission(mission), later, missionPersonToken(mission, "https://person.example", "after-termination"),
		), "revoked")
		assertMissionTerminated(t, fixture.Store.CommitMissionAuthToken(
			context.Background(), cloneMission(mission), later, missionAuthToken(mission, "after-termination", 3),
		), "revoked")
		_, err = fixture.Store.AppendMissionUpdate(context.Background(), cloneMission(mission), later, missionUpdate(t, "too late"))
		assertMissionTerminated(t, err, "revoked")
		_, err = fixture.Store.CompleteMission(context.Background(), cloneMission(mission), later, missionCompletion(t, "too late"))
		assertMissionTerminated(t, err, "revoked")
	})

	t.Run("termination materializes expiry and keeps a completion", func(t *testing.T) {
		fixture, expiring := committedMissionFixture(t, contract, "mission-terminate-expired")
		expired, err := fixture.Store.TerminateMission(
			context.Background(), expiring.Agent, expiring.S256, expiring.ExpiresAt, "revoked",
		)
		if err != nil || expired.State != personserver.MissionTerminated || expired.TerminationReason != "expired" {
			t.Fatalf("termination at expiry = %#v, %v; want expired", expired, err)
		}
		completedFixture, mission := committedMissionFixture(t, contract, "mission-terminate-completed")
		acceptedAt := mission.ApprovedAt.Add(time.Minute)
		completed, err := completedFixture.Store.CompleteMission(
			context.Background(), cloneMission(mission), acceptedAt, missionCompletion(t, "Done."),
		)
		if err != nil {
			t.Fatal(err)
		}
		terminated, err := completedFixture.Store.TerminateMission(
			context.Background(), mission.Agent, mission.S256, acceptedAt.Add(time.Minute), "administrative",
		)
		if err != nil || !terminated.Equal(completed) {
			t.Fatalf("termination after completion = %#v, %v; want the completion kept", terminated, err)
		}
	})

	t.Run("mission tokens are every token retained under the mission", func(t *testing.T) {
		fixture := newMissionFixture(t, contract)
		mission := missionRecord(t, "mission-token-list")
		other := missionRecord(t, "mission-token-list-other")
		approved := missionPersonToken(mission, "https://person.example", "approved-person-token")
		if err := fixture.Store.CommitMission(context.Background(), mission, []personserver.PersonTokenRecord{approved}); err != nil {
			t.Fatal(err)
		}
		if err := fixture.Store.CommitMission(context.Background(), other, []personserver.PersonTokenRecord{
			missionPersonToken(other, "https://person.example", "other-mission-person-token"),
		}); err != nil {
			t.Fatal(err)
		}
		missionless := missionPersonToken(mission, "https://person.example", "missionless-person-token")
		missionless.MissionS256 = ""
		if err := fixture.Store.Commit(context.Background(), missionless); err != nil {
			t.Fatal(err)
		}
		at := mission.ApprovedAt.Add(time.Minute)
		issued := missionPersonToken(mission, "https://person.example", "issued-person-token")
		if err := fixture.Store.CommitMissionPersonToken(context.Background(), cloneMission(mission), at, issued); err != nil {
			t.Fatal(err)
		}
		authToken := missionAuthToken(mission, "mission-auth-token", 4)
		if err := fixture.Store.CommitMissionAuthToken(context.Background(), cloneMission(mission), at, authToken); err != nil {
			t.Fatal(err)
		}
		if err := fixture.Store.CommitMissionAuthToken(context.Background(), cloneMission(other), at, missionAuthToken(other, "other-mission-auth-token", 5)); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.Store.TerminateMission(context.Background(), mission.Agent, mission.S256, at.Add(time.Minute), "revoked"); err != nil {
			t.Fatal(err)
		}
		listed, err := fixture.Store.LoadMissionTokens(context.Background(), mission.S256)
		if err != nil {
			t.Fatal(err)
		}
		sort.Slice(listed.PersonTokens, func(left, right int) bool {
			return listed.PersonTokens[left].JTI < listed.PersonTokens[right].JTI
		})
		if !reflect.DeepEqual(listed.PersonTokens, []personserver.PersonTokenRecord{approved, issued}) ||
			!reflect.DeepEqual(listed.AuthTokens, []personserver.IssuedAuthTokenRecord{authToken}) {
			t.Fatalf("mission tokens = %#v; want the approval's and the issued person tokens and the auth token", listed)
		}
		none, err := fixture.Store.LoadMissionTokens(context.Background(), missionRecord(t, "mission-token-list-unknown").S256)
		if err != nil || len(none.PersonTokens) != 0 || len(none.AuthTokens) != 0 {
			t.Fatalf("tokens of a mission never committed = %#v, %v", none, err)
		}
	})

	t.Run("concurrent completions select one exact terminal state", func(t *testing.T) {
		fixture, mission := committedMissionFixture(t, contract, "mission-completion-race")
		documents := []aauth.MissionCompletionDocument{
			missionCompletion(t, "left completion"), missionCompletion(t, "right completion"),
		}
		errorsByCall := make([]error, len(documents))
		results := make([]personserver.MissionRecord, len(documents))
		start := make(chan struct{})
		var wait sync.WaitGroup
		for index := range documents {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				<-start
				results[index], errorsByCall[index] = fixture.Store.CompleteMission(
					context.Background(), cloneMission(mission), mission.ApprovedAt.Add(time.Minute), documents[index],
				)
			}(index)
		}
		close(start)
		wait.Wait()
		winner := -1
		for index, err := range errorsByCall {
			if err == nil {
				if winner != -1 {
					t.Fatal("both concurrent completions succeeded")
				}
				winner = index
				continue
			}
			assertMissionTerminated(t, err, "completed")
		}
		if winner == -1 {
			t.Fatalf("no concurrent completion succeeded: %v", errorsByCall)
		}
		retained, err := fixture.Store.LoadMissionForAgent(
			context.Background(), mission.Agent, mission.S256, mission.ApprovedAt.Add(time.Minute),
		)
		if err != nil || !retained.Equal(results[winner]) {
			t.Fatalf("concurrent completion retained = %#v, %v; want %#v", retained, err, results[winner])
		}
	})
}

type missionComparisonChange struct {
	name    string
	apply   func(*personserver.MissionRecord)
	wantErr error
}

func missionComparisonChanges(t *testing.T) []missionComparisonChange {
	t.Helper()
	return []missionComparisonChange{
		{name: "S256", apply: func(record *personserver.MissionRecord) { record.S256 = "different-digest" }, wantErr: personserver.ErrMissionNotFound},
		{name: "Agent", apply: func(record *personserver.MissionRecord) { record.Agent = "aauth:other@provider.example" }, wantErr: personserver.ErrMissionNotFound},
		{name: "ExactJSON", apply: func(record *personserver.MissionRecord) { record.ExactJSON[0] = '[' }, wantErr: personserver.ErrMissionConflict},
		{name: "ApprovedAt", apply: func(record *personserver.MissionRecord) { record.ApprovedAt = record.ApprovedAt.Add(-time.Second) }, wantErr: personserver.ErrMissionConflict},
		{name: "ExpiresAt", apply: func(record *personserver.MissionRecord) { record.ExpiresAt = record.ExpiresAt.Add(time.Second) }, wantErr: personserver.ErrMissionConflict},
		{name: "Capabilities", apply: func(record *personserver.MissionRecord) { record.Capabilities[0] = "different" }, wantErr: personserver.ErrMissionConflict},
		{name: "State", apply: func(record *personserver.MissionRecord) { record.State = personserver.MissionTerminated }, wantErr: personserver.ErrMissionConflict},
		{name: "TerminationReason", apply: func(record *personserver.MissionRecord) { record.TerminationReason = "different" }, wantErr: personserver.ErrMissionConflict},
		{name: "AcceptedUpdates", apply: func(record *personserver.MissionRecord) {
			record.AcceptedUpdates = []personserver.MissionUpdateRecord{{
				Document: missionUpdate(t, "invented update"), AcceptedAt: record.ApprovedAt,
			}}
		}, wantErr: personserver.ErrMissionConflict},
		{name: "Completion", apply: func(record *personserver.MissionRecord) {
			record.Completion = &personserver.MissionCompletionRecord{
				Document: missionCompletion(t, "invented completion"), AcceptedAt: record.ApprovedAt,
			}
		}, wantErr: personserver.ErrMissionConflict},
	}
}

type missionComparisonOperation struct {
	name  string
	apply func(*testing.T, MissionFixture, personserver.MissionRecord, time.Time) error
}

func missionComparisonOperations() []missionComparisonOperation {
	return []missionComparisonOperation{
		{name: "AppendMissionUpdate", apply: func(t *testing.T, fixture MissionFixture, expected personserver.MissionRecord, at time.Time) error {
			_, err := fixture.Store.AppendMissionUpdate(context.Background(), expected, at, missionUpdate(t, "real update"))
			return err
		}},
		{name: "CompleteMission", apply: func(t *testing.T, fixture MissionFixture, expected personserver.MissionRecord, at time.Time) error {
			_, err := fixture.Store.CompleteMission(context.Background(), expected, at, missionCompletion(t, "real completion"))
			return err
		}},
		{name: "CommitMissionPersonToken", apply: func(t *testing.T, fixture MissionFixture, expected personserver.MissionRecord, at time.Time) error {
			t.Helper()
			token := missionPersonToken(expected, "https://person.example", "compare-person-token")
			err := fixture.Store.CommitMissionPersonToken(context.Background(), expected, at, token)
			if _, loadErr := fixture.Store.Load(context.Background(), token.PersonServer, token.JTI); !errors.Is(loadErr, personserver.ErrPersonTokenNotFound) {
				t.Fatalf("failed expected-state comparison retained Person token = %v", loadErr)
			}
			return err
		}},
		{name: "CommitMissionAuthToken", apply: func(t *testing.T, fixture MissionFixture, expected personserver.MissionRecord, at time.Time) error {
			t.Helper()
			token := missionAuthToken(expected, "compare-auth-token", 9)
			err := fixture.Store.CommitMissionAuthToken(context.Background(), expected, at, token)
			if _, ok := fixture.LoadAuthToken(token.Reference); ok {
				t.Fatal("failed expected-state comparison retained Auth token")
			}
			return err
		}},
	}
}

func newMissionFixture(t *testing.T, contract MissionContract) MissionFixture {
	t.Helper()
	fixture := contract.New(t)
	if fixture.Store == nil {
		t.Fatal("storetest: MissionContract.New returned a nil Store")
	}
	if fixture.LoadAuthToken == nil {
		t.Fatal("storetest: MissionFixture.LoadAuthToken is required")
	}
	return fixture
}

func committedMissionFixture(t *testing.T, contract MissionContract, label string) (MissionFixture, personserver.MissionRecord) {
	t.Helper()
	fixture := newMissionFixture(t, contract)
	mission := missionRecord(t, label)
	if err := fixture.Store.CommitMission(context.Background(), mission, nil); err != nil {
		t.Fatal(err)
	}
	return fixture, mission
}

func missionRecord(t *testing.T, label string) personserver.MissionRecord {
	t.Helper()
	approvedAt := time.Date(2026, 9, 1, 18, 0, 0, 0, time.UTC)
	expiresAt := approvedAt.Add(time.Hour)
	agent := "aauth:worker@provider.example"
	document, err := aauth.EncodeMission(aauth.MissionBlob{
		Agent: agent, ApprovedAt: approvedAt, ExpiresAt: &expiresAt,
		Description:       "Store contract " + label,
		ApprovedTools:     []aauth.MissionTool{{Name: "files.write", Description: "Write one report."}},
		ApprovedResources: []string{"https://resource.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return personserver.MissionRecord{
		S256: document.S256, Agent: agent, ExactJSON: append([]byte(nil), document.ExactJSON...),
		ApprovedAt: approvedAt, ExpiresAt: expiresAt,
		Capabilities: []string{"files.write", "messages.send"}, State: personserver.MissionActive,
	}
}

func missionPersonToken(mission personserver.MissionRecord, issuer, jti string) personserver.PersonTokenRecord {
	return personserver.PersonTokenRecord{
		JTI: jti, PersonServer: issuer, Resource: "https://resource.example", Subject: "person-1",
		MissionS256: mission.S256, Tenant: "tenant-1", AgentProvider: "https://provider.example",
		Agent: mission.Agent, Confirmation: jose.JWK{Kty: "OKP", Crv: "Ed25519", X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Alg: jose.Ed25519Algorithm},
		ExpiresAt: mission.ExpiresAt, RetainUntil: mission.ExpiresAt.Add(time.Minute),
	}
}

func missionAuthToken(mission personserver.MissionRecord, jti string, marker byte) personserver.IssuedAuthTokenRecord {
	return personserver.IssuedAuthTokenRecord{
		Reference: aauth.TokenReference{Issuer: "https://person.example", JTI: jti},
		Resource:  "https://resource.example", MissionS256: mission.S256,
		CompactSHA256: [32]byte{marker}, IssuedAt: mission.ApprovedAt.Add(time.Minute),
		ExpiresAt: mission.ExpiresAt,
	}
}

func missionUpdate(t *testing.T, description string) aauth.MissionUpdateDocument {
	t.Helper()
	document, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{Action: "update", Description: description})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func missionCompletion(t *testing.T, summary string) aauth.MissionCompletionDocument {
	t.Helper()
	document, err := aauth.EncodeMissionCompletion(aauth.MissionCompletion{Action: "completion", Summary: summary})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func assertMissionAbsent(t *testing.T, store personserver.MissionStore, mission personserver.MissionRecord) {
	t.Helper()
	if _, err := store.LoadMissionForAgent(
		context.Background(), mission.Agent, mission.S256, mission.ApprovedAt,
	); !errors.Is(err, personserver.ErrMissionNotFound) {
		t.Fatalf("mission exists after failed atomic commit: %v", err)
	}
}

func assertMissionTerminated(t *testing.T, err error, reason string) {
	t.Helper()
	var terminated *personserver.MissionTerminatedError
	if !errors.As(err, &terminated) || terminated.TerminationReason != reason {
		t.Fatalf("mission terminal error = %T %v; want reason %q", err, err, reason)
	}
}
