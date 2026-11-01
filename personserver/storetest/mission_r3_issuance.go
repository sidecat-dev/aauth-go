package storetest

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

// MissionR3IssuanceContract constructs a fresh mission store that supports
// atomic direct R3 issuance.
type MissionR3IssuanceContract struct {
	New func(testing.TB) MissionR3IssuanceFixture
}

// MissionR3IssuanceFixture connects one production store adapter to the R3
// extension contract. The observation functions are test-only.
type MissionR3IssuanceFixture struct {
	Store         personserver.MissionR3IssuanceStore
	LoadAuthToken func(aauth.TokenReference) (personserver.IssuedAuthTokenRecord, bool)
	LoadIssuance  func(aauth.TokenReference) (r3.IssuanceRecord, bool)
}

// RunMissionR3Issuance checks cross-record validation, conflict refusal, input
// ownership, and concurrent pairing for a direct mission-bound Auth token and
// its mandatory R3 issuance record. Applications must separately inject
// backend failures to prove their transaction cannot split the two writes.
func RunMissionR3Issuance(t *testing.T, contract MissionR3IssuanceContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: MissionR3IssuanceContract.New is required")
	}

	t.Run("matching records commit together", func(t *testing.T) {
		fixture, mission := committedMissionR3Fixture(t, contract, "mission-r3-success")
		token := missionAuthToken(mission, "mission-r3-auth", 1)
		issuance := missionR3Issuance(t, mission, token)
		wantIssuance := issuance.Clone()
		if err := fixture.Store.CommitMissionR3AuthToken(
			context.Background(), cloneMission(mission), token.IssuedAt, token, issuance,
		); err != nil {
			t.Fatal(err)
		}
		*issuance.Account = "mutated-after-commit"
		assertMissionR3Pair(t, fixture, token, wantIssuance)
		// Terminating the mission reaches an R3 auth token too.
		listed, err := fixture.Store.LoadMissionTokens(context.Background(), mission.S256)
		if err != nil || !reflect.DeepEqual(listed.AuthTokens, []personserver.IssuedAuthTokenRecord{token}) {
			t.Fatalf("mission tokens after R3 issuance = %#v, %v", listed, err)
		}
	})

	t.Run("every cross-record mismatch leaves neither record", func(t *testing.T) {
		for _, mismatch := range missionR3Mismatches() {
			t.Run(mismatch.name, func(t *testing.T) {
				fixture, mission := committedMissionR3Fixture(t, contract, "mission-r3-mismatch-"+mismatch.name)
				token := missionAuthToken(mission, "mission-r3-mismatch-auth", 2)
				issuance := missionR3Issuance(t, mission, token)
				mismatch.apply(&token, &issuance)
				if err := fixture.Store.CommitMissionR3AuthToken(
					context.Background(), cloneMission(mission), token.IssuedAt, token, issuance,
				); !errors.Is(err, personserver.ErrMissionConflict) {
					t.Fatalf("mismatched %s = %v", mismatch.name, err)
				}
				assertMissionR3PairAbsent(t, fixture, token.Reference)
				if issuance.AuthTokenReference != token.Reference {
					assertMissionR3PairAbsent(t, fixture, issuance.AuthTokenReference)
				}
			})
		}
	})

	t.Run("stale mission leaves neither record", func(t *testing.T) {
		fixture, mission := committedMissionR3Fixture(t, contract, "mission-r3-stale")
		if _, err := fixture.Store.AppendMissionUpdate(
			context.Background(), cloneMission(mission), mission.ApprovedAt.Add(time.Second), missionUpdate(t, "state advanced"),
		); err != nil {
			t.Fatal(err)
		}
		token := missionAuthToken(mission, "mission-r3-stale-auth", 3)
		issuance := missionR3Issuance(t, mission, token)
		if err := fixture.Store.CommitMissionR3AuthToken(
			context.Background(), mission, token.IssuedAt, token, issuance,
		); !errors.Is(err, personserver.ErrMissionConflict) {
			t.Fatalf("stale mission R3 issuance = %v", err)
		}
		assertMissionR3PairAbsent(t, fixture, token.Reference)
	})

	t.Run("concurrent conflicts retain one complete pair", func(t *testing.T) {
		fixture, mission := committedMissionR3Fixture(t, contract, "mission-r3-race")
		tokens := []personserver.IssuedAuthTokenRecord{
			missionAuthToken(mission, "mission-r3-race-auth", 4),
			missionAuthToken(mission, "mission-r3-race-auth", 5),
		}
		issuances := []r3.IssuanceRecord{
			missionR3Issuance(t, mission, tokens[0]),
			missionR3Issuance(t, mission, tokens[1]),
		}
		issuances[1].Subject = "person-2"
		errorsByCall := make([]error, 2)
		start := make(chan struct{})
		var wait sync.WaitGroup
		for index := range tokens {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				<-start
				errorsByCall[index] = fixture.Store.CommitMissionR3AuthToken(
					context.Background(), cloneMission(mission), tokens[index].IssuedAt, tokens[index], issuances[index],
				)
			}(index)
		}
		close(start)
		wait.Wait()
		winner := -1
		for index, err := range errorsByCall {
			if err == nil {
				if winner != -1 {
					t.Fatal("both conflicting mission R3 issuances succeeded")
				}
				winner = index
			}
		}
		if winner == -1 {
			t.Fatalf("no mission R3 issuance won: %v", errorsByCall)
		}
		assertMissionR3Pair(t, fixture, tokens[winner], issuances[winner])
	})
}

type missionR3Mismatch struct {
	name  string
	apply func(*personserver.IssuedAuthTokenRecord, *r3.IssuanceRecord)
}

func missionR3Mismatches() []missionR3Mismatch {
	return []missionR3Mismatch{
		{name: "mission digest", apply: func(token *personserver.IssuedAuthTokenRecord, _ *r3.IssuanceRecord) {
			token.MissionS256 = "different-mission"
		}},
		{name: "Auth-token reference", apply: func(_ *personserver.IssuedAuthTokenRecord, issuance *r3.IssuanceRecord) {
			issuance.AuthTokenReference.JTI = "different-auth-token"
		}},
		{name: "Resource", apply: func(_ *personserver.IssuedAuthTokenRecord, issuance *r3.IssuanceRecord) {
			issuance.Resource = "https://other-resource.example"
		}},
		{name: "issuance instant", apply: func(_ *personserver.IssuedAuthTokenRecord, issuance *r3.IssuanceRecord) {
			issuance.IssuedAt = issuance.IssuedAt.Add(time.Second)
		}},
		{name: "Person Server", apply: func(_ *personserver.IssuedAuthTokenRecord, issuance *r3.IssuanceRecord) {
			issuance.PersonServer = "https://other-person.example"
		}},
		{name: "Agent", apply: func(_ *personserver.IssuedAuthTokenRecord, issuance *r3.IssuanceRecord) {
			issuance.Agent = "aauth:other@provider.example"
		}},
	}
}

func committedMissionR3Fixture(
	t *testing.T,
	contract MissionR3IssuanceContract,
	label string,
) (MissionR3IssuanceFixture, personserver.MissionRecord) {
	t.Helper()
	fixture := contract.New(t)
	if fixture.Store == nil {
		t.Fatal("storetest: MissionR3IssuanceContract.New returned a nil Store")
	}
	if fixture.LoadAuthToken == nil {
		t.Fatal("storetest: MissionR3IssuanceFixture.LoadAuthToken is required")
	}
	if fixture.LoadIssuance == nil {
		t.Fatal("storetest: MissionR3IssuanceFixture.LoadIssuance is required")
	}
	mission := missionRecord(t, label)
	if err := fixture.Store.CommitMission(context.Background(), mission, nil); err != nil {
		t.Fatal(err)
	}
	return fixture, mission
}

func missionR3Issuance(
	t *testing.T,
	mission personserver.MissionRecord,
	token personserver.IssuedAuthTokenRecord,
) r3.IssuanceRecord {
	t.Helper()
	reference, err := r3.NewReference(
		"https://resource.example/r3/document-1",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	)
	if err != nil {
		t.Fatal(err)
	}
	account := "account-1"
	return r3.IssuanceRecord{
		AuthTokenReference: token.Reference, Resource: token.Resource, R3Reference: reference,
		Vocabulary: r3.VocabularyURI("https://modelcontextprotocol.io/schema/2025-11-25"),
		IssuedAt:   token.IssuedAt, PersonServer: token.Reference.Issuer, Subject: "person-1",
		Account: &account, PresentedJTI: "person-token-1", AgentJKT: "agent-thumbprint",
		Agent: mission.Agent,
	}
}

func assertMissionR3Pair(
	t *testing.T,
	fixture MissionR3IssuanceFixture,
	token personserver.IssuedAuthTokenRecord,
	issuance r3.IssuanceRecord,
) {
	t.Helper()
	loadedToken, tokenOK := fixture.LoadAuthToken(token.Reference)
	loadedIssuance, issuanceOK := fixture.LoadIssuance(token.Reference)
	if !tokenOK || !issuanceOK || !reflect.DeepEqual(loadedToken, token) || !reflect.DeepEqual(loadedIssuance, issuance) {
		t.Fatalf("mission R3 pair = token %#v/%t, issuance %#v/%t; want %#v, %#v",
			loadedToken, tokenOK, loadedIssuance, issuanceOK, token, issuance)
	}
}

func assertMissionR3PairAbsent(t *testing.T, fixture MissionR3IssuanceFixture, reference aauth.TokenReference) {
	t.Helper()
	if _, ok := fixture.LoadAuthToken(reference); ok {
		t.Fatal("failed mission R3 commit retained Auth token")
	}
	if _, ok := fixture.LoadIssuance(reference); ok {
		t.Fatal("failed mission R3 commit retained issuance record")
	}
}
