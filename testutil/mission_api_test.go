package testutil_test

import (
	"context"
	"errors"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	pstest "gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

// A consumer must be able to use the advertised contracts without discovering
// hidden interfaces through a type assertion or copying an internal store.
func TestExportedMissionProposalStore(t *testing.T) {
	pstest.RunMissionProposal(t, pstest.MissionProposalContract{New: func(testing.TB) personserver.MissionProposalStore {
		return testutil.NewMissionStore()
	}})
}

func TestExportedMissionR3StoreRejectsAnUnknownMission(t *testing.T) {
	store := testutil.NewMissionStore()
	if err := store.CommitMissionR3AuthToken(context.Background(), personserver.MissionRecord{}, time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC), personserver.IssuedAuthTokenRecord{}, r3.IssuanceRecord{}); !errors.Is(err, personserver.ErrMissionNotFound) {
		t.Fatalf("unknown mission issuance: %v", err)
	}
}

func TestExportedPermissionStore(t *testing.T) {
	pstest.RunPermission(t, pstest.PermissionContract{New: func(testing.TB) personserver.PermissionStore {
		return testutil.NewPermissionStore()
	}})
}

func TestExportedInteractionQuestionStore(t *testing.T) {
	pstest.RunInteractionQuestion(t, pstest.InteractionQuestionContract{New: func(testing.TB) personserver.InteractionQuestionStore {
		return testutil.NewInteractionQuestionStore()
	}})
}

func TestExportedInteractionRelayStore(t *testing.T) {
	pstest.RunInteractionRelay(t, pstest.InteractionRelayContract{New: func(testing.TB) personserver.InteractionRelayStore {
		return testutil.NewInteractionRelayStore()
	}})
}

func TestExportedMissionInteractionQuestionStore(t *testing.T) {
	pstest.RunMissionInteractionQuestion(t, pstest.MissionInteractionQuestionContract{New: func(tb testing.TB) (personserver.MissionInteractionQuestionStore, personserver.MissionRecord) {
		store := testutil.NewMissionInteractionQuestionStore()
		mission := commitPublicMission(tb, store, time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC))
		return store, mission
	}})
	t.Run("proposal contract on the same store", func(t *testing.T) {
		pstest.RunMissionProposal(t, pstest.MissionProposalContract{New: func(testing.TB) personserver.MissionProposalStore {
			return testutil.NewMissionInteractionQuestionStore()
		}})
	})
}

func TestExportedMissionInteractionRelayStore(t *testing.T) {
	pstest.RunMissionInteractionRelay(t, pstest.MissionInteractionRelayContract{New: func(tb testing.TB) (personserver.MissionInteractionRelayStore, personserver.MissionRecord) {
		store := testutil.NewMissionInteractionRelayStore()
		mission := commitPublicMission(tb, store, time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC))
		return store, mission
	}})
	t.Run("proposal contract on the same store", func(t *testing.T) {
		pstest.RunMissionProposal(t, pstest.MissionProposalContract{New: func(testing.TB) personserver.MissionProposalStore {
			return testutil.NewMissionInteractionRelayStore()
		}})
	})
}

func commitPublicMission(tb testing.TB, store personserver.MissionStore, approvedAt time.Time) personserver.MissionRecord {
	tb.Helper()
	expires := approvedAt.Add(2 * time.Hour)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Agent: "aauth:operator@ap.example", ApprovedAt: approvedAt, ExpiresAt: &expires, Description: "Review an itinerary.",
	})
	if err != nil {
		tb.Fatal(err)
	}
	record := personserver.MissionRecord{S256: mission.S256, Agent: mission.Blob.Agent, ExactJSON: mission.ExactJSON, ApprovedAt: approvedAt, ExpiresAt: expires, State: personserver.MissionActive}
	if err := store.CommitMission(context.Background(), record, nil); err != nil {
		tb.Fatal(err)
	}
	return record
}
