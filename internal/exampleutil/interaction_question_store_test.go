package exampleutil

import (
	"context"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
)

func TestInteractionQuestionStoreContract(t *testing.T) {
	storetest.RunInteractionQuestion(t, storetest.InteractionQuestionContract{
		New: func(testing.TB) personserver.InteractionQuestionStore { return NewInteractionQuestionStore() },
	})
}

func TestMissionInteractionQuestionStoreContract(t *testing.T) {
	storetest.RunMissionInteractionQuestion(t, storetest.MissionInteractionQuestionContract{
		New: func(tb testing.TB) (personserver.MissionInteractionQuestionStore, personserver.MissionRecord) {
			tb.Helper()
			store := NewMissionInteractionQuestionStore()
			approvedAt := time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC)
			expiresAt := approvedAt.Add(2 * time.Hour)
			mission, err := aauth.EncodeMission(aauth.MissionBlob{
				Agent:      "aauth:operator@ap.example",
				ApprovedAt: approvedAt, ExpiresAt: &expiresAt, Description: "Test mission.",
			})
			if err != nil {
				tb.Fatal(err)
			}
			record := personserver.MissionRecord{
				S256: mission.S256, Agent: mission.Blob.Agent, ExactJSON: mission.ExactJSON,
				ApprovedAt: approvedAt, ExpiresAt: expiresAt, State: personserver.MissionActive,
			}
			if err := store.CommitMission(context.Background(), record, nil); err != nil {
				tb.Fatal(err)
			}
			return store, record
		},
	})
}
