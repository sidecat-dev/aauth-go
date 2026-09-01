package exampleutil

import (
	"context"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
)

func TestInteractionRelayStoreContract(t *testing.T) {
	storetest.RunInteractionRelay(t, storetest.InteractionRelayContract{
		New: func(testing.TB) personserver.InteractionRelayStore {
			return NewInteractionRelayStore()
		},
	})
}

func TestMissionInteractionRelayStoreContract(t *testing.T) {
	storetest.RunMissionInteractionRelay(t, storetest.MissionInteractionRelayContract{
		New: func(tb testing.TB) (personserver.MissionInteractionRelayStore, personserver.MissionRecord) {
			tb.Helper()
			store := NewMissionInteractionRelayStore()
			now := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
			expiresAt := now.Add(time.Hour)
			mission, err := aauth.EncodeMission(aauth.MissionBlob{
				Approver: "https://ps.example", Agent: "aauth:operator@ap.example",
				ApprovedAt: now, ExpiresAt: &expiresAt, Description: "Relay contract mission.",
			})
			if err != nil {
				tb.Fatal(err)
			}
			record := personserver.MissionRecord{
				S256: mission.S256, Agent: mission.Blob.Agent, ExactJSON: mission.ExactJSON,
				ApprovedAt: now, ExpiresAt: expiresAt, State: personserver.MissionActive,
			}
			if err := store.CommitMission(context.Background(), record, nil); err != nil {
				tb.Fatal(err)
			}
			return store, record
		},
	})
}
