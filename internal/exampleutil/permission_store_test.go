package exampleutil_test

import (
	"context"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
)

func TestPermissionStoreContract(t *testing.T) {
	storetest.RunPermission(t, storetest.PermissionContract{
		New: func(testing.TB) personserver.PermissionStore {
			return exampleutil.NewPermissionStore()
		},
	})
}

func TestMissionPermissionStoreContract(t *testing.T) {
	storetest.RunMissionPermission(t, storetest.MissionPermissionContract{
		New: func(tb testing.TB) (personserver.MissionPermissionStore, personserver.MissionRecord) {
			tb.Helper()
			store := exampleutil.NewMissionPermissionStore()
			now := time.Date(2026, 8, 31, 23, 0, 0, 0, time.UTC)
			expiresAt := now.Add(time.Hour)
			mission, err := aauth.EncodeMission(aauth.MissionBlob{
				Approver: "https://person.example", Agent: "aauth:operator@provider.example",
				ApprovedAt: now, ExpiresAt: &expiresAt, Description: "Permission store contract mission.",
			})
			if err != nil {
				tb.Fatal(err)
			}
			record := personserver.MissionRecord{
				S256: mission.S256, Agent: mission.Blob.Agent, ExactJSON: append([]byte(nil), mission.ExactJSON...),
				ApprovedAt: now, ExpiresAt: expiresAt, State: personserver.MissionActive,
			}
			if err := store.CommitMission(context.Background(), record, nil); err != nil {
				tb.Fatal(err)
			}
			return store, record
		},
	})
}
