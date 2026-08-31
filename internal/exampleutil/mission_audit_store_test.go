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

func TestMissionAuditStoreContract(t *testing.T) {
	storetest.RunAudit(t, storetest.AuditContract{
		New: func(tb testing.TB) (personserver.MissionAuditStore, personserver.MissionRecord) {
			tb.Helper()
			store := exampleutil.NewMissionStore()
			now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
			expiresAt := now.Add(time.Hour)
			mission, err := aauth.EncodeMission(aauth.MissionBlob{
				Approver: "https://person.example", Agent: "aauth:operator@provider.example",
				ApprovedAt: now, ExpiresAt: &expiresAt, Description: "Audit store contract mission.",
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
