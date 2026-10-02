package testutil_test

import (
	"context"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	aptest "gitlab.com/sidecat-dev/aauth-go/agentprovider/storetest"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	pstest "gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func TestExportedEnrollmentStore(t *testing.T) {
	aptest.RunEnrollment(t, aptest.EnrollmentContract{New: func(_ testing.TB, clock aauth.Clock) agentprovider.EnrollmentStore {
		return testutil.NewEnrollmentStore(clock)
	}})
}

func TestExportedMissionStore(t *testing.T) {
	newStore := func(tb testing.TB, now time.Time) (testutil.MissionStore, personserver.MissionRecord) {
		tb.Helper()
		store := testutil.NewMissionStore()
		expires := now.Add(time.Hour)
		mission, err := aauth.EncodeMission(aauth.MissionBlob{Approver: "https://person.example", Agent: "aauth:operator@provider.example",
			ApprovedAt: now, ExpiresAt: &expires, Description: "Public store contract."})
		if err != nil {
			tb.Fatal(err)
		}
		record := personserver.MissionRecord{S256: mission.S256, Agent: mission.Blob.Agent, ExactJSON: mission.ExactJSON,
			ApprovedAt: now, ExpiresAt: expires, State: personserver.MissionActive}
		if err := store.CommitMission(context.Background(), record, nil); err != nil {
			tb.Fatal(err)
		}
		return store, record
	}
	t.Run("permission", func(t *testing.T) {
		pstest.RunMissionPermission(t, pstest.MissionPermissionContract{New: func(tb testing.TB) (personserver.MissionPermissionStore, personserver.MissionRecord) {
			return newStore(tb, time.Date(2026, 8, 31, 23, 0, 0, 0, time.UTC))
		}})
	})
	t.Run("audit", func(t *testing.T) {
		pstest.RunAudit(t, pstest.AuditContract{New: func(tb testing.TB) (personserver.MissionAuditStore, personserver.MissionRecord) {
			return newStore(tb, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
		}})
	})
}
