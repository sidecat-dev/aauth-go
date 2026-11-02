package testutil_test

import (
	"context"
	"errors"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	aptest "gitlab.com/sidecat-dev/aauth-go/agentprovider/storetest"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	pstest "gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	resourcetest "gitlab.com/sidecat-dev/aauth-go/resource/storetest"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func TestExportedAgentTokenRevocationStore(t *testing.T) {
	resourcetest.RunAgentTokenRevocation(t, resourcetest.AgentTokenRevocationContract{
		New: func(testing.TB) resource.AgentTokenRevocationStore {
			return testutil.NewAgentTokenRevocationStore()
		},
	})
}

func TestExportedIssuedAgentTokenStore(t *testing.T) {
	aptest.RunIssuedAgentTokens(t, aptest.IssuedAgentTokensContract{New: func(testing.TB) agentprovider.IssuedAgentTokenStore {
		return testutil.NewIssuedAgentTokenStore()
	}})
}

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
		mission, err := aauth.EncodeMission(aauth.MissionBlob{Agent: "aauth:operator@provider.example",
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

func TestExportedEventInboxStore(t *testing.T) {
	aptest.RunEventInbox(t, aptest.EventInboxContract{
		New: func(testing.TB) agentprovider.EventInboxStore {
			return testutil.NewEventInboxStore()
		},
		Delivery: func(_ testing.TB, store agentprovider.EventInboxStore, fingerprint events.DeliveryFingerprint) (agentprovider.EventDelivery, error) {
			delivery, ok := store.(testutil.EventInboxStore).LoadDelivery(fingerprint)
			if !ok {
				return agentprovider.EventDelivery{}, errors.New("testutil: no such delivery")
			}
			return delivery, nil
		},
	})
	aptest.RunEventInboxReader(t, aptest.EventInboxReaderContract{
		New: func(testing.TB) aptest.EventInboxReaderStore {
			return testutil.NewEventInboxStore()
		},
	})
}

func TestExportedProtectedEventStore(t *testing.T) {
	resourcetest.RunProtectedEvents(t, resourcetest.ProtectedEventsContract{
		New: func(testing.TB) resource.ProtectedSubscriptionStore {
			return testutil.NewProtectedEventStore()
		},
	})
}
