package main

import (
	"path/filepath"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	agentstoretest "gitlab.com/sidecat-dev/aauth-go/agentprovider/storetest"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	personstoretest "gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/storetest"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	resourcestoretest "gitlab.com/sidecat-dev/aauth-go/resource/storetest"
)

func TestHostedEnrollmentStoreContract(t *testing.T) {
	agentstoretest.RunEnrollment(t, agentstoretest.EnrollmentContract{New: func(tb testing.TB, clock aauth.Clock) agentprovider.EnrollmentStore {
		tb.Helper()
		path := filepath.Join(tb.TempDir(), "enrollment.json")
		if err := writeJSONFile(path, 0o600, enrollmentStoreState{
			Enrollments: map[string]agentprovider.EnrollmentRecord{}, Refreshes: map[string]agentprovider.RefreshRecord{},
		}); err != nil {
			tb.Fatal(err)
		}
		return newEnrollmentFileStore(path, func() time.Time { return clock.Now() })
	}})
}

func TestHostedMissionStoreContract(t *testing.T) {
	personstoretest.RunMission(t, personstoretest.MissionContract{New: func(tb testing.TB) personstoretest.MissionFixture {
		store := newProtocolTestStore(tb)
		return personstoretest.MissionFixture{
			Store: store,
			LoadAuthToken: func(reference aauth.TokenReference) (personserver.IssuedAuthTokenRecord, bool) {
				store.mu.Lock()
				defer store.mu.Unlock()
				state, err := store.load()
				if err != nil {
					tb.Fatal(err)
				}
				record, ok := state.AuthTokens[referenceKey(reference)]
				return record, ok
			},
		}
	}})
}

func TestHostedMissionR3StoreContract(t *testing.T) {
	personstoretest.RunMissionR3Issuance(t, personstoretest.MissionR3IssuanceContract{New: func(tb testing.TB) personstoretest.MissionR3IssuanceFixture {
		store := newProtocolTestStore(tb)
		return personstoretest.MissionR3IssuanceFixture{
			Store: store,
			LoadAuthToken: func(reference aauth.TokenReference) (personserver.IssuedAuthTokenRecord, bool) {
				store.mu.Lock()
				defer store.mu.Unlock()
				state, err := store.load()
				if err != nil {
					tb.Fatal(err)
				}
				record, ok := state.AuthTokens[referenceKey(reference)]
				return record, ok
			},
			LoadIssuance: func(reference aauth.TokenReference) (r3.IssuanceRecord, bool) {
				store.mu.Lock()
				defer store.mu.Unlock()
				state, err := store.load()
				if err != nil {
					tb.Fatal(err)
				}
				encoded, ok := state.R3Issuances[referenceKey(reference)]
				if !ok {
					return r3.IssuanceRecord{}, false
				}
				record, err := decodeHostedR3Issuance(encoded)
				if err != nil {
					tb.Fatal(err)
				}
				return record, true
			},
		}
	}})
}

func TestHostedBudgetStoreContract(t *testing.T) {
	resourcestoretest.RunBudget(t, resourcestoretest.BudgetContract{New: func(tb testing.TB) resource.BudgetStore {
		return hostedBudgetStore{store: newProtocolTestStore(tb)}
	}})
}

func newProtocolTestStore(tb testing.TB) *hostedProtocolStore {
	tb.Helper()
	store := newHostedProtocolStore(filepath.Join(tb.TempDir(), "protocol.json"))
	if err := initializeHostedProtocolStore(store.path); err != nil {
		tb.Fatal(err)
	}
	return store
}

func TestHostedR3DocumentStoreContract(t *testing.T) {
	resourcestoretest.RunR3Document(t, resourcestoretest.R3DocumentContract{New: func(tb testing.TB) resource.R3DocumentStore {
		tb.Helper()
		store := newProtocolTestStore(tb)
		return hostedR3DocumentStore{store: store}
	}})
}

func TestHostedR3IssuanceStoreContract(t *testing.T) {
	storetest.RunIssuance(t, storetest.IssuanceContract{New: func(tb testing.TB) r3.IssuanceStore {
		tb.Helper()
		store := newProtocolTestStore(tb)
		return hostedR3IssuanceStore{store: store}
	}})
}
