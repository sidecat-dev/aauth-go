package exampleutil

import (
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func TestMissionStoreContract(t *testing.T) {
	t.Parallel()

	storetest.RunMission(t, storetest.MissionContract{
		New: func(testing.TB) storetest.MissionFixture {
			store := newMissionStore()
			return storetest.MissionFixture{
				Store: store,
				LoadAuthToken: func(reference aauth.TokenReference) (personserver.IssuedAuthTokenRecord, bool) {
					store.mu.Lock()
					defer store.mu.Unlock()
					record, ok := store.auth[reference.Issuer+"\x00"+reference.JTI]
					return record, ok
				},
			}
		},
	})
}

func TestMissionR3IssuanceStoreContract(t *testing.T) {
	t.Parallel()

	storetest.RunMissionR3Issuance(t, storetest.MissionR3IssuanceContract{
		New: func(testing.TB) storetest.MissionR3IssuanceFixture {
			store := newMissionStore()
			return storetest.MissionR3IssuanceFixture{
				Store: store,
				LoadAuthToken: func(reference aauth.TokenReference) (personserver.IssuedAuthTokenRecord, bool) {
					store.mu.Lock()
					defer store.mu.Unlock()
					record, ok := store.auth[reference.Issuer+"\x00"+reference.JTI]
					return record, ok
				},
				LoadIssuance: func(reference aauth.TokenReference) (r3.IssuanceRecord, bool) {
					store.mu.Lock()
					defer store.mu.Unlock()
					record, ok := store.r3Issuances[reference]
					return record.Clone(), ok
				},
			}
		},
	})
}
