package testutil_test

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func TestPublicMissionStoreContracts(t *testing.T) {
	t.Run("mission lifecycle", func(t *testing.T) {
		storetest.RunMission(t, storetest.MissionContract{
			New: func(testing.TB) storetest.MissionFixture {
				store := testutil.NewMissionStore()
				return storetest.MissionFixture{
					Store: store, LoadAuthToken: store.LoadAuthToken,
				}
			},
		})
	})
	t.Run("mission R3 issuance", func(t *testing.T) {
		storetest.RunMissionR3Issuance(t, storetest.MissionR3IssuanceContract{
			New: func(testing.TB) storetest.MissionR3IssuanceFixture {
				store := testutil.NewMissionStore()
				return storetest.MissionR3IssuanceFixture{
					Store: store, LoadAuthToken: store.LoadAuthToken,
					LoadIssuance: store.LoadR3Issuance,
				}
			},
		})
	})
}
