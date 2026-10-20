package testutil_test

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	accessstoretest "gitlab.com/sidecat-dev/aauth-go/accessserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	personstoretest "gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func TestPublicFederationStores(t *testing.T) {
	t.Run("AS", func(t *testing.T) {
		accessstoretest.RunDeferredAuthorization(t, accessstoretest.DeferredAuthorizationContract{New: func(testing.TB) accessserver.DeferredAuthorizationStore {
			return testutil.NewAccessAuthorizationStore()
		}})
	})
	t.Run("PS", func(t *testing.T) {
		personstoretest.RunFederatedAuthorization(t, personstoretest.FederatedAuthorizationContract{New: func(testing.TB) personserver.FederatedAuthorizationStore {
			return testutil.NewFederatedAuthorizationStore()
		}})
	})
}
