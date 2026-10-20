package main

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func TestAuthorizationStoreContracts(t *testing.T) {
	storetest.RunDeferredAuthorization(t, storetest.DeferredAuthorizationContract{
		New: func(testing.TB) personserver.DeferredAuthorizationStore {
			return testutil.NewDeferredAuthorizationStore()
		},
	})
	storetest.RunClarification(t, storetest.Contract{
		New: func(testing.TB) storetest.ClarificationStore {
			return testutil.NewDeferredAuthorizationStore()
		},
	})
}
