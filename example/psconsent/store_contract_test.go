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
		New: func(tb testing.TB) storetest.ClarificationStore {
			tb.Helper()
			store, ok := testutil.NewDeferredAuthorizationStore().(storetest.ClarificationStore)
			if !ok {
				tb.Fatal("deferred authorization store does not implement the optional clarification contract")
			}
			return store
		},
	})
}
