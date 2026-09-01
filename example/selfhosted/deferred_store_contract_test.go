package main

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
)

func TestDeferredPersonTokenStoreContract(t *testing.T) {
	storetest.RunDeferredToken(t, storetest.DeferredTokenContract{
		New: func(testing.TB) personserver.DeferredTokenStore {
			return newDeferredPersonTokenStore()
		},
	})
}
