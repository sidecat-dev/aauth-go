package main

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
	personstoretest "gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	resourcestoretest "gitlab.com/sidecat-dev/aauth-go/resource/storetest"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func TestAuthTokenRevocationStoreContracts(t *testing.T) {
	t.Run("Person Server issuance", func(t *testing.T) {
		personstoretest.RunIssuedAuthToken(t, personstoretest.IssuedAuthTokenContract{
			New: func(testing.TB) personserver.IssuedAuthTokenStore {
				return testutil.NewIssuedAuthTokenStore()
			},
		})
	})
	t.Run("Resource status", func(t *testing.T) {
		resourcestoretest.RunAuthTokenStatus(t, resourcestoretest.AuthTokenStatusContract{
			New: func(testing.TB) resource.AuthTokenStatusStore {
				return testutil.NewAuthTokenStatusStore()
			},
		})
	})
}
