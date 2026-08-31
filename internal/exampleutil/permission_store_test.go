package exampleutil_test

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
)

func TestPermissionStoreContract(t *testing.T) {
	storetest.RunPermission(t, storetest.PermissionContract{
		New: func(testing.TB) personserver.PermissionStore {
			return exampleutil.NewPermissionStore()
		},
	})
}
