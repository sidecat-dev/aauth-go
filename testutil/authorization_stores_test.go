package testutil_test

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
	pstest "gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	r3test "gitlab.com/sidecat-dev/aauth-go/r3/storetest"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	resourcetest "gitlab.com/sidecat-dev/aauth-go/resource/storetest"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func TestExportedDeferredAuthorizationStore(t *testing.T) {
	pstest.RunDeferredAuthorization(t, pstest.DeferredAuthorizationContract{
		New: func(testing.TB) personserver.DeferredAuthorizationStore {
			return testutil.NewDeferredAuthorizationStore()
		},
	})
	pstest.RunClarification(t, pstest.Contract{
		New: func(testing.TB) pstest.ClarificationStore {
			return testutil.NewDeferredAuthorizationStore()
		},
	})
}

func TestExportedBudgetStore(t *testing.T) {
	resourcetest.RunBudget(t, resourcetest.BudgetContract{
		New: func(testing.TB) resource.BudgetStore { return testutil.NewBudgetStore() },
	})
}

func TestExportedR3DocumentStore(t *testing.T) {
	resourcetest.RunR3Document(t, resourcetest.R3DocumentContract{
		New: func(testing.TB) resource.R3DocumentStore { return testutil.NewR3DocumentStore() },
	})
}

func TestExportedR3IssuanceStore(t *testing.T) {
	r3test.RunIssuance(t, r3test.IssuanceContract{
		New: func(testing.TB) r3.IssuanceStore { return testutil.NewR3IssuanceStore() },
	})
}

func TestExportedIssuedAuthTokenStore(t *testing.T) {
	pstest.RunIssuedAuthToken(t, pstest.IssuedAuthTokenContract{
		New: func(testing.TB) personserver.IssuedAuthTokenStore { return testutil.NewIssuedAuthTokenStore() },
	})
}

func TestExportedAuthTokenStatusStore(t *testing.T) {
	resourcetest.RunAuthTokenStatus(t, resourcetest.AuthTokenStatusContract{
		New: func(testing.TB) resource.AuthTokenStatusStore { return testutil.NewAuthTokenStatusStore() },
	})
}
