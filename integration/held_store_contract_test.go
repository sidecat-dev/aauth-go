package integration_test

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/resource"
	resourcestoretest "gitlab.com/sidecat-dev/aauth-go/resource/storetest"
)

func TestR3PerCallHeldStoreSatisfiesPublicContract(t *testing.T) {
	resourcestoretest.RunHeldInvocation(t, resourcestoretest.HeldInvocationContract{
		New: func(testing.TB) resource.HeldInvocationStore {
			return newR3PerCallHeldStore()
		},
	})
}

func TestHeldBudgetStoreSatisfiesPublicContract(t *testing.T) {
	resourcestoretest.RunHeldBudget(t, resourcestoretest.HeldBudgetContract{
		New: func(testing.TB) resource.HeldBudgetStore {
			return newR3PerCallHeldStore()
		},
	})
}
