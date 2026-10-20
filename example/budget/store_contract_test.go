package main

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/resource"
	resourcestoretest "gitlab.com/sidecat-dev/aauth-go/resource/storetest"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

func TestBudgetStoreSatisfiesPublicContract(t *testing.T) {
	resourcestoretest.RunBudget(t, resourcestoretest.BudgetContract{
		New: func(testing.TB) resource.BudgetStore {
			return testutil.NewBudgetStore()
		},
	})
}
