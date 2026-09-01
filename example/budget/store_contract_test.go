package main

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/resource"
	resourcestoretest "gitlab.com/sidecat-dev/aauth-go/resource/storetest"
)

func TestBudgetStoreSatisfiesPublicContract(t *testing.T) {
	resourcestoretest.RunBudget(t, resourcestoretest.BudgetContract{
		New: func(testing.TB) resource.BudgetStore {
			return newMemoryBudgetStore()
		},
	})
}
