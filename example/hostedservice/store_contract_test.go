package main

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
	r3storetest "gitlab.com/sidecat-dev/aauth-go/r3/storetest"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	resourcestoretest "gitlab.com/sidecat-dev/aauth-go/resource/storetest"
)

func TestHostedServiceStoresSatisfyPublicContracts(t *testing.T) {
	t.Run("R3 document", func(t *testing.T) {
		resourcestoretest.RunR3Document(t, resourcestoretest.R3DocumentContract{
			New: func(testing.TB) resource.R3DocumentStore {
				return newR3DocumentStore()
			},
		})
	})
	t.Run("R3 issuance", func(t *testing.T) {
		r3storetest.RunIssuance(t, r3storetest.IssuanceContract{
			New: func(testing.TB) r3.IssuanceStore {
				return newR3IssuanceStore()
			},
		})
	})
	t.Run("Budget", func(t *testing.T) {
		resourcestoretest.RunBudget(t, resourcestoretest.BudgetContract{
			New: func(testing.TB) resource.BudgetStore {
				return newBudgetStore()
			},
		})
	})
}
