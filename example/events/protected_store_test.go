package main

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/resource/storetest"
)

func TestProtectedEventStoreContract(t *testing.T) {
	storetest.RunProtectedEvents(t, storetest.ProtectedEventsContract{
		New: func(testing.TB) resource.ProtectedSubscriptionStore {
			return newResourceEventStore()
		},
	})
}
