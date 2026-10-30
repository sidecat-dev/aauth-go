package main

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider/storetest"
	"gitlab.com/sidecat-dev/aauth-go/events"
)

func TestEventInboxStoreContract(t *testing.T) {
	storetest.RunEventInbox(t, storetest.EventInboxContract{
		New: func(testing.TB) agentprovider.EventInboxStore {
			return newProviderEventStore()
		},
		Delivery: func(
			_ testing.TB,
			store agentprovider.EventInboxStore,
			fingerprint events.DeliveryFingerprint,
		) (agentprovider.EventDelivery, error) {
			return store.(*providerEventStore).deliveryFor(fingerprint)
		},
	})
}
