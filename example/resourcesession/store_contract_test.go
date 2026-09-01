package main

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/resource"
	resourcestoretest "gitlab.com/sidecat-dev/aauth-go/resource/storetest"
)

func TestSessionStoreContracts(t *testing.T) {
	t.Run("immediate", func(t *testing.T) {
		resourcestoretest.RunSession(t, resourcestoretest.SessionContract{
			New: func(testing.TB) resource.SessionStore {
				return newMemorySessionStore()
			},
		})
	})
	t.Run("deferred", func(t *testing.T) {
		resourcestoretest.RunDeferredSession(t, resourcestoretest.DeferredSessionContract{
			New: func(testing.TB) resource.DeferredSessionStore {
				return newMemorySessionStore()
			},
		})
	})
}
