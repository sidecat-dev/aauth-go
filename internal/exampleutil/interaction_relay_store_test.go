package exampleutil

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
)

func TestInteractionRelayStoreContract(t *testing.T) {
	storetest.RunInteractionRelay(t, storetest.InteractionRelayContract{
		New: func(testing.TB) personserver.InteractionRelayStore {
			return NewInteractionRelayStore()
		},
	})
}
