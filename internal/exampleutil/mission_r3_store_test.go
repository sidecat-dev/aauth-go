package exampleutil

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

func TestMissionStoreSupportsAtomicR3Issuance(t *testing.T) {
	t.Parallel()

	store := newMissionStore()
	var contract personserver.MissionR3IssuanceStore = store
	if contract == nil {
		t.Fatal("mission R3 issuance store is nil")
	}
}
