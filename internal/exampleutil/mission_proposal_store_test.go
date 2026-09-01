package exampleutil_test

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
)

func TestMissionProposalStoreContract(t *testing.T) {
	storetest.RunMissionProposal(t, storetest.MissionProposalContract{
		New: func(tb testing.TB) personserver.MissionProposalStore {
			tb.Helper()
			store, ok := exampleutil.NewMissionStore().(personserver.MissionProposalStore)
			if !ok {
				tb.Fatal("example mission store does not implement personserver.MissionProposalStore")
			}
			return store
		},
	})
}
