package testutil_test

import (
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	pstest "gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
	"testing"
)

func TestExportedPendingPermissionQueues(t *testing.T) {
	for name, newStore := range map[string]func() personserver.PermissionQueueStore{
		"missionless":      func() personserver.PermissionQueueStore { return testutil.NewPermissionStore() },
		"mission":          func() personserver.PermissionQueueStore { return testutil.NewMissionStore() },
		"mission question": func() personserver.PermissionQueueStore { return testutil.NewMissionInteractionQuestionStore() },
		"mission relay":    func() personserver.PermissionQueueStore { return testutil.NewMissionInteractionRelayStore() },
	} {
		t.Run(name, func(t *testing.T) {
			pstest.RunPermissionQueue(t, pstest.PermissionQueueContract{New: func(testing.TB) personserver.PermissionQueueStore { return newStore() }})
		})
	}
}

func TestExportedPendingQuestionQueues(t *testing.T) {
	for name, newStore := range map[string]func() personserver.InteractionQuestionQueueStore{
		"missionless": func() personserver.InteractionQuestionQueueStore { return testutil.NewInteractionQuestionStore() },
		"mission": func() personserver.InteractionQuestionQueueStore {
			return testutil.NewMissionInteractionQuestionStore()
		},
	} {
		t.Run(name, func(t *testing.T) {
			pstest.RunInteractionQuestionQueue(t, pstest.InteractionQuestionQueueContract{New: func(testing.TB) personserver.InteractionQuestionQueueStore { return newStore() }})
		})
	}
}
