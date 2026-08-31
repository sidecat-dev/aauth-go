package exampleutil

import (
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/personserver/storetest"
)

func TestInteractionQuestionStoreContract(t *testing.T) {
	storetest.RunInteractionQuestion(t, storetest.InteractionQuestionContract{
		New: func(testing.TB) personserver.InteractionQuestionStore { return NewInteractionQuestionStore() },
	})
}
