package exampleutil_test

import (
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider/storetest"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
)

func TestEnrollmentStoreContract(t *testing.T) {
	storetest.RunEnrollment(t, storetest.EnrollmentContract{
		New: func(_ testing.TB, clock aauth.Clock) agentprovider.EnrollmentStore {
			return exampleutil.NewEnrollmentStore(clock)
		},
	})
}
