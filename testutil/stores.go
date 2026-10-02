// Package testutil supplies in-memory stores for examples and integration
// tests that compose the public protocol roles. These stores do not persist
// across processes and are not production persistence adapters.
package testutil

import (
	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)

// MissionStore combines mission lifecycle with permission and audit state in
// one in-memory transaction boundary.
type MissionStore interface {
	personserver.MissionPermissionStore
	personserver.MissionAuditStore
}

// NewMissionStore returns an empty, concurrency-safe in-memory mission store.
func NewMissionStore() MissionStore {
	return exampleutil.NewMissionPermissionStore().(MissionStore)
}

// NewEnrollmentStore returns an empty, concurrency-safe in-memory enrollment
// and refresh store using clock for refresh expiry.
func NewEnrollmentStore(clock aauth.Clock) agentprovider.EnrollmentStore {
	return exampleutil.NewEnrollmentStore(clock)
}
