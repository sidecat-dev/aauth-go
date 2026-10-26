// Package testutil supplies in-memory stores for local development, examples
// and tests that compose the public protocol roles.
//
// Stability: the exported APIs follow the same versioning expectations as
// the role packages; pre-v1 APIs may change as the drafts evolve. Pin a module
// revision. These stores do not persist across processes or bound retention.
package testutil

import (
	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

// MissionStore combines mission lifecycle, proposals, permissions, audit and
// R3 issuance in one in-memory Person Server transaction boundary.
type MissionStore interface {
	personserver.MissionProposalStore
	personserver.MissionPermissionStore
	personserver.PermissionQueueStore
	personserver.MissionAuditStore
	personserver.MissionR3IssuanceStore
	// LoadAuthToken and LoadR3Issuance are read-only observations for storetest
	// fixtures. They return independent copies and do not enforce expiry.
	LoadAuthToken(aauth.TokenReference) (personserver.IssuedAuthTokenRecord, bool)
	LoadR3Issuance(aauth.TokenReference) (r3.IssuanceRecord, bool)
}

// NewMissionStore returns an empty, concurrency-safe in-memory mission store.
func NewMissionStore() MissionStore {
	return exampleutil.NewMissionPermissionStore().(MissionStore)
}

// MissionInteractionQuestionStore keeps questions and their mission state in
// the same transaction boundary. It also supports missionless questions.
type MissionInteractionQuestionStore interface {
	MissionStore
	personserver.MissionInteractionQuestionStore
	personserver.InteractionQuestionQueueStore
}

// NewMissionInteractionQuestionStore returns an empty, concurrency-safe
// in-memory store for mission lifecycle and questions.
func NewMissionInteractionQuestionStore() MissionInteractionQuestionStore {
	return exampleutil.NewMissionInteractionQuestionStore().(MissionInteractionQuestionStore)
}

// MissionInteractionRelayStore keeps relays and their mission state in the
// same transaction boundary. It also supports missionless relays.
type MissionInteractionRelayStore interface {
	MissionStore
	personserver.MissionInteractionRelayStore
}

// NewMissionInteractionRelayStore returns an empty, concurrency-safe in-memory
// store for mission lifecycle and interaction relays.
func NewMissionInteractionRelayStore() MissionInteractionRelayStore {
	return exampleutil.NewMissionInteractionRelayStore().(MissionInteractionRelayStore)
}

// NewPermissionStore returns an empty, concurrency-safe in-memory store for
// missionless permissions.
func NewPermissionStore() personserver.PermissionQueueStore {
	return exampleutil.NewPermissionStore()
}

// NewInteractionQuestionStore returns an empty, concurrency-safe in-memory
// store for missionless questions.
func NewInteractionQuestionStore() personserver.InteractionQuestionQueueStore {
	return exampleutil.NewInteractionQuestionStore()
}

// NewInteractionRelayStore returns an empty, concurrency-safe in-memory store
// for missionless interaction relays.
func NewInteractionRelayStore() personserver.InteractionRelayStore {
	return exampleutil.NewInteractionRelayStore()
}

// NewEnrollmentStore returns an empty, concurrency-safe in-memory enrollment
// and refresh store using clock for refresh expiry.
func NewEnrollmentStore(clock aauth.Clock) agentprovider.EnrollmentStore {
	return exampleutil.NewEnrollmentStore(clock)
}
