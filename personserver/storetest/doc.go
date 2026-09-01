// Package storetest checks reusable Person Server store contracts.
//
// An application that implements deferred authorization with clarification can
// run the clarification contract against its real store adapter:
//
//	func TestClarificationStore(t *testing.T) {
//		storetest.RunClarification(t, storetest.Contract{
//			New: func(testing.TB) storetest.ClarificationStore {
//				return newApplicationStore()
//			},
//		})
//	}
//
// A missionless permission store uses the separate focused contract:
//
//	func TestPermissionStore(t *testing.T) {
//		storetest.RunPermission(t, storetest.PermissionContract{
//			New: func(testing.TB) personserver.PermissionStore {
//				return newApplicationPermissionStore()
//			},
//		})
//	}
//
// A mission and permission store uses the atomic combined contract:
//
//	func TestMissionPermissionStore(t *testing.T) {
//		storetest.RunMissionPermission(t, storetest.MissionPermissionContract{
//			New: func(testing.TB) (personserver.MissionPermissionStore, personserver.MissionRecord) {
//				return newApplicationMissionPermissionStore()
//			},
//		})
//	}
//
// A mission store that also accepts audit records uses:
//
//	func TestMissionAuditStore(t *testing.T) {
//		storetest.RunAudit(t, storetest.AuditContract{
//			New: func(testing.TB) (personserver.MissionAuditStore, personserver.MissionRecord) {
//				return newApplicationMissionAuditStore()
//			},
//		})
//	}
//
// Missionless and mission-bound Interaction-question stores use
// RunInteractionQuestion and RunMissionInteractionQuestion respectively.
//
// Missionless and mission-bound Interaction-relay stores use
// RunInteractionRelay and RunMissionInteractionRelay respectively.
//
// New must return a fresh, empty store. The contract checks the public state
// transitions, identity binding, copy isolation, retry rules, concurrency,
// expiry, cancellation, and error atomicity appropriate to that store.
// Applications still need their own restart, transaction, and backend-failure
// tests.
package storetest
