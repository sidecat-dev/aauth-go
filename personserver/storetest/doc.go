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
// New must return a fresh, empty store. The contract checks the public state
// transitions, identity binding, copy isolation, retry rules, concurrency,
// expiry, cancellation, and error atomicity appropriate to that store.
// Applications still need their own restart, transaction, and backend-failure
// tests.
package storetest
