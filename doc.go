// Package aauth implements the Core token profiles and validation primitives
// used by the AAuth role packages in this module.
//
// The current implementation covers direct Agent and Person identity access,
// Resource-managed opaque sessions, immediate and deferred three-party PS
// authorization, immediate four-party federation, mission-bound authorization
// through both topologies, parent-mediated one-level sub-agents, bounded
// three-party revocation, and one same-Person-Server Resource call chain. It
// also includes Person-Server-hosted interaction and baseline or Resource-held
// delivery of the auth-token requirement. See CONFORMANCE.md for exact limits.
package aauth
