// Package aauth implements the Core token profiles and validation primitives
// used by the AAuth role packages in this module.
//
// The current implementation covers direct Agent and Person identity access,
// Resource-managed opaque sessions, immediate and deferred three-party PS
// authorization, and one top-level four-party federated path. It also includes
// Person-Server-hosted interaction and baseline or Resource-held delivery of
// the auth-token requirement. See CONFORMANCE.md for the exact implemented and
// unimplemented boundaries.
package aauth
