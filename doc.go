// Package aauth implements the Core token profiles and validation primitives
// used by the AAuth role packages in this module.
//
// Start with [VerifyAgentToken], [VerifyPersonToken], [VerifyResourceToken]
// or [VerifyAuthToken] to check an individual token. [MintAgentToken] creates
// an Agent token with an issuer-owned signing key. These Core checks do not
// verify an HTTP request or apply application access policy; the resource
// package provides handlers that compose those checks. See
// USE-IN-YOUR-SERVICE.md for the tested service example and GLOSSARY.md for
// roles, token fields, key resolution and clocks.
//
// The current implementation covers direct Agent and Person identity access,
// Resource-managed opaque sessions, immediate and deferred three-party PS
// authorization, immediate four-party federation, mission-bound authorization
// through both topologies, parent-mediated one-level sub-agents, bounded
// three-party revocation, and one same-Person-Server Resource call chain. It
// also includes Person-Server-hosted interaction and baseline or Resource-held
// delivery of the auth-token requirement. See CONFORMANCE.md for exact limits.
package aauth
