// Package signaturekey implements the selected HTTP Signature-Key and
// HTTP Message Signatures profile used by AAuth.
//
// It signs and verifies exact HTTP request proofs, with one signature or
// several, signs and verifies server response signatures, and parses the hwk, jkt-jwt, jwks_uri, jwks, jwt, self-jwt, x509,
// and cached credential schemes. It resolves admitted issuer and JWKS keys,
// validates host-supplied certificate chains, issues and resolves assertion
// cache identifiers, and exposes typed negotiation failures. JWT credentials
// remain opaque: callers such as the root aauth package own token semantics
// and choose the confirmation key used to finish verification.
package signaturekey

import "time"

// Clock supplies the trusted instant used to sign or verify a request.
type Clock interface {
	Now() time.Time
}

// systemClock is the default Clock: the system's current time.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }
