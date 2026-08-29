// Package signaturekey implements the selected HTTP Signature-Key and
// HTTP Message Signatures profile used by AAuth.
//
// It signs and verifies exact HTTP request proofs, parses the closed supported
// credential schemes, resolves admitted issuer keys, and exposes typed
// negotiation failures. JWT credentials remain opaque: callers such as the
// root aauth package own token semantics and choose the confirmation key used
// to finish verification.
package signaturekey

import "time"

// Clock supplies the trusted instant used to sign or verify a request.
type Clock interface {
	Now() time.Time
}
