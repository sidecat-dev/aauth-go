package resource

import (
	"context"
	"errors"

	"aauth-go/r3"
)

var (
	// ErrR3DocumentNotFound reports that no retained document has the URI.
	ErrR3DocumentNotFound = errors.New("resource: R3 document not found")
	// ErrR3DocumentConflict reports an attempted change to an immutable record.
	ErrR3DocumentConflict = errors.New("resource: R3 document conflicts with retained state")
)

// R3DocumentRecord is one exact Resource-owned document and the two server
// roles entitled to fetch it. ExactJSON is the byte identity named by
// Reference; it is not a re-serializable model.
type R3DocumentRecord struct {
	Reference    r3.Reference
	ExactJSON    []byte
	PersonServer string
	AccessServer string
}

// R3DocumentStore durably and confidentially retains exact R3 bytes before
// their Resource token becomes observable. The signed document endpoint is
// the only protocol surface that may expose a record. No pruning operation is
// defined: committed records remain loadable across Resource recomposition.
//
// Commit must copy its input, atomically retain the whole record, accept
// concurrent exact repeats, and return ErrR3DocumentConflict when the same URI
// already names any different bytes or entitlement. A failed commit must not
// alter an existing record. A non-sentinel error may have committed a new
// record; retrying that exact record must therefore converge.
//
// Load returns an independent copy keyed by exact reference URI and returns
// ErrR3DocumentNotFound when the URI has never been committed.
type R3DocumentStore interface {
	Commit(context.Context, R3DocumentRecord) error
	Load(context.Context, string) (R3DocumentRecord, error)
}
