package resource

import (
	"context"
	"encoding/json"
	"errors"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

var (
	// ErrR3DocumentNotFound reports that no retained document has the URI.
	ErrR3DocumentNotFound = errors.New("resource: R3 document not found")
	// ErrR3DocumentConflict reports an attempted change to an immutable record.
	ErrR3DocumentConflict = errors.New("resource: R3 document conflicts with retained state")
)

// R3ClassAuthorizationContext retains the original verified token lineage
// needed to validate and extend one class authorization.
type R3ClassAuthorizationContext struct {
	ExactResourceToken   string
	ResourceToken        aauth.ResourceTokenClaims
	PersonTokenIssuedAt  int64
	PersonTokenNotBefore int64
	PersonTokenExpiresAt int64
}

// R3DocumentRecord is one exact class document, its fetch entitlement, and
// the original verified Person-token lineage needed to form a later per-call
// Resource token.
type R3DocumentRecord struct {
	Reference       r3.Reference
	ExactJSON       []byte
	PersonServer    string
	AuthTokenIssuer string
	// AuthTokenIssuerDocument is aauth-person.json for direct three-party
	// issuance and aauth-access.json for federated issuance.
	AuthTokenIssuerDocument string
	ClassContext            R3ClassAuthorizationContext
}

// Clone returns an independent copy suitable for crossing an R3DocumentStore
// boundary.
func (record R3DocumentRecord) Clone() R3DocumentRecord {
	cloned := record
	cloned.ExactJSON = append([]byte(nil), record.ExactJSON...)
	claims := record.ClassContext.ResourceToken
	if claims.Account != nil {
		account := *claims.Account
		claims.Account = &account
	}
	if claims.Interaction != nil {
		interaction := *claims.Interaction
		claims.Interaction = &interaction
	}
	if claims.AdditionalClaims != nil {
		claims.AdditionalClaims = make(map[string]json.RawMessage, len(claims.AdditionalClaims))
		for name, value := range record.ClassContext.ResourceToken.AdditionalClaims {
			claims.AdditionalClaims[name] = append(json.RawMessage(nil), value...)
		}
	}
	cloned.ClassContext.ResourceToken = claims
	return cloned
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
