package r3

import (
	"context"
	"errors"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// ErrIssuanceConflict reports an attempted replacement of one retained
// Auth-token issuance with different audit facts.
var ErrIssuanceConflict = errors.New("r3: issuance conflicts with retained state")

// IssuanceRecord contains the mandatory R3 audit facts committed as one object
// before the corresponding token becomes observable.
type IssuanceRecord struct {
	AuthTokenReference aauth.TokenReference
	Resource           string
	R3Reference        Reference
	// Vocabulary is the exact URI selected while parsing the referenced
	// document or proposal, retained so audit consumers need not re-fetch it.
	Vocabulary   VocabularyURI
	IssuedAt     time.Time
	PersonServer string
	Subject      string
	Account      *string
	PresentedJTI string
	AgentJKT     string
	Agent        string
	ParentAgent  string
}

// IssuanceStore durably and confidentially retains one complete mandatory
// issuance audit record. Commits for one Auth-token reference must be
// linearizable: Commit copies the record, concurrent exact repeats converge,
// and different state returns ErrIssuanceConflict. A non-sentinel error may
// have committed; the caller must withhold the token and perform no hidden
// retry because R3 defines no request replay key.
type IssuanceStore interface {
	Commit(context.Context, IssuanceRecord) error
}
