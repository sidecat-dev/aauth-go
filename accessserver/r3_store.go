package accessserver

import (
	"context"
	"errors"
	"time"

	aauth "aauth-go"
	"aauth-go/r3"
)

// ErrR3IssuanceConflict reports an attempted replacement of one retained
// Auth-token issuance with different token or audit facts.
var ErrR3IssuanceConflict = errors.New("accessserver: R3 issuance conflicts with retained state")

// R3IssuanceRecord is the exact issued credential and the mandatory R3 audit
// facts committed as one object before the token becomes observable.
type R3IssuanceRecord struct {
	AuthTokenReference aauth.TokenReference
	ExactAuthToken     string
	Resource           string
	R3Reference        r3.Reference
	IssuedAt           time.Time
	PersonServer       string
	Subject            string
	Account            *string
	PresentedJTI       string
	AgentJKT           string
	Agent              string
	ParentAgent        string
}

// R3IssuanceStore durably and confidentially retains one complete issuance as
// permanent audit provenance. Commits for one Auth-token reference must be
// linearizable: Commit copies the record, concurrent exact repeats converge,
// and different state returns ErrR3IssuanceConflict. A non-sentinel error may
// have committed; the handler still withholds the token and performs no hidden
// retry because R3 defines no request replay key.
type R3IssuanceStore interface {
	Commit(context.Context, R3IssuanceRecord) error
}
