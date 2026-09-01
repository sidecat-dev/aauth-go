package agentprovider

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

var (
	// ErrEnrollmentNotFound reports an unknown durable-key identity.
	ErrEnrollmentNotFound = errors.New("aauth: agent enrollment not found")
	// ErrEnrollmentConflict reports retained enrollment facts that do not match.
	ErrEnrollmentConflict = errors.New("aauth: agent enrollment conflicts with retained state")
	// ErrEnrollmentInactive reports a disabled or revoked enrollment.
	ErrEnrollmentInactive = errors.New("aauth: agent enrollment is not active")
	// ErrEnrollmentDenied reports an application-policy refusal.
	ErrEnrollmentDenied = errors.New("aauth: agent enrollment denied by policy")
	// ErrInvalidEnrollmentRequest reports invalid repository-profile input.
	ErrInvalidEnrollmentRequest = errors.New("aauth: invalid Agent enrollment request")
	// ErrRefreshNotFound reports an unknown refresh identity.
	ErrRefreshNotFound = errors.New("aauth: agent refresh not found")
	// ErrRefreshConflict reports a refresh identity reused with changed input.
	ErrRefreshConflict = errors.New("aauth: agent refresh conflicts with retained state")
	// ErrRefreshExpired reports that no first result may be committed after the
	// verified delegation's expiry.
	ErrRefreshExpired = errors.New("aauth: agent refresh delegation expired before commit")
	// ErrRefreshDenied reports an application-policy refusal.
	ErrRefreshDenied = errors.New("aauth: agent refresh denied by policy")
	// ErrInvalidRefreshRequest reports invalid repository-profile input.
	ErrInvalidRefreshRequest = errors.New("aauth: invalid Agent refresh request")
)

// EnrollmentState is the Agent Provider's current renewal state for one
// durable-key identity.
type EnrollmentState string

const (
	// EnrollmentActive permits new Agent-token issuance.
	EnrollmentActive EnrollmentState = "active"
	// EnrollmentDisabled temporarily refuses new issuance. A host may restore
	// it to active only by increasing the record revision.
	EnrollmentDisabled EnrollmentState = "disabled"
	// EnrollmentRevoked permanently refuses this durable-key enrollment.
	EnrollmentRevoked EnrollmentState = "revoked"
)

// EnrollmentRecord binds one durable key to one stable top-level Agent.
// Revision starts at one and must increase on every host-managed state change;
// administrative transitions are outside the issuance-store interface.
type EnrollmentRecord struct {
	Identity    string
	IdentityKey jose.JWK
	Agent       string
	State       EnrollmentState
	Revision    uint64
}

// Equal reports whether every enrollment fact is identical.
func (record EnrollmentRecord) Equal(other EnrollmentRecord) bool {
	return record.Identity == other.Identity && record.Agent == other.Agent &&
		record.State == other.State && record.Revision == other.Revision &&
		record.IdentityKey.Equal(other.IdentityKey)
}

// RefreshProfile identifies the key pattern authenticated by one refresh.
type RefreshProfile string

const (
	RefreshProfileTwoKey    RefreshProfile = "two-key"
	RefreshProfileSingleKey RefreshProfile = "single-key"
)

// RefreshRecord binds one exact verified refresh request to its first issued
// Agent token. Hosts retain it through RequestExpiresAt at minimum.
type RefreshRecord struct {
	Identity         string
	Profile          RefreshProfile
	RequestJTI       string
	RequestSHA256    [sha256.Size]byte
	Agent            string
	PersonServer     string
	Confirmation     jose.JWK
	RequestExpiresAt time.Time
	AgentToken       string
	TokenExpiresAt   time.Time
}

// SameRequest reports whether two records identify the same refresh request.
func (record RefreshRecord) SameRequest(other RefreshRecord) bool {
	return record.Identity == other.Identity && record.Profile == other.Profile &&
		record.RequestJTI == other.RequestJTI &&
		record.RequestSHA256 == other.RequestSHA256 && record.Agent == other.Agent &&
		record.PersonServer == other.PersonServer && record.Confirmation.Equal(other.Confirmation) &&
		record.RequestExpiresAt.Equal(other.RequestExpiresAt)
}

// EnrollmentStore atomically creates stable enrollments and exact refresh
// results. CommitEnrollment must reject an Agent already bound to a different
// durable Identity. Refresh identity is (Identity, RequestJTI). CommitRefresh must
// compare the current enrollment with expected, let one first writer retain
// the complete candidate, return that retained winner to every concurrent
// exact caller, and reject any different request under the same identity.
//
// A refresh record, including its compact AgentToken, must remain available
// through RequestExpiresAt. If the token expires first, an exact replay
// still returns those bytes and the Agent rejects the expired token; the
// caller must start a new refresh with a new JTI. After its trusted clock
// reaches RequestExpiresAt, CommitRefresh may return an existing exact
// winner or conflict but must return ErrRefreshExpired rather than create a
// first record. That lookup/insert decision and any pruning must be
// linearizable. This prevents a request verified just before expiry from
// recreating a pruned result. Policy and candidate minting may run more than
// once before a first writer wins, so those dependencies must be
// concurrency-safe and side-effect-free or idempotent.
type EnrollmentStore interface {
	CommitEnrollment(context.Context, EnrollmentRecord) (EnrollmentRecord, error)
	LoadEnrollment(context.Context, string) (EnrollmentRecord, error)
	LoadRefresh(context.Context, string, string) (RefreshRecord, error)
	CommitRefresh(context.Context, EnrollmentRecord, RefreshRecord) (RefreshRecord, error)
}

// EnrollmentRequest contains the verified durable-key identity and opaque
// evidence bytes authenticated by that request. The host policy must validate
// the evidence's account or session state, nonce freshness, and any platform
// trust chain it relies on.
type EnrollmentRequest struct {
	Identity    string
	IdentityKey jose.JWK
	Evidence    json.RawMessage
}

// EnrollmentDecision assigns the stable top-level Agent identity.
type EnrollmentDecision struct {
	Agent string
}

// RefreshRequest contains the retained enrollment, verified delegation, and
// application-owned policy input.
type RefreshRequest struct {
	Enrollment            EnrollmentRecord
	Profile               RefreshProfile
	Delegation            signaturekey.JKTJWTDelegation
	RequestedPersonServer string
	Evidence              json.RawMessage
}

// RefreshDecision supplies the permitted claims for one Agent token.
// PersonServer must exactly approve RequestedPersonServer; it cannot replace
// the caller's requested value.
type RefreshDecision struct {
	PersonServer     string
	Lifetime         time.Duration
	AdditionalClaims map[string]json.RawMessage
}

// EnrollmentServiceConfig composes Agent Provider issuance with host policy
// and retained enrollment state.
type EnrollmentServiceConfig struct {
	Provider *Server
	Store    EnrollmentStore
	// Enroll is called only when no enrollment exists for the verified durable
	// identity. It validates application evidence and must not consume an
	// irreversible external consequence; CommitEnrollment owns publication.
	Enroll func(context.Context, EnrollmentRequest) (EnrollmentDecision, error)
	// Refresh may run concurrently for the same first request before the store
	// selects a winner. It must be safe to repeat; only the retained winner is
	// returned to callers.
	Refresh func(context.Context, RefreshRequest) (RefreshDecision, error)
}

// EnrollmentService performs verified enrollment and exact-result refresh.
type EnrollmentService struct {
	provider *Server
	store    EnrollmentStore
	enroll   func(context.Context, EnrollmentRequest) (EnrollmentDecision, error)
	refresh  func(context.Context, RefreshRequest) (RefreshDecision, error)
}

type enrollmentHTTPInput struct {
	Evidence json.RawMessage `json:"evidence"`
}

type refreshHTTPInput struct {
	PersonServer     string          `json:"ps,omitempty"`
	Evidence         json.RawMessage `json:"evidence"`
	RefreshJTI       string          `json:"refresh_jti,omitempty"`
	RefreshExpiresAt int64           `json:"refresh_expires_at,omitempty"`
}

// NewEnrollmentService validates and constructs an enrollment service.
func NewEnrollmentService(config EnrollmentServiceConfig) (*EnrollmentService, error) {
	if config.Provider == nil || config.Store == nil || config.Enroll == nil || config.Refresh == nil {
		return nil, errors.New("aauth: complete Agent Provider enrollment configuration is required")
	}
	return &EnrollmentService{
		provider: config.Provider,
		store:    config.Store,
		enroll:   config.Enroll,
		refresh:  config.Refresh,
	}, nil
}
