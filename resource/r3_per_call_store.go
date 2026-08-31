package resource

import (
	"context"
	"errors"
	"time"

	"aauth-go/r3"
)

var (
	// ErrR3ProposalNotFound reports that no exact proposal has the URI.
	ErrR3ProposalNotFound = errors.New("resource: R3 proposal not found")
	// ErrR3ProposalConflict reports that a proposal URI was already reserved.
	// Proposal identifiers are per-invocation and never converge, even when the
	// proposed bytes are identical.
	ErrR3ProposalConflict = errors.New("resource: R3 proposal conflicts with retained state")

	// ErrR3RetryNotFound reports that no baseline retry has the reference.
	ErrR3RetryNotFound = errors.New("resource: R3 retry not found")
	// ErrR3RetryExpired reports a retry that expired before execution.
	ErrR3RetryExpired = errors.New("resource: R3 retry expired")
	// ErrR3RetryConflict reports an incompatible retry lifecycle transition.
	ErrR3RetryConflict = errors.New("resource: R3 retry state conflict")
	// ErrR3RetryTokenMismatch reports a token other than the exact first
	// successfully claimed compact token.
	ErrR3RetryTokenMismatch = errors.New("resource: R3 retry auth token does not match")
	// ErrR3RetryUnresolved reports an execution whose consequence can never be
	// safely reclaimed.
	ErrR3RetryUnresolved = errors.New("resource: R3 retry execution is unresolved")
	// ErrR3RetryCompletionStale reports a retain fence that no longer owns the
	// execution.
	ErrR3RetryCompletionStale = errors.New("resource: R3 retry completion fence is stale")
)

// R3ProposalRecord is one immutable proposal artifact. ExactJSON is the byte
// identity named by Reference. ClassReference binds it to the class
// authorization that caused this one invocation.
type R3ProposalRecord struct {
	Reference        r3.Reference
	ExactJSON        []byte
	PersonServer     string
	AccessServer     string
	ResourceTokenJTI string
	ClassReference   r3.Reference
}

// R3ProposalStore durably and confidentially retains exact proposal bytes
// before their Resource token becomes observable. Commit atomically creates a
// new record and returns ErrR3ProposalConflict whenever the URI already exists,
// including an exact repeat. Load returns an independent copy. Exact proposal
// bytes remain fetchable indefinitely: Auth-token audit provenance retains
// only their URI and digest, and both PS and AS rely on later re-fetch.
type R3ProposalStore interface {
	Commit(context.Context, R3ProposalRecord) error
	Load(context.Context, string) (R3ProposalRecord, error)
}

// R3RetryInvocation is the verified authorization context for one baseline
// 401 retry. ExpiresAt is the proposal Resource-token expiry; CompletionUntil
// is the bounded latest first use of an Auth token issued before ExpiresAt.
// The mutable state keyed by Reference is distinct from immutable proposal
// bytes that may share a content digest with another invocation. ExactProposal
// is the sole durable operation representation and is parsed through the
// Resource's current registry after Load.
type R3RetryInvocation struct {
	Reference       r3.Reference
	ClassReference  r3.Reference
	ResourceToken   string
	ExactProposal   []byte
	RequiredScopes  []string
	PreparedAt      time.Time
	ExpiresAt       time.Time
	CompletionUntil time.Time
}

// R3RetryAuthToken is the exact-token replay binding shared with held
// invocation custody.
type R3RetryAuthToken = HeldAuthToken

// R3RetryClaim is either a fenced first execution or an exact retained replay.
type R3RetryClaim = HeldClaim

// R3RetryExecution is the fenced permission for one application execution.
type R3RetryExecution = HeldExecution

// R3RetryStore owns the baseline 401 single-use and retained-result lifecycle.
// Prepare must durably retain a complete independent copy before the Resource
// exposes the challenge. Claim and Retain have the same exact-token, fencing,
// uncertain-commit, and no-reclaim contract documented by
// HeldInvocationStore, keyed here by the full proposal Reference.
type R3RetryStore interface {
	Prepare(context.Context, R3RetryInvocation) error
	Load(context.Context, r3.Reference) (R3RetryInvocation, error)
	Claim(context.Context, r3.Reference, R3RetryAuthToken) (R3RetryClaim, error)
	Retain(context.Context, R3RetryExecution, HeldResponse) (HeldResponse, error)
}
