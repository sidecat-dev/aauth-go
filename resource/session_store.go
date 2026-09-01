package resource

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrPendingSessionNotFound reports an unknown pending authorization.
	ErrPendingSessionNotFound = errors.New("resource: pending session not found")
	// ErrPendingSessionConflict reports an inconsistent pending transition.
	ErrPendingSessionConflict = errors.New("resource: pending session conflicts with retained state")
	// ErrPendingSessionExpired reports an expired pending authorization.
	ErrPendingSessionExpired = errors.New("resource: pending session expired")
	// ErrPendingSessionGone reports a pending URL after its terminal response.
	ErrPendingSessionGone = errors.New("resource: pending session is gone")
	// ErrSessionInteractionCodeInvalid reports a failed correlation attempt.
	ErrSessionInteractionCodeInvalid = errors.New("resource: session interaction code is invalid")
	// ErrSessionInteractionCodeUsed reports a correlation code already consumed.
	ErrSessionInteractionCodeUsed = errors.New("resource: session interaction code was already used")
	// ErrSessionNotFound reports an unknown opaque session token.
	ErrSessionNotFound = errors.New("resource: session not found")
	// ErrSessionExpired reports a session outside its Resource-owned lifetime.
	ErrSessionExpired = errors.New("resource: session expired")
)

// SessionRecord is the Resource-owned authorization behind one opaque session
// token. AgentProvider, Agent, and ParentAgent form the stable Agent identity;
// the current request proof key is verified separately on every use.
type SessionRecord struct {
	Resource      string
	AgentProvider string
	Agent         string
	ParentAgent   string
	Subject       string
	Scope         []string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// SessionApproval is one opaque token and the exact record retained before
// that token becomes observable.
type SessionApproval struct {
	Token  string
	Record SessionRecord
}

// SessionStore owns opaque token generation or wrapping and its Resource-local
// authorization state. Create copies and retains the record before returning a
// nonempty token and an independent record copy. One token must never identify
// two different retained records. Load returns an independent copy,
// ErrSessionNotFound for an unknown token, and ErrSessionExpired at or after
// the retained expiry.
type SessionStore interface {
	Create(context.Context, SessionRecord) (SessionApproval, error)
	Load(context.Context, string, time.Time) (SessionRecord, error)
}

// PendingSessionRecord is the immutable verified context retained before a
// Resource exposes an interaction URL and code.
type PendingSessionRecord struct {
	ID                  string
	CodeSHA256          [32]byte
	Resource            string
	Request             SessionAuthorizationRequest
	CreatedAt           time.Time
	ExpiresAt           time.Time
	RetryAfter          time.Duration
	MaximumCodeAttempts int
}

// SessionPollState is one Resource-managed pending authorization state.
type SessionPollState uint8

const (
	SessionPollPending SessionPollState = iota + 1
	SessionPollInteracting
	SessionPollApproved
	SessionPollDenied
	SessionPollExpired
	SessionPollGone
)

// PendingSessionSnapshot lets the authenticated host resume one interaction.
type PendingSessionSnapshot struct {
	Record   PendingSessionRecord
	State    SessionPollState
	Approval SessionApproval
}

// SessionPollIdentity binds a pending URL to the stable Agent identity that
// created it.
type SessionPollIdentity struct {
	Resource      string
	AgentProvider string
	Agent         string
	ParentAgent   string
}

// SessionPollRecord is the exact result about to become an HTTP response.
type SessionPollRecord struct {
	State      SessionPollState
	Approval   SessionApproval
	RetryAfter time.Duration
}

// DeferredSessionStore adds Resource-hosted interaction to SessionStore.
// Implementations provide these atomic transitions:
//
//   - CreatePending retains one unique verified request before its 202.
//   - ConsumeInteractionCode normalizes no input itself: it compares the
//     supplied digest, increments failed attempts, and enforces the retained
//     attempt bound, single use, and expiry.
//   - Approve transitions only an interacting record: it preserves every
//     terminal state, atomically refuses expiry, or creates and retains the
//     exact session before approved polling. An exact repeat after approval
//     returns the retained approval; changed state returns
//     ErrPendingSessionConflict.
//   - Poll authenticates the stable Agent identity on every read.
//   - ConsumeResult compares the exact terminal result and changes it to gone
//     immediately before HTTP delivery, as Core requires.
//   - An exact Deny replay succeeds. Invalidate may cancel only pending or
//     interacting state, exact gone replay succeeds, and an approved, denied,
//     or expired terminal decision returns ErrPendingSessionConflict.
//
// All mutable slices and maps crossing this boundary are independent copies.
type DeferredSessionStore interface {
	SessionStore
	CreatePending(context.Context, PendingSessionRecord) error
	ConsumeInteractionCode(context.Context, string, string, [32]byte, time.Time) (PendingSessionRecord, error)
	LoadPending(context.Context, string) (PendingSessionSnapshot, error)
	Approve(context.Context, string, SessionRecord, time.Time) (SessionApproval, error)
	Deny(context.Context, string, time.Time) error
	Invalidate(context.Context, string, time.Time) error
	Poll(context.Context, string, SessionPollIdentity, time.Time) (SessionPollRecord, error)
	ConsumeResult(context.Context, string, SessionPollRecord) error
}

func cloneSessionRecord(record SessionRecord) SessionRecord {
	record.Scope = append([]string(nil), record.Scope...)
	return record
}

func cloneSessionApproval(approval SessionApproval) SessionApproval {
	approval.Record = cloneSessionRecord(approval.Record)
	return approval
}

func cloneSessionAuthorizationRequest(request SessionAuthorizationRequest) SessionAuthorizationRequest {
	request.AgentPrincipal.AdditionalClaims = cloneAdditionalClaims(request.AgentPrincipal.AdditionalClaims)
	request.RequiredScopes = append([]string(nil), request.RequiredScopes...)
	return request
}

func clonePendingSessionRecord(record PendingSessionRecord) PendingSessionRecord {
	record.Request = cloneSessionAuthorizationRequest(record.Request)
	return record
}
