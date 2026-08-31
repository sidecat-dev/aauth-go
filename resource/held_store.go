package resource

import (
	"context"
	"errors"
	"net/http"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/r3"
)

// ErrHeldInvocationNotFound reports that no held invocation has the supplied
// pending identifier.
var ErrHeldInvocationNotFound = errors.New("resource: held invocation not found")

// ErrHeldInvocationExpired reports that a held invocation expired before it
// could be claimed.
var ErrHeldInvocationExpired = errors.New("resource: held invocation expired")

// ErrHeldInvocationConflict reports that the requested transition conflicts
// with the held invocation's current state.
var ErrHeldInvocationConflict = errors.New("resource: held invocation state conflict")

// ErrHeldExecutionUnresolved reports that a claimed invocation became
// indeterminate and can never be executed again.
var ErrHeldExecutionUnresolved = errors.New("resource: held execution is unresolved")

// ErrHeldAuthTokenMismatch reports that a completed invocation was claimed
// with an auth token other than the exact token bound to its completion.
var ErrHeldAuthTokenMismatch = errors.New("resource: held auth token does not match")

// ErrHeldCompletionStale reports that an execution fence no longer authorizes
// retaining a held invocation.
var ErrHeldCompletionStale = errors.New("resource: held completion fence is stale")

// HeldInvocation is the application request and verified authorization
// context that a Resource retains while returning a pending response.
//
// ResourceTokenIssuedAt anchors signature and claim verification after the
// short Resource token expires. ExpiresAt is that token's expiry;
// CompletionUntil is the latest first-presentation horizon for an Auth token
// issued before ExpiresAt. A completed response remains replayable afterward.
// Header, Body, and
// RequiredScopes and R3PerCall are mutable Go values. Store implementations
// must copy them at the Create and Load boundaries described by
// HeldInvocationStore.
type HeldInvocation struct {
	Method                string
	Scheme                string
	URLHost               string
	Host                  string
	EscapedPath           string
	RawPath               string
	RawQuery              string
	ForceQuery            bool
	RequestURI            string
	Header                http.Header
	Body                  []byte
	BodyKind              HeldRequestBodyKind
	HasGetBody            bool
	ContentLength         int64
	Proto                 string
	ProtoMajor            int
	ProtoMinor            int
	ResourceToken         string
	ResourceTokenIssuedAt time.Time
	RequiredScopes        []string
	ExpiresAt             time.Time
	CompletionUntil       time.Time
	R3PerCall             *HeldR3PerCall
}

// HeldR3PerCall binds a pending invocation to the exact per-call proposal
// created before the Resource exposed its 202 response. The proposal and
// class references identify immutable retained records. ExactProposal carries
// the complete operation, parameter, account, and display artifact and is
// parsed through the Resource's current registry after Load.
type HeldR3PerCall struct {
	Reference      r3.Reference
	ClassReference r3.Reference
	ExactProposal  []byte
}

// HeldRequestBodyKind preserves the handler-visible representation of an
// empty or byte-backed request body across delayed execution.
type HeldRequestBodyKind string

const (
	HeldRequestBodyNil    HeldRequestBodyKind = "nil"
	HeldRequestBodyNoBody HeldRequestBodyKind = "no-body"
	HeldRequestBodyBytes  HeldRequestBodyKind = "bytes"
)

// HeldAuthToken identifies the exact compact auth token presented when an
// invocation is claimed. SHA256 is the digest of the compact token's exact
// bytes. PresentedAt is the verified poll-proof time. RetainUntil is the latest
// time its replay binding must remain available.
type HeldAuthToken struct {
	SHA256      [32]byte
	PresentedAt time.Time
	RetainUntil time.Time
}

// HeldResponse is the exact logical application response retained for replay.
// Header, Body, and Trailer exclude transport-specific framing.
type HeldResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Trailer    http.Header
}

// HeldExecution is a fenced grant to execute one held invocation. InvocationID
// identifies the invocation, and Fence prevents a stale executor from
// completing it.
type HeldExecution struct {
	InvocationID string
	Fence        string
}

type heldClaimKind uint8

const (
	heldClaimExecution heldClaimKind = iota + 1
	heldClaimReplay
)

// HeldClaim is exactly one successful Claim result: either permission to
// execute a pending invocation or a previously retained response to replay.
// Its zero value is invalid and exposes neither branch.
type HeldClaim struct {
	kind      heldClaimKind
	execution HeldExecution
	replay    HeldResponse
}

// NewHeldExecution returns a claim that grants the fenced execution.
func NewHeldExecution(execution HeldExecution) HeldClaim {
	return HeldClaim{kind: heldClaimExecution, execution: execution}
}

// NewHeldReplay returns a replay claim that owns an independent copy of
// response.
func NewHeldReplay(response HeldResponse) HeldClaim {
	return HeldClaim{kind: heldClaimReplay, replay: cloneHeldResponse(response)}
}

// Execution returns the fenced execution when claim is an execution branch.
func (claim HeldClaim) Execution() (HeldExecution, bool) {
	if claim.kind != heldClaimExecution {
		return HeldExecution{}, false
	}
	return claim.execution, true
}

// Replay returns an independent copy of the retained response when claim is a
// replay branch.
func (claim HeldClaim) Replay() (HeldResponse, bool) {
	if claim.kind != heldClaimReplay {
		return HeldResponse{}, false
	}
	return cloneHeldResponse(claim.replay), true
}

func cloneHeldResponse(response HeldResponse) HeldResponse {
	return HeldResponse{
		StatusCode: response.StatusCode,
		Header:     response.Header.Clone(),
		Body:       append([]byte(nil), response.Body...),
		Trailer:    response.Trailer.Clone(),
	}
}

// HeldInvocationStore is the Resource host's durable authorization and
// persistence boundary for held application requests. Records contain
// sensitive request headers, bodies, and tokens. Implementations must preserve
// their confidentiality and every field's exact integrity across Create and
// Load. The Resource does not repeat the original request proof or mutable route
// policy after Load; changing a method, target, header, or body can change the
// protected consequence. The Resource, not the store, owns application
// execution. Store methods must never invoke application code.
//
// Before calling Claim, the Resource fully verifies the compact auth token and
// its request proof. The store receives only the digest of those exact compact
// token bytes as the completion and replay binding.
type HeldInvocationStore interface {
	// Create durably takes ownership of an independent copy of invocation
	// before returning an opaque, unguessable, URL-safe pending identifier.
	// Later caller mutations must not change the stored invocation.
	// The Resource must not send the corresponding HTTP 202 response until
	// Create returns successfully.
	Create(context.Context, HeldInvocation) (string, error)

	// Load returns an independent, immutable snapshot of the held invocation
	// so the Resource can verify the later request before attempting Claim.
	// Mutating the returned value must not change the stored invocation.
	Load(context.Context, string) (HeldInvocation, error)

	// Claim atomically moves a pending invocation to executing and binds it to
	// the exact auth-token digest. That transition returns an execution claim.
	// PresentedAt is the verified poll-proof time. Claim must return
	// ErrHeldInvocationExpired instead of an execution claim when PresentedAt
	// is not before the pending invocation's CompletionUntil. The Resource has
	// already verified that the Auth token was issued before ExpiresAt. Completed invocations
	// remain replayable after that pending deadline.
	// A missing invocation returns ErrHeldInvocationNotFound, an expired pending
	// invocation returns ErrHeldInvocationExpired, and an invocation already
	// executing returns ErrHeldInvocationConflict. A completed invocation
	// claimed with the same digest returns a replay claim; a different digest
	// returns ErrHeldAuthTokenMismatch. An unresolved invocation returns
	// ErrHeldExecutionUnresolved and must never become executable again.
	Claim(context.Context, string, HeldAuthToken) (HeldClaim, error)

	// Retain verifies execution's fence, durably stores an independent copy of
	// the exact logical response before returning, and returns an independent
	// copy of the stored response. The Resource must not publish any response
	// status, header, body, or trailer before Retain succeeds and returns;
	// retention and publication must not run concurrently. A fence that no
	// longer owns the execution returns ErrHeldCompletionStale. Any other error
	// has uncertain commit state. The Resource must not infer that retention
	// failed, return the claim to pending, or execute the application again.
	// Once Retain returns such an error, a later Claim must expose either the
	// committed replay or ErrHeldExecutionUnresolved.
	// ErrHeldInvocationConflict is only valid while the original execution or
	// retention call is still active.
	Retain(context.Context, HeldExecution, HeldResponse) (HeldResponse, error)
}
