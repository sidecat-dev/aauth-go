package revocation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sort"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// maximumCascades bounds the cascades a Tracker remembers. Past it, the
// cascade retained for the shortest time is forgotten; a poll of its pending
// URL is then 404 and its caller revokes again, which is idempotent.
const maximumCascades = 4096

// Tracker remembers, for each revoked token, which downstream revocations it
// has made and how each ended, and the pending URL a caller polls while any
// has not. It holds soft state only: the revocation itself is recorded in the
// role's store before any cascade runs, and a forgotten cascade is rebuilt by
// revoking again. It is safe for concurrent use.
type Tracker struct {
	mu        sync.Mutex
	cascades  map[aauth.TokenReference]*cascade
	byPending map[string]*cascade
}

type cascade struct {
	key         aauth.TokenReference
	caller      string
	targets     []Target
	outcomes    map[string]Outcome
	pendingID   string
	delivered   bool
	retainUntil time.Time
}

// NewTracker returns an empty tracker.
func NewTracker() *Tracker {
	return &Tracker{cascades: make(map[aauth.TokenReference]*cascade), byPending: make(map[string]*cascade)}
}

// Run is one cascade step for the token key, revoked by caller.
type Run struct {
	Key    aauth.TokenReference
	Caller string
	// Targets are the downstream revocations this token requires. A poll
	// passes none and continues the targets already known.
	Targets []Target
	// Retry re-attempts every target that did not record. A poll continues
	// only the pending ones.
	Retry bool
	// Hold bounds how long the step waits for downstream answers. A target
	// still unanswered then stays pending and is attempted again later.
	Hold time.Duration
	// RetainUntil is how long to remember the cascade.
	RetainUntil time.Time
	// Now is the caller's current time, for eviction.
	Now time.Time
}

// Result is the state of a cascade after one step, one entry per target.
type Result struct {
	Targets    []Target
	Outcomes   []Outcome
	Pending    bool
	PendingID  string
	RetryAfter time.Duration
}

// Step attempts the targets that need it, concurrently, until each answers or
// the hold ends.
func (tracker *Tracker) Step(ctx context.Context, sender *Sender, run Run) Result {
	tracker.mu.Lock()
	current := tracker.cascades[run.Key]
	if current == nil {
		current = &cascade{key: run.Key, caller: run.Caller, outcomes: make(map[string]Outcome)}
		tracker.cascades[run.Key] = current
		tracker.evict(run.Now)
	}
	if run.Targets != nil {
		current.targets = mergeTargets(current.targets, run.Targets)
	}
	if run.RetainUntil.After(current.retainUntil) {
		current.retainUntil = run.RetainUntil
	}
	targets := append([]Target(nil), current.targets...)
	previous := make(map[string]Outcome, len(current.outcomes))
	for key, outcome := range current.outcomes {
		previous[key] = outcome
	}
	tracker.mu.Unlock()

	attempted := make(map[string]Outcome)
	if len(targets) > 0 {
		attempted = attempt(ctx, sender, targets, previous, run)
	}

	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	for key, outcome := range attempted {
		current.outcomes[key] = outcome
	}
	result := Result{Targets: targets, Outcomes: make([]Outcome, len(targets))}
	for index, target := range targets {
		outcome, known := current.outcomes[target.key()]
		if !known {
			outcome = Outcome{Pending: true}
		}
		result.Outcomes[index] = outcome
		if outcome.Pending {
			result.Pending = true
			if outcome.RetryAfter > result.RetryAfter {
				result.RetryAfter = outcome.RetryAfter
			}
		}
	}
	if result.Pending {
		if current.pendingID == "" {
			current.pendingID = newPendingID()
			tracker.byPending[current.pendingID] = current
		}
		current.delivered = false
		result.PendingID = current.pendingID
		if result.RetryAfter <= 0 {
			result.RetryAfter = DefaultRetryAfter
		}
	} else if current.pendingID != "" {
		// The terminal response is now being delivered on the pending URL.
		current.delivered = true
	}
	return result
}

// Pending finds the cascade a pending URL names. It reports false for an
// unknown URL, and for one the caller did not start, which answers 404 alike.
func (tracker *Tracker) Pending(id, caller string) (aauth.TokenReference, bool, bool) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	current := tracker.byPending[id]
	if current == nil || current.caller != caller {
		return aauth.TokenReference{}, false, false
	}
	return current.key, current.delivered, true
}

func (tracker *Tracker) evict(now time.Time) {
	if len(tracker.cascades) <= maximumCascades {
		return
	}
	for key, current := range tracker.cascades {
		if !now.Before(current.retainUntil) {
			tracker.forget(key, current)
		}
	}
	if len(tracker.cascades) <= maximumCascades {
		return
	}
	ordered := make([]*cascade, 0, len(tracker.cascades))
	for _, current := range tracker.cascades {
		ordered = append(ordered, current)
	}
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left].retainUntil.Before(ordered[right].retainUntil)
	})
	for _, current := range ordered[:len(ordered)-maximumCascades] {
		tracker.forget(current.key, current)
	}
}

func (tracker *Tracker) forget(key aauth.TokenReference, current *cascade) {
	delete(tracker.cascades, key)
	if current.pendingID != "" {
		delete(tracker.byPending, current.pendingID)
	}
}

func attempt(ctx context.Context, sender *Sender, targets []Target, previous map[string]Outcome, run Run) map[string]Outcome {
	holdContext, cancel := context.WithTimeout(ctx, run.Hold)
	defer cancel()
	type answer struct {
		key     string
		outcome Outcome
	}
	answers := make(chan answer, len(targets))
	started := 0
	for _, target := range targets {
		prior, known := previous[target.key()]
		switch {
		case known && prior.Recorded:
			continue
		case known && !prior.Pending && !run.Retry:
			continue
		}
		started++
		go func(target Target, prior Outcome) {
			var outcome Outcome
			if prior.Pending && prior.Location != "" {
				outcome = sender.Poll(holdContext, prior.Location, remaining(holdContext))
			} else {
				outcome = sender.Send(holdContext, target, remaining(holdContext))
			}
			if !outcome.Recorded && !outcome.Pending && holdContext.Err() != nil && ctx.Err() == nil &&
				errors.Is(outcome.Cause, context.DeadlineExceeded) {
				// The hold ended before the recipient answered. Its answer is not
				// terminal, so the attempt stays pending and is made again.
				outcome = Outcome{Pending: true, Location: prior.Location, Cause: outcome.Cause}
			}
			answers <- answer{key: target.key(), outcome: outcome}
		}(target, prior)
	}
	attempted := make(map[string]Outcome, started)
	for range started {
		received := <-answers
		attempted[received.key] = received.outcome
	}
	return attempted
}

func remaining(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	return time.Until(deadline)
}

func mergeTargets(known, added []Target) []Target {
	seen := make(map[string]struct{}, len(known)+len(added))
	merged := make([]Target, 0, len(known)+len(added))
	for _, target := range append(append([]Target(nil), known...), added...) {
		if _, duplicate := seen[target.key()]; duplicate {
			continue
		}
		seen[target.key()] = struct{}{}
		merged = append(merged, target)
	}
	return merged
}

func newPendingID() string {
	var random [24]byte
	_, _ = rand.Read(random[:])
	return base64.RawURLEncoding.EncodeToString(random[:])
}

// Aggregate reports one entry per recipient: pending when any revocation
// there is pending, otherwise the worse error, otherwise recorded.
func Aggregate(result Result) []aauth.RevocationAttempt {
	var order []string
	byRecipient := make(map[string]*aauth.RevocationAttempt)
	for index, target := range result.Targets {
		outcome := result.Outcomes[index]
		attempt := byRecipient[target.Recipient]
		if attempt == nil {
			attempt = &aauth.RevocationAttempt{Recipient: target.Recipient}
			byRecipient[target.Recipient] = attempt
			order = append(order, target.Recipient)
		}
		attempt.Downstream = append(attempt.Downstream, outcome.Downstream...)
		if outcome.RetryAfter > attempt.RetryAfter {
			attempt.RetryAfter = outcome.RetryAfter
		}
		switch {
		case outcome.Pending:
			attempt.Pending = true
			attempt.Error = ""
		case attempt.Pending:
		case outcome.Error == aauth.RevocationUnavailable:
			attempt.Error, attempt.Cause = outcome.Error, outcome.Cause
		case outcome.Error == aauth.RevocationUnsupported && attempt.Error == "":
			attempt.Error, attempt.Cause = outcome.Error, outcome.Cause
		}
	}
	attempts := make([]aauth.RevocationAttempt, 0, len(order))
	for _, recipient := range order {
		attempts = append(attempts, *byRecipient[recipient])
	}
	return attempts
}

// Report is the downstream member of a terminal revocation response.
func Report(attempts []aauth.RevocationAttempt) []aauth.DownstreamRevocation {
	report := make([]aauth.DownstreamRevocation, 0, len(attempts))
	for _, attempt := range attempts {
		report = append(report, aauth.DownstreamRevocation{Recipient: attempt.Recipient, Error: attempt.Error})
	}
	return report
}
