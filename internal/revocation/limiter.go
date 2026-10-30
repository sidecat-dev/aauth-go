package revocation

import (
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// maximumTrackedCallers bounds the limiter's memory. Past it, callers whose
// window has emptied are forgotten first.
const maximumTrackedCallers = 10000

// Limiter bounds the revocation requests each verified caller sends within a
// sliding window. It is safe for concurrent use.
type Limiter struct {
	mu       sync.Mutex
	requests int
	window   time.Duration
	hits     map[string][]time.Time
}

// NewLimiter returns a limiter for limits, with zero members defaulted.
func NewLimiter(limits aauth.RevocationLimits) *Limiter {
	limits = Limits(limits)
	return &Limiter{requests: limits.Requests, window: limits.Window, hits: make(map[string][]time.Time)}
}

// Allow counts one request from caller at now. When the caller has used its
// window it counts nothing and returns the delay until it may send again.
func (limiter *Limiter) Allow(caller string, now time.Time) (time.Duration, bool) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	hits := limiter.current(caller, now)
	if len(hits) >= limiter.requests {
		limiter.hits[caller] = hits
		return hits[0].Add(limiter.window).Sub(now), false
	}
	if _, tracked := limiter.hits[caller]; !tracked && len(limiter.hits) >= maximumTrackedCallers {
		limiter.forgetIdle(now)
	}
	limiter.hits[caller] = append(hits, now)
	return 0, true
}

func (limiter *Limiter) current(caller string, now time.Time) []time.Time {
	hits := limiter.hits[caller]
	kept := hits[:0]
	for _, hit := range hits {
		if now.Sub(hit) < limiter.window {
			kept = append(kept, hit)
		}
	}
	return kept
}

func (limiter *Limiter) forgetIdle(now time.Time) {
	for caller := range limiter.hits {
		if len(limiter.current(caller, now)) == 0 {
			delete(limiter.hits, caller)
		}
	}
}
