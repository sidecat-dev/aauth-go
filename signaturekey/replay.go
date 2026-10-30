package signaturekey

import (
	"container/heap"
	"errors"
	"sync"
	"time"
)

const defaultReplayCacheEntries = 1 << 16

// ErrReplayCacheFull reports that a ReplayCache holds as many unexpired
// entries as it may. The request is refused rather than admitted unrecorded,
// because a cache that forgot an entry early would no longer span the skew
// its verifier accepts.
var ErrReplayCacheFull = errors.New("aauth: replay cache is full")

// ReplayCacheConfig bounds a ReplayCache. Zero MaxEntries selects a finite
// default; a negative value is invalid.
type ReplayCacheConfig struct {
	MaxEntries int
}

// ReplayCache refuses a signed request whose (signing-key thumbprint,
// created, @method, @authority, @path) it has already seen while that request
// could still verify. Each entry is held until created plus the request's
// MaxAge: the signature window for an online verifier, or the whole
// created-to-verification skew a delayed verifier accepts, so the cache always
// spans what its verifier admits. A replay is invalid_signature. One cache
// serves one verifier; it is safe for concurrent use.
type ReplayCache struct {
	mu         sync.Mutex
	maxEntries int
	entries    map[replayTuple]time.Time
	expiry     replayExpiryHeap
}

type replayTuple struct {
	thumbprint string
	created    int64
	method     string
	authority  string
	path       string
}

// NewReplayCache constructs an empty replay cache.
func NewReplayCache(config ReplayCacheConfig) (*ReplayCache, error) {
	if config.MaxEntries < 0 {
		return nil, errors.New("aauth: replay cache maximum entries must not be negative")
	}
	maxEntries := config.MaxEntries
	if maxEntries == 0 {
		maxEntries = defaultReplayCacheEntries
	}
	return &ReplayCache{maxEntries: maxEntries, entries: make(map[replayTuple]time.Time)}, nil
}

// Check records one verified request and refuses it with invalid_signature
// when the same tuple is already held. Entries whose span ended before the
// request's verification time are discarded first. A full cache refuses with
// ErrReplayCacheFull.
func (cache *ReplayCache) Check(verified VerifiedRequest) error {
	if cache == nil {
		return errors.New("aauth: replay cache is required")
	}
	if verified.verifiedAt.IsZero() || verified.publicKey.Kty == "" {
		return errors.New("aauth: replay cache requires a verified request")
	}
	thumbprint, err := verified.publicKey.Thumbprint()
	if err != nil {
		return newError(ErrorInvalidKey, err)
	}
	tuple := replayTuple{
		thumbprint: thumbprint,
		created:    verified.created.Unix(),
		method:     verified.method,
		authority:  verified.authority,
		path:       verified.path,
	}
	retainUntil := verified.created.Add(verified.maxAge)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.discardBeforeLocked(verified.verifiedAt)
	if _, seen := cache.entries[tuple]; seen {
		return newError(ErrorInvalidSignature, errors.New("aauth: signed request was already presented"))
	}
	if len(cache.entries) >= cache.maxEntries {
		return ErrReplayCacheFull
	}
	cache.entries[tuple] = retainUntil
	heap.Push(&cache.expiry, replayExpiry{tuple: tuple, retainUntil: retainUntil})
	return nil
}

// Len returns the number of entries the cache holds.
func (cache *ReplayCache) Len() int {
	if cache == nil {
		return 0
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return len(cache.entries)
}

func (cache *ReplayCache) discardBeforeLocked(now time.Time) {
	for cache.expiry.Len() > 0 && cache.expiry[0].retainUntil.Before(now) {
		oldest := heap.Pop(&cache.expiry).(replayExpiry)
		if retained, ok := cache.entries[oldest.tuple]; ok && retained.Equal(oldest.retainUntil) {
			delete(cache.entries, oldest.tuple)
		}
	}
}

type replayExpiry struct {
	tuple       replayTuple
	retainUntil time.Time
}

type replayExpiryHeap []replayExpiry

func (expiry replayExpiryHeap) Len() int { return len(expiry) }
func (expiry replayExpiryHeap) Less(left, right int) bool {
	return expiry[left].retainUntil.Before(expiry[right].retainUntil)
}
func (expiry replayExpiryHeap) Swap(left, right int) {
	expiry[left], expiry[right] = expiry[right], expiry[left]
}
func (expiry *replayExpiryHeap) Push(value any) { *expiry = append(*expiry, value.(replayExpiry)) }
func (expiry *replayExpiryHeap) Pop() any {
	old := *expiry
	last := old[len(old)-1]
	*expiry = old[:len(old)-1]
	return last
}
