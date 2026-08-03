package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultDiscoveryFreshness = 5 * time.Minute
	minimumDiscoveryRefresh   = time.Minute
	maximumDiscoveryRetention = 24 * time.Hour
	maximumDiscoveryDocument  = 1 << 20
	maximumDiscoveryFailures  = 1024
)

var discoveryDocumentPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.json$`)

// EgressAdmitter decides whether a discovery endpoint may be contacted.
type EgressAdmitter func(ctx context.Context, endpoint string) error

type HTTPKeyResolverConfig struct {
	Client *http.Client
	Clock  Clock
	Admit  EgressAdmitter
}

// HTTPKeyResolver performs the Signature-Key two-hop metadata/JWKS discovery
// path with explicit egress admission, bounded reads, caching, and the AAuth
// one-minute unknown-kid refresh floor.
type HTTPKeyResolver struct {
	client *http.Client
	clock  Clock
	admit  EgressAdmitter

	mu       sync.Mutex
	cache    map[discoveryCacheKey]discoveryCacheEntry
	inflight map[discoveryCacheKey]chan struct{}
	attempts map[discoveryCacheKey]discoveryAttempt
}

type discoveryCacheKey struct {
	issuer   string
	document string
}

type discoveryCacheEntry struct {
	keys          map[string]JWK
	eventMetadata *AgentEventMetadata
	fetchedAt     time.Time
	freshUntil    time.Time
	discardAt     time.Time
}

// AgentEventMetadata is the admitted Events routing projection of one current
// agent-provider discovery document.
type AgentEventMetadata struct {
	Issuer        string
	EventEndpoint string
}

type discoveryAttempt struct {
	at  time.Time
	err error
}

func NewHTTPKeyResolver(config HTTPKeyResolverConfig) (*HTTPKeyResolver, error) {
	if config.Client == nil || config.Clock == nil || config.Admit == nil {
		return nil, errors.New("aauth: HTTP key resolver requires client, clock, and egress admitter")
	}
	return &HTTPKeyResolver{
		client:   config.Client,
		clock:    config.Clock,
		admit:    config.Admit,
		cache:    make(map[discoveryCacheKey]discoveryCacheEntry),
		inflight: make(map[discoveryCacheKey]chan struct{}),
		attempts: make(map[discoveryCacheKey]discoveryAttempt),
	}, nil
}

func (resolver *HTTPKeyResolver) ResolveKey(
	ctx context.Context,
	issuer string,
	discoveryDocument string,
	keyID string,
) (JWK, error) {
	return resolver.resolveKey(ctx, issuer, discoveryDocument, keyID, false)
}

// RefreshKey deliberately re-checks metadata and JWKS after a verification
// failure, while retaining the same one-minute issuer refresh floor.
func (resolver *HTTPKeyResolver) RefreshKey(
	ctx context.Context,
	issuer string,
	discoveryDocument string,
	keyID string,
) (JWK, error) {
	return resolver.resolveKey(ctx, issuer, discoveryDocument, keyID, true)
}

// ResolveAgentEventMetadata returns the current admitted Events endpoint under
// the same discovery cache and single-flight boundary used for issuer keys.
func (resolver *HTTPKeyResolver) ResolveAgentEventMetadata(
	ctx context.Context,
	issuer string,
) (AgentEventMetadata, error) {
	var zero AgentEventMetadata
	if err := ValidateServerIdentifier(issuer); err != nil {
		return zero, keyResolutionError(KeyResolutionInvalid, fmt.Errorf("aauth: event metadata issuer: %w", err))
	}
	cacheKey := discoveryCacheKey{issuer: issuer, document: AgentDiscoveryDocument}
	for {
		now := resolver.clock.Now()
		resolver.mu.Lock()
		entry, cached := resolver.cache[cacheKey]
		if cached && !entry.discardAt.After(now) {
			delete(resolver.cache, cacheKey)
			entry = discoveryCacheEntry{}
			cached = false
		}
		if cached && entry.freshUntil.After(now) {
			metadata := entry.eventMetadata
			resolver.mu.Unlock()
			if metadata == nil {
				return zero, keyResolutionError(KeyResolutionInvalid, errors.New("aauth: agent metadata does not advertise Events"))
			}
			return *metadata, nil
		}
		if attempt, attempted := resolver.attempts[cacheKey]; attempted {
			if attempt.at.Add(minimumDiscoveryRefresh).After(now) && attempt.err != nil {
				resolver.mu.Unlock()
				return zero, attempt.err
			}
			delete(resolver.attempts, cacheKey)
		}
		if pending, ok := resolver.inflight[cacheKey]; ok {
			resolver.mu.Unlock()
			select {
			case <-ctx.Done():
				return zero, keyResolutionError(KeyResolutionUnavailable, ctx.Err())
			case <-pending:
				continue
			}
		}
		pending := make(chan struct{})
		resolver.inflight[cacheKey] = pending
		resolver.mu.Unlock()

		fetched, fetchErr := resolver.fetch(ctx, issuer, AgentDiscoveryDocument)

		resolver.mu.Lock()
		delete(resolver.inflight, cacheKey)
		if retainDiscoveryFailure(fetchErr) {
			resolver.rememberDiscoveryFailureLocked(cacheKey, resolver.clock.Now(), fetchErr)
		}
		if fetchErr == nil {
			resolver.cache[cacheKey] = fetched
		}
		close(pending)
		resolver.mu.Unlock()
		if fetchErr != nil {
			return zero, fetchErr
		}
		if fetched.eventMetadata == nil {
			return zero, keyResolutionError(KeyResolutionInvalid, errors.New("aauth: agent metadata does not advertise Events"))
		}
		return *fetched.eventMetadata, nil
	}
}

func (resolver *HTTPKeyResolver) resolveKey(
	ctx context.Context,
	issuer string,
	discoveryDocument string,
	keyID string,
	forceRefresh bool,
) (JWK, error) {
	if err := ValidateServerIdentifier(issuer); err != nil {
		return JWK{}, keyResolutionError(
			KeyResolutionInvalid,
			fmt.Errorf("aauth: discovery issuer: %w", err),
		)
	}
	if !discoveryDocumentPattern.MatchString(discoveryDocument) {
		return JWK{}, keyResolutionError(
			KeyResolutionInvalid,
			errors.New("aauth: discovery document name is invalid"),
		)
	}
	if keyID == "" {
		return JWK{}, keyResolutionError(
			KeyResolutionInvalid,
			errors.New("aauth: discovery key id is required"),
		)
	}
	cacheKey := discoveryCacheKey{issuer: issuer, document: discoveryDocument}

	for {
		now := resolver.clock.Now()
		resolver.mu.Lock()
		entry, cached := resolver.cache[cacheKey]
		if cached && !entry.discardAt.After(now) {
			delete(resolver.cache, cacheKey)
			entry = discoveryCacheEntry{}
			cached = false
		}
		attempt, attempted := resolver.attempts[cacheKey]
		if attempted && !attempt.at.Add(minimumDiscoveryRefresh).After(now) {
			delete(resolver.attempts, cacheKey)
			attempt = discoveryAttempt{}
			attempted = false
		}
		if cached && !forceRefresh && entry.freshUntil.After(now) {
			if key, ok := entry.keys[keyID]; ok {
				resolver.mu.Unlock()
				return key, nil
			}
			if now.Sub(entry.fetchedAt) < minimumDiscoveryRefresh {
				resolver.mu.Unlock()
				return JWK{}, keyResolutionError(
					KeyResolutionUnknown,
					fmt.Errorf("aauth: issuer %q has no key %q and refresh is rate-limited", issuer, keyID),
				)
			}
		}
		if attempted {
			if attempt.err != nil {
				if !forceRefresh && cached {
					if key, ok := entry.keys[keyID]; ok {
						resolver.mu.Unlock()
						return key, nil
					}
				}
				resolver.mu.Unlock()
				return JWK{}, attempt.err
			}
			if cached {
				if key, ok := entry.keys[keyID]; ok {
					resolver.mu.Unlock()
					return key, nil
				}
				resolver.mu.Unlock()
				return JWK{}, keyResolutionError(
					KeyResolutionUnknown,
					fmt.Errorf("aauth: issuer %q has no key %q and refresh is rate-limited", issuer, keyID),
				)
			}
		}
		if cached && now.Sub(entry.fetchedAt) < minimumDiscoveryRefresh {
			if key, ok := entry.keys[keyID]; ok {
				resolver.mu.Unlock()
				return key, nil
			}
			resolver.mu.Unlock()
			return JWK{}, keyResolutionError(
				KeyResolutionUnknown,
				fmt.Errorf("aauth: issuer %q has no key %q and refresh is rate-limited", issuer, keyID),
			)
		}
		if pending, ok := resolver.inflight[cacheKey]; ok {
			resolver.mu.Unlock()
			select {
			case <-ctx.Done():
				return JWK{}, keyResolutionError(KeyResolutionUnavailable, ctx.Err())
			case <-pending:
				continue
			}
		}
		pending := make(chan struct{})
		resolver.inflight[cacheKey] = pending
		resolver.mu.Unlock()

		fetched, fetchErr := resolver.fetch(ctx, issuer, discoveryDocument)

		resolver.mu.Lock()
		delete(resolver.inflight, cacheKey)
		if retainDiscoveryFailure(fetchErr) {
			resolver.rememberDiscoveryFailureLocked(cacheKey, resolver.clock.Now(), fetchErr)
		}
		if fetchErr == nil {
			resolver.cache[cacheKey] = fetched
			entry = fetched
		} else if cached {
			entry = resolver.cache[cacheKey]
		}
		close(pending)
		resolver.mu.Unlock()

		if fetchErr != nil {
			if !forceRefresh && cached && entry.discardAt.After(now) {
				if key, ok := entry.keys[keyID]; ok {
					return key, nil
				}
			}
			return JWK{}, fetchErr
		}
		key, ok := fetched.keys[keyID]
		if !ok {
			return JWK{}, keyResolutionError(
				KeyResolutionUnknown,
				fmt.Errorf("aauth: issuer %q has no key %q", issuer, keyID),
			)
		}
		return key, nil
	}
}

// retainDiscoveryFailure distinguishes a shared remote failure from a
// caller-local interruption or an egress decision. A canceled caller must not
// make an issuer unavailable to healthy callers, and a denied request did not
// fetch the issuer's JWKS, so neither participates in the remote refresh floor.
func retainDiscoveryFailure(err error) bool {
	if err == nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var resolutionError *KeyResolutionError
	return !errors.As(err, &resolutionError) || resolutionError.Code != KeyResolutionDenied
}

// rememberDiscoveryFailureLocked bounds negative refresh state even when an
// attacker supplies many unique issuer/document pairs. Expired entries are
// removed on every insertion; when the live set reaches its cap, the oldest
// attempt is evicted.
func (resolver *HTTPKeyResolver) rememberDiscoveryFailureLocked(
	key discoveryCacheKey,
	now time.Time,
	err error,
) {
	var oldestKey discoveryCacheKey
	var oldestAt time.Time
	for existingKey, attempt := range resolver.attempts {
		if !attempt.at.Add(minimumDiscoveryRefresh).After(now) {
			delete(resolver.attempts, existingKey)
			continue
		}
		if oldestAt.IsZero() || attempt.at.Before(oldestAt) {
			oldestKey = existingKey
			oldestAt = attempt.at
		}
	}
	if _, exists := resolver.attempts[key]; !exists &&
		len(resolver.attempts) >= maximumDiscoveryFailures {
		delete(resolver.attempts, oldestKey)
	}
	resolver.attempts[key] = discoveryAttempt{at: now, err: err}
}

func (resolver *HTTPKeyResolver) fetch(
	ctx context.Context,
	issuer string,
	discoveryDocument string,
) (discoveryCacheEntry, error) {
	metadataEndpoint := issuer + "/.well-known/" + discoveryDocument
	metadataBytes, metadataFreshness, err := resolver.fetchJSON(ctx, metadataEndpoint)
	if err != nil {
		return discoveryCacheEntry{}, err
	}
	var metadata struct {
		Issuer        string `json:"issuer"`
		JWKSURI       string `json:"jwks_uri"`
		EventEndpoint string `json:"event_endpoint"`
	}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return discoveryCacheEntry{}, keyResolutionError(
			KeyResolutionInvalid,
			fmt.Errorf("aauth: decode discovery metadata: %w", err),
		)
	}
	if metadata.Issuer != issuer {
		return discoveryCacheEntry{}, keyResolutionError(
			KeyResolutionInvalid,
			fmt.Errorf("aauth: discovery metadata issuer %q does not match %q", metadata.Issuer, issuer),
		)
	}
	if err := validateDiscoveryURL(metadata.JWKSURI); err != nil {
		return discoveryCacheEntry{}, keyResolutionError(
			KeyResolutionInvalid,
			fmt.Errorf("aauth: discovery jwks_uri: %w", err),
		)
	}
	var eventMetadata *AgentEventMetadata
	if discoveryDocument == AgentDiscoveryDocument && metadata.EventEndpoint != "" {
		if err := validateDiscoveryURL(metadata.EventEndpoint); err != nil {
			return discoveryCacheEntry{}, keyResolutionError(
				KeyResolutionInvalid,
				fmt.Errorf("aauth: discovery event_endpoint: %w", err),
			)
		}
		eventMetadata = &AgentEventMetadata{Issuer: issuer, EventEndpoint: metadata.EventEndpoint}
	}

	keySetBytes, keySetFreshness, err := resolver.fetchJSON(ctx, metadata.JWKSURI)
	if err != nil {
		return discoveryCacheEntry{}, err
	}
	var keySet struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(keySetBytes, &keySet); err != nil {
		return discoveryCacheEntry{}, keyResolutionError(
			KeyResolutionInvalid,
			fmt.Errorf("aauth: decode JWKS: %w", err),
		)
	}
	if len(keySet.Keys) == 0 {
		return discoveryCacheEntry{}, keyResolutionError(
			KeyResolutionInvalid,
			errors.New("aauth: discovered JWKS contains no keys"),
		)
	}
	keys := make(map[string]JWK, len(keySet.Keys))
	for _, key := range keySet.Keys {
		if key.Kid == "" {
			return discoveryCacheEntry{}, keyResolutionError(
				KeyResolutionInvalid,
				errors.New("aauth: discovered JWK has no kid"),
			)
		}
		if _, exists := keys[key.Kid]; exists {
			return discoveryCacheEntry{}, keyResolutionError(
				KeyResolutionInvalid,
				fmt.Errorf("aauth: discovered JWKS has duplicate kid %q", key.Kid),
			)
		}
		if _, err := key.PublicKey(); err != nil {
			return discoveryCacheEntry{}, keyResolutionError(
				KeyResolutionInvalid,
				fmt.Errorf("aauth: discovered JWK %q: %w", key.Kid, err),
			)
		}
		keys[key.Kid] = key
	}

	freshness := metadataFreshness
	if keySetFreshness < freshness {
		freshness = keySetFreshness
	}
	now := resolver.clock.Now()
	return discoveryCacheEntry{
		keys:          keys,
		eventMetadata: eventMetadata,
		fetchedAt:     now,
		freshUntil:    now.Add(freshness),
		discardAt:     now.Add(maximumDiscoveryRetention),
	}, nil
}

func (resolver *HTTPKeyResolver) fetchJSON(ctx context.Context, endpoint string) ([]byte, time.Duration, error) {
	if err := validateDiscoveryURL(endpoint); err != nil {
		return nil, 0, keyResolutionError(KeyResolutionInvalid, err)
	}
	if err := resolver.admit(ctx, endpoint); err != nil {
		code := KeyResolutionDenied
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			code = KeyResolutionUnavailable
		}
		return nil, 0, keyResolutionError(
			code,
			fmt.Errorf("aauth: discovery egress admission failed for %q: %w", endpoint, err),
		)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, keyResolutionError(
			KeyResolutionInvalid,
			fmt.Errorf("aauth: create discovery request: %w", err),
		)
	}
	request.Header.Set("Accept", "application/json")

	client := *resolver.client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("aauth: discovery redirects are not followed")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, keyResolutionError(
			KeyResolutionUnavailable,
			fmt.Errorf("aauth: fetch discovery endpoint %q: %w", endpoint, err),
		)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8<<10))
		return nil, 0, keyResolutionError(
			KeyResolutionUnavailable,
			fmt.Errorf("aauth: discovery endpoint %q returned %s", endpoint, response.Status),
		)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumDiscoveryDocument+1))
	if err != nil {
		return nil, 0, keyResolutionError(
			KeyResolutionUnavailable,
			fmt.Errorf("aauth: read discovery endpoint %q: %w", endpoint, err),
		)
	}
	if len(body) > maximumDiscoveryDocument {
		return nil, 0, keyResolutionError(
			KeyResolutionInvalid,
			fmt.Errorf("aauth: discovery endpoint %q exceeds %d bytes", endpoint, maximumDiscoveryDocument),
		)
	}
	return body, cacheFreshness(response.Header.Get("Cache-Control")), nil
}

func validateDiscoveryURL(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("URL must be absolute https")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return errors.New("URL must not contain userinfo or fragment")
	}
	return nil
}

func cacheFreshness(cacheControl string) time.Duration {
	directives := strings.Split(cacheControl, ",")
	for _, directive := range directives {
		name, _, _ := strings.Cut(strings.TrimSpace(strings.ToLower(directive)), "=")
		if name == "no-store" || name == "no-cache" {
			return 0
		}
	}
	for _, directive := range directives {
		name, value, found := strings.Cut(strings.TrimSpace(strings.ToLower(directive)), "=")
		if !found || name != "max-age" {
			continue
		}
		seconds, err := strconv.ParseInt(strings.Trim(value, `"`), 10, 64)
		if err != nil || seconds < 0 {
			break
		}
		duration := time.Duration(seconds) * time.Second
		if duration > maximumDiscoveryRetention {
			return maximumDiscoveryRetention
		}
		return duration
	}
	return defaultDiscoveryFreshness
}
