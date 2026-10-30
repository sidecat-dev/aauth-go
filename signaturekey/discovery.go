package signaturekey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

const (
	defaultDiscoveryFreshness       = 5 * time.Minute
	minimumDiscoveryRefresh         = time.Minute
	maximumDiscoveryRetention       = 24 * time.Hour
	maximumDiscoveryDocument        = 1 << 20
	defaultDiscoveryPositiveEntries = 1024
	defaultDiscoveryNegativeEntries = 1024
	defaultDiscoveryInFlightEntries = 128
	defaultDiscoveryTimeout         = 10 * time.Second
)

// EgressAdmitter decides whether a discovery endpoint may be contacted.
type EgressAdmitter func(ctx context.Context, endpoint string) error

// HTTPKeyResolverConfig supplies network, time, egress, and capacity policy.
//
// Admit decides, before each fetch, whether a metadata or JWKS URL may be
// contacted. The resolver also checks every connection itself: it dials
// through a clone of Client's *http.Transport (or of a direct default
// transport when Client has none), resolves the host once, refuses the
// destination when any resolved address is not public (PublicDestination) and
// AllowDestination does not admit it, and connects to the exact address it
// checked, so DNS rebinding cannot move the connection. Redirects are never
// followed.
type HTTPKeyResolverConfig struct {
	Client  *http.Client
	Clock   Clock
	Admit   EgressAdmitter
	Limits  HTTPKeyResolverLimits
	Timeout time.Duration
	// AllowDestination admits a non-public destination address that
	// deployment configuration explicitly allows, such as an internal issuer.
	// Nil admits none.
	AllowDestination func(netip.Addr) bool
	// LookupAddresses resolves a discovery host. Nil uses the system resolver.
	LookupAddresses func(context.Context, string) ([]netip.Addr, error)
	// TransportEnforcesEgress states that Client's transport applies these
	// destination controls itself, or makes no network connection at all. The
	// resolver then uses it unchanged. Without it, a transport the resolver
	// cannot dial through (not an *http.Transport, or one with a proxy or a
	// custom TLS dialer) is refused.
	TransportEnforcesEgress bool
}

// HTTPKeyResolverLimits bounds retained successful issuers, retained remote
// failures, and concurrent unique discovery work. Zero fields select finite
// defaults; negative values are invalid.
type HTTPKeyResolverLimits struct {
	PositiveEntries int
	NegativeEntries int
	InFlightEntries int
}

// HTTPKeyResolver performs the Signature-Key two-hop metadata/JWKS discovery
// path with explicit egress admission, bounded reads, caching, and the AAuth
// one-minute unknown-kid refresh floor.
type HTTPKeyResolver struct {
	client  *http.Client
	clock   Clock
	admit   EgressAdmitter
	limits  HTTPKeyResolverLimits
	timeout time.Duration

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
	keys          map[string]jose.JWK
	duplicateKeys map[string]struct{}
	cacheable     bool
	fetchedAt     time.Time
	freshUntil    time.Time
	discardAt     time.Time
}

type discoveryAttempt struct {
	at  time.Time
	err error
}

type discoveryCachePolicy struct {
	freshness time.Duration
	storable  bool
}

// NewHTTPKeyResolver constructs a bounded metadata and JWKS resolver.
func NewHTTPKeyResolver(config HTTPKeyResolverConfig) (*HTTPKeyResolver, error) {
	if config.Client == nil || config.Clock == nil || config.Admit == nil {
		return nil, errors.New("aauth: HTTP key resolver requires client, clock, and egress admitter")
	}
	limits, err := normalizeHTTPKeyResolverLimits(config.Limits)
	if err != nil {
		return nil, err
	}
	if config.Timeout < 0 {
		return nil, errors.New("aauth: HTTP key resolver timeout must not be negative")
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultDiscoveryTimeout
	}
	client, err := discoveryHTTPClient(config)
	if err != nil {
		return nil, err
	}
	return &HTTPKeyResolver{
		client:   client,
		clock:    config.Clock,
		admit:    config.Admit,
		limits:   limits,
		timeout:  timeout,
		cache:    make(map[discoveryCacheKey]discoveryCacheEntry),
		inflight: make(map[discoveryCacheKey]chan struct{}),
		attempts: make(map[discoveryCacheKey]discoveryAttempt),
	}, nil
}

func normalizeHTTPKeyResolverLimits(limits HTTPKeyResolverLimits) (HTTPKeyResolverLimits, error) {
	if limits.PositiveEntries < 0 || limits.NegativeEntries < 0 || limits.InFlightEntries < 0 {
		return HTTPKeyResolverLimits{}, errors.New("aauth: HTTP key resolver limits must not be negative")
	}
	if limits.PositiveEntries == 0 {
		limits.PositiveEntries = defaultDiscoveryPositiveEntries
	}
	if limits.NegativeEntries == 0 {
		limits.NegativeEntries = defaultDiscoveryNegativeEntries
	}
	if limits.InFlightEntries == 0 {
		limits.InFlightEntries = defaultDiscoveryInFlightEntries
	}
	return limits, nil
}

func (resolver *HTTPKeyResolver) ResolveKey(
	ctx context.Context,
	issuer string,
	discoveryDocument string,
	keyID string,
) (jose.JWK, error) {
	return resolver.resolveKey(ctx, issuer, discoveryDocument, keyID, false)
}

// RefreshKey deliberately re-checks metadata and JWKS after a verification
// failure, while retaining the same one-minute issuer refresh floor.
func (resolver *HTTPKeyResolver) RefreshKey(
	ctx context.Context,
	issuer string,
	discoveryDocument string,
	keyID string,
) (jose.JWK, error) {
	return resolver.resolveKey(ctx, issuer, discoveryDocument, keyID, true)
}

func (resolver *HTTPKeyResolver) resolveKey(
	ctx context.Context,
	issuer string,
	discoveryDocument string,
	keyID string,
	forceRefresh bool,
) (jose.JWK, error) {
	if err := validateHTTPSIdentifier(issuer); err != nil {
		return jose.JWK{}, resolutionError(
			ResolutionInvalid,
			fmt.Errorf("aauth: discovery issuer: %w", err),
		)
	}
	if !discoveryNamePattern.MatchString(discoveryDocument) {
		return jose.JWK{}, resolutionError(
			ResolutionInvalid,
			errors.New("aauth: discovery document name is invalid"),
		)
	}
	if keyID == "" {
		return jose.JWK{}, resolutionError(
			ResolutionInvalid,
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
			key, selectionErr := selectDiscoveryKey(entry, issuer, keyID)
			if selectionErr == nil {
				resolver.mu.Unlock()
				return key, nil
			}
			if !isUnknownResolution(selectionErr) {
				resolver.mu.Unlock()
				return jose.JWK{}, selectionErr
			}
			if now.Sub(entry.fetchedAt) < minimumDiscoveryRefresh {
				resolver.mu.Unlock()
				return jose.JWK{}, selectionErr
			}
		}
		if attempted {
			if attempt.err != nil {
				if !forceRefresh && cached {
					key, selectionErr := selectDiscoveryKey(entry, issuer, keyID)
					if selectionErr == nil {
						resolver.mu.Unlock()
						return key, nil
					}
					if !isUnknownResolution(selectionErr) {
						resolver.mu.Unlock()
						return jose.JWK{}, selectionErr
					}
				}
				resolver.mu.Unlock()
				return jose.JWK{}, attempt.err
			}
			if cached {
				key, selectionErr := selectDiscoveryKey(entry, issuer, keyID)
				if selectionErr == nil {
					resolver.mu.Unlock()
					return key, nil
				}
				resolver.mu.Unlock()
				return jose.JWK{}, selectionErr
			}
		}
		if cached && now.Sub(entry.fetchedAt) < minimumDiscoveryRefresh {
			key, selectionErr := selectDiscoveryKey(entry, issuer, keyID)
			if selectionErr == nil {
				resolver.mu.Unlock()
				return key, nil
			}
			resolver.mu.Unlock()
			return jose.JWK{}, selectionErr
		}
		if pending, ok := resolver.inflight[cacheKey]; ok {
			resolver.mu.Unlock()
			select {
			case <-ctx.Done():
				return jose.JWK{}, resolutionError(ResolutionUnavailable, ctx.Err())
			case <-pending:
				continue
			}
		}
		if len(resolver.inflight) >= resolver.limits.InFlightEntries {
			resolver.mu.Unlock()
			return jose.JWK{}, resolutionError(
				ResolutionUnavailable,
				errors.New("aauth: concurrent discovery capacity is exhausted"),
			)
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
			fetchedAt := resolver.clock.Now()
			if fetched.cacheable {
				delete(resolver.attempts, cacheKey)
				resolver.rememberDiscoveryEntryLocked(cacheKey, fetchedAt, fetched)
			} else {
				delete(resolver.cache, cacheKey)
				resolver.rememberDiscoveryFailureLocked(
					cacheKey,
					fetchedAt,
					resolutionError(
						ResolutionUnavailable,
						errors.New("aauth: discovery response forbids reuse and the one-minute refresh floor is active"),
					),
				)
			}
			entry = fetched
		} else if cached {
			entry = resolver.cache[cacheKey]
		}
		close(pending)
		resolver.mu.Unlock()

		if fetchErr != nil {
			if !forceRefresh && cached && entry.discardAt.After(now) {
				key, selectionErr := selectDiscoveryKey(entry, issuer, keyID)
				if selectionErr == nil {
					return key, nil
				}
				if !isUnknownResolution(selectionErr) {
					return jose.JWK{}, selectionErr
				}
			}
			return jose.JWK{}, fetchErr
		}
		return selectDiscoveryKey(fetched, issuer, keyID)
	}
}

func selectDiscoveryKey(entry discoveryCacheEntry, issuer, keyID string) (jose.JWK, error) {
	if _, duplicate := entry.duplicateKeys[keyID]; duplicate {
		return jose.JWK{}, resolutionError(
			ResolutionInvalid,
			fmt.Errorf("aauth: issuer %q has duplicate key id %q", issuer, keyID),
		)
	}
	key, ok := entry.keys[keyID]
	if !ok {
		return jose.JWK{}, resolutionError(
			ResolutionUnknown,
			fmt.Errorf("aauth: issuer %q has no key %q", issuer, keyID),
		)
	}
	if _, err := key.PublicKey(); err != nil {
		return jose.JWK{}, classifyResolvedJWKError(err)
	}
	return key, nil
}

func isUnknownResolution(err error) bool {
	var resolutionError *ResolutionError
	return errors.As(err, &resolutionError) && resolutionError.Code == ResolutionUnknown
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
	var resolutionError *ResolutionError
	return !errors.As(err, &resolutionError) || resolutionError.Code != ResolutionDenied
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
		if oldestAt.IsZero() || attempt.at.Before(oldestAt) ||
			(attempt.at.Equal(oldestAt) && discoveryCacheKeyBefore(existingKey, oldestKey)) {
			oldestKey = existingKey
			oldestAt = attempt.at
		}
	}
	if _, exists := resolver.attempts[key]; !exists &&
		len(resolver.attempts) >= resolver.limits.NegativeEntries {
		delete(resolver.attempts, oldestKey)
	}
	resolver.attempts[key] = discoveryAttempt{at: now, err: err}
}

func (resolver *HTTPKeyResolver) rememberDiscoveryEntryLocked(
	key discoveryCacheKey,
	now time.Time,
	entry discoveryCacheEntry,
) {
	var oldestKey discoveryCacheKey
	var oldestAt time.Time
	for existingKey, existing := range resolver.cache {
		if !existing.discardAt.After(now) {
			delete(resolver.cache, existingKey)
			continue
		}
		if oldestAt.IsZero() || existing.fetchedAt.Before(oldestAt) ||
			(existing.fetchedAt.Equal(oldestAt) && discoveryCacheKeyBefore(existingKey, oldestKey)) {
			oldestKey = existingKey
			oldestAt = existing.fetchedAt
		}
	}
	if _, exists := resolver.cache[key]; !exists &&
		len(resolver.cache) >= resolver.limits.PositiveEntries {
		delete(resolver.cache, oldestKey)
	}
	resolver.cache[key] = entry
}

func discoveryCacheKeyBefore(left, right discoveryCacheKey) bool {
	if left.issuer != right.issuer {
		return left.issuer < right.issuer
	}
	return left.document < right.document
}

func (resolver *HTTPKeyResolver) fetch(
	ctx context.Context,
	issuer string,
	discoveryDocument string,
) (discoveryCacheEntry, error) {
	metadataEndpoint := issuer + "/.well-known/" + discoveryDocument
	metadataBytes, metadataPolicy, err := resolver.fetchJSON(ctx, metadataEndpoint)
	if err != nil {
		return discoveryCacheEntry{}, err
	}
	if err := jsonstrict.RejectAmbiguousNames(metadataBytes); err != nil {
		return discoveryCacheEntry{}, resolutionError(
			ResolutionInvalid,
			fmt.Errorf("aauth: validate discovery metadata JSON: %w", err),
		)
	}
	var metadata struct {
		Issuer           string `json:"issuer"`
		JWKSURI          string `json:"jwks_uri"`
		LogoURI          string `json:"logo_uri"`
		LogoDarkURI      string `json:"logo_dark_uri"`
		DocumentationURI string `json:"documentation_uri"`
		TosURI           string `json:"tos_uri"`
		PolicyURI        string `json:"policy_uri"`
	}
	if err := jsonstrict.RejectCaseVariants(metadataBytes, &metadata); err != nil {
		return discoveryCacheEntry{}, resolutionError(
			ResolutionInvalid,
			fmt.Errorf("aauth: validate discovery metadata fields: %w", err),
		)
	}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return discoveryCacheEntry{}, resolutionError(
			ResolutionInvalid,
			fmt.Errorf("aauth: decode discovery metadata: %w", err),
		)
	}
	if metadata.Issuer == "" {
		return discoveryCacheEntry{}, resolutionError(
			ResolutionIssuerMissing,
			errors.New("aauth: discovery metadata issuer is required"),
		)
	}
	if metadata.Issuer != issuer {
		return discoveryCacheEntry{}, resolutionError(
			ResolutionIssuerMismatch,
			fmt.Errorf("aauth: discovery metadata issuer %q does not match %q", metadata.Issuer, issuer),
		)
	}
	if err := validateDiscoveryURL(metadata.JWKSURI); err != nil {
		return discoveryCacheEntry{}, resolutionError(
			ResolutionInvalid,
			fmt.Errorf("aauth: discovery jwks_uri: %w", err),
		)
	}
	if err := validateOptionalDisplayURIs(map[string]string{
		"logo_uri": metadata.LogoURI, "logo_dark_uri": metadata.LogoDarkURI,
		"documentation_uri": metadata.DocumentationURI, "tos_uri": metadata.TosURI,
		"policy_uri": metadata.PolicyURI,
	}); err != nil {
		return discoveryCacheEntry{}, resolutionError(
			ResolutionInvalid,
			fmt.Errorf("aauth: discovery metadata: %w", err),
		)
	}
	keySetBytes, keySetPolicy, err := resolver.fetchJSON(ctx, metadata.JWKSURI)
	if err != nil {
		return discoveryCacheEntry{}, err
	}
	if err := jsonstrict.RejectAmbiguousNames(keySetBytes); err != nil {
		return discoveryCacheEntry{}, resolutionError(
			ResolutionInvalid,
			fmt.Errorf("aauth: validate JWKS JSON: %w", err),
		)
	}
	var keySet struct {
		Keys []jose.JWK `json:"keys"`
	}
	if err := jsonstrict.RejectCaseVariants(keySetBytes, &keySet); err != nil {
		return discoveryCacheEntry{}, resolutionError(
			ResolutionInvalid,
			fmt.Errorf("aauth: validate JWKS fields: %w", err),
		)
	}
	if err := json.Unmarshal(keySetBytes, &keySet); err != nil {
		return discoveryCacheEntry{}, resolutionError(
			ResolutionInvalid,
			fmt.Errorf("aauth: decode JWKS: %w", err),
		)
	}
	if len(keySet.Keys) == 0 {
		return discoveryCacheEntry{}, resolutionError(
			ResolutionInvalid,
			errors.New("aauth: discovered JWKS contains no keys"),
		)
	}
	keys := make(map[string]jose.JWK, len(keySet.Keys))
	duplicateKeys := make(map[string]struct{})
	for _, key := range keySet.Keys {
		if key.Kid == "" {
			continue
		}
		if _, duplicate := duplicateKeys[key.Kid]; duplicate {
			continue
		}
		if _, exists := keys[key.Kid]; exists {
			delete(keys, key.Kid)
			duplicateKeys[key.Kid] = struct{}{}
			continue
		}
		keys[key.Kid] = key
	}

	freshness := metadataPolicy.freshness
	if keySetPolicy.freshness < freshness {
		freshness = keySetPolicy.freshness
	}
	now := resolver.clock.Now()
	return discoveryCacheEntry{
		keys:          keys,
		duplicateKeys: duplicateKeys,
		cacheable:     metadataPolicy.storable && keySetPolicy.storable,
		fetchedAt:     now,
		freshUntil:    now.Add(freshness),
		discardAt:     now.Add(maximumDiscoveryRetention),
	}, nil
}

func (resolver *HTTPKeyResolver) fetchJSON(ctx context.Context, endpoint string) ([]byte, discoveryCachePolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, resolver.timeout)
	defer cancel()
	if err := validateDiscoveryURL(endpoint); err != nil {
		return nil, discoveryCachePolicy{}, resolutionError(ResolutionInvalid, err)
	}
	if err := resolver.admit(ctx, endpoint); err != nil {
		code := ResolutionDenied
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			code = ResolutionUnavailable
		}
		return nil, discoveryCachePolicy{}, resolutionError(
			code,
			fmt.Errorf("aauth: discovery egress admission failed for %q: %w", endpoint, err),
		)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, discoveryCachePolicy{}, resolutionError(
			ResolutionInvalid,
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
		var classified *ResolutionError
		if errors.As(err, &classified) && classified.Code == ResolutionDenied {
			return nil, discoveryCachePolicy{}, resolutionError(
				ResolutionDenied,
				fmt.Errorf("aauth: discovery connection denied for %q: %w", endpoint, err),
			)
		}
		return nil, discoveryCachePolicy{}, resolutionError(
			ResolutionUnavailable,
			fmt.Errorf("aauth: fetch discovery endpoint %q: %w", endpoint, err),
		)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8<<10))
		return nil, discoveryCachePolicy{}, resolutionError(
			ResolutionUnavailable,
			fmt.Errorf("aauth: discovery endpoint %q returned %s", endpoint, response.Status),
		)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumDiscoveryDocument+1))
	if err != nil {
		return nil, discoveryCachePolicy{}, resolutionError(
			ResolutionUnavailable,
			fmt.Errorf("aauth: read discovery endpoint %q: %w", endpoint, err),
		)
	}
	if len(body) > maximumDiscoveryDocument {
		return nil, discoveryCachePolicy{}, resolutionError(
			ResolutionInvalid,
			fmt.Errorf("aauth: discovery endpoint %q exceeds %d bytes", endpoint, maximumDiscoveryDocument),
		)
	}
	return body, parseDiscoveryCachePolicy(strings.Join(response.Header.Values("Cache-Control"), ",")), nil
}

func validateOptionalDisplayURIs(fields map[string]string) error {
	for name, value := range fields {
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return fmt.Errorf("%s must be an absolute https URL", name)
		}
	}
	return nil
}

func validateDiscoveryURL(endpoint string) error {
	if strings.Contains(endpoint, "#") {
		return errors.New("URL must not contain a fragment")
	}
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

func parseDiscoveryCachePolicy(cacheControl string) discoveryCachePolicy {
	directives := strings.Split(cacheControl, ",")
	noCache := false
	for _, directive := range directives {
		name, _, _ := strings.Cut(strings.TrimSpace(strings.ToLower(directive)), "=")
		if name == "no-store" {
			return discoveryCachePolicy{}
		}
		if name == "no-cache" {
			noCache = true
		}
	}
	if noCache {
		return discoveryCachePolicy{storable: true}
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
			duration = maximumDiscoveryRetention
		}
		return discoveryCachePolicy{freshness: duration, storable: true}
	}
	return discoveryCachePolicy{freshness: defaultDiscoveryFreshness, storable: true}
}
