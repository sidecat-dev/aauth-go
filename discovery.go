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
}

type discoveryCacheKey struct {
	issuer   string
	document string
}

type discoveryCacheEntry struct {
	keys       map[string]JWK
	fetchedAt  time.Time
	freshUntil time.Time
	discardAt  time.Time
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

func (resolver *HTTPKeyResolver) resolveKey(
	ctx context.Context,
	issuer string,
	discoveryDocument string,
	keyID string,
	forceRefresh bool,
) (JWK, error) {
	if err := ValidateServerIdentifier(issuer); err != nil {
		return JWK{}, fmt.Errorf("aauth: discovery issuer: %w", err)
	}
	if !discoveryDocumentPattern.MatchString(discoveryDocument) {
		return JWK{}, errors.New("aauth: discovery document name is invalid")
	}
	if keyID == "" {
		return JWK{}, errors.New("aauth: discovery key id is required")
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
		if cached && !forceRefresh && entry.freshUntil.After(now) {
			if key, ok := entry.keys[keyID]; ok {
				resolver.mu.Unlock()
				return key, nil
			}
			if now.Sub(entry.fetchedAt) < minimumDiscoveryRefresh {
				resolver.mu.Unlock()
				return JWK{}, fmt.Errorf("aauth: issuer %q has no key %q and refresh is rate-limited", issuer, keyID)
			}
		}
		if cached && now.Sub(entry.fetchedAt) < minimumDiscoveryRefresh {
			if forceRefresh {
				resolver.mu.Unlock()
				return JWK{}, fmt.Errorf("aauth: issuer %q refresh is rate-limited", issuer)
			}
			if key, ok := entry.keys[keyID]; ok {
				resolver.mu.Unlock()
				return key, nil
			}
			resolver.mu.Unlock()
			return JWK{}, fmt.Errorf("aauth: issuer %q has no key %q and refresh is rate-limited", issuer, keyID)
		}
		if pending, ok := resolver.inflight[cacheKey]; ok {
			resolver.mu.Unlock()
			select {
			case <-ctx.Done():
				return JWK{}, ctx.Err()
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
		if fetchErr == nil {
			resolver.cache[cacheKey] = fetched
			entry = fetched
		} else if cached {
			entry = resolver.cache[cacheKey]
		}
		close(pending)
		resolver.mu.Unlock()

		if fetchErr != nil {
			if cached && entry.discardAt.After(now) {
				if key, ok := entry.keys[keyID]; ok {
					return key, nil
				}
			}
			return JWK{}, fetchErr
		}
		key, ok := fetched.keys[keyID]
		if !ok {
			return JWK{}, fmt.Errorf("aauth: issuer %q has no key %q", issuer, keyID)
		}
		return key, nil
	}
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
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return discoveryCacheEntry{}, fmt.Errorf("aauth: decode discovery metadata: %w", err)
	}
	if metadata.Issuer != issuer {
		return discoveryCacheEntry{}, fmt.Errorf("aauth: discovery metadata issuer %q does not match %q", metadata.Issuer, issuer)
	}
	if err := validateDiscoveryURL(metadata.JWKSURI); err != nil {
		return discoveryCacheEntry{}, fmt.Errorf("aauth: discovery jwks_uri: %w", err)
	}

	keySetBytes, keySetFreshness, err := resolver.fetchJSON(ctx, metadata.JWKSURI)
	if err != nil {
		return discoveryCacheEntry{}, err
	}
	var keySet struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(keySetBytes, &keySet); err != nil {
		return discoveryCacheEntry{}, fmt.Errorf("aauth: decode JWKS: %w", err)
	}
	if len(keySet.Keys) == 0 {
		return discoveryCacheEntry{}, errors.New("aauth: discovered JWKS contains no keys")
	}
	keys := make(map[string]JWK, len(keySet.Keys))
	for _, key := range keySet.Keys {
		if key.Kid == "" {
			return discoveryCacheEntry{}, errors.New("aauth: discovered JWK has no kid")
		}
		if _, exists := keys[key.Kid]; exists {
			return discoveryCacheEntry{}, fmt.Errorf("aauth: discovered JWKS has duplicate kid %q", key.Kid)
		}
		if _, err := key.PublicKey(); err != nil {
			return discoveryCacheEntry{}, fmt.Errorf("aauth: discovered JWK %q: %w", key.Kid, err)
		}
		keys[key.Kid] = key
	}

	freshness := metadataFreshness
	if keySetFreshness < freshness {
		freshness = keySetFreshness
	}
	now := resolver.clock.Now()
	return discoveryCacheEntry{
		keys:       keys,
		fetchedAt:  now,
		freshUntil: now.Add(freshness),
		discardAt:  now.Add(maximumDiscoveryRetention),
	}, nil
}

func (resolver *HTTPKeyResolver) fetchJSON(ctx context.Context, endpoint string) ([]byte, time.Duration, error) {
	if err := validateDiscoveryURL(endpoint); err != nil {
		return nil, 0, err
	}
	if err := resolver.admit(ctx, endpoint); err != nil {
		return nil, 0, fmt.Errorf("aauth: discovery egress denied for %q: %w", endpoint, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("aauth: create discovery request: %w", err)
	}
	request.Header.Set("Accept", "application/json")

	client := *resolver.client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("aauth: discovery redirects are not followed")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("aauth: fetch discovery endpoint %q: %w", endpoint, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8<<10))
		return nil, 0, fmt.Errorf("aauth: discovery endpoint %q returned %s", endpoint, response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumDiscoveryDocument+1))
	if err != nil {
		return nil, 0, fmt.Errorf("aauth: read discovery endpoint %q: %w", endpoint, err)
	}
	if len(body) > maximumDiscoveryDocument {
		return nil, 0, fmt.Errorf("aauth: discovery endpoint %q exceeds %d bytes", endpoint, maximumDiscoveryDocument)
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
	for _, directive := range strings.Split(cacheControl, ",") {
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
