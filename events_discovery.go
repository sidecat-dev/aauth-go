package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultEventsContractEntries  = 256
	defaultEventsContractInFlight = 64
)

// AgentEventMetadata is the Events-routing projection of one admitted agent
// provider metadata document. It is intentionally separate from Signature-Key
// key discovery.
type AgentEventMetadata struct {
	Issuer        string
	EventEndpoint string
}

// HTTPEventsContractResolverConfig supplies the explicit network, time, and
// egress-policy boundaries for AsyncAPI resource discovery.
type HTTPEventsContractResolverConfig struct {
	Client *http.Client
	Clock  Clock
	Admit  EgressAdmitter
	Limits HTTPEventsContractResolverLimits
}

// HTTPEventsContractResolverLimits bounds retained resource contracts and
// concurrent unique fetches. Zero selects finite defaults.
type HTTPEventsContractResolverLimits struct {
	PositiveEntries int
	InFlightEntries int
}

// HTTPEventsContractResolver discovers the Events AsyncAPI R3 value through
// resource metadata and retains parsed exact contracts under standard HTTP
// freshness. Contract endpoints must remain on the resource origin.
type HTTPEventsContractResolver struct {
	client *http.Client
	clock  Clock
	admit  EgressAdmitter
	limits HTTPEventsContractResolverLimits

	mu       sync.Mutex
	cache    map[string]eventsContractCacheEntry
	inflight map[string]chan struct{}
}

type eventsContractCacheEntry struct {
	contract   *EventsAsyncAPIContract
	fetchedAt  time.Time
	freshUntil time.Time
	discardAt  time.Time
}

func NewHTTPEventsContractResolver(
	config HTTPEventsContractResolverConfig,
) (*HTTPEventsContractResolver, error) {
	if config.Client == nil || config.Clock == nil || config.Admit == nil {
		return nil, errors.New("aauth: Events contract resolver requires client, clock, and egress admitter")
	}
	limits := config.Limits
	if limits.PositiveEntries < 0 || limits.InFlightEntries < 0 {
		return nil, errors.New("aauth: Events contract resolver limits must not be negative")
	}
	if limits.PositiveEntries == 0 {
		limits.PositiveEntries = defaultEventsContractEntries
	}
	if limits.InFlightEntries == 0 {
		limits.InFlightEntries = defaultEventsContractInFlight
	}
	return &HTTPEventsContractResolver{
		client: config.Client, clock: config.Clock, admit: config.Admit, limits: limits,
		cache: make(map[string]eventsContractCacheEntry), inflight: make(map[string]chan struct{}),
	}, nil
}

// Resolve returns the exact current admitted Events contract for one resource.
func (resolver *HTTPEventsContractResolver) Resolve(
	ctx context.Context,
	resource string,
) (*EventsAsyncAPIContract, error) {
	if resolver == nil {
		return nil, errors.New("aauth: Events contract resolver is required")
	}
	if err := ValidateServerIdentifier(resource); err != nil {
		return nil, fmt.Errorf("aauth: Events contract resource: %w", err)
	}
	for {
		now := resolver.clock.Now()
		resolver.mu.Lock()
		entry, cached := resolver.cache[resource]
		if cached && !entry.discardAt.After(now) {
			delete(resolver.cache, resource)
			entry = eventsContractCacheEntry{}
			cached = false
		}
		if cached && entry.freshUntil.After(now) {
			resolver.mu.Unlock()
			return entry.contract, nil
		}
		if pending, ok := resolver.inflight[resource]; ok {
			resolver.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-pending:
				continue
			}
		}
		if len(resolver.inflight) >= resolver.limits.InFlightEntries {
			resolver.mu.Unlock()
			return nil, errors.New("aauth: concurrent Events contract discovery capacity is exhausted")
		}
		pending := make(chan struct{})
		resolver.inflight[resource] = pending
		resolver.mu.Unlock()

		fetched, err := resolver.fetch(ctx, resource)

		resolver.mu.Lock()
		delete(resolver.inflight, resource)
		if err == nil {
			resolver.rememberLocked(resource, fetched, resolver.clock.Now())
		}
		close(pending)
		resolver.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return fetched.contract, nil
	}
}

func (resolver *HTTPEventsContractResolver) rememberLocked(
	resource string,
	entry eventsContractCacheEntry,
	now time.Time,
) {
	var oldestResource string
	var oldestAt time.Time
	for existingResource, existing := range resolver.cache {
		if !existing.discardAt.After(now) {
			delete(resolver.cache, existingResource)
			continue
		}
		if oldestAt.IsZero() || existing.fetchedAt.Before(oldestAt) ||
			(existing.fetchedAt.Equal(oldestAt) && existingResource < oldestResource) {
			oldestResource = existingResource
			oldestAt = existing.fetchedAt
		}
	}
	if _, exists := resolver.cache[resource]; !exists && len(resolver.cache) >= resolver.limits.PositiveEntries {
		delete(resolver.cache, oldestResource)
	}
	resolver.cache[resource] = entry
}

func (resolver *HTTPEventsContractResolver) fetch(
	ctx context.Context,
	resource string,
) (eventsContractCacheEntry, error) {
	metadataEndpoint := resource + "/.well-known/" + ResourceDiscoveryDocument
	metadataBytes, metadataFreshness, err := resolver.fetchJSON(ctx, metadataEndpoint)
	if err != nil {
		return eventsContractCacheEntry{}, err
	}
	if err := rejectDuplicateJSONNames(metadataBytes); err != nil {
		return eventsContractCacheEntry{}, fmt.Errorf("aauth: Events resource metadata: %w", err)
	}
	var metadata struct {
		Issuer         string                     `json:"issuer"`
		R3Vocabularies map[string]json.RawMessage `json:"r3_vocabularies"`
	}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return eventsContractCacheEntry{}, fmt.Errorf("aauth: decode Events resource metadata: %w", err)
	}
	if metadata.Issuer != resource {
		return eventsContractCacheEntry{}, errors.New("aauth: Events resource metadata issuer does not match")
	}
	rawEndpoint, ok := metadata.R3Vocabularies[R3VocabularyAsyncAPI]
	if !ok {
		return eventsContractCacheEntry{}, errors.New("aauth: resource does not advertise the Events AsyncAPI vocabulary")
	}
	var endpointReference string
	if err := json.Unmarshal(rawEndpoint, &endpointReference); err != nil || endpointReference == "" {
		return eventsContractCacheEntry{}, errors.New("aauth: Events AsyncAPI vocabulary endpoint is invalid")
	}
	contractEndpoint, err := sameResourceEventsEndpoint(resource, endpointReference)
	if err != nil {
		return eventsContractCacheEntry{}, err
	}
	contractBytes, contractFreshness, err := resolver.fetchJSON(ctx, contractEndpoint)
	if err != nil {
		return eventsContractCacheEntry{}, err
	}
	contract, err := ParseEventsAsyncAPI(contractBytes)
	if err != nil {
		return eventsContractCacheEntry{}, err
	}
	freshness := metadataFreshness
	if contractFreshness < freshness {
		freshness = contractFreshness
	}
	now := resolver.clock.Now()
	return eventsContractCacheEntry{
		contract: contract, fetchedAt: now, freshUntil: now.Add(freshness),
		discardAt: now.Add(maximumDiscoveryRetention),
	}, nil
}

func sameResourceEventsEndpoint(resource string, reference string) (string, error) {
	base, err := url.Parse(resource)
	if err != nil {
		return "", fmt.Errorf("aauth: parse Events resource: %w", err)
	}
	relative, err := url.Parse(reference)
	if err != nil {
		return "", errors.New("aauth: Events AsyncAPI endpoint is invalid")
	}
	if relative.User != nil || relative.RawQuery != "" || relative.Fragment != "" || relative.Path == "" {
		return "", errors.New("aauth: Events AsyncAPI endpoint must be an unqualified path or same-origin URL")
	}
	if !relative.IsAbs() && !strings.HasPrefix(reference, "/") {
		return "", errors.New("aauth: Events AsyncAPI relative endpoint must be root-relative")
	}
	resolved := base.ResolveReference(relative)
	if resolved.Scheme != base.Scheme || resolved.Host != base.Host || resolved.RawQuery != "" || resolved.Fragment != "" {
		return "", errors.New("aauth: Events AsyncAPI endpoint must remain on the resource origin")
	}
	return resolved.String(), nil
}

func (resolver *HTTPEventsContractResolver) fetchJSON(
	ctx context.Context,
	endpoint string,
) ([]byte, time.Duration, error) {
	if err := validateDiscoveryURL(endpoint); err != nil {
		return nil, 0, fmt.Errorf("aauth: Events discovery endpoint: %w", err)
	}
	if err := resolver.admit(ctx, endpoint); err != nil {
		return nil, 0, fmt.Errorf("aauth: Events discovery egress admission failed for %q: %w", endpoint, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Accept", "application/json")
	client := *resolver.client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("aauth: Events discovery redirects are not followed")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("aauth: fetch Events discovery endpoint %q: %w", endpoint, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8<<10))
		return nil, 0, fmt.Errorf("aauth: Events discovery endpoint %q returned %s", endpoint, response.Status)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, 0, fmt.Errorf("aauth: Events discovery endpoint %q did not return application/json", endpoint)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumEventsAsyncAPIDocument+1))
	if err != nil {
		return nil, 0, fmt.Errorf("aauth: read Events discovery endpoint %q: %w", endpoint, err)
	}
	if len(body) > maximumEventsAsyncAPIDocument {
		return nil, 0, fmt.Errorf("aauth: Events discovery endpoint %q exceeds %d bytes", endpoint, maximumEventsAsyncAPIDocument)
	}
	return body, cacheFreshness(response.Header.Get("Cache-Control")), nil
}
