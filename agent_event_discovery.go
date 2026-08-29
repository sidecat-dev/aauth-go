package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	defaultAgentEventMetadataEntries  = 1024
	defaultAgentEventMetadataInFlight = 128
	maximumAgentMetadataDocument      = 1 << 20
)

// HTTPAgentEventMetadataResolverConfig supplies the explicit network, time,
// and egress boundaries for Events delivery routing.
type HTTPAgentEventMetadataResolverConfig struct {
	Client *http.Client
	Clock  Clock
	Admit  EgressAdmitter
	Limits HTTPAgentEventMetadataResolverLimits
}

// HTTPAgentEventMetadataResolverLimits bounds retained metadata and concurrent
// unique fetches. Zero fields select finite defaults.
type HTTPAgentEventMetadataResolverLimits struct {
	PositiveEntries int
	InFlightEntries int
}

// HTTPAgentEventMetadataResolver discovers only the Events delivery endpoint.
// It does not resolve or retain Signature-Key material.
type HTTPAgentEventMetadataResolver struct {
	client *http.Client
	clock  Clock
	admit  EgressAdmitter
	limits HTTPAgentEventMetadataResolverLimits

	mu       sync.Mutex
	cache    map[string]agentEventMetadataCacheEntry
	inflight map[string]chan struct{}
}

type agentEventMetadataCacheEntry struct {
	metadata   AgentEventMetadata
	fetchedAt  time.Time
	freshUntil time.Time
	discardAt  time.Time
}

func NewHTTPAgentEventMetadataResolver(config HTTPAgentEventMetadataResolverConfig) (*HTTPAgentEventMetadataResolver, error) {
	if config.Client == nil || config.Clock == nil || config.Admit == nil {
		return nil, errors.New("aauth: agent event metadata resolver requires client, clock, and egress admitter")
	}
	limits := config.Limits
	if limits.PositiveEntries < 0 || limits.InFlightEntries < 0 {
		return nil, errors.New("aauth: agent event metadata resolver limits must not be negative")
	}
	if limits.PositiveEntries == 0 {
		limits.PositiveEntries = defaultAgentEventMetadataEntries
	}
	if limits.InFlightEntries == 0 {
		limits.InFlightEntries = defaultAgentEventMetadataInFlight
	}
	return &HTTPAgentEventMetadataResolver{
		client: config.Client, clock: config.Clock, admit: config.Admit, limits: limits,
		cache: make(map[string]agentEventMetadataCacheEntry), inflight: make(map[string]chan struct{}),
	}, nil
}

// ResolveAgentEventMetadata returns the current admitted Events endpoint for
// one agent provider.
func (resolver *HTTPAgentEventMetadataResolver) ResolveAgentEventMetadata(ctx context.Context, issuer string) (AgentEventMetadata, error) {
	var zero AgentEventMetadata
	if resolver == nil {
		return zero, errors.New("aauth: agent event metadata resolver is required")
	}
	if err := ValidateServerIdentifier(issuer); err != nil {
		return zero, fmt.Errorf("aauth: event metadata issuer: %w", err)
	}
	for {
		now := resolver.clock.Now()
		resolver.mu.Lock()
		entry, cached := resolver.cache[issuer]
		if cached && !entry.discardAt.After(now) {
			delete(resolver.cache, issuer)
			entry = agentEventMetadataCacheEntry{}
			cached = false
		}
		if cached && entry.freshUntil.After(now) {
			resolver.mu.Unlock()
			return entry.metadata, nil
		}
		if pending, ok := resolver.inflight[issuer]; ok {
			resolver.mu.Unlock()
			select {
			case <-ctx.Done():
				return zero, ctx.Err()
			case <-pending:
				continue
			}
		}
		if len(resolver.inflight) >= resolver.limits.InFlightEntries {
			resolver.mu.Unlock()
			return zero, errors.New("aauth: concurrent agent event metadata discovery capacity is exhausted")
		}
		pending := make(chan struct{})
		resolver.inflight[issuer] = pending
		resolver.mu.Unlock()

		fetched, err := resolver.fetch(ctx, issuer)

		resolver.mu.Lock()
		delete(resolver.inflight, issuer)
		if err == nil {
			resolver.rememberLocked(issuer, fetched, resolver.clock.Now())
		}
		close(pending)
		resolver.mu.Unlock()
		if err != nil {
			return zero, err
		}
		return fetched.metadata, nil
	}
}

func (resolver *HTTPAgentEventMetadataResolver) rememberLocked(issuer string, entry agentEventMetadataCacheEntry, now time.Time) {
	var oldestIssuer string
	var oldestAt time.Time
	for existingIssuer, existing := range resolver.cache {
		if !existing.discardAt.After(now) {
			delete(resolver.cache, existingIssuer)
			continue
		}
		if oldestAt.IsZero() || existing.fetchedAt.Before(oldestAt) ||
			(existing.fetchedAt.Equal(oldestAt) && existingIssuer < oldestIssuer) {
			oldestIssuer = existingIssuer
			oldestAt = existing.fetchedAt
		}
	}
	if _, exists := resolver.cache[issuer]; !exists && len(resolver.cache) >= resolver.limits.PositiveEntries {
		delete(resolver.cache, oldestIssuer)
	}
	resolver.cache[issuer] = entry
}

func (resolver *HTTPAgentEventMetadataResolver) fetch(ctx context.Context, issuer string) (agentEventMetadataCacheEntry, error) {
	endpoint := issuer + "/.well-known/" + AgentDiscoveryDocument
	if err := resolver.admit(ctx, endpoint); err != nil {
		return agentEventMetadataCacheEntry{}, fmt.Errorf("aauth: event metadata egress admission failed for %q: %w", endpoint, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return agentEventMetadataCacheEntry{}, err
	}
	request.Header.Set("Accept", "application/json")
	client := *resolver.client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("aauth: event metadata redirects are not followed")
	}
	response, err := client.Do(request)
	if err != nil {
		return agentEventMetadataCacheEntry{}, fmt.Errorf("aauth: fetch event metadata %q: %w", endpoint, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8<<10))
		return agentEventMetadataCacheEntry{}, fmt.Errorf("aauth: event metadata endpoint %q returned %s", endpoint, response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumAgentMetadataDocument+1))
	if err != nil {
		return agentEventMetadataCacheEntry{}, err
	}
	if len(body) > maximumAgentMetadataDocument {
		return agentEventMetadataCacheEntry{}, fmt.Errorf("aauth: event metadata endpoint %q exceeds %d bytes", endpoint, maximumAgentMetadataDocument)
	}
	var metadata struct {
		Issuer        string `json:"issuer"`
		EventEndpoint string `json:"event_endpoint"`
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return agentEventMetadataCacheEntry{}, fmt.Errorf("aauth: decode event metadata: %w", err)
	}
	if metadata.Issuer != issuer {
		return agentEventMetadataCacheEntry{}, errors.New("aauth: event metadata issuer does not match")
	}
	if metadata.EventEndpoint == "" {
		return agentEventMetadataCacheEntry{}, errors.New("aauth: agent metadata does not advertise Events")
	}
	if err := validateDiscoveryURL(metadata.EventEndpoint); err != nil {
		return agentEventMetadataCacheEntry{}, fmt.Errorf("aauth: discovery event_endpoint: %w", err)
	}
	now := resolver.clock.Now()
	return agentEventMetadataCacheEntry{
		metadata:   AgentEventMetadata{Issuer: issuer, EventEndpoint: metadata.EventEndpoint},
		fetchedAt:  now,
		freshUntil: now.Add(cacheFreshness(response.Header.Get("Cache-Control"))),
		discardAt:  now.Add(maximumDiscoveryRetention),
	}, nil
}
