package reference

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrPersonTokenResourceLimit identifies a deployment policy refusal because
// one signing agent has reached its distinct-resource bound.
var ErrPersonTokenResourceLimit = errors.New("reference: person-token distinct-resource limit exceeded")

// PersonTokenResourceLimiter is a deployment-owned policy seam. Agent is the
// verified signing agent, not a target sub-agent named in the request.
type PersonTokenResourceLimiter interface {
	AllowResource(context.Context, string, string) error
}

// MemoryPersonTokenResourceLimiter is a concurrency-safe reference limiter.
// Deployments that need restart or multi-process continuity should provide a
// limiter backed by their durable policy store.
type MemoryPersonTokenResourceLimiter struct {
	maximum   int
	mu        sync.Mutex
	resources map[string]map[string]struct{}
}

func NewMemoryPersonTokenResourceLimiter(maximum int) (*MemoryPersonTokenResourceLimiter, error) {
	if maximum <= 0 {
		return nil, fmt.Errorf("reference: person-token distinct-resource limit must be positive")
	}
	return &MemoryPersonTokenResourceLimiter{
		maximum:   maximum,
		resources: make(map[string]map[string]struct{}),
	}, nil
}

func (limiter *MemoryPersonTokenResourceLimiter) AllowResource(_ context.Context, agent, resource string) error {
	if limiter == nil || limiter.maximum <= 0 {
		return errors.New("reference: person-token resource limiter is not initialized")
	}
	if agent == "" || resource == "" {
		return errors.New("reference: person-token resource limiter input is incomplete")
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	resources := limiter.resources[agent]
	if resources == nil {
		resources = make(map[string]struct{})
		limiter.resources[agent] = resources
	}
	if _, exists := resources[resource]; exists {
		return nil
	}
	if len(resources) >= limiter.maximum {
		return ErrPersonTokenResourceLimit
	}
	resources[resource] = struct{}{}
	return nil
}

var _ PersonTokenResourceLimiter = (*MemoryPersonTokenResourceLimiter)(nil)
