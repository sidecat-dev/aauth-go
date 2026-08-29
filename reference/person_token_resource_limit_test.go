package reference

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryPersonTokenResourceLimiterAllowsRepeatsAndSeparatesAgents(t *testing.T) {
	t.Parallel()
	limiter, err := NewMemoryPersonTokenResourceLimiter(2)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, resource := range []string{"https://one.example", "https://one.example", "https://two.example"} {
		if err := limiter.AllowResource(ctx, "agent-one", resource); err != nil {
			t.Fatalf("allow %s: %v", resource, err)
		}
	}
	if err := limiter.AllowResource(ctx, "agent-one", "https://three.example"); !errors.Is(err, ErrPersonTokenResourceLimit) {
		t.Fatalf("third distinct resource error = %v", err)
	}
	if err := limiter.AllowResource(ctx, "agent-two", "https://three.example"); err != nil {
		t.Fatalf("independent agent resource = %v", err)
	}
}

func TestMemoryPersonTokenResourceLimiterRejectsInvalidConfigurationAndInput(t *testing.T) {
	t.Parallel()
	if _, err := NewMemoryPersonTokenResourceLimiter(0); err == nil {
		t.Fatal("zero limit was accepted")
	}
	limiter, err := NewMemoryPersonTokenResourceLimiter(1)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][2]string{{"", "https://resource.example"}, {"agent", ""}} {
		if err := limiter.AllowResource(context.Background(), input[0], input[1]); err == nil {
			t.Fatalf("invalid limiter input %q was accepted", input)
		}
	}
}
