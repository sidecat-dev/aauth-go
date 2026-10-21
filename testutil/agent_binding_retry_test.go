package testutil_test

import (
	"context"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

// AgentBindingRevocationStore permits an indeterminate write error and
// promises exact retries are safe. A delayed retry must not undo a later
// host-authenticated lifecycle transition for the same binding.
func TestAgentBindingDelayedRetriesPreserveLaterLifecycleState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	binding := personserver.AgentBinding{
		AgentProvider: "https://provider.example", Agent: "aauth:planner@provider.example",
	}
	revokedAt := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	reestablishedAt := revokedAt.Add(time.Minute)

	t.Run("old revocation cannot revoke its replacement", func(t *testing.T) {
		t.Parallel()
		store := testutil.NewAgentBindingRevocationStore()
		if err := store.RevokeAgentBinding(ctx, binding, revokedAt); err != nil {
			t.Fatal(err)
		}
		if err := store.ReestablishAgentBinding(ctx, binding, reestablishedAt); err != nil {
			t.Fatal(err)
		}
		retryErr := store.RevokeAgentBinding(ctx, binding, revokedAt)
		state, err := store.LoadAgentBindingRevocation(ctx, binding)
		if err != nil {
			t.Fatal(err)
		}
		if !state.RevokedAt.Equal(revokedAt) || !state.ReestablishedAt.Equal(reestablishedAt) {
			t.Fatalf("old revocation retry changed the replacement: state=%#v retry error=%v", state, retryErr)
		}
	})

	t.Run("old replacement cannot undo a newer revocation", func(t *testing.T) {
		t.Parallel()
		store := testutil.NewAgentBindingRevocationStore()
		if err := store.RevokeAgentBinding(ctx, binding, revokedAt); err != nil {
			t.Fatal(err)
		}
		if err := store.ReestablishAgentBinding(ctx, binding, reestablishedAt); err != nil {
			t.Fatal(err)
		}
		secondRevocation := revokedAt.Add(2 * time.Minute)
		if err := store.RevokeAgentBinding(ctx, binding, secondRevocation); err != nil {
			t.Fatal(err)
		}
		retryErr := store.ReestablishAgentBinding(ctx, binding, reestablishedAt)
		state, err := store.LoadAgentBindingRevocation(ctx, binding)
		if err != nil {
			t.Fatal(err)
		}
		if !state.RevokedAt.Equal(secondRevocation) || !state.ReestablishedAt.IsZero() {
			t.Fatalf("old replacement retry reopened the newer revocation: state=%#v retry error=%v", state, retryErr)
		}
	})
}
