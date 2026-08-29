package reference

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	aa "gitlab.com/sidecat-dev/aauth-go"
)

func TestMemoryTokenRevocationStoreKeysByIssuerAndJTI(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	request := aa.TokenRevocationRequest{Issuer: "https://agent.example", JTI: "agent-token-1"}
	store := NewMemoryTokenRevocationStore()
	if err := store.Observe(ctx, TokenRevocationObservation{Request: request, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if revoked, err := store.IsRevoked(ctx, request); err != nil || revoked {
		t.Fatalf("before revoke = %v, %v", revoked, err)
	}
	firstKey := aa.S256([]byte("revoke-1"))
	if err := store.Revoke(ctx, request, firstKey, now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if revoked, err := store.IsRevoked(ctx, request); err != nil || !revoked {
		t.Fatalf("after revoke = %v, %v", revoked, err)
	}
	if err := store.Revoke(ctx, request, aa.S256([]byte("revoke-2")), now.Add(2*time.Minute), now); err != nil {
		t.Fatalf("idempotent revoke = %v", err)
	}
	if err := store.Revoke(ctx, request, firstKey, now.Add(time.Minute), now); !errors.Is(err, ErrTokenRevocationReplay) {
		t.Fatalf("same proof error = %v, want replay", err)
	}
	unknown := aa.TokenRevocationRequest{Issuer: "https://agent.example", JTI: "other-token"}
	if err := store.Revoke(ctx, unknown, aa.S256([]byte("unknown")), now.Add(time.Minute), now); !errors.Is(err, ErrTokenRevocationNotFound) {
		t.Fatalf("unknown error = %v, want not found", err)
	}
	if err := store.Observe(ctx, TokenRevocationObservation{Request: request, ExpiresAt: now.Add(2 * time.Hour)}); !errors.Is(err, ErrTokenRevocationConflict) {
		t.Fatalf("conflicting observation = %v, want conflict", err)
	}
}

func TestFileTokenRevocationStoreSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	request := aa.TokenRevocationRequest{Issuer: "https://agent.example", JTI: "agent-token-1"}
	path := filepath.Join(t.TempDir(), "revocations.json")
	store, err := OpenFileTokenRevocationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Observe(ctx, TokenRevocationObservation{Request: request, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	replayKey := aa.S256([]byte("revoke-restart"))
	if err := store.Revoke(ctx, request, replayKey, now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileTokenRevocationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if revoked, err := reopened.IsRevoked(ctx, request); err != nil || !revoked {
		t.Fatalf("reopened state = %v, %v", revoked, err)
	}
	if err := reopened.Revoke(ctx, request, replayKey, now.Add(time.Minute), now); !errors.Is(err, ErrTokenRevocationReplay) {
		t.Fatalf("reopened replay error = %v, want replay", err)
	}
}
