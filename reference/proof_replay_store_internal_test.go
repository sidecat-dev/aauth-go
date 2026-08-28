package reference

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestProofReplayStoresExpireAndEnforceCapacity(t *testing.T) {
	now := time.Date(2026, 8, 28, 22, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	first := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))
	second := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32))

	for _, test := range []struct {
		name string
		open func(*testing.T) (ProofReplayStore, func())
	}{
		{
			name: "memory",
			open: func(t *testing.T) (ProofReplayStore, func()) {
				store, err := NewMemoryProofReplayStore(clock, 1)
				if err != nil {
					t.Fatal(err)
				}
				return store, func() {}
			},
		},
		{
			name: "file",
			open: func(t *testing.T) (ProofReplayStore, func()) {
				store, err := OpenFileProofReplayStore(FileProofReplayStoreConfig{
					Directory: filepath.Join(t.TempDir(), "proof-replays"), Clock: clock,
					MaxEntries: 1, MaxBytes: 4096,
				})
				if err != nil {
					t.Fatal(err)
				}
				return store, func() { _ = store.Close() }
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, closeStore := test.open(t)
			defer closeStore()
			if err := store.Consume(context.Background(), first, now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := store.Consume(context.Background(), second, now.Add(time.Minute)); !errors.Is(err, ErrProofReplayStoreCapacity) {
				t.Fatalf("live-capacity error = %v", err)
			}
			now = now.Add(time.Second)
			if err := store.Consume(context.Background(), second, now.Add(time.Minute)); err != nil {
				t.Fatalf("consume after exact expiry = %v", err)
			}
			now = now.Add(-time.Second)
		})
	}
}

func TestFileProofReplayStoreFailsClosedAfterCloseAndUncertainCommit(t *testing.T) {
	now := time.Date(2026, 8, 28, 22, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	config := FileProofReplayStoreConfig{
		Directory: filepath.Join(t.TempDir(), "proof-replays"), Clock: clock,
		MaxEntries: 4, MaxBytes: 4096,
	}
	store, err := OpenFileProofReplayStore(config)
	if err != nil {
		t.Fatal(err)
	}
	replayKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32))
	store.file.failCommit = func(phase eventFileCommitPhase) error {
		if phase == eventFileCommitAfterRename {
			return errors.New("injected directory-sync loss")
		}
		return nil
	}
	if err := store.Consume(context.Background(), replayKey, now.Add(time.Minute)); !errors.Is(err, ErrProofReplayStoreCommitUncertain) {
		t.Fatalf("uncertain consume error = %v", err)
	}
	store.file.failCommit = nil
	if err := store.Consume(context.Background(), replayKey, now.Add(time.Minute)); !errors.Is(err, ErrProofReplay) {
		t.Fatalf("published uncertain proof error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(context.Background(), replayKey, now.Add(time.Minute)); !errors.Is(err, ErrProofReplayStoreClosed) {
		t.Fatalf("closed consume error = %v", err)
	}
	reopened, err := OpenFileProofReplayStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Consume(context.Background(), replayKey, now.Add(time.Minute)); !errors.Is(err, ErrProofReplay) {
		t.Fatalf("reopened uncertain proof error = %v", err)
	}
}
