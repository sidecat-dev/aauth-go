package reference

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/internal/snapshotfile"
)

func TestFileAuthorizationStateStoreReopensExactCanonicalSnapshot(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "authorization")
	config := FileAuthorizationStateStoreConfig{Directory: directory, MaxEntries: 4, MaxBytes: 4096}
	store, err := OpenFileAuthorizationStateStore(config)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"schema":"aauth.reference.test-authorization-state","records":[{"id":"pending-1"}]}`)
	if err := store.Replace(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileAuthorizationStateStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, err := reopened.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(body) {
		t.Fatalf("restored snapshot = %s, want %s", restored, body)
	}
}

func TestAuthorizationStateStoresFailClosedForCapacityCorruptionUnsafeCustodyAndClose(t *testing.T) {
	t.Run("memory capacity", func(t *testing.T) {
		store, err := NewMemoryAuthorizationStateStore(1, 256)
		if err != nil {
			t.Fatal(err)
		}
		err = store.Replace(context.Background(), []byte(`{"schema":"test","records":[{"id":"1"},{"id":"2"}]}`))
		if !errors.Is(err, ErrAuthorizationStateCapacity) {
			t.Fatalf("capacity error = %v", err)
		}
	})

	t.Run("corrupt canonical state", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "authorization")
		store, err := OpenFileAuthorizationStateStore(FileAuthorizationStateStoreConfig{
			Directory: directory, MaxEntries: 4, MaxBytes: 4096,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		statePath := filepath.Join(directory, "state.json")
		if err := os.WriteFile(statePath, []byte(`{"records":[],"schema":"wrong-order"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = OpenFileAuthorizationStateStore(FileAuthorizationStateStoreConfig{
			Directory: directory, MaxEntries: 4, MaxBytes: 4096,
		})
		if !errors.Is(err, ErrAuthorizationStateIntegrity) {
			t.Fatalf("corruption error = %v", err)
		}
	})

	t.Run("unsafe directory", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "authorization")
		if err := os.Mkdir(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := OpenFileAuthorizationStateStore(FileAuthorizationStateStoreConfig{
			Directory: directory, MaxEntries: 4, MaxBytes: 4096,
		})
		if !errors.Is(err, ErrAuthorizationStateUnsafe) {
			t.Fatalf("unsafe custody error = %v", err)
		}
	})

	t.Run("closed", func(t *testing.T) {
		store, err := OpenFileAuthorizationStateStore(FileAuthorizationStateStoreConfig{
			Directory: filepath.Join(t.TempDir(), "authorization"), MaxEntries: 4, MaxBytes: 4096,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(context.Background()); !errors.Is(err, ErrAuthorizationStateClosed) {
			t.Fatalf("closed load error = %v", err)
		}
		if err := store.Replace(context.Background(), []byte(`{"schema":"test","records":[]}`)); !errors.Is(err, ErrAuthorizationStateClosed) {
			t.Fatalf("closed replace error = %v", err)
		}
	})

	t.Run("uncertain commit publishes exact state", func(t *testing.T) {
		store, err := OpenFileAuthorizationStateStore(FileAuthorizationStateStoreConfig{
			Directory: filepath.Join(t.TempDir(), "authorization"), MaxEntries: 4, MaxBytes: 4096,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		store.file.SetFailureInjectorForTesting(func(phase snapshotfile.CommitPhase) error {
			if phase == snapshotfile.CommitAfterRename {
				return errors.New("injected directory-sync loss")
			}
			return nil
		})
		body := []byte(`{"schema":"test","records":[]}`)
		err = store.Replace(context.Background(), body)
		if !errors.Is(err, ErrAuthorizationStateUncertain) {
			t.Fatalf("uncertain commit error = %v", err)
		}
		loaded, loadErr := store.Load(context.Background())
		if loadErr != nil || string(loaded) != string(body) {
			t.Fatalf("published uncertain state = %s, err = %v", loaded, loadErr)
		}
	})
}
