package reference

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func privateR3TestDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(t.TempDir(), "private-")
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestFileR3DocumentStoreRejectsUnsafeDirectoryPermissions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileR3DocumentStore(FileR3DocumentStoreConfig{
		Directory: directory,
		Clock:     aauth.ClockFunc(time.Now),
	}); err == nil {
		t.Fatal("R3 document store accepted group-writable custody")
	}
}

func TestFileR3DocumentStoreRetainsExactBytesAcrossRestart(t *testing.T) {
	now := time.Date(2026, 8, 2, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	config := FileR3DocumentStoreConfig{
		Directory: privateR3TestDirectory(t), Clock: clock,
		MaxDocuments: 1, MaxBytes: 512, MaxDocumentBytes: 256,
	}
	store, err := OpenFileR3DocumentStore(config)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read_record"}]}`)
	firstHash := r3.S256(first)
	firstExpiry := now.Add(5 * time.Minute)
	if err := store.Retain(context.Background(), firstHash, first, firstExpiry); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileR3DocumentStore(config)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Load(context.Background(), firstHash)
	if err != nil || !bytes.Equal(loaded, first) {
		t.Fatalf("reopened exact bytes = %q, %v", loaded, err)
	}
	loaded[0] ^= 1
	again, err := reopened.Load(context.Background(), firstHash)
	if err != nil || !bytes.Equal(again, first) {
		t.Fatal("caller mutation changed retained R3 bytes")
	}

	second := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"write_record"}]}`)
	secondHash := r3.S256(second)
	if err := reopened.Retain(context.Background(), secondHash, second, now.Add(5*time.Minute)); !errors.Is(err, ErrR3DocumentCapacity) {
		t.Fatalf("live-document capacity error = %v", err)
	}
	now = firstExpiry
	if err := reopened.Retain(context.Background(), secondHash, second, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Load(context.Background(), firstHash); !errors.Is(err, ErrR3DocumentNotFound) {
		t.Fatalf("expired document load error = %v", err)
	}
}

func TestFileR3DocumentStoreRefusesInvalidRetentionAndCustodyEntries(t *testing.T) {
	now := time.Date(2026, 8, 2, 18, 0, 0, 0, time.UTC)
	directory := privateR3TestDirectory(t)
	config := FileR3DocumentStoreConfig{
		Directory: directory, Clock: aauth.ClockFunc(func() time.Time { return now }),
		MaxDocuments: 2, MaxBytes: 128, MaxDocumentBytes: 64,
	}
	store, err := OpenFileR3DocumentStore(config)
	if err != nil {
		t.Fatal(err)
	}
	oversized := bytes.Repeat([]byte("x"), 65)
	if err := store.Retain(context.Background(), r3.S256(oversized), oversized, now.Add(time.Minute)); !errors.Is(err, ErrR3DocumentCapacity) {
		t.Fatalf("oversized-document error = %v", err)
	}
	valid := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`)
	if err := store.Retain(context.Background(), r3.S256(valid), valid, now); !errors.Is(err, ErrR3DocumentRetention) {
		t.Fatalf("expired-retention error = %v", err)
	}
	if err := store.Retain(context.Background(), r3.S256([]byte("different")), valid, now.Add(time.Minute)); !errors.Is(err, ErrR3DocumentIntegrity) {
		t.Fatalf("digest mismatch error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "obsolete.proposal"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileR3DocumentStore(config); err == nil {
		t.Fatal("R3 document store accepted an obsolete proposal-state entry")
	}
}

func TestFileR3DocumentStoreRejectsNonCanonicalDigestPaths(t *testing.T) {
	now := time.Date(2026, 8, 2, 18, 0, 0, 0, time.UTC)
	directory := privateR3TestDirectory(t)
	store, err := OpenFileR3DocumentStore(FileR3DocumentStoreConfig{
		Directory: directory, Clock: aauth.ClockFunc(func() time.Time { return now }),
		MaxDocuments: 1, MaxBytes: 256, MaxDocumentBytes: 256,
	})
	if err != nil {
		t.Fatal(err)
	}
	document := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`)
	digest := r3.S256(document)
	escapeDigest := "../" + digest
	escapedPath := filepath.Join(filepath.Dir(directory), digest+".r3")
	t.Cleanup(func() { _ = os.Remove(escapedPath) })
	if err := store.write(escapeDigest, document, now.Add(time.Minute)); !errors.Is(err, ErrR3DocumentIntegrity) {
		t.Fatalf("non-canonical write error = %v", err)
	}
	if _, _, err := store.read(escapeDigest); !errors.Is(err, ErrR3DocumentIntegrity) {
		t.Fatalf("non-canonical read error = %v", err)
	}
}
