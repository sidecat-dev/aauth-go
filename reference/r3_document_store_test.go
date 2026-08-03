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
)

func TestFileR3DocumentStoreRetainsExactBytesAcrossRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 2, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	config := FileR3DocumentStoreConfig{
		Directory:        t.TempDir(),
		Clock:            clock,
		MaxDocuments:     1,
		MaxBytes:         512,
		MaxDocumentBytes: 256,
	}
	store, err := OpenFileR3DocumentStore(config)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte(
		`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
			`"operations":[{"tool":"read_record"}]}`,
	)
	firstHash := aauth.R3S256(first)
	firstExpiry := now.Add(5 * time.Minute)
	if err := store.Retain(
		context.Background(),
		firstHash,
		first,
		firstExpiry,
	); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileR3DocumentStore(config)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Load(context.Background(), firstHash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, first) {
		t.Fatalf("reopened exact bytes = %q, want %q", loaded, first)
	}
	loaded[0] ^= 1
	again, err := reopened.Load(context.Background(), firstHash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, first) {
		t.Fatal("caller mutation changed the retained document")
	}

	second := []byte(
		`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
			`"operations":[{"tool":"write_record"}]}`,
	)
	secondHash := aauth.R3S256(second)
	if err := reopened.Retain(
		context.Background(),
		secondHash,
		second,
		now.Add(5*time.Minute),
	); !errors.Is(err, ErrR3DocumentCapacity) {
		t.Fatalf("live-document capacity error = %v", err)
	}
	if _, err := reopened.Load(context.Background(), firstHash); err != nil {
		t.Fatalf("live document was evicted: %v", err)
	}

	now = firstExpiry
	if err := reopened.Retain(
		context.Background(),
		secondHash,
		second,
		now.Add(5*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Load(context.Background(), firstHash); !errors.Is(err, ErrR3DocumentNotFound) {
		t.Fatalf("expired document load error = %v", err)
	}
	if loaded, err := reopened.Load(context.Background(), secondHash); err != nil || !bytes.Equal(loaded, second) {
		t.Fatalf("replacement document = %q, %v", loaded, err)
	}
}

func TestFileR3DocumentStoreRefusesOversizedOrInvalidRetention(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 2, 18, 0, 0, 0, time.UTC)
	store, err := OpenFileR3DocumentStore(FileR3DocumentStoreConfig{
		Directory:        t.TempDir(),
		Clock:            aauth.ClockFunc(func() time.Time { return now }),
		MaxDocuments:     2,
		MaxBytes:         128,
		MaxDocumentBytes: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	document := bytes.Repeat([]byte("x"), 65)
	if err := store.Retain(
		context.Background(),
		aauth.R3S256(document),
		document,
		now.Add(time.Minute),
	); !errors.Is(err, ErrR3DocumentCapacity) {
		t.Fatalf("oversized-document error = %v", err)
	}
	valid := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`)
	if err := store.Retain(
		context.Background(),
		aauth.R3S256(valid),
		valid,
		now,
	); !errors.Is(err, ErrR3DocumentRetention) {
		t.Fatalf("expired-retention error = %v", err)
	}
	if err := store.Retain(
		context.Background(),
		aauth.R3S256([]byte("different")),
		valid,
		now.Add(time.Minute),
	); !errors.Is(err, ErrR3DocumentIntegrity) {
		t.Fatalf("hash-mismatch error = %v", err)
	}
}

func TestFileR3DocumentStoreRemovesExpiredDocumentsBeforeStartupCapacityCheck(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 2, 18, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	clock := aauth.ClockFunc(func() time.Time { return now })
	store, err := OpenFileR3DocumentStore(FileR3DocumentStoreConfig{
		Directory:        directory,
		Clock:            clock,
		MaxDocuments:     2,
		MaxBytes:         512,
		MaxDocumentBytes: 256,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range [][]byte{
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`),
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"write"}]}`),
	} {
		if err := store.Retain(
			context.Background(),
			aauth.R3S256(document),
			document,
			now.Add(time.Minute),
		); err != nil {
			t.Fatal(err)
		}
	}

	now = now.Add(time.Minute)
	if _, err := OpenFileR3DocumentStore(FileR3DocumentStoreConfig{
		Directory:        directory,
		Clock:            clock,
		MaxDocuments:     1,
		MaxBytes:         256,
		MaxDocumentBytes: 256,
	}); err != nil {
		t.Fatalf("reopen after every document expired: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expired files remain after reopen: %v", entries)
	}
}

func TestFileR3DocumentStoreRejectsNonCanonicalDigestPaths(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 2, 18, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	store, err := OpenFileR3DocumentStore(FileR3DocumentStoreConfig{
		Directory:        directory,
		Clock:            aauth.ClockFunc(func() time.Time { return now }),
		MaxDocuments:     1,
		MaxBytes:         256,
		MaxDocumentBytes: 256,
	})
	if err != nil {
		t.Fatal(err)
	}
	document := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`)
	digest := aauth.R3S256(document)
	escapeDigest := "../" + digest
	escapedPath := filepath.Join(filepath.Dir(directory), digest+".r3")
	t.Cleanup(func() { _ = os.Remove(escapedPath) })

	if err := store.write(escapeDigest, document, now.Add(time.Minute)); !errors.Is(err, ErrR3DocumentIntegrity) {
		t.Fatalf("non-canonical write error = %v", err)
	}
	if _, err := os.Stat(escapedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-canonical write escaped custody directory: %v", err)
	}
	if _, _, err := store.read(escapeDigest); !errors.Is(err, ErrR3DocumentIntegrity) {
		t.Fatalf("non-canonical read error = %v", err)
	}
}
