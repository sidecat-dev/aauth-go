package reference

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func privateR3TestDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(t.TempDir(), "private-")
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestFileR3DocumentStoreConsumesProposalOnceAcrossRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 2, 20, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	config := FileR3DocumentStoreConfig{
		Directory:        privateR3TestDirectory(t),
		Clock:            clock,
		MaxDocuments:     2,
		MaxBytes:         2048,
		MaxDocumentBytes: 1024,
	}
	store, err := OpenFileR3DocumentStore(config)
	if err != nil {
		t.Fatal(err)
	}
	proposal := []byte(
		`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
			`"operations":[{"tool":"send_message"}],` +
			`"parameters":{"body":{"s256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}}`,
	)
	digest := aauth.R3S256(proposal)
	expiresAt := now.Add(5 * time.Minute)
	if err := store.RetainProposal(context.Background(), digest, proposal, expiresAt); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileR3DocumentStore(config)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.LoadProposal(context.Background(), digest)
	if err != nil || !bytes.Equal(loaded, proposal) {
		t.Fatalf("reopened proposal = %q, %v", loaded, err)
	}

	results := make(chan error, 2)
	start := make(chan struct{})
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- reopened.ConsumeProposal(
				context.Background(),
				digest,
				"per-call-auth-token",
				expiresAt,
			)
		}()
	}
	close(start)
	group.Wait()
	close(results)
	succeeded := 0
	consumed := 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrR3ProposalConsumed):
			consumed++
		default:
			t.Fatalf("proposal consumption error = %v", err)
		}
	}
	if succeeded != 1 || consumed != 1 {
		t.Fatalf("proposal consume results: success = %d, consumed = %d", succeeded, consumed)
	}

	restarted, err := OpenFileR3DocumentStore(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ConsumeProposal(
		context.Background(),
		digest,
		"per-call-auth-token",
		expiresAt,
	); !errors.Is(err, ErrR3ProposalConsumed) {
		t.Fatalf("restart replay error = %v", err)
	}
	if err := restarted.ConsumeProposal(
		context.Background(),
		digest,
		"independently-approved-token",
		expiresAt,
	); err != nil {
		t.Fatalf("identical proposal for another token was refused: %v", err)
	}
	if loaded, err := restarted.Load(context.Background(), digest); err != nil || !bytes.Equal(loaded, proposal) {
		t.Fatalf("consumed proposal is no longer fetchable by AS: %q, %v", loaded, err)
	}
}

func TestFileR3DocumentStoreRejectsUnsafeDirectoryPermissions(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "r3-documents")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileR3DocumentStore(FileR3DocumentStoreConfig{
		Directory: directory,
		Clock:     aauth.ClockFunc(time.Now),
	}); err == nil {
		t.Fatal("R3 document store accepted a group-writable custody directory")
	}
}

func TestFileR3DocumentStoreProposalSurvivesRetentionExtensionAcrossRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 2, 20, 0, 0, 0, time.UTC)
	config := FileR3DocumentStoreConfig{
		Directory:        privateR3TestDirectory(t),
		Clock:            aauth.ClockFunc(func() time.Time { return now }),
		MaxDocuments:     1,
		MaxBytes:         2048,
		MaxDocumentBytes: 1024,
	}
	store, err := OpenFileR3DocumentStore(config)
	if err != nil {
		t.Fatal(err)
	}
	proposal := []byte(
		`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
			`"operations":[{"tool":"send_message"}],` +
			`"parameters":{"recipient":"person@example.com"}}`,
	)
	digest := aauth.R3S256(proposal)
	initialExpiry := now.Add(5 * time.Minute)
	extendedExpiry := now.Add(10 * time.Minute)
	if err := store.RetainProposal(
		context.Background(),
		digest,
		proposal,
		initialExpiry,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Retain(
		context.Background(),
		digest,
		proposal,
		extendedExpiry,
	); err != nil {
		t.Fatal(err)
	}

	restarted, err := OpenFileR3DocumentStore(config)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := restarted.LoadProposal(context.Background(), digest)
	if err != nil || !bytes.Equal(loaded, proposal) {
		t.Fatalf("extended proposal after restart = %q, %v", loaded, err)
	}
	if err := restarted.ConsumeProposal(
		context.Background(),
		digest,
		"extended-per-call-token",
		extendedExpiry,
	); err != nil {
		t.Fatalf("consume through extended retention = %v", err)
	}
	if _, err := OpenFileR3DocumentStore(config); err != nil {
		t.Fatalf("proposal state after extended consumption did not restart: %v", err)
	}
}

func TestFileR3DocumentStoreCountsProposalStateAgainstTotalByteLimit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 2, 20, 0, 0, 0, time.UTC)
	store, err := OpenFileR3DocumentStore(FileR3DocumentStoreConfig{
		Directory:        privateR3TestDirectory(t),
		Clock:            aauth.ClockFunc(func() time.Time { return now }),
		MaxDocuments:     1,
		MaxBytes:         2048,
		MaxDocumentBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	proposal := []byte(
		`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
			`"operations":[{"tool":"send_message"}],` +
			`"parameters":{"recipient":"person@example.com"}}`,
	)
	digest := aauth.R3S256(proposal)
	expiresAt := now.Add(5 * time.Minute)
	if err := store.RetainProposal(context.Background(), digest, proposal, expiresAt); err != nil {
		t.Fatal(err)
	}
	proposalPath, err := store.proposalPath(digest)
	if err != nil {
		t.Fatal(err)
	}
	proposalInfo, err := os.Stat(proposalPath)
	if err != nil {
		t.Fatal(err)
	}
	wantBytes := int64(len(proposal)) + proposalInfo.Size()
	if store.bytes != wantBytes {
		t.Fatalf("accounted custody bytes = %d, want %d", store.bytes, wantBytes)
	}

	store.maxBytes = store.bytes
	if err := store.ConsumeProposal(
		context.Background(),
		digest,
		"per-call-auth-token",
		expiresAt,
	); !errors.Is(err, ErrR3DocumentCapacity) {
		t.Fatalf("proposal-state growth beyond total-byte limit error = %v", err)
	}
}

func TestFileR3DocumentStoreRollsBackNewDocumentWhenProposalStateCannotFit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 2, 20, 0, 0, 0, time.UTC)
	proposal := []byte(
		`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
			`"operations":[{"tool":"send_message"}],` +
			`"parameters":{"recipient":"person@example.com"}}`,
	)
	digest := aauth.R3S256(proposal)
	config := FileR3DocumentStoreConfig{
		Directory:        privateR3TestDirectory(t),
		Clock:            aauth.ClockFunc(func() time.Time { return now }),
		MaxDocuments:     1,
		MaxBytes:         int64(len(proposal)),
		MaxDocumentBytes: int64(len(proposal)),
	}
	store, err := OpenFileR3DocumentStore(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RetainProposal(
		context.Background(),
		digest,
		proposal,
		now.Add(5*time.Minute),
	); !errors.Is(err, ErrR3DocumentCapacity) {
		t.Fatalf("proposal metadata capacity error = %v", err)
	}
	if store.bytes != 0 || len(store.entries) != 0 {
		t.Fatalf("failed proposal retained capacity: bytes=%d entries=%d", store.bytes, len(store.entries))
	}
	if _, err := store.Load(context.Background(), digest); !errors.Is(err, ErrR3DocumentNotFound) {
		t.Fatalf("failed proposal document load error = %v", err)
	}
	restarted, err := OpenFileR3DocumentStore(config)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.bytes != 0 || len(restarted.entries) != 0 {
		t.Fatalf("failed proposal survived restart: bytes=%d entries=%d", restarted.bytes, len(restarted.entries))
	}
}

func TestFileR3DocumentStoreFailsClosedForMissingExpiredOrCorruptProposalCustody(t *testing.T) {
	t.Parallel()

	proposal := []byte(
		`{"vocabulary":"urn:aauth:vocabulary:mcp",` +
			`"operations":[{"tool":"send_message"}],` +
			`"parameters":{"recipient":"person@example.com"}}`,
	)
	digest := aauth.R3S256(proposal)

	t.Run("missing exact bytes", func(t *testing.T) {
		now := time.Date(2026, 8, 2, 20, 0, 0, 0, time.UTC)
		store, err := OpenFileR3DocumentStore(FileR3DocumentStoreConfig{
			Directory:        privateR3TestDirectory(t),
			Clock:            aauth.ClockFunc(func() time.Time { return now }),
			MaxDocuments:     1,
			MaxBytes:         1024,
			MaxDocumentBytes: 512,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.RetainProposal(context.Background(), digest, proposal, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		path, err := store.documentPath(digest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadProposal(context.Background(), digest); err == nil {
			t.Fatal("proposal with missing exact bytes was loaded")
		}
	})

	t.Run("expired exact bytes", func(t *testing.T) {
		now := time.Date(2026, 8, 2, 20, 0, 0, 0, time.UTC)
		clock := aauth.ClockFunc(func() time.Time { return now })
		store, err := OpenFileR3DocumentStore(FileR3DocumentStoreConfig{
			Directory:        privateR3TestDirectory(t),
			Clock:            clock,
			MaxDocuments:     1,
			MaxBytes:         1024,
			MaxDocumentBytes: 512,
		})
		if err != nil {
			t.Fatal(err)
		}
		expiresAt := now.Add(time.Minute)
		if err := store.RetainProposal(context.Background(), digest, proposal, expiresAt); err != nil {
			t.Fatal(err)
		}
		now = expiresAt
		restarted, err := OpenFileR3DocumentStore(FileR3DocumentStoreConfig{
			Directory:        store.directory,
			Clock:            clock,
			MaxDocuments:     1,
			MaxBytes:         1024,
			MaxDocumentBytes: 512,
		})
		if err != nil {
			t.Fatalf("reopen after proposal expiry: %v", err)
		}
		if _, err := restarted.LoadProposal(context.Background(), digest); !errors.Is(err, ErrR3DocumentNotFound) {
			t.Fatalf("expired proposal load error = %v", err)
		}
	})

	t.Run("substituted exact bytes", func(t *testing.T) {
		now := time.Date(2026, 8, 2, 20, 0, 0, 0, time.UTC)
		store, err := OpenFileR3DocumentStore(FileR3DocumentStoreConfig{
			Directory:        privateR3TestDirectory(t),
			Clock:            aauth.ClockFunc(func() time.Time { return now }),
			MaxDocuments:     1,
			MaxBytes:         1024,
			MaxDocumentBytes: 512,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.RetainProposal(context.Background(), digest, proposal, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		path, err := store.documentPath(digest)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		encoded[len(encoded)-1] ^= 1
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadProposal(context.Background(), digest); !errors.Is(err, ErrR3DocumentIntegrity) {
			t.Fatalf("substituted proposal load error = %v", err)
		}
	})
}

func TestFileR3DocumentStoreRetainsExactBytesAcrossRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 2, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	config := FileR3DocumentStoreConfig{
		Directory:        privateR3TestDirectory(t),
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
		Directory:        privateR3TestDirectory(t),
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
	directory := privateR3TestDirectory(t)
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
	directory := privateR3TestDirectory(t)
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
