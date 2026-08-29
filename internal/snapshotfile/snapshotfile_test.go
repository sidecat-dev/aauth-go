package snapshotfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileRoundTripPreservesExactBytesAndExclusiveWriter(t *testing.T) {
	limits, err := NewLimits(4, 128, 64)
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxRecords() != 4 || limits.MaxBytes() != 128 || limits.MaxRecordBytes() != 64 {
		t.Fatalf(
			"limits = %d/%d/%d, want 4/128/64",
			limits.MaxRecords(), limits.MaxBytes(), limits.MaxRecordBytes(),
		)
	}

	directory := filepath.Join(t.TempDir(), "snapshot")
	file, body, err := Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		t.Fatalf("initial body = %x, want nil", body)
	}
	if _, _, err := Open(directory, limits); !errors.Is(err, ErrLocked) {
		t.Fatalf("second writer error = %v, want locked", err)
	}

	want := []byte{0x00, 0xff, 'o', 'p', 'a', 'q', 'u', 'e'}
	published, err := file.Replace(want, [][]byte{{0x00, 0xff}, {'o', 'p', 'a', 'q', 'u', 'e'}})
	if err != nil || !published {
		t.Fatalf("replace = %v, %v, want published success", published, err)
	}
	statePath := filepath.Join(directory, stateName)
	retained, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retained, want) {
		t.Fatalf("retained body = %x, want %x", retained, want)
	}
	if info, err := os.Stat(statePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %v, %v, want 0600", info, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if published, err := file.Replace([]byte("closed"), nil); published || !errors.Is(err, ErrClosed) {
		t.Fatalf("replace after close = %v, %v, want unpublished closed", published, err)
	}

	crashTemporary := filepath.Join(directory, temporaryPrefix+"crash")
	if err := os.WriteFile(crashTemporary, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, body, err := Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !bytes.Equal(body, want) {
		t.Fatalf("reopened body = %x, want %x", body, want)
	}
	if _, err := os.Stat(crashTemporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("crash temporary stat = %v, want not-exist", err)
	}
}

func TestFileLimitsAreStrictAndBoundEveryReplacement(t *testing.T) {
	for _, test := range []struct {
		name           string
		maxRecords     int
		maxBytes       int64
		maxRecordBytes int64
	}{
		{name: "zero records", maxRecords: 0, maxBytes: 8, maxRecordBytes: 8},
		{name: "zero bytes", maxRecords: 1, maxBytes: 0, maxRecordBytes: 8},
		{name: "zero record bytes", maxRecords: 1, maxBytes: 8, maxRecordBytes: 0},
		{name: "negative records", maxRecords: -1, maxBytes: 8, maxRecordBytes: 8},
		{name: "negative bytes", maxRecords: 1, maxBytes: -1, maxRecordBytes: 8},
		{name: "negative record bytes", maxRecords: 1, maxBytes: 8, maxRecordBytes: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewLimits(test.maxRecords, test.maxBytes, test.maxRecordBytes); !errors.Is(err, ErrConfig) {
				t.Fatalf("NewLimits error = %v, want config", err)
			}
		})
	}

	limits, err := NewLimits(1, 8, 4)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "snapshot")
	file, _, err := Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, test := range []struct {
		name    string
		body    []byte
		records [][]byte
	}{
		{name: "body", body: []byte("123456789")},
		{name: "record count", body: []byte("ok"), records: [][]byte{{1}, {2}}},
		{name: "record bytes", body: []byte("ok"), records: [][]byte{[]byte("12345")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			published, err := file.Replace(test.body, test.records)
			if published || !errors.Is(err, ErrCapacity) {
				t.Fatalf("Replace = %v, %v, want unpublished capacity", published, err)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(directory, stateName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state after capacity refusals = %v, want not-exist", err)
	}
	if _, _, err := Open("relative", limits); !errors.Is(err, ErrConfig) {
		t.Fatalf("relative directory error = %v, want config", err)
	}
}

func TestFileFailureInjectionDistinguishesPublication(t *testing.T) {
	injected := errors.New("injected commit failure")
	for _, test := range []struct {
		name      string
		phase     CommitPhase
		published bool
		uncertain bool
	}{
		{name: "after write", phase: CommitAfterWrite},
		{name: "after file sync", phase: CommitAfterFileSync},
		{name: "after rename", phase: CommitAfterRename, published: true, uncertain: true},
		{name: "after directory sync", phase: CommitAfterDirectorySync, published: true, uncertain: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits, err := NewLimits(1, 64, 64)
			if err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(t.TempDir(), "snapshot")
			file, _, err := Open(directory, limits)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			file.SetFailureInjectorForTesting(func(phase CommitPhase) error {
				if phase == test.phase {
					return injected
				}
				return nil
			})

			published, err := file.Replace([]byte("candidate"), [][]byte{[]byte("candidate")})
			if published != test.published || !errors.Is(err, injected) {
				t.Fatalf("Replace = %v, %v, want published %v and injected", published, err, test.published)
			}
			if errors.Is(err, ErrCommitUncertain) != test.uncertain {
				t.Fatalf("uncertain = %v, want %v: %v", errors.Is(err, ErrCommitUncertain), test.uncertain, err)
			}
			retained, readErr := os.ReadFile(filepath.Join(directory, stateName))
			switch {
			case test.published && (readErr != nil || !bytes.Equal(retained, []byte("candidate"))):
				t.Fatalf("published retained body = %q, %v", retained, readErr)
			case !test.published && !errors.Is(readErr, os.ErrNotExist):
				t.Fatalf("unpublished retained state = %q, %v, want absent", retained, readErr)
			}
		})
	}
}
