// Package snapshotfile owns bounded, private, single-writer replacement of one
// exact opaque snapshot. Snapshot semantics and encoding belong to callers.
package snapshotfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	ErrConfig          = errors.New("snapshotfile: configuration is invalid")
	ErrCapacity        = errors.New("snapshotfile: capacity is exhausted")
	ErrUnsafe          = errors.New("snapshotfile: custody is unsafe")
	ErrLocked          = errors.New("snapshotfile: already has a writer")
	ErrIntegrity       = errors.New("snapshotfile: retained bytes could not be read")
	ErrCommitUncertain = errors.New("snapshotfile: commit is uncertain")
	ErrClosed          = errors.New("snapshotfile: file is closed")
)

const (
	stateName       = "state.json"
	lockName        = "writer.lock"
	temporaryPrefix = ".state-"
)

// CommitPhase identifies a test injection point in the replacement sequence.
type CommitPhase uint8

const (
	CommitAfterWrite CommitPhase = iota + 1
	CommitAfterFileSync
	CommitAfterRename
	CommitAfterDirectorySync
)

// Limits is an immutable set of finite snapshot bounds.
type Limits struct {
	maxRecords     int
	maxBytes       int64
	maxRecordBytes int64
}

// NewLimits constructs strict finite snapshot bounds. Callers own any default
// policy and must pass all three effective values explicitly.
func NewLimits(maxRecords int, maxBytes, maxRecordBytes int64) (Limits, error) {
	if maxRecords <= 0 || maxBytes <= 0 || maxRecordBytes <= 0 {
		return Limits{}, ErrConfig
	}
	return Limits{
		maxRecords:     maxRecords,
		maxBytes:       maxBytes,
		maxRecordBytes: maxRecordBytes,
	}, nil
}

func (limits Limits) MaxRecords() int       { return limits.maxRecords }
func (limits Limits) MaxBytes() int64       { return limits.maxBytes }
func (limits Limits) MaxRecordBytes() int64 { return limits.maxRecordBytes }
func (limits Limits) valid() bool {
	return limits.maxRecords > 0 && limits.maxBytes > 0 && limits.maxRecordBytes > 0
}

// File owns one private snapshot directory and its exclusive writer lock.
type File struct {
	mu         sync.Mutex
	directory  string
	limits     Limits
	lock       *fileLock
	failCommit func(CommitPhase) error
	closed     bool
}

// Open validates or creates a private snapshot directory, obtains its single
// writer lock, removes safe crash temporaries, and reads exact retained bytes.
func Open(directory string, limits Limits) (file *File, body []byte, err error) {
	if !limits.valid() {
		return nil, nil, ErrConfig
	}
	resolved, err := prepareDirectory(directory)
	if err != nil {
		return nil, nil, err
	}
	lock, err := acquireFileLock(resolved)
	if err != nil {
		return nil, nil, err
	}
	file = &File{directory: resolved, limits: limits, lock: lock}
	opened := file
	defer func() {
		if err != nil {
			_ = opened.Close()
			file = nil
		}
	}()
	if err = file.cleanAndValidateEntries(); err != nil {
		return nil, nil, err
	}
	body, err = file.readState()
	if err != nil {
		return nil, nil, err
	}
	return file, body, nil
}

// Limits returns the immutable bounds used by file.
func (file *File) Limits() Limits {
	if file == nil {
		return Limits{}
	}
	return file.limits
}

// SetFailureInjectorForTesting installs a test-only replacement failure hook.
// Production callers must leave the hook nil.
func (file *File) SetFailureInjectorForTesting(injector func(CommitPhase) error) {
	if file == nil {
		return
	}
	file.mu.Lock()
	defer file.mu.Unlock()
	file.failCommit = injector
}

// Replace atomically replaces the exact snapshot bytes. published reports
// whether rename made the successor visible before an error was returned.
func (file *File) Replace(body []byte, records [][]byte) (published bool, err error) {
	if file == nil {
		return false, ErrClosed
	}
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed || file.lock == nil {
		return false, ErrClosed
	}
	if len(records) > file.limits.maxRecords || int64(len(body)) > file.limits.maxBytes {
		return false, ErrCapacity
	}
	for _, record := range records {
		if int64(len(record)) > file.limits.maxRecordBytes {
			return false, ErrCapacity
		}
	}

	temporary, err := os.CreateTemp(file.directory, temporaryPrefix)
	if err != nil {
		return false, fmt.Errorf("snapshotfile: create temporary: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if !published {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return false, fmt.Errorf("snapshotfile: protect temporary: %w", err)
	}
	temporaryInfo, err := temporary.Stat()
	if err != nil || !ownedByCurrentUser(temporaryInfo) || !hasSingleLink(temporaryInfo) {
		return false, ErrUnsafe
	}
	if _, err := temporary.Write(body); err != nil {
		return false, fmt.Errorf("snapshotfile: write state: %w", err)
	}
	if err := file.inject(CommitAfterWrite); err != nil {
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		return false, fmt.Errorf("snapshotfile: sync state: %w", err)
	}
	if err := file.inject(CommitAfterFileSync); err != nil {
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("snapshotfile: close state: %w", err)
	}
	if err := os.Rename(temporaryPath, filepath.Join(file.directory, stateName)); err != nil {
		return false, fmt.Errorf("snapshotfile: publish state: %w", err)
	}
	published = true
	if err := file.inject(CommitAfterRename); err != nil {
		return true, errors.Join(ErrCommitUncertain, err)
	}
	if err := syncDirectory(file.directory); err != nil {
		return true, errors.Join(ErrCommitUncertain, err)
	}
	if err := file.inject(CommitAfterDirectorySync); err != nil {
		return true, errors.Join(ErrCommitUncertain, err)
	}
	return true, nil
}

// Close releases the exclusive writer lock. Repeated calls are harmless.
func (file *File) Close() error {
	if file == nil {
		return nil
	}
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed {
		return nil
	}
	file.closed = true
	lock := file.lock
	file.lock = nil
	return lock.Close()
}

func (file *File) inject(phase CommitPhase) error {
	if file.failCommit == nil {
		return nil
	}
	return file.failCommit(phase)
}

func prepareDirectory(directory string) (string, error) {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return "", ErrConfig
	}
	if err := rejectSymlinkComponents(directory); err != nil {
		return "", err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("%w: create directory: %v", ErrUnsafe, err)
	}
	if err := rejectSymlinkComponents(directory); err != nil {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 ||
		!ownedByCurrentUser(info) {
		return "", ErrUnsafe
	}
	return directory, nil
}

func rejectSymlinkComponents(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return ErrUnsafe
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: inspect directory: %v", ErrUnsafe, err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func (file *File) cleanAndValidateEntries() error {
	entries, err := os.ReadDir(file.directory)
	if err != nil {
		return fmt.Errorf("%w: read directory: %v", ErrUnsafe, err)
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(file.directory, name)
		switch {
		case name == lockName, name == stateName:
			if err := validatePrivateFile(path); err != nil {
				return err
			}
		case strings.HasPrefix(name, temporaryPrefix) && len(name) > len(temporaryPrefix):
			if err := validatePrivateFile(path); err != nil {
				return err
			}
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("%w: remove crash temporary: %v", ErrUnsafe, err)
			}
			removed = true
		default:
			return fmt.Errorf("%w: unexpected entry %q", ErrUnsafe, name)
		}
	}
	if removed {
		return syncDirectory(file.directory)
	}
	return nil
}

func validatePrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || !hasSingleLink(info) || !ownedByCurrentUser(info) {
		return ErrUnsafe
	}
	return nil
}

func (file *File) readState() ([]byte, error) {
	path := filepath.Join(file.directory, stateName)
	if err := validatePrivateFile(path); err != nil {
		if errors.Is(err, ErrUnsafe) {
			if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
				return nil, nil
			}
		}
		return nil, err
	}
	openedFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: open state: %v", ErrUnsafe, err)
	}
	defer openedFile.Close()
	opened, err := openedFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: inspect opened state: %v", ErrUnsafe, err)
	}
	linked, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, linked) || opened.Mode().Perm() != 0o600 ||
		!opened.Mode().IsRegular() || !hasSingleLink(opened) || !ownedByCurrentUser(opened) {
		return nil, ErrUnsafe
	}
	body, err := io.ReadAll(io.LimitReader(openedFile, file.limits.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read state: %v", ErrIntegrity, err)
	}
	if int64(len(body)) > file.limits.maxBytes {
		return nil, ErrCapacity
	}
	return body, nil
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("snapshotfile: open directory: %w", err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("snapshotfile: sync directory: %w", err)
	}
	return nil
}
