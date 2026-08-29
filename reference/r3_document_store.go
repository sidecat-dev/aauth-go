package reference

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

const (
	fileR3DocumentMagic       = "AAR3DOC2"
	fileR3DocumentHeaderBytes = len(fileR3DocumentMagic) + 8 + 4 + 8
	defaultR3DocumentLimit    = 128
	defaultR3DocumentBytes    = int64(maxJSONBody)
	maximumR3ReaderBytes      = 4096
	maximumR3Readers          = 16
)

var (
	// ErrR3DocumentNotFound means no unexpired document is retained under the
	// requested exact-byte digest.
	ErrR3DocumentNotFound = errors.New("reference: R3 document is not retained")
	// ErrR3DocumentCapacity means retaining another document would exceed a
	// configured count, total-byte, or per-document bound while every possible
	// eviction candidate is still referenced by a live resource token.
	ErrR3DocumentCapacity = errors.New("reference: R3 document capacity is exhausted")
	// ErrR3DocumentRetention means the requested retention does not extend into
	// the future according to the deployment clock.
	ErrR3DocumentRetention = errors.New("reference: R3 document retention is invalid")
	// ErrR3DocumentIntegrity means the supplied digest and exact bytes differ,
	// or durable custody contains bytes that do not match their identity.
	ErrR3DocumentIntegrity = errors.New("reference: R3 document integrity check failed")
	// ErrR3DocumentUnauthorized means the authenticated server is not one of
	// the exact readers retained before the document reference was released.
	ErrR3DocumentUnauthorized = errors.New("reference: R3 document reader is not authorized")
)

// R3DocumentStore is the resource deployment's exact-byte custody boundary.
// Retain must not return success unless Load can recover the same bytes through
// retainUntil, including after reconstructing the Resource process.
type R3DocumentStore interface {
	Retain(
		context.Context,
		string,
		[]byte,
		time.Time,
	) error
	Load(context.Context, string) ([]byte, error)
}

// R3RestrictedDocumentStore atomically binds exact document bytes to the
// server identities entitled to retrieve them.
type R3RestrictedDocumentStore interface {
	R3DocumentStore
	RetainAuthorized(context.Context, string, []byte, []string, time.Time) error
	LoadAuthorized(context.Context, string, string) ([]byte, error)
}

// FileR3DocumentStoreConfig bounds a single-writer, restart-safe reference
// store. Directory is dedicated to R3 custody. All three limits are enforced
// before new bytes become reachable from a resource token.
type FileR3DocumentStoreConfig struct {
	Directory        string
	Clock            aauth.Clock
	MaxDocuments     int
	MaxBytes         int64
	MaxDocumentBytes int64
}

// FileR3DocumentStore retains one atomically replaced, mode-0600 file per
// exact-byte digest. Expired files may be evicted; live files never are.
// Deployments needing multi-process writers should supply another
// R3DocumentStore implementation with equivalent retention guarantees.
type FileR3DocumentStore struct {
	directory        string
	clock            aauth.Clock
	maxDocuments     int
	maxBytes         int64
	maxDocumentBytes int64

	mu      sync.Mutex
	entries map[string]fileR3DocumentEntry
	bytes   int64
}

type fileR3DocumentEntry struct {
	bytes       int64
	retainUntil time.Time
	readers     []string
}

// OpenFileR3DocumentStore opens or creates a bounded durable document store
// and verifies every retained file before making the store available.
func OpenFileR3DocumentStore(
	config FileR3DocumentStoreConfig,
) (*FileR3DocumentStore, error) {
	if config.Clock == nil {
		return nil, errors.New("reference: R3 document store requires a clock")
	}
	directory, err := filepath.Abs(config.Directory)
	if err != nil || config.Directory == "" || filepath.Clean(directory) != directory {
		return nil, errors.New("reference: R3 document store directory is invalid")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("reference: create R3 document store: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("reference: R3 document store directory is unsafe")
	}
	maxDocuments := config.MaxDocuments
	if maxDocuments == 0 {
		maxDocuments = defaultR3DocumentLimit
	}
	maxDocumentBytes := config.MaxDocumentBytes
	if maxDocumentBytes == 0 {
		maxDocumentBytes = defaultR3DocumentBytes
	}
	maxBytes := config.MaxBytes
	if maxBytes == 0 {
		maxBytes = int64(maxDocuments) * maxDocumentBytes
	}
	if maxDocuments < 0 || maxDocumentBytes < 0 || maxBytes < 0 ||
		maxDocumentBytes > maxBytes {
		return nil, errors.New("reference: R3 document store limits are invalid")
	}
	store := &FileR3DocumentStore{
		directory:        directory,
		clock:            config.Clock,
		maxDocuments:     maxDocuments,
		maxBytes:         maxBytes,
		maxDocumentBytes: maxDocumentBytes,
		entries:          make(map[string]fileR3DocumentEntry),
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *FileR3DocumentStore) load() error {
	directoryEntries, err := os.ReadDir(store.directory)
	if err != nil {
		return fmt.Errorf("reference: read R3 document store: %w", err)
	}
	now := store.clock.Now()
	removedExpired := false
	for _, directoryEntry := range directoryEntries {
		name := directoryEntry.Name()
		if strings.HasPrefix(name, ".r3-document-") {
			if directoryEntry.Type().IsRegular() {
				_ = os.Remove(filepath.Join(store.directory, name))
			}
			continue
		}
		digest, ok := fileR3DocumentDigest(name)
		if !ok || directoryEntry.Type()&os.ModeSymlink != 0 || !directoryEntry.Type().IsRegular() {
			return fmt.Errorf("reference: R3 document store contains unexpected entry %q", name)
		}
		exactBytes, retainUntil, readers, err := store.read(digest)
		if err != nil {
			return err
		}
		if r3.S256(exactBytes) != digest {
			return fmt.Errorf("%w: retained digest %s", ErrR3DocumentIntegrity, digest)
		}
		if !retainUntil.After(now) {
			path, err := store.documentPath(digest)
			if err != nil {
				return err
			}
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("reference: remove expired R3 document: %w", err)
			}
			removedExpired = true
			continue
		}
		if len(store.entries) >= store.maxDocuments ||
			int64(len(exactBytes)) > store.maxDocumentBytes ||
			store.bytes+int64(len(exactBytes)) > store.maxBytes {
			return errors.New("reference: retained R3 documents exceed configured capacity")
		}
		store.entries[digest] = fileR3DocumentEntry{
			bytes: int64(len(exactBytes)), retainUntil: retainUntil, readers: readers,
		}
		store.bytes += int64(len(exactBytes))
	}
	if removedExpired {
		if err := syncR3Directory(store.directory); err != nil {
			return err
		}
	}
	return store.removeExpired(store.clock.Now())
}

// Retain durably preserves exactBytes until retainUntil. It removes only
// already-expired entries when capacity is needed.
func (store *FileR3DocumentStore) Retain(
	ctx context.Context,
	digest string,
	exactBytes []byte,
	retainUntil time.Time,
) error {
	if err := store.validateRetention(ctx, digest, exactBytes, retainUntil); err != nil {
		return err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	_, _, err := store.retainLocked(digest, exactBytes, nil, retainUntil, store.clock.Now())
	return err
}

// RetainAuthorized durably preserves exact bytes and the complete set of
// server identities entitled to fetch them. Repeated retention merges readers
// and extends the deadline in one atomic file replacement.
func (store *FileR3DocumentStore) RetainAuthorized(
	ctx context.Context,
	digest string,
	exactBytes []byte,
	readers []string,
	retainUntil time.Time,
) error {
	if err := store.validateRetention(ctx, digest, exactBytes, retainUntil); err != nil {
		return err
	}
	canonical, err := canonicalR3Readers(readers)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	_, _, err = store.retainLocked(digest, exactBytes, canonical, retainUntil, store.clock.Now())
	return err
}

func (store *FileR3DocumentStore) validateRetention(
	ctx context.Context,
	digest string,
	exactBytes []byte,
	retainUntil time.Time,
) error {
	if store == nil || store.clock == nil {
		return errors.New("reference: R3 document store is unavailable")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if r3.S256(exactBytes) != digest {
		return ErrR3DocumentIntegrity
	}
	now := store.clock.Now()
	if !retainUntil.After(now) {
		return ErrR3DocumentRetention
	}
	if int64(len(exactBytes)) > store.maxDocumentBytes {
		return ErrR3DocumentCapacity
	}
	return nil
}

func (store *FileR3DocumentStore) retainLocked(
	digest string,
	exactBytes []byte,
	readers []string,
	retainUntil time.Time,
	now time.Time,
) (fileR3DocumentEntry, bool, error) {
	if err := store.removeExpired(now); err != nil {
		return fileR3DocumentEntry{}, false, err
	}
	if existing, exists := store.entries[digest]; exists {
		previous := existing
		retained, _, retainedReaders, err := store.read(digest)
		if err != nil {
			return fileR3DocumentEntry{}, false, err
		}
		if !bytes.Equal(retained, exactBytes) {
			return fileR3DocumentEntry{}, false, ErrR3DocumentIntegrity
		}
		mergedReaders := mergeR3Readers(retainedReaders, readers)
		if len(mergedReaders) > maximumR3Readers {
			return fileR3DocumentEntry{}, false, ErrR3DocumentCapacity
		}
		if !retainUntil.After(existing.retainUntil) && equalR3Readers(mergedReaders, retainedReaders) {
			return previous, true, nil
		}
		if existing.retainUntil.After(retainUntil) {
			retainUntil = existing.retainUntil
		}
		if err := store.write(digest, exactBytes, mergedReaders, retainUntil); err != nil {
			return fileR3DocumentEntry{}, false, err
		}
		existing.retainUntil = retainUntil.UTC()
		existing.readers = mergedReaders
		store.entries[digest] = existing
		return previous, true, nil
	}
	if len(store.entries) >= store.maxDocuments ||
		store.bytes+int64(len(exactBytes)) > store.maxBytes {
		return fileR3DocumentEntry{}, false, ErrR3DocumentCapacity
	}
	if err := store.write(digest, exactBytes, readers, retainUntil); err != nil {
		return fileR3DocumentEntry{}, false, err
	}
	store.entries[digest] = fileR3DocumentEntry{
		bytes:       int64(len(exactBytes)),
		retainUntil: retainUntil.UTC(),
		readers:     append([]string(nil), readers...),
	}
	store.bytes += int64(len(exactBytes))
	return fileR3DocumentEntry{}, false, nil
}

// Load returns an independent copy of one unexpired exact document.
func (store *FileR3DocumentStore) Load(
	ctx context.Context,
	digest string,
) ([]byte, error) {
	if store == nil || store.clock == nil {
		return nil, errors.New("reference: R3 document store is unavailable")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, exists := store.entries[digest]
	if !exists {
		return nil, ErrR3DocumentNotFound
	}
	if !entry.retainUntil.After(store.clock.Now()) {
		if err := store.remove(digest, entry); err != nil {
			return nil, err
		}
		return nil, ErrR3DocumentNotFound
	}
	exactBytes, retainUntil, readers, err := store.read(digest)
	if err != nil {
		return nil, err
	}
	if !retainUntil.Equal(entry.retainUntil) || !equalR3Readers(readers, entry.readers) || r3.S256(exactBytes) != digest {
		return nil, ErrR3DocumentIntegrity
	}
	return exactBytes, nil
}

// LoadAuthorized returns exact bytes only to a server identity retained before
// the corresponding token reference was released.
func (store *FileR3DocumentStore) LoadAuthorized(
	ctx context.Context,
	digest string,
	reader string,
) ([]byte, error) {
	if err := aauth.ValidateServerIdentifier(reader); err != nil {
		return nil, ErrR3DocumentUnauthorized
	}
	exact, err := store.Load(ctx, digest)
	if err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, exists := store.entries[digest]
	if !exists || !containsR3Reader(entry.readers, reader) {
		return nil, ErrR3DocumentUnauthorized
	}
	return exact, nil
}

func (store *FileR3DocumentStore) removeExpired(now time.Time) error {
	for digest, entry := range store.entries {
		if entry.retainUntil.After(now) {
			continue
		}
		if err := store.remove(digest, entry); err != nil {
			return err
		}
	}
	return nil
}

func (store *FileR3DocumentStore) remove(
	digest string,
	entry fileR3DocumentEntry,
) error {
	path, err := store.documentPath(digest)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("reference: remove expired R3 document: %w", err)
	}
	delete(store.entries, digest)
	store.bytes -= entry.bytes
	return syncR3Directory(store.directory)
}

func (store *FileR3DocumentStore) read(
	digest string,
) ([]byte, time.Time, []string, error) {
	path, err := store.documentPath(digest)
	if err != nil {
		return nil, time.Time{}, nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, nil, fmt.Errorf("reference: open R3 document: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, time.Time{}, nil, errors.New("reference: retained R3 document file is unsafe")
	}
	maximum := int64(fileR3DocumentHeaderBytes+maximumR3ReaderBytes) + store.maxDocumentBytes
	encoded, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, time.Time{}, nil, fmt.Errorf("reference: read R3 document: %w", err)
	}
	if int64(len(encoded)) > maximum || len(encoded) < fileR3DocumentHeaderBytes ||
		string(encoded[:len(fileR3DocumentMagic)]) != fileR3DocumentMagic {
		return nil, time.Time{}, nil, ErrR3DocumentIntegrity
	}
	offset := len(fileR3DocumentMagic)
	retainUnixNano := int64(binary.BigEndian.Uint64(
		encoded[offset : offset+8],
	))
	offset += 8
	readerLength := int(binary.BigEndian.Uint32(encoded[offset : offset+4]))
	offset += 4
	length := binary.BigEndian.Uint64(
		encoded[offset : offset+8],
	)
	offset += 8
	if readerLength < 0 || readerLength > maximumR3ReaderBytes || offset+readerLength > len(encoded) ||
		length != uint64(len(encoded)-offset-readerLength) {
		return nil, time.Time{}, nil, ErrR3DocumentIntegrity
	}
	var readers []string
	if readerLength != 0 {
		if err := json.Unmarshal(encoded[offset:offset+readerLength], &readers); err != nil {
			return nil, time.Time{}, nil, ErrR3DocumentIntegrity
		}
		canonical, err := canonicalR3Readers(readers)
		if err != nil || !equalR3Readers(canonical, readers) {
			return nil, time.Time{}, nil, ErrR3DocumentIntegrity
		}
	}
	offset += readerLength
	return append([]byte(nil), encoded[offset:]...),
		time.Unix(0, retainUnixNano).UTC(), readers, nil
}

func (store *FileR3DocumentStore) write(
	digest string,
	exactBytes []byte,
	readers []string,
	retainUntil time.Time,
) error {
	path, err := store.documentPath(digest)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(store.directory, ".r3-document-*")
	if err != nil {
		return fmt.Errorf("reference: create R3 document temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("reference: protect R3 document temporary file: %w", err)
	}
	readerBytes, err := json.Marshal(readers)
	if err != nil || len(readerBytes) > maximumR3ReaderBytes {
		return ErrR3DocumentIntegrity
	}
	if len(readers) == 0 {
		readerBytes = nil
	}
	header := make([]byte, fileR3DocumentHeaderBytes)
	copy(header, fileR3DocumentMagic)
	offset := len(fileR3DocumentMagic)
	binary.BigEndian.PutUint64(
		header[offset:offset+8],
		uint64(retainUntil.UTC().UnixNano()),
	)
	offset += 8
	binary.BigEndian.PutUint32(header[offset:offset+4], uint32(len(readerBytes)))
	offset += 4
	binary.BigEndian.PutUint64(
		header[offset:offset+8],
		uint64(len(exactBytes)),
	)
	if _, err := temporary.Write(header); err != nil {
		return fmt.Errorf("reference: write R3 document header: %w", err)
	}
	if _, err := temporary.Write(readerBytes); err != nil {
		return fmt.Errorf("reference: write R3 document readers: %w", err)
	}
	if _, err := temporary.Write(exactBytes); err != nil {
		return fmt.Errorf("reference: write R3 document bytes: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("reference: sync R3 document: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("reference: close R3 document: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("reference: publish R3 document: %w", err)
	}
	return syncR3Directory(store.directory)
}

func (store *FileR3DocumentStore) documentPath(digest string) (string, error) {
	canonical, ok := fileR3DocumentDigest(digest + ".r3")
	if !ok || canonical != digest {
		return "", ErrR3DocumentIntegrity
	}
	return filepath.Join(store.directory, digest+".r3"), nil
}

func fileR3DocumentDigest(name string) (string, bool) {
	if !strings.HasSuffix(name, ".r3") {
		return "", false
	}
	digest := strings.TrimSuffix(name, ".r3")
	if len(digest) != 43 {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(digest)
	return digest, err == nil && len(decoded) == 32 &&
		base64.RawURLEncoding.EncodeToString(decoded) == digest
}

func canonicalR3Readers(readers []string) ([]string, error) {
	if len(readers) == 0 || len(readers) > maximumR3Readers {
		return nil, errors.New("reference: R3 document readers must be a bounded nonempty set")
	}
	canonical := append([]string(nil), readers...)
	sort.Strings(canonical)
	for index, reader := range canonical {
		if err := aauth.ValidateServerIdentifier(reader); err != nil {
			return nil, fmt.Errorf("reference: R3 document reader: %w", err)
		}
		if index != 0 && canonical[index-1] == reader {
			return nil, errors.New("reference: R3 document readers contain a duplicate")
		}
	}
	return canonical, nil
}

func mergeR3Readers(left, right []string) []string {
	if len(right) == 0 {
		return append([]string(nil), left...)
	}
	merged := append(append([]string(nil), left...), right...)
	sort.Strings(merged)
	unique := merged[:0]
	for _, reader := range merged {
		if len(unique) == 0 || unique[len(unique)-1] != reader {
			unique = append(unique, reader)
		}
	}
	return unique
}

func equalR3Readers(left, right []string) bool {
	return slices.Equal(left, right)
}

func containsR3Reader(readers []string, reader string) bool {
	position, found := slices.BinarySearch(readers, reader)
	return found && position < len(readers)
}

func syncR3Directory(directory string) error {
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("reference: open R3 document directory: %w", err)
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("reference: sync R3 document directory: %w", err)
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("reference: R3 document operation requires context")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
