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
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

const (
	fileR3DocumentMagic       = "AAR3DOC1"
	fileR3DocumentHeaderBytes = len(fileR3DocumentMagic) + 8 + 8
	defaultR3DocumentLimit    = 128
	defaultR3DocumentBytes    = int64(maxJSONBody)
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
	// ErrR3ProposalConsumed means this per-call auth-token identifier already
	// crossed the durable operation-admission boundary for the proposal.
	ErrR3ProposalConsumed = errors.New("reference: R3 per-call authorization was already consumed")
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

// R3ProposalDocumentStore adds durable proposal classification and one-shot
// per-call-token consumption while retaining the exact bytes for AS fetches.
type R3ProposalDocumentStore interface {
	R3DocumentStore
	RetainProposal(context.Context, string, []byte, time.Time) error
	LoadProposal(context.Context, string) ([]byte, error)
	ConsumeProposal(context.Context, string, string, time.Time) error
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
	bytes         int64
	proposalBytes int64
	retainUntil   time.Time
	proposal      bool
	consumed      map[string]time.Time
}

type fileR3ProposalState struct {
	Schema      string           `json:"schema"`
	Digest      string           `json:"digest"`
	RetainUntil int64            `json:"retain_until_unix_nano"`
	Consumed    map[string]int64 `json:"consumed"`
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
		if strings.HasPrefix(name, ".r3-document-") || strings.HasPrefix(name, ".r3-proposal-") {
			if directoryEntry.Type().IsRegular() {
				_ = os.Remove(filepath.Join(store.directory, name))
			}
			continue
		}
		if _, proposal := fileR3ProposalDigest(name); proposal {
			continue
		}
		digest, ok := fileR3DocumentDigest(name)
		if !ok || directoryEntry.Type()&os.ModeSymlink != 0 || !directoryEntry.Type().IsRegular() {
			return fmt.Errorf("reference: R3 document store contains unexpected entry %q", name)
		}
		exactBytes, retainUntil, err := store.read(digest)
		if err != nil {
			return err
		}
		if aauth.R3S256(exactBytes) != digest {
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
			proposalPath, pathErr := store.proposalPath(digest)
			if pathErr != nil {
				return pathErr
			}
			if err := os.Remove(proposalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("reference: remove expired R3 proposal state: %w", err)
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
			bytes:       int64(len(exactBytes)),
			retainUntil: retainUntil,
		}
		store.bytes += int64(len(exactBytes))
	}
	if removedExpired {
		if err := syncR3Directory(store.directory); err != nil {
			return err
		}
		directoryEntries, err = os.ReadDir(store.directory)
		if err != nil {
			return fmt.Errorf("reference: reread R3 document store: %w", err)
		}
	}
	for _, directoryEntry := range directoryEntries {
		name := directoryEntry.Name()
		digest, proposal := fileR3ProposalDigest(name)
		if !proposal {
			continue
		}
		if directoryEntry.Type()&os.ModeSymlink != 0 || !directoryEntry.Type().IsRegular() {
			return fmt.Errorf("reference: R3 proposal state contains unsafe entry %q", name)
		}
		entry, exists := store.entries[digest]
		if !exists {
			return fmt.Errorf("reference: R3 proposal state has no retained document %q", name)
		}
		state, proposalBytes, err := store.readProposalState(digest)
		if err != nil {
			return err
		}
		if store.bytes+proposalBytes > store.maxBytes {
			return errors.New("reference: retained R3 proposal state exceeds configured capacity")
		}
		// The exact document is the retention authority. Its lifetime may have
		// been extended after proposal metadata was published (including a crash
		// between the two single-file replacements), so older proposal metadata
		// remains valid but must never claim a later lifetime.
		if state.Digest != digest || state.RetainUntil <= 0 ||
			state.RetainUntil > entry.retainUntil.UnixNano() {
			return ErrR3DocumentIntegrity
		}
		entry.proposal = true
		entry.proposalBytes = proposalBytes
		entry.consumed = make(map[string]time.Time, len(state.Consumed))
		for tokenID, expiresUnixNano := range state.Consumed {
			expiresAt := time.Unix(0, expiresUnixNano).UTC()
			if tokenID == "" || expiresAt.After(entry.retainUntil) {
				return ErrR3DocumentIntegrity
			}
			if expiresAt.After(now) {
				entry.consumed[tokenID] = expiresAt
			}
		}
		store.entries[digest] = entry
		store.bytes += proposalBytes
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
	_, _, err := store.retainLocked(digest, exactBytes, retainUntil, store.clock.Now())
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
	if aauth.R3S256(exactBytes) != digest {
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
	retainUntil time.Time,
	now time.Time,
) (fileR3DocumentEntry, bool, error) {
	if err := store.removeExpired(now); err != nil {
		return fileR3DocumentEntry{}, false, err
	}
	if existing, exists := store.entries[digest]; exists {
		previous := existing
		retained, _, err := store.read(digest)
		if err != nil {
			return fileR3DocumentEntry{}, false, err
		}
		if !bytes.Equal(retained, exactBytes) {
			return fileR3DocumentEntry{}, false, ErrR3DocumentIntegrity
		}
		if !retainUntil.After(existing.retainUntil) {
			return previous, true, nil
		}
		if err := store.write(digest, exactBytes, retainUntil); err != nil {
			return fileR3DocumentEntry{}, false, err
		}
		existing.retainUntil = retainUntil.UTC()
		store.entries[digest] = existing
		return previous, true, nil
	}
	if len(store.entries) >= store.maxDocuments ||
		store.bytes+int64(len(exactBytes)) > store.maxBytes {
		return fileR3DocumentEntry{}, false, ErrR3DocumentCapacity
	}
	if err := store.write(digest, exactBytes, retainUntil); err != nil {
		return fileR3DocumentEntry{}, false, err
	}
	store.entries[digest] = fileR3DocumentEntry{
		bytes:       int64(len(exactBytes)),
		retainUntil: retainUntil.UTC(),
	}
	store.bytes += int64(len(exactBytes))
	return fileR3DocumentEntry{}, false, nil
}

// RetainProposal durably marks exact bytes as a per-call proposal before a
// referencing resource token can be exposed.
func (store *FileR3DocumentStore) RetainProposal(
	ctx context.Context,
	digest string,
	exactBytes []byte,
	retainUntil time.Time,
) error {
	document, err := aauth.ParseR3Document(exactBytes)
	if err != nil {
		return fmt.Errorf("reference: invalid R3 proposal: %w", err)
	}
	if document.Parameters == nil {
		return errors.New("reference: invalid R3 proposal: parameters are required")
	}
	if err := store.validateRetention(ctx, digest, exactBytes, retainUntil); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	previous, existed, err := store.retainLocked(
		digest,
		exactBytes,
		retainUntil,
		store.clock.Now(),
	)
	if err != nil {
		return err
	}
	entry, exists := store.entries[digest]
	if !exists || !entry.retainUntil.After(store.clock.Now()) {
		return ErrR3DocumentNotFound
	}
	entry.proposal = true
	if entry.consumed == nil {
		entry.consumed = make(map[string]time.Time)
	}
	proposalBytes, err := store.writeProposalState(digest, entry)
	if err != nil {
		rollbackErr := store.rollbackProposalRetention(digest, exactBytes, previous, existed)
		return errors.Join(err, rollbackErr)
	}
	store.bytes += proposalBytes - entry.proposalBytes
	entry.proposalBytes = proposalBytes
	store.entries[digest] = entry
	return nil
}

func (store *FileR3DocumentStore) rollbackProposalRetention(
	digest string,
	exactBytes []byte,
	previous fileR3DocumentEntry,
	existed bool,
) error {
	current, currentExists := store.entries[digest]
	if !currentExists {
		return ErrR3DocumentIntegrity
	}
	if !existed {
		return store.remove(digest, current)
	}

	var rollbackErrors []error
	if previous.proposal {
		if _, err := store.writeProposalState(digest, previous); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("restore R3 proposal state: %w", err))
		}
	} else {
		path, err := store.proposalPath(digest)
		if err != nil {
			rollbackErrors = append(rollbackErrors, err)
		} else if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("remove failed R3 proposal state: %w", err))
		}
	}
	if !current.retainUntil.Equal(previous.retainUntil) {
		if err := store.write(digest, exactBytes, previous.retainUntil); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("restore R3 document retention: %w", err))
		}
	}
	if len(rollbackErrors) == 0 {
		store.entries[digest] = previous
	}
	return errors.Join(rollbackErrors...)
}

// LoadProposal returns exact bytes only when durable metadata classifies the
// retained document as a per-call proposal.
func (store *FileR3DocumentStore) LoadProposal(
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
	if !exists || !entry.proposal {
		return nil, ErrR3DocumentNotFound
	}
	if !entry.retainUntil.After(store.clock.Now()) {
		if err := store.remove(digest, entry); err != nil {
			return nil, err
		}
		return nil, ErrR3DocumentNotFound
	}
	exactBytes, retainUntil, err := store.read(digest)
	if err != nil {
		return nil, err
	}
	if !retainUntil.Equal(entry.retainUntil) || aauth.R3S256(exactBytes) != digest {
		return nil, ErrR3DocumentIntegrity
	}
	return exactBytes, nil
}

// ConsumeProposal atomically admits one per-call auth-token JTI at most once.
// Consumption happens before the operation; a crash afterward is fail-closed
// and therefore at-most-once, not exactly-once consequence delivery.
func (store *FileR3DocumentStore) ConsumeProposal(
	ctx context.Context,
	digest string,
	authTokenID string,
	expiresAt time.Time,
) error {
	if store == nil || store.clock == nil {
		return errors.New("reference: R3 document store is unavailable")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if authTokenID == "" {
		return errors.New("reference: per-call auth-token JTI is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, exists := store.entries[digest]
	now := store.clock.Now()
	if !exists || !entry.proposal || !entry.retainUntil.After(now) {
		return ErrR3DocumentNotFound
	}
	if !expiresAt.After(now) || expiresAt.After(entry.retainUntil) {
		return ErrR3DocumentRetention
	}
	candidate := entry
	candidate.consumed = make(map[string]time.Time, len(entry.consumed)+1)
	for tokenID, retainedUntil := range entry.consumed {
		candidate.consumed[tokenID] = retainedUntil
	}
	for tokenID, retainedUntil := range candidate.consumed {
		if !retainedUntil.After(now) {
			delete(candidate.consumed, tokenID)
		}
	}
	if _, consumed := candidate.consumed[authTokenID]; consumed {
		return ErrR3ProposalConsumed
	}
	candidate.consumed[authTokenID] = expiresAt.UTC()
	proposalBytes, err := store.writeProposalState(digest, candidate)
	if err != nil {
		return err
	}
	store.bytes += proposalBytes - entry.proposalBytes
	candidate.proposalBytes = proposalBytes
	store.entries[digest] = candidate
	return nil
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
	exactBytes, retainUntil, err := store.read(digest)
	if err != nil {
		return nil, err
	}
	if !retainUntil.Equal(entry.retainUntil) || aauth.R3S256(exactBytes) != digest {
		return nil, ErrR3DocumentIntegrity
	}
	return exactBytes, nil
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
	proposalPath, err := store.proposalPath(digest)
	if err != nil {
		return err
	}
	if err := os.Remove(proposalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("reference: remove expired R3 proposal state: %w", err)
	}
	delete(store.entries, digest)
	store.bytes -= entry.bytes + entry.proposalBytes
	return syncR3Directory(store.directory)
}

func (store *FileR3DocumentStore) read(
	digest string,
) ([]byte, time.Time, error) {
	path, err := store.documentPath(digest)
	if err != nil {
		return nil, time.Time{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("reference: open R3 document: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, time.Time{}, errors.New("reference: retained R3 document file is unsafe")
	}
	maximum := int64(fileR3DocumentHeaderBytes) + store.maxDocumentBytes
	encoded, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("reference: read R3 document: %w", err)
	}
	if int64(len(encoded)) > maximum || len(encoded) < fileR3DocumentHeaderBytes ||
		string(encoded[:len(fileR3DocumentMagic)]) != fileR3DocumentMagic {
		return nil, time.Time{}, ErrR3DocumentIntegrity
	}
	retainUnixNano := int64(binary.BigEndian.Uint64(
		encoded[len(fileR3DocumentMagic) : len(fileR3DocumentMagic)+8],
	))
	length := binary.BigEndian.Uint64(
		encoded[len(fileR3DocumentMagic)+8 : fileR3DocumentHeaderBytes],
	)
	if length != uint64(len(encoded)-fileR3DocumentHeaderBytes) {
		return nil, time.Time{}, ErrR3DocumentIntegrity
	}
	return append([]byte(nil), encoded[fileR3DocumentHeaderBytes:]...),
		time.Unix(0, retainUnixNano).UTC(), nil
}

func (store *FileR3DocumentStore) write(
	digest string,
	exactBytes []byte,
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
	header := make([]byte, fileR3DocumentHeaderBytes)
	copy(header, fileR3DocumentMagic)
	binary.BigEndian.PutUint64(
		header[len(fileR3DocumentMagic):len(fileR3DocumentMagic)+8],
		uint64(retainUntil.UTC().UnixNano()),
	)
	binary.BigEndian.PutUint64(
		header[len(fileR3DocumentMagic)+8:],
		uint64(len(exactBytes)),
	)
	if _, err := temporary.Write(header); err != nil {
		return fmt.Errorf("reference: write R3 document header: %w", err)
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

func (store *FileR3DocumentStore) readProposalState(
	digest string,
) (fileR3ProposalState, int64, error) {
	var state fileR3ProposalState
	path, err := store.proposalPath(digest)
	if err != nil {
		return state, 0, err
	}
	file, err := os.Open(path)
	if err != nil {
		return state, 0, fmt.Errorf("reference: open R3 proposal state: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return state, 0, errors.New("reference: retained R3 proposal state file is unsafe")
	}
	if err := decodeJSONBytes(io.LimitReader(file, store.maxDocumentBytes+1), &state); err != nil {
		return state, 0, fmt.Errorf("reference: decode R3 proposal state: %w", err)
	}
	if state.Schema != "aauth.reference.r3-proposal-state.v1" || state.Consumed == nil {
		return state, 0, ErrR3DocumentIntegrity
	}
	return state, info.Size(), nil
}

func (store *FileR3DocumentStore) writeProposalState(
	digest string,
	entry fileR3DocumentEntry,
) (int64, error) {
	path, err := store.proposalPath(digest)
	if err != nil {
		return 0, err
	}
	consumed := make(map[string]int64, len(entry.consumed))
	for tokenID, expiresAt := range entry.consumed {
		consumed[tokenID] = expiresAt.UTC().UnixNano()
	}
	encoded, err := json.Marshal(fileR3ProposalState{
		Schema:      "aauth.reference.r3-proposal-state.v1",
		Digest:      digest,
		RetainUntil: entry.retainUntil.UTC().UnixNano(),
		Consumed:    consumed,
	})
	if err != nil {
		return 0, fmt.Errorf("reference: encode R3 proposal state: %w", err)
	}
	encodedBytes := int64(len(encoded))
	if encodedBytes > store.maxDocumentBytes ||
		store.bytes-entry.proposalBytes+encodedBytes > store.maxBytes {
		return 0, ErrR3DocumentCapacity
	}
	temporary, err := os.CreateTemp(store.directory, ".r3-proposal-*")
	if err != nil {
		return 0, fmt.Errorf("reference: create R3 proposal state temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return 0, fmt.Errorf("reference: protect R3 proposal state temporary file: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		return 0, fmt.Errorf("reference: write R3 proposal state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return 0, fmt.Errorf("reference: sync R3 proposal state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return 0, fmt.Errorf("reference: close R3 proposal state: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return 0, fmt.Errorf("reference: publish R3 proposal state: %w", err)
	}
	if err := syncR3Directory(store.directory); err != nil {
		return 0, err
	}
	return encodedBytes, nil
}

func (store *FileR3DocumentStore) documentPath(digest string) (string, error) {
	canonical, ok := fileR3DocumentDigest(digest + ".r3")
	if !ok || canonical != digest {
		return "", ErrR3DocumentIntegrity
	}
	return filepath.Join(store.directory, digest+".r3"), nil
}

func (store *FileR3DocumentStore) proposalPath(digest string) (string, error) {
	canonical, ok := fileR3ProposalDigest(digest + ".proposal")
	if !ok || canonical != digest {
		return "", ErrR3DocumentIntegrity
	}
	return filepath.Join(store.directory, digest+".proposal"), nil
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

func fileR3ProposalDigest(name string) (string, bool) {
	if !strings.HasSuffix(name, ".proposal") {
		return "", false
	}
	digest := strings.TrimSuffix(name, ".proposal")
	decoded, err := base64.RawURLEncoding.DecodeString(digest)
	return digest, len(digest) == 43 && err == nil && len(decoded) == 32 &&
		base64.RawURLEncoding.EncodeToString(decoded) == digest
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
