package reference

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/internal/snapshotfile"
)

var (
	// ErrProofReplay is returned when an exact protected-request proof has
	// already crossed the resource's operation-admission boundary.
	ErrProofReplay = errors.New("reference: request proof was replayed")
	// ErrProofReplayStoreConfig means a replay adapter was not given explicit,
	// usable clock, capacity, or directory configuration.
	ErrProofReplayStoreConfig = errors.New("reference: proof replay store configuration is invalid")
	// ErrProofReplayStoreCapacity means retaining another live proof would
	// exceed the adapter's explicit finite bounds.
	ErrProofReplayStoreCapacity = errors.New("reference: proof replay store capacity is exhausted")
	// ErrProofReplayStoreUnsafe means file custody is not private, regular,
	// single-linked, and non-symlinked.
	ErrProofReplayStoreUnsafe = errors.New("reference: proof replay store custody is unsafe")
	// ErrProofReplayStoreLocked means another writer owns the file-store
	// directory.
	ErrProofReplayStoreLocked = errors.New("reference: proof replay store already has a writer")
	// ErrProofReplayStoreIntegrity means retained state is not the one strict,
	// canonical schema accepted by this adapter.
	ErrProofReplayStoreIntegrity = errors.New("reference: proof replay store integrity check failed")
	// ErrProofReplayStoreCommitUncertain means replacement reached rename but
	// the final directory durability boundary did not report success.
	ErrProofReplayStoreCommitUncertain = errors.New("reference: proof replay store commit is uncertain")
	// ErrProofReplayStoreClosed means a file adapter was used after its writer
	// custody was released.
	ErrProofReplayStoreClosed = errors.New("reference: proof replay store is closed")
)

const (
	fileProofReplaySchema        = "aauth.reference.proof-replay-store"
	maxProofReplayRecordBytes    = int64(256)
	minimumProofReplayStoreBytes = int64(128)
)

// ProofReplayStore is the resource deployment's atomic proof-admission
// boundary. Consume returns ErrProofReplay for an exact live duplicate. It
// must not return nil unless that replay key remains consumed through
// expiresAt, including across process reconstruction for durable adapters.
type ProofReplayStore interface {
	Consume(context.Context, string, time.Time) error
}

// MemoryProofReplayStore is a bounded in-process implementation for embedded
// deployments and tests that do not claim restart recovery.
type MemoryProofReplayStore struct {
	mu         sync.Mutex
	clock      aauth.Clock
	maxEntries int
	entries    map[string]time.Time
}

// NewMemoryProofReplayStore constructs an explicitly bounded memory store.
func NewMemoryProofReplayStore(clock aauth.Clock, maxEntries int) (*MemoryProofReplayStore, error) {
	if clock == nil || maxEntries <= 0 {
		return nil, ErrProofReplayStoreConfig
	}
	return &MemoryProofReplayStore{
		clock:      clock,
		maxEntries: maxEntries,
		entries:    make(map[string]time.Time),
	}, nil
}

// Consume atomically admits one exact live proof key.
func (store *MemoryProofReplayStore) Consume(ctx context.Context, replayKey string, expiresAt time.Time) error {
	if store == nil || store.clock == nil {
		return ErrProofReplayStoreConfig
	}
	if err := validateProofReplayConsumption(ctx, replayKey, expiresAt, store.clock.Now()); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.clock.Now()
	for key, expiry := range store.entries {
		if !expiry.After(now) {
			delete(store.entries, key)
		}
	}
	if _, exists := store.entries[replayKey]; exists {
		return ErrProofReplay
	}
	if len(store.entries) >= store.maxEntries {
		return ErrProofReplayStoreCapacity
	}
	store.entries[replayKey] = expiresAt.UTC()
	return nil
}

// FileProofReplayStoreConfig configures one bounded, single-writer durable
// replay authority. Directory must be a canonical absolute path dedicated to
// this store. Both limits are required; there are no implicit defaults.
type FileProofReplayStoreConfig struct {
	Directory  string
	Clock      aauth.Clock
	MaxEntries int
	MaxBytes   int64
}

// FileProofReplayStore retains a canonical snapshot by synced temporary-file
// replacement under exclusive private directory custody.
type FileProofReplayStore struct {
	mu      sync.Mutex
	clock   aauth.Clock
	file    *snapshotfile.File
	entries map[string]time.Time
	closed  bool
}

type fileProofReplaySnapshot struct {
	Schema  string                  `json:"schema"`
	Entries []fileProofReplayRecord `json:"entries"`
}

type fileProofReplayRecord struct {
	ReplayKey string `json:"replay_key"`
	ExpiresAt int64  `json:"expires_at_unix_nano"`
}

// OpenFileProofReplayStore opens or creates the one current replay snapshot.
// It accepts no alternate schema or import format.
func OpenFileProofReplayStore(config FileProofReplayStoreConfig) (*FileProofReplayStore, error) {
	if config.Clock == nil || config.MaxEntries <= 0 || config.MaxBytes < minimumProofReplayStoreBytes {
		return nil, ErrProofReplayStoreConfig
	}
	limits, err := snapshotfile.NewLimits(config.MaxEntries, config.MaxBytes, maxProofReplayRecordBytes)
	if err != nil {
		return nil, ErrProofReplayStoreConfig
	}
	file, body, err := snapshotfile.Open(config.Directory, limits)
	if err != nil {
		return nil, mapProofReplayFileError(err)
	}
	store := &FileProofReplayStore{
		clock:   config.Clock,
		file:    file,
		entries: make(map[string]time.Time),
	}
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
		}
	}()
	if len(body) == 0 {
		if err := store.persistLocked(store.entries); err != nil {
			return nil, err
		}
		failed = false
		return store, nil
	}
	entries, err := decodeFileProofReplaySnapshot(body, limits)
	if err != nil {
		return nil, err
	}
	store.entries = entries
	now := store.clock.Now()
	pruned := cloneProofReplayEntries(store.entries)
	for replayKey, expiresAt := range pruned {
		if !expiresAt.After(now) {
			delete(pruned, replayKey)
		}
	}
	if len(pruned) != len(store.entries) {
		if err := store.persistLocked(pruned); err != nil {
			return nil, err
		}
		store.entries = pruned
	}
	failed = false
	return store, nil
}

// Consume atomically persists one exact live proof before reporting success.
func (store *FileProofReplayStore) Consume(ctx context.Context, replayKey string, expiresAt time.Time) error {
	if store == nil || store.clock == nil {
		return ErrProofReplayStoreConfig
	}
	if err := validateProofReplayConsumption(ctx, replayKey, expiresAt, store.clock.Now()); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed || store.file == nil {
		return ErrProofReplayStoreClosed
	}
	now := store.clock.Now()
	next := cloneProofReplayEntries(store.entries)
	for key, expiry := range next {
		if !expiry.After(now) {
			delete(next, key)
		}
	}
	if _, exists := next[replayKey]; exists {
		return ErrProofReplay
	}
	if len(next) >= store.file.Limits().MaxRecords() {
		return ErrProofReplayStoreCapacity
	}
	next[replayKey] = expiresAt.UTC()
	body, records, err := marshalFileProofReplaySnapshot(next)
	if err != nil {
		return err
	}
	published, err := store.file.Replace(body, records)
	if published {
		store.entries = next
	}
	if err != nil {
		return mapProofReplayFileError(err)
	}
	store.entries = next
	return nil
}

// Close releases the file adapter's exclusive writer custody.
func (store *FileProofReplayStore) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	file := store.file
	store.file = nil
	return mapProofReplayFileError(file.Close())
}

func (store *FileProofReplayStore) persistLocked(entries map[string]time.Time) error {
	body, records, err := marshalFileProofReplaySnapshot(entries)
	if err != nil {
		return err
	}
	_, err = store.file.Replace(body, records)
	return mapProofReplayFileError(err)
}

func decodeFileProofReplaySnapshot(body []byte, limits snapshotfile.Limits) (map[string]time.Time, error) {
	if len(body) == 0 || int64(len(body)) > limits.MaxBytes() {
		return nil, ErrProofReplayStoreIntegrity
	}
	if err := jsonstrict.RejectAmbiguousNames(body); err != nil {
		return nil, errors.Join(ErrProofReplayStoreIntegrity, err)
	}
	var snapshot fileProofReplaySnapshot
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, errors.Join(ErrProofReplayStoreIntegrity, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return nil, errors.Join(ErrProofReplayStoreIntegrity, err)
	}
	if snapshot.Schema != fileProofReplaySchema || len(snapshot.Entries) > limits.MaxRecords() {
		return nil, ErrProofReplayStoreIntegrity
	}
	entries := make(map[string]time.Time, len(snapshot.Entries))
	previous := ""
	for _, record := range snapshot.Entries {
		encoded, err := json.Marshal(record)
		if err != nil || int64(len(encoded)) > limits.MaxRecordBytes() ||
			!validProofReplayKey(record.ReplayKey) || record.ExpiresAt <= 0 ||
			record.ReplayKey <= previous {
			return nil, ErrProofReplayStoreIntegrity
		}
		previous = record.ReplayKey
		entries[record.ReplayKey] = time.Unix(0, record.ExpiresAt).UTC()
	}
	canonical, _, err := marshalFileProofReplaySnapshot(entries)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, ErrProofReplayStoreIntegrity
	}
	return entries, nil
}

func marshalFileProofReplaySnapshot(entries map[string]time.Time) ([]byte, [][]byte, error) {
	keys := make([]string, 0, len(entries))
	for replayKey := range entries {
		keys = append(keys, replayKey)
	}
	sort.Strings(keys)
	snapshot := fileProofReplaySnapshot{
		Schema:  fileProofReplaySchema,
		Entries: make([]fileProofReplayRecord, 0, len(keys)),
	}
	records := make([][]byte, 0, len(keys))
	for _, replayKey := range keys {
		record := fileProofReplayRecord{
			ReplayKey: replayKey,
			ExpiresAt: entries[replayKey].UTC().UnixNano(),
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, nil, errors.Join(ErrProofReplayStoreIntegrity, err)
		}
		snapshot.Entries = append(snapshot.Entries, record)
		records = append(records, encoded)
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		return nil, nil, errors.Join(ErrProofReplayStoreIntegrity, err)
	}
	return body, records, nil
}

func validateProofReplayConsumption(ctx context.Context, replayKey string, expiresAt, now time.Time) error {
	if ctx == nil {
		return ErrProofReplayStoreConfig
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if !validProofReplayKey(replayKey) || expiresAt.IsZero() || !expiresAt.After(now) {
		return ErrProofReplayStoreConfig
	}
	return nil
}

func validProofReplayKey(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func cloneProofReplayEntries(entries map[string]time.Time) map[string]time.Time {
	cloned := make(map[string]time.Time, len(entries))
	for replayKey, expiresAt := range entries {
		cloned[replayKey] = expiresAt
	}
	return cloned
}

func mapProofReplayFileError(err error) error {
	eventErr := mapEventSnapshotFileError(err)
	if eventErr == nil {
		return nil
	}
	var target error
	switch {
	case errors.Is(eventErr, ErrEventStoreConfig):
		target = ErrProofReplayStoreConfig
	case errors.Is(eventErr, ErrEventStoreCapacity):
		target = ErrProofReplayStoreCapacity
	case errors.Is(eventErr, ErrEventStoreUnsafe):
		target = ErrProofReplayStoreUnsafe
	case errors.Is(eventErr, ErrEventStoreLocked):
		target = ErrProofReplayStoreLocked
	case errors.Is(eventErr, ErrEventStoreIntegrity):
		target = ErrProofReplayStoreIntegrity
	case errors.Is(eventErr, ErrEventStoreCommitUncertain):
		target = ErrProofReplayStoreCommitUncertain
	case errors.Is(eventErr, ErrEventStoreClosed):
		target = ErrProofReplayStoreClosed
	default:
		return eventErr
	}
	return fmt.Errorf("%w: %v", target, eventErr)
}
