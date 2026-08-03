package reference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

var (
	// ErrEventStoreConfig means a bounded file adapter configuration is invalid.
	ErrEventStoreConfig = errors.New("reference: event file store configuration is invalid")
	// ErrEventStoreCapacity means a complete candidate snapshot exceeds one of
	// the adapter's configured finite bounds.
	ErrEventStoreCapacity = errors.New("reference: event file store capacity is exhausted")
	// ErrEventStoreUnsafe means filesystem custody is not private, regular, and
	// non-symlinked as required by the reference adapter.
	ErrEventStoreUnsafe = errors.New("reference: event file store custody is unsafe")
	// ErrEventStoreLocked means another writer owns the adapter directory.
	ErrEventStoreLocked = errors.New("reference: event file store already has a writer")
	// ErrEventStoreIntegrity means retained bytes fail strict schema or domain
	// validation and no authority was made available from them.
	ErrEventStoreIntegrity = errors.New("reference: event file store integrity check failed")
	// ErrEventStoreCommitUncertain means atomic rename published a complete
	// successor but the final durability boundary did not report success.
	ErrEventStoreCommitUncertain = errors.New("reference: event file store commit is uncertain")
	// ErrEventStoreClosed means an adapter was used after releasing its writer
	// lock.
	ErrEventStoreClosed = errors.New("reference: event file store is closed")
)

const (
	eventFileStateName       = "state.json"
	eventFileLockName        = "writer.lock"
	eventFileTemporaryPrefix = ".state-"

	defaultEventFileMaxRecords     = 1024
	defaultEventFileMaxBytes       = int64(8 << 20)
	defaultEventFileMaxRecordBytes = int64(1 << 20)

	fileAPSnapshotSchema        = "aauth.reference.events.ap-store.v1"
	fileAPSubscriptionSchema    = "aauth.reference.events.ap-subscription.v1"
	fileAPDeliverySchema        = "aauth.reference.events.ap-delivery.v1"
	fileResourceSnapshotSchema  = "aauth.reference.events.resource-store.v1"
	fileResourceAuthoritySchema = "aauth.reference.events.resource-authority.v1"
	fileAgentSnapshotSchema     = "aauth.reference.events.agent-store.v1"
	fileAgentContextSchema      = "aauth.reference.events.agent-context.v1"
	fileAgentProcessingSchema   = "aauth.reference.events.agent-processing.v1"
	fileAgentDispositionSchema  = "aauth.reference.events.agent-disposition.v1"
)

type eventFileCommitPhase uint8

const (
	eventFileCommitAfterWrite eventFileCommitPhase = iota + 1
	eventFileCommitAfterFileSync
	eventFileCommitAfterRename
	eventFileCommitAfterDirectorySync
)

type eventFileLimits struct {
	maxRecords     int
	maxBytes       int64
	maxRecordBytes int64
}

func normalizeEventFileLimits(maxRecords int, maxBytes, maxRecordBytes int64) (eventFileLimits, error) {
	if maxRecords < 0 || maxBytes < 0 || maxRecordBytes < 0 {
		return eventFileLimits{}, ErrEventStoreConfig
	}
	if maxRecords == 0 {
		maxRecords = defaultEventFileMaxRecords
	}
	if maxBytes == 0 {
		maxBytes = defaultEventFileMaxBytes
	}
	if maxRecordBytes == 0 {
		maxRecordBytes = defaultEventFileMaxRecordBytes
	}
	if maxRecords <= 0 || maxBytes <= 0 || maxRecordBytes <= 0 {
		return eventFileLimits{}, ErrEventStoreConfig
	}
	return eventFileLimits{maxRecords: maxRecords, maxBytes: maxBytes, maxRecordBytes: maxRecordBytes}, nil
}

type eventFileEngine struct {
	directory  string
	limits     eventFileLimits
	lock       *eventFileLock
	failCommit func(eventFileCommitPhase) error
}

func openEventFileEngine(directory string, limits eventFileLimits) (engine *eventFileEngine, body []byte, err error) {
	resolved, err := prepareEventFileDirectory(directory)
	if err != nil {
		return nil, nil, err
	}
	lock, err := acquireEventFileLock(resolved)
	if err != nil {
		return nil, nil, err
	}
	engine = &eventFileEngine{directory: resolved, limits: limits, lock: lock}
	opened := engine
	defer func() {
		if err != nil {
			_ = opened.Close()
			engine = nil
		}
	}()
	if err = engine.cleanAndValidateEntries(); err != nil {
		return nil, nil, err
	}
	body, err = engine.readState()
	if err != nil {
		return nil, nil, err
	}
	return engine, body, nil
}

func (engine *eventFileEngine) Close() error {
	if engine == nil || engine.lock == nil {
		return nil
	}
	lock := engine.lock
	engine.lock = nil
	return lock.Close()
}

func prepareEventFileDirectory(directory string) (string, error) {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return "", ErrEventStoreConfig
	}
	if err := rejectEventFileSymlinkComponents(directory); err != nil {
		return "", err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("%w: create directory: %v", ErrEventStoreUnsafe, err)
	}
	if err := rejectEventFileSymlinkComponents(directory); err != nil {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return "", ErrEventStoreUnsafe
	}
	return directory, nil
}

func rejectEventFileSymlinkComponents(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return ErrEventStoreUnsafe
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: inspect directory: %v", ErrEventStoreUnsafe, err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func (engine *eventFileEngine) cleanAndValidateEntries() error {
	entries, err := os.ReadDir(engine.directory)
	if err != nil {
		return fmt.Errorf("%w: read directory: %v", ErrEventStoreUnsafe, err)
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(engine.directory, name)
		switch {
		case name == eventFileLockName:
			if err := validatePrivateEventFile(path); err != nil {
				return err
			}
		case name == eventFileStateName:
			if err := validatePrivateEventFile(path); err != nil {
				return err
			}
		case strings.HasPrefix(name, eventFileTemporaryPrefix) && len(name) > len(eventFileTemporaryPrefix):
			if err := validatePrivateEventFile(path); err != nil {
				return err
			}
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("%w: remove crash temporary: %v", ErrEventStoreUnsafe, err)
			}
			removed = true
		default:
			return fmt.Errorf("%w: unexpected entry %q", ErrEventStoreUnsafe, name)
		}
	}
	if removed {
		return syncEventFileDirectory(engine.directory)
	}
	return nil
}

func validatePrivateEventFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || !eventFileHasSingleLink(info) {
		return ErrEventStoreUnsafe
	}
	return nil
}

func (engine *eventFileEngine) readState() ([]byte, error) {
	path := filepath.Join(engine.directory, eventFileStateName)
	if err := validatePrivateEventFile(path); err != nil {
		if errors.Is(err, ErrEventStoreUnsafe) {
			if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
				return nil, nil
			}
		}
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: open state: %v", ErrEventStoreUnsafe, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: inspect opened state: %v", ErrEventStoreUnsafe, err)
	}
	linked, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, linked) || opened.Mode().Perm() != 0o600 ||
		!opened.Mode().IsRegular() || !eventFileHasSingleLink(opened) {
		return nil, ErrEventStoreUnsafe
	}
	body, err := io.ReadAll(io.LimitReader(file, engine.limits.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read state: %v", ErrEventStoreIntegrity, err)
	}
	if int64(len(body)) > engine.limits.maxBytes {
		return nil, ErrEventStoreCapacity
	}
	return body, nil
}

func (engine *eventFileEngine) commit(body []byte, records [][]byte) (published bool, err error) {
	if len(records) > engine.limits.maxRecords || int64(len(body)) > engine.limits.maxBytes {
		return false, ErrEventStoreCapacity
	}
	for _, record := range records {
		if int64(len(record)) > engine.limits.maxRecordBytes {
			return false, ErrEventStoreCapacity
		}
	}
	temporary, err := os.CreateTemp(engine.directory, eventFileTemporaryPrefix)
	if err != nil {
		return false, fmt.Errorf("reference: create event state temporary: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if !published {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return false, fmt.Errorf("reference: protect event state temporary: %w", err)
	}
	if _, err := temporary.Write(body); err != nil {
		return false, fmt.Errorf("reference: write event state: %w", err)
	}
	if err := engine.inject(eventFileCommitAfterWrite); err != nil {
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		return false, fmt.Errorf("reference: sync event state: %w", err)
	}
	if err := engine.inject(eventFileCommitAfterFileSync); err != nil {
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("reference: close event state: %w", err)
	}
	statePath := filepath.Join(engine.directory, eventFileStateName)
	if err := os.Rename(temporaryPath, statePath); err != nil {
		return false, fmt.Errorf("reference: publish event state: %w", err)
	}
	published = true
	if err := engine.inject(eventFileCommitAfterRename); err != nil {
		return true, errors.Join(ErrEventStoreCommitUncertain, err)
	}
	if err := syncEventFileDirectory(engine.directory); err != nil {
		return true, errors.Join(ErrEventStoreCommitUncertain, err)
	}
	if err := engine.inject(eventFileCommitAfterDirectorySync); err != nil {
		return true, errors.Join(ErrEventStoreCommitUncertain, err)
	}
	return true, nil
}

func (engine *eventFileEngine) inject(phase eventFileCommitPhase) error {
	if engine.failCommit == nil {
		return nil
	}
	return engine.failCommit(phase)
}

func syncEventFileDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("reference: open event state directory: %w", err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("reference: sync event state directory: %w", err)
	}
	return nil
}

func decodeEventFileSnapshot(body []byte, destination any) error {
	if len(body) == 0 {
		return ErrEventStoreIntegrity
	}
	if err := jsonstrict.RejectAmbiguousNames(body); err != nil {
		return errors.Join(ErrEventStoreIntegrity, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.Join(ErrEventStoreIntegrity, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return errors.Join(ErrEventStoreIntegrity, err)
	}
	return nil
}

func marshalEventFileSnapshot(snapshot any, records []any) ([]byte, [][]byte, error) {
	body, err := json.Marshal(snapshot)
	if err != nil {
		return nil, nil, errors.Join(ErrEventStoreIntegrity, err)
	}
	encodedRecords := make([][]byte, 0, len(records))
	for _, record := range records {
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, nil, errors.Join(ErrEventStoreIntegrity, err)
		}
		encodedRecords = append(encodedRecords, encoded)
	}
	return body, encodedRecords, nil
}

// FileAPEventStoreConfig configures one bounded AP authority/inbox snapshot.
type FileAPEventStoreConfig struct {
	Directory      string
	Issuer         string
	MaxRecords     int
	MaxBytes       int64
	MaxRecordBytes int64
}

// FileResourceEventStoreConfig configures one bounded resource authority and
// pending-delivery snapshot.
type FileResourceEventStoreConfig struct {
	Directory      string
	MaxRecords     int
	MaxBytes       int64
	MaxRecordBytes int64
}

// FileAgentEventStoreConfig configures one bounded agent context and
// consequence-processing snapshot.
type FileAgentEventStoreConfig struct {
	Directory      string
	MaxRecords     int
	MaxBytes       int64
	MaxRecordBytes int64
}

type fileAPSnapshot struct {
	Schema        string                     `json:"schema"`
	Issuer        string                     `json:"issuer"`
	NextDelivery  uint64                     `json:"next_delivery"`
	Subscriptions []fileAPSubscriptionRecord `json:"subscriptions"`
	Inbox         []fileAPDeliveryRecord     `json:"inbox"`
}

type fileAPSnapshotEnvelope struct {
	Schema        string            `json:"schema"`
	Issuer        string            `json:"issuer"`
	NextDelivery  uint64            `json:"next_delivery"`
	Subscriptions []json.RawMessage `json:"subscriptions"`
	Inbox         []json.RawMessage `json:"inbox"`
}

type fileAPSubscriptionRecord struct {
	Schema       string              `json:"schema"`
	Subscription APEventSubscription `json:"subscription"`
}

type fileAPDeliveryRecord struct {
	Schema   string        `json:"schema"`
	Accepted AcceptedEvent `json:"accepted"`
}

type fileResourceSnapshot struct {
	Schema      string                        `json:"schema"`
	Authorities []fileResourceAuthorityRecord `json:"authorities"`
}

type fileResourceSnapshotEnvelope struct {
	Schema      string            `json:"schema"`
	Authorities []json.RawMessage `json:"authorities"`
}

type fileResourceAuthorityRecord struct {
	Schema       string                     `json:"schema"`
	APIssuer     string                     `json:"ap_issuer"`
	EventID      string                     `json:"event_id"`
	Subscription *ResourceEventSubscription `json:"subscription"`
	Pending      *PendingEventDelivery      `json:"pending"`
}

type fileAgentSnapshot struct {
	Schema       string                       `json:"schema"`
	Contexts     []fileAgentContextRecord     `json:"contexts"`
	Processing   []fileAgentProcessingRecord  `json:"processing"`
	Dispositions []fileAgentDispositionRecord `json:"dispositions"`
}

type fileAgentSnapshotEnvelope struct {
	Schema       string            `json:"schema"`
	Contexts     []json.RawMessage `json:"contexts"`
	Processing   []json.RawMessage `json:"processing"`
	Dispositions []json.RawMessage `json:"dispositions"`
}

type fileAgentContextRecord struct {
	Schema  string            `json:"schema"`
	Context AgentEventContext `json:"context"`
}

type fileAgentProcessingRecord struct {
	Schema        string               `json:"schema"`
	Processing    AgentEventProcessing `json:"processing"`
	RefusalReason EventRefusalReason   `json:"refusal_reason,omitempty"`
}

type fileAgentDispositionRecord struct {
	Schema        string               `json:"schema"`
	Delivery      EventDeliveryKey     `json:"delivery"`
	State         EventProcessingState `json:"state"`
	RefusalReason EventRefusalReason   `json:"refusal_reason"`
}

// FileAPEventStore is a bounded, single-writer AP authority adapter. Its
// replaceable interface is APEventStore; the snapshot format is deployment
// custody rather than Events protocol wire.
type FileAPEventStore struct {
	mu     sync.Mutex
	file   *eventFileEngine
	memory *MemoryAPEventStore
	closed bool
}

func OpenFileAPEventStore(config FileAPEventStoreConfig) (*FileAPEventStore, error) {
	if err := validateEventSubscriptionKey(config.Issuer, "configuration-check"); err != nil {
		return nil, errors.Join(ErrEventStoreConfig, err)
	}
	limits, err := normalizeEventFileLimits(config.MaxRecords, config.MaxBytes, config.MaxRecordBytes)
	if err != nil {
		return nil, err
	}
	file, body, err := openEventFileEngine(config.Directory, limits)
	if err != nil {
		return nil, err
	}
	store := &FileAPEventStore{file: file, memory: NewMemoryAPEventStore(config.Issuer)}
	if len(body) == 0 {
		if err := store.persistInitial(); err != nil {
			_ = file.Close()
			return nil, err
		}
		return store, nil
	}
	memory, err := decodeFileAPSnapshot(body, config.Issuer, limits)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	store.memory = memory
	return store, nil
}

func (store *FileAPEventStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	return store.file.Close()
}

func (store *FileAPEventStore) CreateSubscription(ctx context.Context, value APEventSubscription) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return err
	}
	candidate := cloneMemoryAPEventStore(store.memory)
	if err := candidate.CreateSubscription(ctx, value); err != nil {
		return err
	}
	return store.commitCandidate(candidate)
}

func (store *FileAPEventStore) AcceptEvent(ctx context.Context, input AcceptedEventInput) (AcceptedEvent, int, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var zero AcceptedEvent
	if err := store.openError(); err != nil {
		return zero, 0, err
	}
	candidate := cloneMemoryAPEventStore(store.memory)
	accepted, remaining, err := candidate.AcceptEvent(ctx, input)
	if err != nil {
		return zero, 0, err
	}
	if err := store.commitCandidate(candidate); err != nil {
		return zero, 0, err
	}
	return accepted, remaining, nil
}

func (store *FileAPEventStore) NextDelivery(ctx context.Context) (AcceptedEvent, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return AcceptedEvent{}, err
	}
	return store.memory.NextDelivery(ctx)
}

func (store *FileAPEventStore) AcknowledgeDelivery(ctx context.Context, deliveryID string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return err
	}
	candidate := cloneMemoryAPEventStore(store.memory)
	if err := candidate.AcknowledgeDelivery(ctx, deliveryID); err != nil {
		return err
	}
	return store.commitCandidate(candidate)
}

func (store *FileAPEventStore) persistInitial() error {
	body, records, err := encodeFileAPSnapshot(store.memory)
	if err != nil {
		return err
	}
	published, err := store.file.commit(body, records)
	if err != nil {
		return err
	}
	if !published {
		return ErrEventStoreIntegrity
	}
	return nil
}

func (store *FileAPEventStore) commitCandidate(candidate *MemoryAPEventStore) error {
	body, records, err := encodeFileAPSnapshot(candidate)
	if err != nil {
		return err
	}
	published, err := store.file.commit(body, records)
	if published {
		store.memory = candidate
	}
	return err
}

func (store *FileAPEventStore) openError() error {
	if store == nil || store.closed || store.file == nil || store.memory == nil {
		return ErrEventStoreClosed
	}
	return nil
}

func encodeFileAPSnapshot(memory *MemoryAPEventStore) ([]byte, [][]byte, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	ids := make([]string, 0, len(memory.subscriptions))
	for eventID := range memory.subscriptions {
		ids = append(ids, eventID)
	}
	sort.Strings(ids)
	snapshot := fileAPSnapshot{Schema: fileAPSnapshotSchema, Issuer: memory.issuer, NextDelivery: memory.nextDelivery}
	records := make([]any, 0, len(ids)+len(memory.inbox))
	for _, eventID := range ids {
		record := fileAPSubscriptionRecord{Schema: fileAPSubscriptionSchema, Subscription: memory.subscriptions[eventID]}
		snapshot.Subscriptions = append(snapshot.Subscriptions, record)
		records = append(records, record)
	}
	seenInbox := make(map[string]struct{}, len(memory.inbox))
	for _, deliveryID := range memory.inboxOrder {
		accepted, exists := memory.inbox[deliveryID]
		if !exists {
			continue
		}
		if accepted.Delivery.DeliveryID != deliveryID {
			return nil, nil, ErrEventStoreIntegrity
		}
		record := fileAPDeliveryRecord{Schema: fileAPDeliverySchema, Accepted: accepted}
		snapshot.Inbox = append(snapshot.Inbox, record)
		records = append(records, record)
		seenInbox[deliveryID] = struct{}{}
	}
	if len(seenInbox) != len(memory.inbox) {
		return nil, nil, ErrEventStoreIntegrity
	}
	return marshalEventFileSnapshot(snapshot, records)
}

func decodeFileAPSnapshot(body []byte, issuer string, limits eventFileLimits) (*MemoryAPEventStore, error) {
	var snapshot fileAPSnapshotEnvelope
	if err := decodeEventFileSnapshot(body, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Schema != fileAPSnapshotSchema || snapshot.Issuer != issuer {
		return nil, ErrEventStoreIntegrity
	}
	if len(snapshot.Subscriptions)+len(snapshot.Inbox) > limits.maxRecords || int64(len(body)) > limits.maxBytes {
		return nil, ErrEventStoreCapacity
	}
	memory := NewMemoryAPEventStore(issuer)
	for _, body := range snapshot.Subscriptions {
		if int64(len(body)) > limits.maxRecordBytes {
			return nil, ErrEventStoreCapacity
		}
		var record fileAPSubscriptionRecord
		if err := decodeEventFileSnapshot(body, &record); err != nil {
			return nil, err
		}
		if record.Schema != fileAPSubscriptionSchema || record.Subscription.APIssuer != issuer {
			return nil, ErrEventStoreIntegrity
		}
		validation := record.Subscription
		useCount := validation.UseCount
		validation.UseCount = 0
		if validateAPEventSubscription(validation) != nil || useCount < 0 || useCount > validation.MaxUses {
			return nil, ErrEventStoreIntegrity
		}
		if _, exists := memory.subscriptions[record.Subscription.EventID]; exists {
			return nil, ErrEventStoreIntegrity
		}
		memory.subscriptions[record.Subscription.EventID] = record.Subscription
	}
	for _, body := range snapshot.Inbox {
		if int64(len(body)) > limits.maxRecordBytes {
			return nil, ErrEventStoreCapacity
		}
		var record fileAPDeliveryRecord
		if err := decodeEventFileSnapshot(body, &record); err != nil {
			return nil, err
		}
		if record.Schema != fileAPDeliverySchema || validateStoredAcceptedEvent(record.Accepted, issuer) != nil {
			return nil, ErrEventStoreIntegrity
		}
		deliveryID := record.Accepted.Delivery.DeliveryID
		sequence, ok := fileAPDeliverySequence(deliveryID)
		if !ok || sequence > snapshot.NextDelivery {
			return nil, ErrEventStoreIntegrity
		}
		if _, exists := memory.inbox[deliveryID]; exists {
			return nil, ErrEventStoreIntegrity
		}
		memory.inbox[deliveryID] = record.Accepted
		memory.inboxOrder = append(memory.inboxOrder, deliveryID)
	}
	memory.nextDelivery = snapshot.NextDelivery
	return memory, nil
}

func fileAPDeliverySequence(deliveryID string) (uint64, bool) {
	const prefix = "event-delivery-"
	if !strings.HasPrefix(deliveryID, prefix) {
		return 0, false
	}
	value := strings.TrimPrefix(deliveryID, prefix)
	sequence, err := strconv.ParseUint(value, 10, 64)
	return sequence, err == nil && sequence > 0 && strconv.FormatUint(sequence, 10) == value
}

func validateStoredAcceptedEvent(accepted AcceptedEvent, issuer string) error {
	if validateEventDeliveryKey(accepted.Delivery) != nil || accepted.Delivery.APIssuer != issuer ||
		accepted.APIssuer != issuer || accepted.Token == "" || accepted.AcceptedAt.IsZero() ||
		accepted.Delivery.TokenDigest != eventTokenDigest(accepted.Token) {
		return ErrEventStoreIntegrity
	}
	return nil
}

func cloneMemoryAPEventStore(source *MemoryAPEventStore) *MemoryAPEventStore {
	source.mu.Lock()
	defer source.mu.Unlock()
	clone := NewMemoryAPEventStore(source.issuer)
	clone.nextDelivery = source.nextDelivery
	for key, value := range source.subscriptions {
		clone.subscriptions[key] = value
	}
	for key, value := range source.inbox {
		clone.inbox[key] = value
	}
	clone.inboxOrder = append(clone.inboxOrder, source.inboxOrder...)
	return clone
}

// FileResourceEventStore is a bounded, single-writer resource authority and
// pending-delivery adapter.
type FileResourceEventStore struct {
	mu     sync.Mutex
	file   *eventFileEngine
	memory *MemoryResourceEventStore
	closed bool
}

func OpenFileResourceEventStore(config FileResourceEventStoreConfig) (*FileResourceEventStore, error) {
	limits, err := normalizeEventFileLimits(config.MaxRecords, config.MaxBytes, config.MaxRecordBytes)
	if err != nil {
		return nil, err
	}
	file, body, err := openEventFileEngine(config.Directory, limits)
	if err != nil {
		return nil, err
	}
	store := &FileResourceEventStore{file: file, memory: NewMemoryResourceEventStore()}
	if len(body) == 0 {
		if err := store.persistInitial(); err != nil {
			_ = file.Close()
			return nil, err
		}
		return store, nil
	}
	memory, err := decodeFileResourceSnapshot(body, limits)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	store.memory = memory
	return store, nil
}

func (store *FileResourceEventStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	return store.file.Close()
}

func (store *FileResourceEventStore) Register(ctx context.Context, value ResourceEventSubscription) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return err
	}
	candidate := cloneMemoryResourceEventStore(store.memory)
	if err := candidate.Register(ctx, value); err != nil {
		return err
	}
	return store.commitCandidate(candidate)
}

func (store *FileResourceEventStore) Load(ctx context.Context, apIssuer, eventID string) (ResourceEventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return ResourceEventSubscription{}, err
	}
	return store.memory.Load(ctx, apIssuer, eventID)
}

func (store *FileResourceEventStore) RetainPending(ctx context.Context, value PendingEventDelivery) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return err
	}
	candidate := cloneMemoryResourceEventStore(store.memory)
	if err := candidate.RetainPending(ctx, value); err != nil {
		return err
	}
	return store.commitCandidate(candidate)
}

func (store *FileResourceEventStore) LoadPending(ctx context.Context, apIssuer, eventID string) (PendingEventDelivery, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return PendingEventDelivery{}, err
	}
	return store.memory.LoadPending(ctx, apIssuer, eventID)
}

func (store *FileResourceEventStore) CompletePending(ctx context.Context, apIssuer, eventID string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return err
	}
	candidate := cloneMemoryResourceEventStore(store.memory)
	if err := candidate.CompletePending(ctx, apIssuer, eventID); err != nil {
		return err
	}
	return store.commitCandidate(candidate)
}

func (store *FileResourceEventStore) persistInitial() error {
	body, records, err := encodeFileResourceSnapshot(store.memory)
	if err != nil {
		return err
	}
	published, err := store.file.commit(body, records)
	if err != nil {
		return err
	}
	if !published {
		return ErrEventStoreIntegrity
	}
	return nil
}

func (store *FileResourceEventStore) commitCandidate(candidate *MemoryResourceEventStore) error {
	body, records, err := encodeFileResourceSnapshot(candidate)
	if err != nil {
		return err
	}
	published, err := store.file.commit(body, records)
	if published {
		store.memory = candidate
	}
	return err
}

func (store *FileResourceEventStore) openError() error {
	if store == nil || store.closed || store.file == nil || store.memory == nil {
		return ErrEventStoreClosed
	}
	return nil
}

func encodeFileResourceSnapshot(memory *MemoryResourceEventStore) ([]byte, [][]byte, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	keys := make([]eventSubscriptionKey, 0, len(memory.subscriptions))
	for key := range memory.subscriptions {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].APIssuer != keys[right].APIssuer {
			return keys[left].APIssuer < keys[right].APIssuer
		}
		return keys[left].EventID < keys[right].EventID
	})
	snapshot := fileResourceSnapshot{Schema: fileResourceSnapshotSchema}
	records := make([]any, 0, len(keys))
	for _, key := range keys {
		subscription := memory.subscriptions[key]
		record := fileResourceAuthorityRecord{
			Schema: fileResourceAuthoritySchema, APIssuer: key.APIssuer, EventID: key.EventID,
			Subscription: &subscription,
		}
		if pending, exists := memory.pending[key]; exists {
			pendingCopy := pending
			record.Pending = &pendingCopy
		}
		snapshot.Authorities = append(snapshot.Authorities, record)
		records = append(records, record)
	}
	if len(memory.pending) > len(memory.subscriptions) {
		return nil, nil, ErrEventStoreIntegrity
	}
	for key := range memory.pending {
		if _, exists := memory.subscriptions[key]; !exists {
			return nil, nil, ErrEventStoreIntegrity
		}
	}
	return marshalEventFileSnapshot(snapshot, records)
}

func decodeFileResourceSnapshot(body []byte, limits eventFileLimits) (*MemoryResourceEventStore, error) {
	var snapshot fileResourceSnapshotEnvelope
	if err := decodeEventFileSnapshot(body, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Schema != fileResourceSnapshotSchema {
		return nil, ErrEventStoreIntegrity
	}
	if len(snapshot.Authorities) > limits.maxRecords || int64(len(body)) > limits.maxBytes {
		return nil, ErrEventStoreCapacity
	}
	memory := NewMemoryResourceEventStore()
	for _, body := range snapshot.Authorities {
		if int64(len(body)) > limits.maxRecordBytes {
			return nil, ErrEventStoreCapacity
		}
		var record fileResourceAuthorityRecord
		if err := decodeEventFileSnapshot(body, &record); err != nil {
			return nil, err
		}
		if record.Schema != fileResourceAuthoritySchema || record.Subscription == nil ||
			validateEventSubscriptionKey(record.APIssuer, record.EventID) != nil {
			return nil, ErrEventStoreIntegrity
		}
		key := eventSubscriptionKey{APIssuer: record.APIssuer, EventID: record.EventID}
		if _, exists := memory.subscriptions[key]; exists || validateResourceEventSubscription(*record.Subscription) != nil ||
			record.Subscription.APIssuer != key.APIssuer || record.Subscription.EventID != key.EventID {
			return nil, ErrEventStoreIntegrity
		}
		memory.subscriptions[key] = *record.Subscription
		if record.Pending != nil {
			if validatePendingEventDelivery(*record.Pending) != nil || record.Pending.APIssuer != key.APIssuer ||
				record.Pending.EventID != key.EventID {
				return nil, ErrEventStoreIntegrity
			}
			memory.pending[key] = *record.Pending
		}
	}
	return memory, nil
}

func cloneMemoryResourceEventStore(source *MemoryResourceEventStore) *MemoryResourceEventStore {
	source.mu.Lock()
	defer source.mu.Unlock()
	clone := NewMemoryResourceEventStore()
	for key, value := range source.subscriptions {
		clone.subscriptions[key] = value
	}
	for key, value := range source.pending {
		clone.pending[key] = value
	}
	return clone
}

// FileAgentEventStore is a bounded, single-writer agent context, replay, and
// consequence-processing adapter.
type FileAgentEventStore struct {
	mu     sync.Mutex
	file   *eventFileEngine
	memory *MemoryAgentEventStore
	closed bool
}

func OpenFileAgentEventStore(config FileAgentEventStoreConfig) (*FileAgentEventStore, error) {
	limits, err := normalizeEventFileLimits(config.MaxRecords, config.MaxBytes, config.MaxRecordBytes)
	if err != nil {
		return nil, err
	}
	file, body, err := openEventFileEngine(config.Directory, limits)
	if err != nil {
		return nil, err
	}
	store := &FileAgentEventStore{file: file, memory: NewMemoryAgentEventStore()}
	if len(body) == 0 {
		if err := store.persistInitial(); err != nil {
			_ = file.Close()
			return nil, err
		}
		return store, nil
	}
	memory, err := decodeFileAgentSnapshot(body, limits)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	store.memory = memory
	return store, nil
}

func (store *FileAgentEventStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	return store.file.Close()
}

func (store *FileAgentEventStore) PutContext(ctx context.Context, value AgentEventContext) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return err
	}
	candidate := cloneMemoryAgentEventStore(store.memory)
	if err := candidate.PutContext(ctx, value); err != nil {
		return err
	}
	return store.commitCandidate(candidate)
}

func (store *FileAgentEventStore) LookupContext(ctx context.Context, apIssuer, eventID string) (AgentEventContext, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return AgentEventContext{}, err
	}
	return store.memory.LookupContext(ctx, apIssuer, eventID)
}

func (store *FileAgentEventStore) AdmitProcessing(ctx context.Context, value AgentEventProcessing) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return err
	}
	candidate := cloneMemoryAgentEventStore(store.memory)
	if err := candidate.AdmitProcessing(ctx, value); err != nil {
		return err
	}
	return store.commitCandidate(candidate)
}

func (store *FileAgentEventStore) BeginDispatch(ctx context.Context, key EventActionKey, now time.Time) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return false, err
	}
	candidate := cloneMemoryAgentEventStore(store.memory)
	claimed, err := candidate.BeginDispatch(ctx, key, now)
	if err != nil || !claimed {
		return claimed, err
	}
	if err := store.commitCandidate(candidate); err != nil {
		return false, err
	}
	return true, nil
}

func (store *FileAgentEventStore) RetryNotApplied(ctx context.Context, key EventActionKey, now time.Time) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return false, err
	}
	candidate := cloneMemoryAgentEventStore(store.memory)
	retried, err := candidate.RetryNotApplied(ctx, key, now)
	if err != nil || !retried {
		return retried, err
	}
	if err := store.commitCandidate(candidate); err != nil {
		return false, err
	}
	return true, nil
}

func (store *FileAgentEventStore) MarkCompleted(ctx context.Context, key EventActionKey) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return err
	}
	candidate := cloneMemoryAgentEventStore(store.memory)
	if err := candidate.MarkCompleted(ctx, key); err != nil {
		return err
	}
	return store.commitCandidate(candidate)
}

func (store *FileAgentEventStore) MarkRefused(ctx context.Context, delivery EventDeliveryKey, reason EventRefusalReason) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return err
	}
	candidate := cloneMemoryAgentEventStore(store.memory)
	if err := candidate.MarkRefused(ctx, delivery, reason); err != nil {
		return err
	}
	return store.commitCandidate(candidate)
}

func (store *FileAgentEventStore) LoadProcessing(ctx context.Context, key EventActionKey) (AgentEventProcessing, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return AgentEventProcessing{}, err
	}
	return store.memory.LoadProcessing(ctx, key)
}

func (store *FileAgentEventStore) LoadProcessingByDelivery(ctx context.Context, delivery EventDeliveryKey) (AgentEventProcessing, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return AgentEventProcessing{}, err
	}
	return store.memory.LoadProcessingByDelivery(ctx, delivery)
}

func (store *FileAgentEventStore) NextProcessing(ctx context.Context, after *EventActionKey) (AgentEventProcessing, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return AgentEventProcessing{}, err
	}
	return store.memory.NextProcessing(ctx, after)
}

func (store *FileAgentEventStore) LoadDisposition(ctx context.Context, delivery EventDeliveryKey) (EventProcessingState, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return "", err
	}
	return store.memory.LoadDisposition(ctx, delivery)
}

func (store *FileAgentEventStore) persistInitial() error {
	body, records, err := encodeFileAgentSnapshot(store.memory)
	if err != nil {
		return err
	}
	published, err := store.file.commit(body, records)
	if err != nil {
		return err
	}
	if !published {
		return ErrEventStoreIntegrity
	}
	return nil
}

func (store *FileAgentEventStore) commitCandidate(candidate *MemoryAgentEventStore) error {
	body, records, err := encodeFileAgentSnapshot(candidate)
	if err != nil {
		return err
	}
	published, err := store.file.commit(body, records)
	if published {
		store.memory = candidate
	}
	return err
}

func (store *FileAgentEventStore) openError() error {
	if store == nil || store.closed || store.file == nil || store.memory == nil {
		return ErrEventStoreClosed
	}
	return nil
}

func encodeFileAgentSnapshot(memory *MemoryAgentEventStore) ([]byte, [][]byte, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	snapshot := fileAgentSnapshot{Schema: fileAgentSnapshotSchema}
	records := make([]any, 0, len(memory.contexts)+len(memory.processing)+len(memory.dispositions))

	contextKeys := make([]eventSubscriptionKey, 0, len(memory.contexts))
	for key := range memory.contexts {
		contextKeys = append(contextKeys, key)
	}
	sort.Slice(contextKeys, func(left, right int) bool {
		if contextKeys[left].APIssuer != contextKeys[right].APIssuer {
			return contextKeys[left].APIssuer < contextKeys[right].APIssuer
		}
		return contextKeys[left].EventID < contextKeys[right].EventID
	})
	for _, key := range contextKeys {
		value := memory.contexts[key]
		value.Value = cloneRawMessage(value.Value)
		record := fileAgentContextRecord{Schema: fileAgentContextSchema, Context: value}
		snapshot.Contexts = append(snapshot.Contexts, record)
		records = append(records, record)
	}

	actionKeys := make([]EventActionKey, 0, len(memory.processing))
	for key := range memory.processing {
		actionKeys = append(actionKeys, key)
	}
	sort.Slice(actionKeys, func(left, right int) bool {
		return compareEventActionKey(actionKeys[left], actionKeys[right]) < 0
	})
	for _, key := range actionKeys {
		processing := memory.processing[key]
		if owner, exists := memory.deliveryOwner[processing.Delivery]; !exists || owner != key ||
			memory.dispositions[processing.Delivery] != processing.State {
			return nil, nil, ErrEventStoreIntegrity
		}
		record := fileAgentProcessingRecord{Schema: fileAgentProcessingSchema, Processing: processing}
		if processing.State == EventRefused {
			record.RefusalReason = memory.refusalReason[processing.Delivery]
		}
		snapshot.Processing = append(snapshot.Processing, record)
		records = append(records, record)
	}
	if len(memory.deliveryOwner) != len(memory.processing) {
		return nil, nil, ErrEventStoreIntegrity
	}

	deliveries := make([]EventDeliveryKey, 0)
	for delivery := range memory.dispositions {
		if _, owned := memory.deliveryOwner[delivery]; !owned {
			deliveries = append(deliveries, delivery)
		}
	}
	sort.Slice(deliveries, func(left, right int) bool {
		return compareEventDeliveryKey(deliveries[left], deliveries[right]) < 0
	})
	for _, delivery := range deliveries {
		record := fileAgentDispositionRecord{
			Schema: fileAgentDispositionSchema, Delivery: delivery,
			State: memory.dispositions[delivery], RefusalReason: memory.refusalReason[delivery],
		}
		snapshot.Dispositions = append(snapshot.Dispositions, record)
		records = append(records, record)
	}
	return marshalEventFileSnapshot(snapshot, records)
}

func decodeFileAgentSnapshot(body []byte, limits eventFileLimits) (*MemoryAgentEventStore, error) {
	var snapshot fileAgentSnapshotEnvelope
	if err := decodeEventFileSnapshot(body, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Schema != fileAgentSnapshotSchema {
		return nil, ErrEventStoreIntegrity
	}
	if len(snapshot.Contexts)+len(snapshot.Processing)+len(snapshot.Dispositions) > limits.maxRecords ||
		int64(len(body)) > limits.maxBytes {
		return nil, ErrEventStoreCapacity
	}
	memory := NewMemoryAgentEventStore()
	for _, body := range snapshot.Contexts {
		if int64(len(body)) > limits.maxRecordBytes {
			return nil, ErrEventStoreCapacity
		}
		var record fileAgentContextRecord
		if err := decodeEventFileSnapshot(body, &record); err != nil {
			return nil, err
		}
		if record.Schema != fileAgentContextSchema || validateAgentEventContext(record.Context) != nil {
			return nil, ErrEventStoreIntegrity
		}
		key := eventSubscriptionKey{APIssuer: record.Context.APIssuer, EventID: record.Context.EventID}
		if _, exists := memory.contexts[key]; exists {
			return nil, ErrEventStoreIntegrity
		}
		record.Context.Value = cloneRawMessage(record.Context.Value)
		memory.contexts[key] = record.Context
	}
	for _, body := range snapshot.Processing {
		if int64(len(body)) > limits.maxRecordBytes {
			return nil, ErrEventStoreCapacity
		}
		var record fileAgentProcessingRecord
		if err := decodeEventFileSnapshot(body, &record); err != nil {
			return nil, err
		}
		validation := record.Processing
		state := validation.State
		validation.State = EventPending
		if record.Schema != fileAgentProcessingSchema || validateAgentEventProcessing(validation) != nil ||
			!validEventProcessingState(state) {
			return nil, ErrEventStoreIntegrity
		}
		if state == EventRefused {
			if !validEventRefusalReason(record.RefusalReason) {
				return nil, ErrEventStoreIntegrity
			}
		} else if record.RefusalReason != "" {
			return nil, ErrEventStoreIntegrity
		}
		contextKey := eventSubscriptionKey{APIssuer: validation.Action.APIssuer, EventID: validation.Action.EventID}
		if _, exists := memory.contexts[contextKey]; !exists {
			return nil, ErrEventStoreIntegrity
		}
		if _, exists := memory.processing[validation.Action]; exists {
			return nil, ErrEventStoreIntegrity
		}
		if _, exists := memory.deliveryOwner[validation.Delivery]; exists {
			return nil, ErrEventStoreIntegrity
		}
		record.Processing.State = state
		memory.processing[record.Processing.Action] = record.Processing
		memory.deliveryOwner[record.Processing.Delivery] = record.Processing.Action
		memory.dispositions[record.Processing.Delivery] = state
		if state == EventRefused {
			memory.refusalReason[record.Processing.Delivery] = record.RefusalReason
		}
	}
	for _, body := range snapshot.Dispositions {
		if int64(len(body)) > limits.maxRecordBytes {
			return nil, ErrEventStoreCapacity
		}
		var record fileAgentDispositionRecord
		if err := decodeEventFileSnapshot(body, &record); err != nil {
			return nil, err
		}
		if record.Schema != fileAgentDispositionSchema || validateEventDeliveryKey(record.Delivery) != nil || record.State != EventRefused ||
			!validEventRefusalReason(record.RefusalReason) || record.RefusalReason == EventRefusalNotApplied {
			return nil, ErrEventStoreIntegrity
		}
		if _, exists := memory.dispositions[record.Delivery]; exists {
			return nil, ErrEventStoreIntegrity
		}
		memory.dispositions[record.Delivery] = EventRefused
		memory.refusalReason[record.Delivery] = record.RefusalReason
	}
	return memory, nil
}

func cloneMemoryAgentEventStore(source *MemoryAgentEventStore) *MemoryAgentEventStore {
	source.mu.Lock()
	defer source.mu.Unlock()
	clone := NewMemoryAgentEventStore()
	for key, value := range source.contexts {
		value.Value = cloneRawMessage(value.Value)
		clone.contexts[key] = value
	}
	for key, value := range source.processing {
		clone.processing[key] = value
	}
	for key, value := range source.dispositions {
		clone.dispositions[key] = value
	}
	for key, value := range source.refusalReason {
		clone.refusalReason[key] = value
	}
	for key, value := range source.deliveryOwner {
		clone.deliveryOwner[key] = value
	}
	return clone
}

func validEventProcessingState(state EventProcessingState) bool {
	switch state {
	case EventPending, EventDispatched, EventCompleted, EventRefused:
		return true
	default:
		return false
	}
}

func compareEventDeliveryKey(left, right EventDeliveryKey) int {
	if left.APIssuer != right.APIssuer {
		return strings.Compare(left.APIssuer, right.APIssuer)
	}
	if left.DeliveryID != right.DeliveryID {
		return strings.Compare(left.DeliveryID, right.DeliveryID)
	}
	return strings.Compare(left.TokenDigest, right.TokenDigest)
}

var (
	_ APEventStore       = (*FileAPEventStore)(nil)
	_ ResourceEventStore = (*FileResourceEventStore)(nil)
	_ AgentEventStore    = (*FileAgentEventStore)(nil)
)
