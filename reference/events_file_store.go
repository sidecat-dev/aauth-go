package reference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/internal/snapshotfile"
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
	defaultEventFileMaxRecords = 1024
	defaultEventFileMaxBytes   = int64(8 << 20)
	// A protected agent context may contain the full admitted 1 MiB AsyncAPI
	// document plus local context and its versioned record envelope.
	defaultEventFileMaxRecordBytes = int64(2 << 20)

	fileAPSnapshotSchema        = "aauth.reference.events.ap-store.v2"
	fileAPSubscriptionSchema    = "aauth.reference.events.ap-subscription.v2"
	fileAPDeliverySchema        = "aauth.reference.events.ap-delivery.v2"
	fileResourceSnapshotSchema  = "aauth.reference.events.resource-store.v2"
	fileResourceAuthoritySchema = "aauth.reference.events.resource-authority.v2"
	fileResourceTicketSchema    = "aauth.reference.events.resource-ticket.v1"
	fileAgentSnapshotSchema     = "aauth.reference.events.agent-store.v2"
	fileAgentContextSchema      = "aauth.reference.events.agent-context.v2"
	fileAgentProcessingSchema   = "aauth.reference.events.agent-processing.v2"
	fileAgentDispositionSchema  = "aauth.reference.events.agent-disposition.v1"
)

func normalizeEventFileLimits(maxRecords int, maxBytes, maxRecordBytes int64) (snapshotfile.Limits, error) {
	if maxRecords < 0 || maxBytes < 0 || maxRecordBytes < 0 {
		return snapshotfile.Limits{}, ErrEventStoreConfig
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
		return snapshotfile.Limits{}, ErrEventStoreConfig
	}
	limits, err := snapshotfile.NewLimits(maxRecords, maxBytes, maxRecordBytes)
	if err != nil {
		return snapshotfile.Limits{}, ErrEventStoreConfig
	}
	return limits, nil
}

func mapEventSnapshotFileError(err error) error {
	if err == nil {
		return nil
	}
	var source, target error
	switch {
	case errors.Is(err, snapshotfile.ErrConfig):
		source = snapshotfile.ErrConfig
		target = ErrEventStoreConfig
	case errors.Is(err, snapshotfile.ErrCapacity):
		source = snapshotfile.ErrCapacity
		target = ErrEventStoreCapacity
	case errors.Is(err, snapshotfile.ErrUnsafe):
		source = snapshotfile.ErrUnsafe
		target = ErrEventStoreUnsafe
	case errors.Is(err, snapshotfile.ErrLocked):
		source = snapshotfile.ErrLocked
		target = ErrEventStoreLocked
	case errors.Is(err, snapshotfile.ErrIntegrity):
		source = snapshotfile.ErrIntegrity
		target = ErrEventStoreIntegrity
	case errors.Is(err, snapshotfile.ErrCommitUncertain):
		source = snapshotfile.ErrCommitUncertain
		target = ErrEventStoreCommitUncertain
	case errors.Is(err, snapshotfile.ErrClosed):
		source = snapshotfile.ErrClosed
		target = ErrEventStoreClosed
	default:
		return mapEventSnapshotOperationError(err)
	}
	if err == source {
		return target
	}
	if source == snapshotfile.ErrCommitUncertain {
		message := target.Error()
		matches := []error{target}
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			for _, cause := range joined.Unwrap() {
				if cause != source {
					mappedCause := mapEventSnapshotOperationError(cause)
					message += "\n" + mappedCause.Error()
					matches = append(matches, mappedCause)
				}
			}
		}
		return mappedSnapshotFileError{message: message, matches: matches}
	}
	return mappedSnapshotFileError{
		message: strings.Replace(err.Error(), source.Error(), target.Error(), 1),
		matches: []error{target},
	}
}

// mappedSnapshotFileError preserves the reference adapter's established error
// text and errors.Is contract while the private custody mechanism retains its
// own internal vocabulary.
type mappedSnapshotFileError struct {
	message string
	matches []error
}

func (err mappedSnapshotFileError) Error() string   { return err.message }
func (err mappedSnapshotFileError) Unwrap() []error { return err.matches }

func mapEventSnapshotOperationError(err error) error {
	message := err.Error()
	for _, replacement := range []struct {
		internal  string
		reference string
	}{
		{internal: "snapshotfile: create temporary", reference: "reference: create event state temporary"},
		{internal: "snapshotfile: protect temporary", reference: "reference: protect event state temporary"},
		{internal: "snapshotfile: write state", reference: "reference: write event state"},
		{internal: "snapshotfile: sync state", reference: "reference: sync event state"},
		{internal: "snapshotfile: close state", reference: "reference: close event state"},
		{internal: "snapshotfile: publish state", reference: "reference: publish event state"},
		{internal: "snapshotfile: open directory", reference: "reference: open event state directory"},
		{internal: "snapshotfile: sync directory", reference: "reference: sync event state directory"},
		{internal: "snapshotfile: close new lock"},
		{internal: "snapshotfile: create lock"},
		{internal: "snapshotfile: inspect lock"},
		{internal: "snapshotfile: open lock"},
		{internal: "snapshotfile: inspect opened lock"},
		{internal: "snapshotfile: acquire writer lock"},
	} {
		if strings.HasPrefix(message, replacement.internal) {
			if replacement.reference == "" {
				if cause := errors.Unwrap(err); cause != nil {
					return cause
				}
			}
			return mappedSnapshotFileError{
				message: replacement.reference + strings.TrimPrefix(message, replacement.internal),
				matches: []error{err},
			}
		}
	}
	return err
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
	Tickets     []fileResourceTicketRecord    `json:"tickets,omitempty"`
}

type fileResourceSnapshotEnvelope struct {
	Schema      string            `json:"schema"`
	Authorities []json.RawMessage `json:"authorities"`
	Tickets     []json.RawMessage `json:"tickets,omitempty"`
}

type fileResourceAuthorityRecord struct {
	Schema       string                     `json:"schema"`
	APIssuer     string                     `json:"ap_issuer"`
	EventID      string                     `json:"event_id"`
	Subscription *ResourceEventSubscription `json:"subscription"`
	Pending      *PendingEventDelivery      `json:"pending"`
}

type fileResourceTicketRecord struct {
	Schema string               `json:"schema"`
	Ticket ProtectedEventTicket `json:"ticket"`
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
	file   *snapshotfile.File
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
	file, body, err := snapshotfile.Open(config.Directory, limits)
	if err != nil {
		return nil, mapEventSnapshotFileError(err)
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
	return mapEventSnapshotFileError(store.file.Close())
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
	published, err := store.file.Replace(body, records)
	if err != nil {
		return mapEventSnapshotFileError(err)
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
	published, err := store.file.Replace(body, records)
	if published {
		store.memory = candidate
	}
	return mapEventSnapshotFileError(err)
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

func decodeFileAPSnapshot(body []byte, issuer string, limits snapshotfile.Limits) (*MemoryAPEventStore, error) {
	var snapshot fileAPSnapshotEnvelope
	if err := decodeEventFileSnapshot(body, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Schema != fileAPSnapshotSchema || snapshot.Issuer != issuer {
		return nil, ErrEventStoreIntegrity
	}
	if len(snapshot.Subscriptions)+len(snapshot.Inbox) > limits.MaxRecords() || int64(len(body)) > limits.MaxBytes() {
		return nil, ErrEventStoreCapacity
	}
	memory := NewMemoryAPEventStore(issuer)
	for _, body := range snapshot.Subscriptions {
		if int64(len(body)) > limits.MaxRecordBytes() {
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
		if int64(len(body)) > limits.MaxRecordBytes() {
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
		record.Accepted.Payload = append([]byte(nil), record.Accepted.Payload...)
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
		accepted.Delivery.TokenDigest != eventTokenDigest(accepted.Token) ||
		validateEventPayloadEnvelope(accepted.ContentType, accepted.Payload, accepted.PayloadDigest) != nil {
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
		value.Payload = append([]byte(nil), value.Payload...)
		clone.inbox[key] = value
	}
	clone.inboxOrder = append(clone.inboxOrder, source.inboxOrder...)
	return clone
}

// FileResourceEventStore is a bounded, single-writer resource authority and
// pending-delivery adapter.
type FileResourceEventStore struct {
	mu     sync.Mutex
	file   *snapshotfile.File
	memory *MemoryResourceEventStore
	closed bool
}

func OpenFileResourceEventStore(config FileResourceEventStoreConfig) (*FileResourceEventStore, error) {
	limits, err := normalizeEventFileLimits(config.MaxRecords, config.MaxBytes, config.MaxRecordBytes)
	if err != nil {
		return nil, err
	}
	file, body, err := snapshotfile.Open(config.Directory, limits)
	if err != nil {
		return nil, mapEventSnapshotFileError(err)
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
	return mapEventSnapshotFileError(store.file.Close())
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

func (store *FileResourceEventStore) CreateTicket(ctx context.Context, value ProtectedEventTicket) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return err
	}
	candidate := cloneMemoryResourceEventStore(store.memory)
	if err := candidate.CreateTicket(ctx, value); err != nil {
		return err
	}
	return store.commitCandidate(candidate)
}

func (store *FileResourceEventStore) LoadTicket(ctx context.Context, digest string) (ProtectedEventTicket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return ProtectedEventTicket{}, err
	}
	return store.memory.LoadTicket(ctx, digest)
}

func (store *FileResourceEventStore) ConsumeTicket(
	ctx context.Context,
	input ProtectedEventTicketConsumption,
) (ResourceEventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.openError(); err != nil {
		return ResourceEventSubscription{}, err
	}
	candidate := cloneMemoryResourceEventStore(store.memory)
	subscription, err := candidate.ConsumeTicket(ctx, input)
	if err != nil {
		return ResourceEventSubscription{}, err
	}
	if err := store.commitCandidate(candidate); err != nil {
		return ResourceEventSubscription{}, err
	}
	return subscription, nil
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
	published, err := store.file.Replace(body, records)
	if err != nil {
		return mapEventSnapshotFileError(err)
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
	published, err := store.file.Replace(body, records)
	if published {
		store.memory = candidate
	}
	return mapEventSnapshotFileError(err)
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
	records := make([]any, 0, len(keys)+len(memory.tickets))
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
	ticketDigests := make([]string, 0, len(memory.tickets))
	for digest := range memory.tickets {
		ticketDigests = append(ticketDigests, digest)
	}
	sort.Strings(ticketDigests)
	for _, digest := range ticketDigests {
		ticket := memory.tickets[digest]
		record := fileResourceTicketRecord{Schema: fileResourceTicketSchema, Ticket: ticket}
		snapshot.Tickets = append(snapshot.Tickets, record)
		records = append(records, record)
	}
	return marshalEventFileSnapshot(snapshot, records)
}

func decodeFileResourceSnapshot(body []byte, limits snapshotfile.Limits) (*MemoryResourceEventStore, error) {
	var snapshot fileResourceSnapshotEnvelope
	if err := decodeEventFileSnapshot(body, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Schema != fileResourceSnapshotSchema {
		return nil, ErrEventStoreIntegrity
	}
	if len(snapshot.Authorities)+len(snapshot.Tickets) > limits.MaxRecords() || int64(len(body)) > limits.MaxBytes() {
		return nil, ErrEventStoreCapacity
	}
	memory := NewMemoryResourceEventStore()
	for _, body := range snapshot.Authorities {
		if int64(len(body)) > limits.MaxRecordBytes() {
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
			memory.pending[key] = clonePendingEventDelivery(*record.Pending)
		}
	}
	for _, body := range snapshot.Tickets {
		if int64(len(body)) > limits.MaxRecordBytes() {
			return nil, ErrEventStoreCapacity
		}
		var record fileResourceTicketRecord
		if err := decodeEventFileSnapshot(body, &record); err != nil {
			return nil, err
		}
		if record.Schema != fileResourceTicketSchema || validateProtectedEventTicket(record.Ticket) != nil {
			return nil, ErrEventStoreIntegrity
		}
		if _, exists := memory.tickets[record.Ticket.TicketDigest]; exists {
			return nil, ErrEventStoreIntegrity
		}
		memory.tickets[record.Ticket.TicketDigest] = record.Ticket
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
		clone.pending[key] = clonePendingEventDelivery(value)
	}
	for digest, value := range source.tickets {
		clone.tickets[digest] = value
	}
	return clone
}

// FileAgentEventStore is a bounded, single-writer agent context, replay, and
// consequence-processing adapter.
type FileAgentEventStore struct {
	mu     sync.Mutex
	file   *snapshotfile.File
	memory *MemoryAgentEventStore
	closed bool
}

func OpenFileAgentEventStore(config FileAgentEventStoreConfig) (*FileAgentEventStore, error) {
	limits, err := normalizeEventFileLimits(config.MaxRecords, config.MaxBytes, config.MaxRecordBytes)
	if err != nil {
		return nil, err
	}
	file, body, err := snapshotfile.Open(config.Directory, limits)
	if err != nil {
		return nil, mapEventSnapshotFileError(err)
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
	return mapEventSnapshotFileError(store.file.Close())
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
	published, err := store.file.Replace(body, records)
	if err != nil {
		return mapEventSnapshotFileError(err)
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
	published, err := store.file.Replace(body, records)
	if published {
		store.memory = candidate
	}
	return mapEventSnapshotFileError(err)
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

func decodeFileAgentSnapshot(body []byte, limits snapshotfile.Limits) (*MemoryAgentEventStore, error) {
	var snapshot fileAgentSnapshotEnvelope
	if err := decodeEventFileSnapshot(body, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Schema != fileAgentSnapshotSchema {
		return nil, ErrEventStoreIntegrity
	}
	if len(snapshot.Contexts)+len(snapshot.Processing)+len(snapshot.Dispositions) > limits.MaxRecords() ||
		int64(len(body)) > limits.MaxBytes() {
		return nil, ErrEventStoreCapacity
	}
	memory := NewMemoryAgentEventStore()
	for _, body := range snapshot.Contexts {
		if int64(len(body)) > limits.MaxRecordBytes() {
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
		record.Context.Contract = append([]byte(nil), record.Context.Contract...)
		memory.contexts[key] = record.Context
	}
	for _, body := range snapshot.Processing {
		if int64(len(body)) > limits.MaxRecordBytes() {
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
		record.Processing.Payload = append([]byte(nil), record.Processing.Payload...)
		memory.processing[record.Processing.Action] = record.Processing
		memory.deliveryOwner[record.Processing.Delivery] = record.Processing.Action
		memory.dispositions[record.Processing.Delivery] = state
		if state == EventRefused {
			memory.refusalReason[record.Processing.Delivery] = record.RefusalReason
		}
	}
	for _, body := range snapshot.Dispositions {
		if int64(len(body)) > limits.MaxRecordBytes() {
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
		value.Contract = append([]byte(nil), value.Contract...)
		clone.contexts[key] = value
	}
	for key, value := range source.processing {
		clone.processing[key] = cloneAgentEventProcessing(value)
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
