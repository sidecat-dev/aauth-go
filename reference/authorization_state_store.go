package reference

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/internal/snapshotfile"
)

type pendingInteractionRecord struct {
	ID                 string                    `json:"id"`
	Code               string                    `json:"code,omitempty"`
	NormalizedCode     string                    `json:"normalized_code,omitempty"`
	CodeConsumed       bool                      `json:"code_consumed"`
	FailedCodeAttempts int                       `json:"failed_code_attempts"`
	State              pendingAuthorizationState `json:"state"`
	PollingError       aauth.PollingErrorCode    `json:"polling_error,omitempty"`
	ExpiresAt          time.Time                 `json:"expires_at"`
}

func snapshotPendingInteraction(value pendingInteraction) pendingInteractionRecord {
	return pendingInteractionRecord{
		ID: value.id, Code: value.code, NormalizedCode: value.normalizedCode,
		CodeConsumed: value.codeConsumed, FailedCodeAttempts: value.failedCodeAttempts,
		State: value.state, PollingError: value.pollingError, ExpiresAt: value.expiresAt.UTC(),
	}
}

func restorePendingInteraction(value pendingInteractionRecord) (pendingInteraction, error) {
	if value.ID == "" || value.State == "" || value.ExpiresAt.IsZero() ||
		value.FailedCodeAttempts < 0 || value.FailedCodeAttempts > maxInteractionCodeAttempts ||
		!validAuthorizationState(value.State) {
		return pendingInteraction{}, ErrAuthorizationStateIntegrity
	}
	return pendingInteraction{
		id: value.ID, code: value.Code, normalizedCode: value.NormalizedCode,
		codeConsumed: value.CodeConsumed, failedCodeAttempts: value.FailedCodeAttempts,
		state: value.State, pollingError: value.PollingError, expiresAt: value.ExpiresAt.UTC(),
	}, nil
}

func validAuthorizationState(state pendingAuthorizationState) bool {
	switch state {
	case pendingAuthorizationWaiting,
		pendingAuthorizationInteracting,
		pendingAuthorizationApproved,
		pendingAuthorizationRejected,
		pendingAuthorizationExpired,
		pendingAuthorizationInvalidCode:
		return true
	default:
		return false
	}
}

func validateAuthorizationTerminalState(
	interaction pendingInteractionRecord,
	terminalToken string,
	terminalExpiresAt int64,
	terminalStatus int,
	terminalCode string,
	terminalDetail string,
) error {
	hasToken := terminalToken != "" || terminalExpiresAt != 0
	if hasToken && (terminalToken == "" || terminalExpiresAt <= 0 || interaction.State != pendingAuthorizationApproved) {
		return ErrAuthorizationStateIntegrity
	}
	hasProblem := terminalStatus != 0 || terminalCode != "" || terminalDetail != ""
	if hasProblem && (terminalStatus < 400 || terminalStatus > 599 || terminalCode == "" || terminalDetail == "" ||
		interaction.State != pendingAuthorizationRejected) {
		return ErrAuthorizationStateIntegrity
	}
	if hasToken && hasProblem {
		return ErrAuthorizationStateIntegrity
	}
	if interaction.PollingError != "" {
		if interaction.State != pendingAuthorizationRejected || hasProblem {
			return ErrAuthorizationStateIntegrity
		}
		switch interaction.PollingError {
		case aauth.PollingDenied, aauth.PollingAbandoned, aauth.PollingServerError:
		default:
			return ErrAuthorizationStateIntegrity
		}
	} else if interaction.State == pendingAuthorizationRejected && !hasProblem {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func validateLocalAuthorizationInteraction(interaction pendingInteractionRecord) error {
	if len(interaction.Code) != 9 || interaction.Code[4] != '-' || len(interaction.NormalizedCode) != 8 {
		return ErrAuthorizationStateIntegrity
	}
	const emittedAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for index, character := range interaction.Code {
		if index == 4 {
			continue
		}
		if !strings.ContainsRune(emittedAlphabet, character) {
			return ErrAuthorizationStateIntegrity
		}
	}
	normalized := interaction.Code[:4] + interaction.Code[5:]
	if normalized != interaction.NormalizedCode {
		return ErrAuthorizationStateIntegrity
	}
	switch interaction.State {
	case pendingAuthorizationWaiting:
		if interaction.CodeConsumed || interaction.FailedCodeAttempts >= maxInteractionCodeAttempts {
			return ErrAuthorizationStateIntegrity
		}
	case pendingAuthorizationInteracting, pendingAuthorizationApproved, pendingAuthorizationRejected:
		if !interaction.CodeConsumed || interaction.FailedCodeAttempts >= maxInteractionCodeAttempts {
			return ErrAuthorizationStateIntegrity
		}
	case pendingAuthorizationExpired:
		// Expiry can race any reachable local state, including the third failed
		// code attempt. restorePendingInteraction already bounds the counter.
	case pendingAuthorizationInvalidCode:
		if interaction.CodeConsumed || interaction.FailedCodeAttempts != maxInteractionCodeAttempts {
			return ErrAuthorizationStateIntegrity
		}
	default:
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func validPendingID(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 16 &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

var (
	ErrAuthorizationStateStoreConfig = errors.New("reference: authorization state store configuration is invalid")
	ErrAuthorizationStateCapacity    = errors.New("reference: authorization state store capacity is exhausted")
	ErrAuthorizationStateUnsafe      = errors.New("reference: authorization state store custody is unsafe")
	ErrAuthorizationStateLocked      = errors.New("reference: authorization state store already has a writer")
	ErrAuthorizationStateIntegrity   = errors.New("reference: authorization state integrity check failed")
	ErrAuthorizationStateUncertain   = errors.New("reference: authorization state commit is uncertain")
	ErrAuthorizationStateClosed      = errors.New("reference: authorization state store is closed")
)

// AuthorizationStateStore atomically replaces one owner's complete current
// authorization-state snapshot. Every deferred-capable protocol role receives
// its own store instance and owns the schema inside the snapshot.
type AuthorizationStateStore interface {
	Load(context.Context) ([]byte, error)
	Replace(context.Context, []byte) error
}

// reconcileAuthorizationState classifies the store's exact authoritative
// snapshot after a failed replacement. A file replacement can become visible
// before a later directory sync reports failure, so a role must distinguish a
// still-current prior snapshot from a published-but-not-yet-settled candidate.
func reconcileAuthorizationState(
	ctx context.Context,
	store AuthorizationStateStore,
	prior []byte,
	candidate []byte,
) ([]byte, bool, error) {
	if store == nil {
		return nil, false, ErrAuthorizationStateStoreConfig
	}
	reconcileContext := context.Background()
	if ctx != nil {
		reconcileContext = context.WithoutCancel(ctx)
	}
	body, err := store.Load(reconcileContext)
	if err != nil {
		return nil, false, err
	}
	if bytes.Equal(body, prior) {
		return body, false, nil
	}
	if len(candidate) != 0 && bytes.Equal(body, candidate) {
		return body, true, nil
	}
	return nil, false, ErrAuthorizationStateIntegrity
}

func authorizationStateReconciliationFailure(commitErr, reconcileErr error) error {
	if reconcileErr == nil {
		reconcileErr = ErrAuthorizationStateIntegrity
	}
	return errors.Join(
		ErrAuthorizationStateUncertain,
		commitErr,
		fmt.Errorf("reference: reconcile authorization state: %w", reconcileErr),
	)
}

func authorizationStatePublishedUncertain(commitErr error) error {
	return errors.Join(ErrAuthorizationStateUncertain, commitErr)
}

// MemoryAuthorizationStateStore is an explicitly bounded ephemeral adapter.
type MemoryAuthorizationStateStore struct {
	mu         sync.Mutex
	maxEntries int
	maxBytes   int64
	body       []byte
}

func NewMemoryAuthorizationStateStore(maxEntries int, maxBytes int64) (*MemoryAuthorizationStateStore, error) {
	if maxEntries <= 0 || maxBytes < 128 {
		return nil, ErrAuthorizationStateStoreConfig
	}
	return &MemoryAuthorizationStateStore{maxEntries: maxEntries, maxBytes: maxBytes}, nil
}

func (store *MemoryAuthorizationStateStore) Load(ctx context.Context) ([]byte, error) {
	if store == nil || store.maxEntries <= 0 || store.maxBytes <= 0 {
		return nil, ErrAuthorizationStateStoreConfig
	}
	if err := authorizationStateContext(ctx); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]byte(nil), store.body...), nil
}

func (store *MemoryAuthorizationStateStore) Replace(ctx context.Context, body []byte) error {
	if store == nil || store.maxEntries <= 0 || store.maxBytes <= 0 {
		return ErrAuthorizationStateStoreConfig
	}
	if err := authorizationStateContext(ctx); err != nil {
		return err
	}
	if _, err := validateAuthorizationStateSnapshot(body, store.maxEntries, store.maxBytes); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.body = append(store.body[:0], body...)
	return nil
}

type FileAuthorizationStateStoreConfig struct {
	Directory  string
	MaxEntries int
	MaxBytes   int64
}

// FileAuthorizationStateStore uses private single-writer directory custody
// and fsync-backed temporary-file replacement.
type FileAuthorizationStateStore struct {
	mu     sync.Mutex
	file   *snapshotfile.File
	body   []byte
	closed bool
}

func OpenFileAuthorizationStateStore(config FileAuthorizationStateStoreConfig) (*FileAuthorizationStateStore, error) {
	if config.MaxEntries <= 0 || config.MaxBytes < 128 {
		return nil, ErrAuthorizationStateStoreConfig
	}
	limits, err := snapshotfile.NewLimits(config.MaxEntries, config.MaxBytes, config.MaxBytes)
	if err != nil {
		return nil, ErrAuthorizationStateStoreConfig
	}
	file, body, err := snapshotfile.Open(config.Directory, limits)
	if err != nil {
		return nil, mapAuthorizationStateFileError(err)
	}
	store := &FileAuthorizationStateStore{file: file}
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
		}
	}()
	if len(body) != 0 {
		if _, err := validateAuthorizationStateSnapshot(body, config.MaxEntries, config.MaxBytes); err != nil {
			return nil, err
		}
		store.body = append([]byte(nil), body...)
	}
	failed = false
	return store, nil
}

func (store *FileAuthorizationStateStore) Load(ctx context.Context) ([]byte, error) {
	if err := authorizationStateContext(ctx); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed || store.file == nil {
		return nil, ErrAuthorizationStateClosed
	}
	return append([]byte(nil), store.body...), nil
}

func (store *FileAuthorizationStateStore) Replace(ctx context.Context, body []byte) error {
	if err := authorizationStateContext(ctx); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed || store.file == nil {
		return ErrAuthorizationStateClosed
	}
	limits := store.file.Limits()
	records, err := validateAuthorizationStateSnapshot(body, limits.MaxRecords(), limits.MaxBytes())
	if err != nil {
		return err
	}
	published, err := store.file.Replace(body, records)
	if published {
		store.body = append(store.body[:0], body...)
	}
	if err != nil {
		return mapAuthorizationStateFileError(err)
	}
	return nil
}

func (store *FileAuthorizationStateStore) Close() error {
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
	return mapAuthorizationStateFileError(file.Close())
}

type authorizationStateEnvelope struct {
	Schema  string            `json:"schema"`
	Records []json.RawMessage `json:"records"`
}

func validateAuthorizationStateSnapshot(body []byte, maxEntries int, maxBytes int64) ([][]byte, error) {
	if len(body) == 0 || int64(len(body)) > maxBytes {
		if int64(len(body)) > maxBytes {
			return nil, ErrAuthorizationStateCapacity
		}
		return nil, ErrAuthorizationStateIntegrity
	}
	if err := jsonstrict.RejectAmbiguousNames(body); err != nil {
		return nil, errors.Join(ErrAuthorizationStateIntegrity, err)
	}
	var envelope authorizationStateEnvelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, errors.Join(ErrAuthorizationStateIntegrity, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return nil, errors.Join(ErrAuthorizationStateIntegrity, err)
	}
	if envelope.Schema == "" || len(envelope.Records) > maxEntries {
		if len(envelope.Records) > maxEntries {
			return nil, ErrAuthorizationStateCapacity
		}
		return nil, ErrAuthorizationStateIntegrity
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, ErrAuthorizationStateIntegrity
	}
	records := make([][]byte, len(envelope.Records))
	for index, record := range envelope.Records {
		if len(record) == 0 || int64(len(record)) > maxBytes {
			return nil, ErrAuthorizationStateCapacity
		}
		records[index] = append([]byte(nil), record...)
	}
	return records, nil
}

func decodeAuthorizationStateRecords(body []byte, schema string) ([]json.RawMessage, error) {
	if len(body) == 0 {
		return nil, nil
	}
	if err := jsonstrict.RejectAmbiguousNames(body); err != nil {
		return nil, errors.Join(ErrAuthorizationStateIntegrity, err)
	}
	var envelope authorizationStateEnvelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, errors.Join(ErrAuthorizationStateIntegrity, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrAuthorizationStateIntegrity
	}
	if envelope.Schema != schema {
		return nil, ErrAuthorizationStateIntegrity
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, ErrAuthorizationStateIntegrity
	}
	return envelope.Records, nil
}

func marshalAuthorizationStateRecords(schema string, records []json.RawMessage) ([]byte, error) {
	if schema == "" {
		return nil, ErrAuthorizationStateIntegrity
	}
	if records == nil {
		records = []json.RawMessage{}
	}
	body, err := json.Marshal(authorizationStateEnvelope{Schema: schema, Records: records})
	if err != nil {
		return nil, errors.Join(ErrAuthorizationStateIntegrity, err)
	}
	return body, nil
}

func decodeAuthorizationStateRecord(raw json.RawMessage, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.Join(ErrAuthorizationStateIntegrity, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrAuthorizationStateIntegrity
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

func authorizationStateContext(ctx context.Context) error {
	if ctx == nil {
		return ErrAuthorizationStateStoreConfig
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func mapAuthorizationStateFileError(err error) error {
	eventErr := mapEventSnapshotFileError(err)
	switch {
	case eventErr == nil:
		return nil
	case errors.Is(eventErr, ErrEventStoreConfig):
		return errors.Join(ErrAuthorizationStateStoreConfig, eventErr)
	case errors.Is(eventErr, ErrEventStoreCapacity):
		return errors.Join(ErrAuthorizationStateCapacity, eventErr)
	case errors.Is(eventErr, ErrEventStoreUnsafe):
		return errors.Join(ErrAuthorizationStateUnsafe, eventErr)
	case errors.Is(eventErr, ErrEventStoreLocked):
		return errors.Join(ErrAuthorizationStateLocked, eventErr)
	case errors.Is(eventErr, ErrEventStoreIntegrity):
		return errors.Join(ErrAuthorizationStateIntegrity, eventErr)
	case errors.Is(eventErr, ErrEventStoreCommitUncertain):
		return errors.Join(ErrAuthorizationStateUncertain, eventErr)
	case errors.Is(eventErr, ErrEventStoreClosed):
		return errors.Join(ErrAuthorizationStateClosed, eventErr)
	default:
		return fmt.Errorf("reference: authorization state file: %w", eventErr)
	}
}
