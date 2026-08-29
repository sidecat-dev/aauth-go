package reference

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

const (
	r3PerCallEnvelopeSchema = "aauth.reference.r3-per-call-envelope.v0"
	r3PerCallStateSchema    = "aauth.reference.r3-per-call-state.v0"
)

var (
	ErrR3PerCallNotFound = errors.New("reference: R3 per-call execution was not found")
	ErrR3PerCallConflict = errors.New("reference: R3 per-call execution conflicts with retained custody")
)

// R3PerCallExecution is the immutable identity retained before invoking one
// provider-keyed operation.
type R3PerCallExecution struct {
	Key             string `json:"key"`
	AuthTokenIssuer string `json:"auth_token_issuer"`
	AuthTokenID     string `json:"auth_token_id"`
	ProposalDigest  string `json:"proposal_digest"`
	Operation       string `json:"operation"`
	ExpiresAt       int64  `json:"expires_at"`
}

// NewR3PerCallExecution derives the immutable identity used both as the
// provider idempotency key and the retained execution key.
func NewR3PerCallExecution(
	authTokenIssuer string,
	authTokenID string,
	proposalDigest string,
	operationJSON json.RawMessage,
	expiresAt int64,
) (R3PerCallExecution, error) {
	operation, err := r3.ParseOperationSet(operationJSON)
	if err != nil || len(operation.Operations) != 1 {
		return R3PerCallExecution{}, errors.New("reference: R3 per-call execution operation is invalid")
	}
	exactOperation, err := json.Marshal(operation)
	if err != nil {
		return R3PerCallExecution{}, err
	}
	execution := R3PerCallExecution{
		AuthTokenIssuer: authTokenIssuer,
		AuthTokenID:     authTokenID, ProposalDigest: proposalDigest,
		Operation: string(exactOperation), ExpiresAt: expiresAt,
	}
	execution.Key, err = r3PerCallExecutionKey(execution)
	if err != nil {
		return R3PerCallExecution{}, err
	}
	return execution, nil
}

// R3PerCallResult is the exact HTTP representation returned after one
// successful operation. This first profile retains canonical JSON responses.
type R3PerCallResult struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        []byte `json:"body"`
}

// R3PerCallRecord is pending after Begin and complete only after the exact
// result is durably retained.
type R3PerCallRecord struct {
	Execution R3PerCallExecution `json:"execution"`
	State     string             `json:"state"`
	Result    *R3PerCallResult   `json:"result,omitempty"`
}

// R3PerCallStore retains one single-use execution and its replayable result.
type R3PerCallStore interface {
	Claim(context.Context, R3PerCallExecution) (R3PerCallRecord, bool, error)
	Release(string)
	Complete(context.Context, string, R3PerCallResult) (R3PerCallRecord, error)
	Load(context.Context, string) (R3PerCallRecord, error)
}

// FileR3PerCallStore is a private, single-writer reference adapter.
type FileR3PerCallStore struct {
	file    *FileGovernanceStore
	mu      sync.Mutex
	records map[string]R3PerCallRecord
	active  map[string]struct{}
}

type r3PerCallEnvelope struct {
	Schema      string          `json:"schema"`
	StateSHA256 string          `json:"state_sha256"`
	State       json.RawMessage `json:"state"`
}

type r3PerCallState struct {
	Schema  string            `json:"schema"`
	Records []R3PerCallRecord `json:"records"`
}

func NewFileR3PerCallStore(path string) (*FileR3PerCallStore, error) {
	file, err := NewFileGovernanceStore(path)
	if err != nil {
		return nil, err
	}
	body, err := file.Load()
	if err != nil {
		return nil, fmt.Errorf("reference: load R3 per-call state: %w", err)
	}
	records, err := decodeR3PerCallState(body)
	if err != nil {
		return nil, err
	}
	return &FileR3PerCallStore{file: file, records: records, active: make(map[string]struct{})}, nil
}

func (store *FileR3PerCallStore) Claim(_ context.Context, execution R3PerCallExecution) (R3PerCallRecord, bool, error) {
	if store == nil || store.file == nil {
		return R3PerCallRecord{}, false, errors.New("reference: R3 per-call file store is not initialized")
	}
	if err := validateR3PerCallExecution(execution); err != nil {
		return R3PerCallRecord{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.records[execution.Key]; found {
		if !reflect.DeepEqual(existing.Execution, execution) {
			return R3PerCallRecord{}, false, ErrR3PerCallConflict
		}
		if existing.State == "complete" {
			return copyR3PerCallRecord(existing), false, nil
		}
		if _, active := store.active[execution.Key]; active {
			return copyR3PerCallRecord(existing), false, nil
		}
		store.active[execution.Key] = struct{}{}
		return copyR3PerCallRecord(existing), true, nil
	}
	record := R3PerCallRecord{Execution: execution, State: "pending"}
	if err := store.saveLocked(record); err != nil {
		return R3PerCallRecord{}, false, err
	}
	store.active[execution.Key] = struct{}{}
	return copyR3PerCallRecord(record), true, nil
}

// Release relinquishes one in-process execution claim after the provider
// returns without a retainable result. A reopened store starts with no active
// claims, allowing the same provider key to recover an interrupted operation.
func (store *FileR3PerCallStore) Release(key string) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.active, key)
}

func (store *FileR3PerCallStore) Complete(_ context.Context, key string, result R3PerCallResult) (R3PerCallRecord, error) {
	if store == nil || store.file == nil {
		return R3PerCallRecord{}, errors.New("reference: R3 per-call file store is not initialized")
	}
	if err := validateR3PerCallResult(result); err != nil {
		return R3PerCallRecord{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	defer delete(store.active, key)
	existing, found := store.records[key]
	if !found {
		return R3PerCallRecord{}, ErrR3PerCallNotFound
	}
	if existing.State == "complete" {
		if existing.Result != nil && reflect.DeepEqual(*existing.Result, result) {
			return copyR3PerCallRecord(existing), nil
		}
		return R3PerCallRecord{}, ErrR3PerCallConflict
	}
	next := copyR3PerCallRecord(existing)
	next.State = "complete"
	copy := result
	copy.Body = append([]byte(nil), result.Body...)
	next.Result = &copy
	if err := store.saveLocked(next); err != nil {
		return R3PerCallRecord{}, err
	}
	return copyR3PerCallRecord(next), nil
}

func (store *FileR3PerCallStore) Load(_ context.Context, key string) (R3PerCallRecord, error) {
	if store == nil || store.file == nil {
		return R3PerCallRecord{}, errors.New("reference: R3 per-call file store is not initialized")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.records[key]
	if !found {
		return R3PerCallRecord{}, ErrR3PerCallNotFound
	}
	return copyR3PerCallRecord(record), nil
}

func (store *FileR3PerCallStore) saveLocked(record R3PerCallRecord) error {
	if err := validateR3PerCallRecord(record); err != nil {
		return err
	}
	next := make(map[string]R3PerCallRecord, len(store.records)+1)
	for key, existing := range store.records {
		next[key] = copyR3PerCallRecord(existing)
	}
	next[record.Execution.Key] = copyR3PerCallRecord(record)
	body, err := encodeR3PerCallState(next)
	if err != nil {
		return err
	}
	if err := store.file.Save(body); err != nil {
		if errors.Is(err, ErrGovernanceStateUncertain) {
			store.records = next
		}
		return fmt.Errorf("reference: save R3 per-call state: %w", err)
	}
	store.records = next
	return nil
}

func validateR3PerCallExecution(execution R3PerCallExecution) error {
	key, keyErr := base64.RawURLEncoding.DecodeString(execution.Key)
	digest, digestErr := base64.RawURLEncoding.DecodeString(execution.ProposalDigest)
	if keyErr != nil || len(key) != sha256.Size || digestErr != nil || len(digest) != sha256.Size ||
		aauth.ValidateServerIdentifier(execution.AuthTokenIssuer) != nil || execution.AuthTokenID == "" ||
		execution.Operation == "" || execution.ExpiresAt <= 0 {
		return errors.New("reference: R3 per-call execution identity is invalid")
	}
	operation, err := r3.ParseOperationSet([]byte(execution.Operation))
	if err != nil || len(operation.Operations) != 1 {
		return errors.New("reference: R3 per-call execution operation is invalid")
	}
	wantKey, err := r3PerCallExecutionKey(execution)
	if err != nil || wantKey != execution.Key {
		return errors.New("reference: R3 per-call execution key does not match its identity")
	}
	return nil
}

func r3PerCallExecutionKey(execution R3PerCallExecution) (string, error) {
	material, err := json.Marshal(struct {
		Domain          string `json:"domain"`
		AuthTokenIssuer string `json:"auth_token_issuer"`
		AuthTokenID     string `json:"auth_token_id"`
		ProposalDigest  string `json:"proposal_digest"`
		Operation       string `json:"operation"`
		ExpiresAt       int64  `json:"expires_at"`
	}{
		Domain:          "gitlab.com/sidecat-dev/aauth-go/r3-per-call-execution/v1",
		AuthTokenIssuer: execution.AuthTokenIssuer, AuthTokenID: execution.AuthTokenID,
		ProposalDigest: execution.ProposalDigest, Operation: execution.Operation,
		ExpiresAt: execution.ExpiresAt,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(material)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func validateR3PerCallResult(result R3PerCallResult) error {
	if result.Status != 200 || result.ContentType != "application/json" || len(result.Body) == 0 || !json.Valid(result.Body) {
		return errors.New("reference: R3 per-call result must be one successful JSON response")
	}
	return nil
}

func validateR3PerCallRecord(record R3PerCallRecord) error {
	if err := validateR3PerCallExecution(record.Execution); err != nil {
		return err
	}
	switch record.State {
	case "pending":
		if record.Result != nil {
			return errors.New("reference: pending R3 per-call record carries a result")
		}
	case "complete":
		if record.Result == nil || validateR3PerCallResult(*record.Result) != nil {
			return errors.New("reference: complete R3 per-call record lacks a valid result")
		}
	default:
		return errors.New("reference: R3 per-call record state is invalid")
	}
	return nil
}

func copyR3PerCallRecord(record R3PerCallRecord) R3PerCallRecord {
	if record.Result != nil {
		result := *record.Result
		result.Body = append([]byte(nil), record.Result.Body...)
		record.Result = &result
	}
	return record
}

func encodeR3PerCallState(records map[string]R3PerCallRecord) ([]byte, error) {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	state := r3PerCallState{Schema: r3PerCallStateSchema}
	for _, key := range keys {
		state.Records = append(state.Records, copyR3PerCallRecord(records[key]))
	}
	body, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	return json.Marshal(r3PerCallEnvelope{Schema: r3PerCallEnvelopeSchema, StateSHA256: hex.EncodeToString(digest[:]), State: body})
}

func decodeR3PerCallState(body []byte) (map[string]R3PerCallRecord, error) {
	records := make(map[string]R3PerCallRecord)
	if len(body) == 0 {
		return records, nil
	}
	var envelope r3PerCallEnvelope
	if err := decodeJSONBytesWithLimit(bytes.NewReader(body), &envelope, maxGovernanceStateBytes); err != nil || envelope.Schema != r3PerCallEnvelopeSchema {
		return nil, errors.New("reference: R3 per-call envelope is invalid")
	}
	digest := sha256.Sum256(envelope.State)
	if hex.EncodeToString(digest[:]) != envelope.StateSHA256 {
		return nil, errors.New("reference: R3 per-call state checksum does not match")
	}
	var state r3PerCallState
	if err := decodeJSONBytesWithLimit(bytes.NewReader(envelope.State), &state, maxGovernanceStateBytes); err != nil || state.Schema != r3PerCallStateSchema {
		return nil, errors.New("reference: R3 per-call state is invalid")
	}
	previous := ""
	for _, record := range state.Records {
		if validateR3PerCallRecord(record) != nil || record.Execution.Key <= previous {
			return nil, errors.New("reference: R3 per-call state contains an invalid record")
		}
		previous = record.Execution.Key
		records[record.Execution.Key] = copyR3PerCallRecord(record)
	}
	return records, nil
}

var _ R3PerCallStore = (*FileR3PerCallStore)(nil)
