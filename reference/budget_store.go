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
	"gitlab.com/sidecat-dev/aauth-go/budgets"
)

const (
	budgetEnvelopeSchema = "aauth.reference.budget-envelope.v0"
	budgetStateSchema    = "aauth.reference.budget-state.v0"
)

var (
	ErrBudgetNotFound     = errors.New("reference: Budget execution was not found")
	ErrBudgetConflict     = errors.New("reference: Budget execution conflicts with retained custody")
	ErrBudgetInsufficient = errors.New("reference: Budget remainder is smaller than the request bound")
)

// BudgetExecution is the immutable reservation identity for one
// provider-keyed metered call.
type BudgetExecution struct {
	Key             string         `json:"key"`
	AuthTokenIssuer string         `json:"auth_token_issuer"`
	AuthTokenID     string         `json:"auth_token_id"`
	CallKey         string         `json:"call_key"`
	Grant           budgets.Budget `json:"grant"`
	Maximum         int64          `json:"maximum"`
	ExpiresAt       int64          `json:"expires_at"`
}

// BudgetResult is one exact successful JSON response and its committed cost.
type BudgetResult struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        []byte `json:"body"`
	Cost        int64  `json:"cost"`
}

// BudgetRecord is reserved before provider invocation and complete only after
// the exact result and actual cost are durable.
type BudgetRecord struct {
	Execution BudgetExecution `json:"execution"`
	State     string          `json:"state"`
	Result    *BudgetResult   `json:"result,omitempty"`
}

// BudgetStore atomically reserves and settles one auth token's hard cap.
type BudgetStore interface {
	Claim(context.Context, BudgetExecution) (BudgetRecord, bool, int64, error)
	Recover(context.Context, string, string, string) (BudgetRecord, int64, error)
	Complete(context.Context, string, BudgetResult) (BudgetRecord, int64, error)
	Release(string)
}

func (store *FileBudgetStore) Recover(_ context.Context, issuer, tokenID, callKey string) (BudgetRecord, int64, error) {
	if store == nil || store.file == nil {
		return BudgetRecord{}, 0, errors.New("reference: Budget file store is not initialized")
	}
	key, err := budgetExecutionKey(BudgetExecution{AuthTokenIssuer: issuer, AuthTokenID: tokenID, CallKey: callKey})
	if err != nil {
		return BudgetRecord{}, 0, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.records[key]
	if !found {
		return BudgetRecord{}, 0, ErrBudgetNotFound
	}
	remaining, err := store.remainingLocked(record.Execution)
	return copyBudgetRecord(record), remaining, err
}

// NewBudgetExecution derives the provider and custody key from the signed token
// identity and a deployment-owned stable call identity. The grant and maximum
// are retained attributes of that key; a retry that changes either conflicts.
func NewBudgetExecution(
	authTokenIssuer, authTokenID, callKey string,
	grant budgets.Budget,
	maximum, expiresAt int64,
) (BudgetExecution, error) {
	execution := BudgetExecution{
		AuthTokenIssuer: authTokenIssuer, AuthTokenID: authTokenID, CallKey: callKey,
		Grant: grant, Maximum: maximum, ExpiresAt: expiresAt,
	}
	key, err := budgetExecutionKey(execution)
	if err != nil {
		return BudgetExecution{}, err
	}
	execution.Key = key
	if err := validateBudgetExecution(execution); err != nil {
		return BudgetExecution{}, err
	}
	return execution, nil
}

// FileBudgetStore is a private bounded single-writer reference adapter.
type FileBudgetStore struct {
	file    *FileGovernanceStore
	mu      sync.Mutex
	records map[string]BudgetRecord
	usage   map[string]BudgetUsageRecord
	active  map[string]struct{}
}

type budgetEnvelope struct {
	Schema      string          `json:"schema"`
	StateSHA256 string          `json:"state_sha256"`
	State       json.RawMessage `json:"state"`
}

type budgetState struct {
	Schema  string              `json:"schema"`
	Records []BudgetRecord      `json:"records"`
	Usage   []BudgetUsageRecord `json:"usage,omitempty"`
}

func NewFileBudgetStore(path string) (*FileBudgetStore, error) {
	file, err := NewFileGovernanceStore(path)
	if err != nil {
		return nil, err
	}
	body, err := file.Load()
	if err != nil {
		return nil, fmt.Errorf("reference: load Budget state: %w", err)
	}
	records, usage, err := decodeBudgetState(body)
	if err != nil {
		return nil, err
	}
	return &FileBudgetStore{file: file, records: records, usage: usage, active: make(map[string]struct{})}, nil
}

func (store *FileBudgetStore) Claim(_ context.Context, execution BudgetExecution) (BudgetRecord, bool, int64, error) {
	if store == nil || store.file == nil {
		return BudgetRecord{}, false, 0, errors.New("reference: Budget file store is not initialized")
	}
	if err := validateBudgetExecution(execution); err != nil {
		return BudgetRecord{}, false, 0, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.records[execution.Key]; found {
		if !reflect.DeepEqual(existing.Execution, execution) {
			return BudgetRecord{}, false, 0, ErrBudgetConflict
		}
		remaining, err := store.remainingLocked(execution)
		if err != nil {
			return BudgetRecord{}, false, 0, err
		}
		if existing.State == "complete" {
			return copyBudgetRecord(existing), false, remaining, nil
		}
		if _, active := store.active[execution.Key]; active {
			return copyBudgetRecord(existing), false, remaining, nil
		}
		store.active[execution.Key] = struct{}{}
		return copyBudgetRecord(existing), true, remaining, nil
	}
	remaining, err := store.remainingLocked(execution)
	if err != nil {
		return BudgetRecord{}, false, 0, err
	}
	if execution.Maximum > remaining {
		return BudgetRecord{}, false, remaining, ErrBudgetInsufficient
	}
	record := BudgetRecord{Execution: execution, State: "reserved"}
	if err := store.saveLocked(record); err != nil {
		return BudgetRecord{}, false, 0, err
	}
	store.active[execution.Key] = struct{}{}
	return copyBudgetRecord(record), true, remaining - execution.Maximum, nil
}

func (store *FileBudgetStore) Complete(ctx context.Context, key string, result BudgetResult) (BudgetRecord, int64, error) {
	return store.complete(ctx, key, result, nil)
}

func (store *FileBudgetStore) CompleteWithUsage(
	ctx context.Context,
	key string,
	result BudgetResult,
	usage BudgetUsageRecord,
) (BudgetRecord, int64, error) {
	return store.complete(ctx, key, result, &usage)
}

func (store *FileBudgetStore) complete(
	_ context.Context,
	key string,
	result BudgetResult,
	usage *BudgetUsageRecord,
) (BudgetRecord, int64, error) {
	if store == nil || store.file == nil {
		return BudgetRecord{}, 0, errors.New("reference: Budget file store is not initialized")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	defer delete(store.active, key)
	existing, found := store.records[key]
	if !found {
		return BudgetRecord{}, 0, ErrBudgetNotFound
	}
	if err := validateBudgetResult(result, existing.Execution.Maximum); err != nil {
		return BudgetRecord{}, 0, err
	}
	if usage != nil {
		if usage.Key != key || usage.Unit != existing.Execution.Grant.Unit || usage.Decimals != existing.Execution.Grant.Decimals || usage.Consumed != result.Cost || usage.Validate() != nil {
			return BudgetRecord{}, 0, ErrBudgetConflict
		}
	}
	if existing.State == "complete" {
		if existing.Result == nil || !reflect.DeepEqual(*existing.Result, result) {
			return BudgetRecord{}, 0, ErrBudgetConflict
		}
		if usage != nil {
			if existingUsage, exists := store.usage[key]; exists {
				if !reflect.DeepEqual(existingUsage, *usage) {
					return BudgetRecord{}, 0, ErrBudgetConflict
				}
			} else if err := store.saveLockedWithUsage(existing, usage); err != nil {
				return BudgetRecord{}, 0, err
			}
		}
		remaining, err := store.remainingLocked(existing.Execution)
		return copyBudgetRecord(existing), remaining, err
	}
	next := copyBudgetRecord(existing)
	next.State = "complete"
	copyResult := result
	copyResult.Body = append([]byte(nil), result.Body...)
	next.Result = &copyResult
	if err := store.saveLockedWithUsage(next, usage); err != nil {
		return BudgetRecord{}, 0, err
	}
	remaining, err := store.remainingLocked(next.Execution)
	return copyBudgetRecord(next), remaining, err
}

func (store *FileBudgetStore) Release(key string) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.active, key)
}

func (store *FileBudgetStore) remainingLocked(execution BudgetExecution) (int64, error) {
	remaining := execution.Grant.Amount
	for _, record := range store.records {
		if record.Execution.AuthTokenIssuer != execution.AuthTokenIssuer || record.Execution.AuthTokenID != execution.AuthTokenID {
			continue
		}
		if record.Execution.Grant != execution.Grant {
			return 0, ErrBudgetConflict
		}
		charge := record.Execution.Maximum
		if record.State == "complete" {
			charge = record.Result.Cost
		}
		if charge < 0 || charge > remaining {
			return 0, ErrBudgetConflict
		}
		remaining -= charge
	}
	return remaining, nil
}

func (store *FileBudgetStore) saveLocked(record BudgetRecord) error {
	return store.saveLockedWithUsage(record, nil)
}

func (store *FileBudgetStore) saveLockedWithUsage(record BudgetRecord, usage *BudgetUsageRecord) error {
	if err := validateBudgetRecord(record); err != nil {
		return err
	}
	next := make(map[string]BudgetRecord, len(store.records)+1)
	for key, existing := range store.records {
		next[key] = copyBudgetRecord(existing)
	}
	next[record.Execution.Key] = copyBudgetRecord(record)
	nextUsage := cloneBudgetUsage(store.usage)
	if usage != nil {
		copyUsage := *usage
		nextUsage[usage.Key] = copyUsage
	}
	body, err := encodeBudgetState(next, nextUsage)
	if err != nil {
		return err
	}
	if err := store.file.Save(body); err != nil {
		if errors.Is(err, ErrGovernanceStateUncertain) {
			store.records = next
			store.usage = nextUsage
		}
		return fmt.Errorf("reference: save Budget state: %w", err)
	}
	store.records = next
	store.usage = nextUsage
	return nil
}

func validateBudgetExecution(execution BudgetExecution) error {
	decoded, keyErr := base64.RawURLEncoding.DecodeString(execution.Key)
	if keyErr != nil || len(decoded) != sha256.Size || aauth.ValidateServerIdentifier(execution.AuthTokenIssuer) != nil ||
		execution.AuthTokenID == "" || execution.CallKey == "" || len(execution.CallKey) > 1024 || execution.ExpiresAt <= 0 ||
		execution.Grant.Validate() != nil || execution.Maximum < 0 || execution.Maximum > execution.Grant.Amount {
		return errors.New("reference: Budget execution identity is invalid")
	}
	want, err := budgetExecutionKey(execution)
	if err != nil || want != execution.Key {
		return errors.New("reference: Budget execution key does not match its identity")
	}
	return nil
}

func budgetExecutionKey(execution BudgetExecution) (string, error) {
	material, err := json.Marshal(struct {
		Domain          string `json:"domain"`
		AuthTokenIssuer string `json:"auth_token_issuer"`
		AuthTokenID     string `json:"auth_token_id"`
		CallKey         string `json:"call_key"`
	}{
		Domain:          "gitlab.com/sidecat-dev/aauth-go/budget-execution/v1",
		AuthTokenIssuer: execution.AuthTokenIssuer, AuthTokenID: execution.AuthTokenID,
		CallKey: execution.CallKey,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(material)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func validateBudgetResult(result BudgetResult, maximum int64) error {
	if result.Status != 200 || result.ContentType != "application/json" ||
		len(result.Body) == 0 || !json.Valid(result.Body) || result.Cost < 0 || result.Cost > maximum {
		return errors.New("reference: Budget result is invalid")
	}
	return nil
}

func validateBudgetRecord(record BudgetRecord) error {
	if err := validateBudgetExecution(record.Execution); err != nil {
		return err
	}
	switch record.State {
	case "reserved":
		if record.Result != nil {
			return errors.New("reference: reserved Budget record carries a result")
		}
	case "complete":
		if record.Result == nil || validateBudgetResult(*record.Result, record.Execution.Maximum) != nil {
			return errors.New("reference: complete Budget record lacks a valid result")
		}
	default:
		return errors.New("reference: Budget record state is invalid")
	}
	return nil
}

func copyBudgetRecord(record BudgetRecord) BudgetRecord {
	if record.Result != nil {
		result := *record.Result
		result.Body = append([]byte(nil), record.Result.Body...)
		record.Result = &result
	}
	return record
}

func encodeBudgetState(records map[string]BudgetRecord, usage map[string]BudgetUsageRecord) ([]byte, error) {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	state := budgetState{Schema: budgetStateSchema}
	for _, key := range keys {
		state.Records = append(state.Records, copyBudgetRecord(records[key]))
	}
	usageKeys := make([]string, 0, len(usage))
	for key := range usage {
		usageKeys = append(usageKeys, key)
	}
	sort.Strings(usageKeys)
	for _, key := range usageKeys {
		state.Usage = append(state.Usage, usage[key])
	}
	body, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	return json.Marshal(budgetEnvelope{Schema: budgetEnvelopeSchema, StateSHA256: hex.EncodeToString(digest[:]), State: body})
}

func decodeBudgetState(body []byte) (map[string]BudgetRecord, map[string]BudgetUsageRecord, error) {
	records := make(map[string]BudgetRecord)
	usage := make(map[string]BudgetUsageRecord)
	if len(body) == 0 {
		return records, usage, nil
	}
	var envelope budgetEnvelope
	if err := decodeJSONBytesWithLimit(bytes.NewReader(body), &envelope, maxGovernanceStateBytes); err != nil || envelope.Schema != budgetEnvelopeSchema {
		return nil, nil, errors.New("reference: Budget envelope is invalid")
	}
	digest := sha256.Sum256(envelope.State)
	if hex.EncodeToString(digest[:]) != envelope.StateSHA256 {
		return nil, nil, errors.New("reference: Budget state checksum does not match")
	}
	var state budgetState
	if err := decodeJSONBytesWithLimit(bytes.NewReader(envelope.State), &state, maxGovernanceStateBytes); err != nil || state.Schema != budgetStateSchema {
		return nil, nil, errors.New("reference: Budget state is invalid")
	}
	previous := ""
	for _, record := range state.Records {
		if record.Execution.Key <= previous || validateBudgetRecord(record) != nil {
			return nil, nil, errors.New("reference: Budget state contains an invalid record")
		}
		previous = record.Execution.Key
		records[record.Execution.Key] = copyBudgetRecord(record)
	}
	previous = ""
	for _, record := range state.Usage {
		if record.Key <= previous || record.Validate() != nil {
			return nil, nil, errors.New("reference: Budget state contains an invalid usage record")
		}
		if retained, exists := records[record.Key]; !exists || retained.State != "complete" || retained.Result == nil || retained.Result.Cost != record.Consumed || retained.Execution.Grant.Unit != record.Unit || retained.Execution.Grant.Decimals != record.Decimals {
			return nil, nil, errors.New("reference: Budget usage record does not match its retained execution")
		}
		previous = record.Key
		usage[record.Key] = record
	}
	store := &FileBudgetStore{records: records, usage: usage}
	for _, record := range records {
		if _, err := store.remainingLocked(record.Execution); err != nil {
			return nil, nil, errors.New("reference: Budget state violates its hard cap")
		}
	}
	return records, usage, nil
}

var _ BudgetStore = (*FileBudgetStore)(nil)
