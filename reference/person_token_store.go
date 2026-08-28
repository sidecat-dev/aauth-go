package reference

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	personTokenEnvelopeSchema = "aauth.reference.person-token-envelope.v0"
	personTokenStateSchema    = "aauth.reference.person-token-state.v0"
)

var (
	ErrPersonTokenNotFound = errors.New("reference: retained person token was not found")
	ErrPersonTokenConflict = errors.New("reference: retained person token conflicts with the existing record")
)

// PersonTokenRecord is the PS custody used to verify a resource token's
// presented_jti. RetainUntil extends beyond token expiry by the longest
// resource-token lifetime the person server accepts.
type PersonTokenRecord struct {
	JTI          string    `json:"jti"`
	PersonServer string    `json:"ps"`
	TokenSHA256  string    `json:"token_sha256"`
	Resource     string    `json:"resource"`
	Subject      string    `json:"sub"`
	MissionS256  string    `json:"mission_s256,omitempty"`
	Tenant       string    `json:"tenant,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	RetainUntil  time.Time `json:"retain_until"`
}

// PersonTokenStore atomically retains and resolves person-token verification
// custody. Committing the exact same record is idempotent; changing a record
// already bound to an issuer and JTI fails closed.
type PersonTokenStore interface {
	Commit(context.Context, PersonTokenRecord) error
	Load(context.Context, string, string) (PersonTokenRecord, error)
}

// FilePersonTokenStore is a single-writer, restart-safe reference adapter.
type FilePersonTokenStore struct {
	file    *FileGovernanceStore
	mu      sync.Mutex
	records map[string]PersonTokenRecord
}

type personTokenEnvelope struct {
	Schema      string          `json:"schema"`
	StateSHA256 string          `json:"state_sha256"`
	State       json.RawMessage `json:"state"`
}

type personTokenState struct {
	Schema  string              `json:"schema"`
	Records []PersonTokenRecord `json:"records"`
}

func NewFilePersonTokenStore(path string) (*FilePersonTokenStore, error) {
	file, err := NewFileGovernanceStore(path)
	if err != nil {
		return nil, err
	}
	body, err := file.Load()
	if err != nil {
		return nil, fmt.Errorf("reference: load person-token state: %w", err)
	}
	records, err := decodePersonTokenState(body)
	if err != nil {
		return nil, err
	}
	return &FilePersonTokenStore{file: file, records: records}, nil
}

func (store *FilePersonTokenStore) Commit(_ context.Context, record PersonTokenRecord) error {
	if store == nil || store.file == nil {
		return errors.New("reference: person-token file store is not initialized")
	}
	if err := validatePersonTokenRecord(record); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := personTokenRecordKey(record.PersonServer, record.JTI)
	if existing, ok := store.records[key]; ok {
		if existing == record {
			return nil
		}
		return ErrPersonTokenConflict
	}
	next := make(map[string]PersonTokenRecord, len(store.records)+1)
	for existingKey, existing := range store.records {
		next[existingKey] = existing
	}
	next[key] = record
	body, err := encodePersonTokenState(next)
	if err != nil {
		return err
	}
	if err := store.file.Save(body); err != nil {
		if errors.Is(err, ErrGovernanceStateUncertain) {
			store.records = next
		}
		return fmt.Errorf("reference: save person-token state: %w", err)
	}
	store.records = next
	return nil
}

func (store *FilePersonTokenStore) Load(
	_ context.Context,
	personServer string,
	jti string,
) (PersonTokenRecord, error) {
	if store == nil || store.file == nil {
		return PersonTokenRecord{}, errors.New("reference: person-token file store is not initialized")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[personTokenRecordKey(personServer, jti)]
	if !ok {
		return PersonTokenRecord{}, ErrPersonTokenNotFound
	}
	return record, nil
}

func personTokenRecordKey(personServer string, jti string) string {
	return personServer + "\x00" + jti
}

func validatePersonTokenRecord(record PersonTokenRecord) error {
	if record.JTI == "" || record.PersonServer == "" || record.TokenSHA256 == "" ||
		record.Resource == "" || record.Subject == "" {
		return errors.New("reference: person-token record is incomplete")
	}
	if record.ExpiresAt.IsZero() || !record.RetainUntil.After(record.ExpiresAt) {
		return errors.New("reference: person-token retention must extend beyond token expiry")
	}
	return nil
}

func encodePersonTokenState(records map[string]PersonTokenRecord) ([]byte, error) {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	state := personTokenState{Schema: personTokenStateSchema}
	for _, key := range keys {
		state.Records = append(state.Records, records[key])
	}
	stateBody, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("reference: encode person-token state: %w", err)
	}
	digest := sha256.Sum256(stateBody)
	body, err := json.Marshal(personTokenEnvelope{
		Schema:      personTokenEnvelopeSchema,
		StateSHA256: hex.EncodeToString(digest[:]),
		State:       stateBody,
	})
	if err != nil {
		return nil, fmt.Errorf("reference: encode person-token envelope: %w", err)
	}
	return body, nil
}

func decodePersonTokenState(body []byte) (map[string]PersonTokenRecord, error) {
	records := make(map[string]PersonTokenRecord)
	if len(body) == 0 {
		return records, nil
	}
	var envelope personTokenEnvelope
	if err := decodeJSONBytesWithLimit(bytes.NewReader(body), &envelope, maxGovernanceStateBytes); err != nil {
		return nil, fmt.Errorf("reference: decode person-token envelope: %w", err)
	}
	if envelope.Schema != personTokenEnvelopeSchema {
		return nil, errors.New("reference: person-token envelope schema is unsupported")
	}
	digest := sha256.Sum256(envelope.State)
	if hex.EncodeToString(digest[:]) != envelope.StateSHA256 {
		return nil, errors.New("reference: person-token state checksum does not match")
	}
	var state personTokenState
	if err := decodeJSONBytesWithLimit(bytes.NewReader(envelope.State), &state, maxGovernanceStateBytes); err != nil {
		return nil, fmt.Errorf("reference: decode person-token state: %w", err)
	}
	if state.Schema != personTokenStateSchema {
		return nil, errors.New("reference: person-token state schema is unsupported")
	}
	for _, record := range state.Records {
		if err := validatePersonTokenRecord(record); err != nil {
			return nil, err
		}
		key := personTokenRecordKey(record.PersonServer, record.JTI)
		if _, duplicate := records[key]; duplicate {
			return nil, errors.New("reference: person-token state contains a duplicate record")
		}
		records[key] = record
	}
	return records, nil
}

var _ PersonTokenStore = (*FilePersonTokenStore)(nil)
