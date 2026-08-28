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
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

const (
	missionIssuanceEnvelopeSchema = "aauth.reference.mission-issuance-envelope.v0"
	missionIssuanceStateSchema    = "aauth.reference.mission-issuance-state.v0"
)

var (
	ErrMissionIssuanceNotFound = errors.New("reference: mission issuance was not found")
	ErrMissionIssuanceConflict = errors.New("reference: mission issuance conflicts with retained custody")
)

// MissionIssuanceState identifies whether an exact mission response is still
// being committed across its child stores or is safe to release.
type MissionIssuanceState string

const (
	MissionIssuancePrepared MissionIssuanceState = "prepared"
	MissionIssuanceComplete MissionIssuanceState = "complete"
)

// MissionIssuancePersonToken retains one exact compact token together with the
// verification record that must be committed before the response is released.
type MissionIssuancePersonToken struct {
	Resource string            `json:"resource"`
	Compact  string            `json:"compact"`
	Record   PersonTokenRecord `json:"record"`
}

// MissionIssuanceRecord is sensitive recovery custody for one exact signed
// mission request. ResponseBody and PersonTokens contain bearer credentials;
// stores must protect them as private material.
type MissionIssuanceRecord struct {
	ReplayKey         string                       `json:"replay_key"`
	ReplayExpiresAt   time.Time                    `json:"replay_expires_at"`
	State             MissionIssuanceState         `json:"state"`
	Agent             string                       `json:"agent"`
	Reference         aauth.MissionReference       `json:"reference"`
	MissionBytes      []byte                       `json:"mission_bytes"`
	Description       string                       `json:"description"`
	ApprovedTools     []aauth.Tool                 `json:"approved_tools,omitempty"`
	ApprovedResources []string                     `json:"approved_resources,omitempty"`
	ExpiresAt         *time.Time                   `json:"expires_at,omitempty"`
	Capabilities      []string                     `json:"capabilities,omitempty"`
	ResponseBody      []byte                       `json:"response_body"`
	PersonTokens      []MissionIssuancePersonToken `json:"person_tokens,omitempty"`
}

// MissionIssuanceStore durably journals the exact response before any child
// person-token record or mission becomes authoritative. Committing the same
// state is idempotent; the only permitted change is prepared to complete.
type MissionIssuanceStore interface {
	Commit(context.Context, MissionIssuanceRecord) error
	Load(context.Context, string) (MissionIssuanceRecord, error)
}

// FileMissionIssuanceStore is a private, single-writer reference adapter.
type FileMissionIssuanceStore struct {
	file    *FileGovernanceStore
	mu      sync.Mutex
	records map[string]MissionIssuanceRecord
}

type missionIssuanceEnvelope struct {
	Schema      string          `json:"schema"`
	StateSHA256 string          `json:"state_sha256"`
	State       json.RawMessage `json:"state"`
}

type missionIssuanceState struct {
	Schema  string                  `json:"schema"`
	Records []MissionIssuanceRecord `json:"records"`
}

type currentMissionApproval struct {
	S256         string            `json:"s256"`
	Mission      string            `json:"mission"`
	Capabilities []string          `json:"capabilities,omitempty"`
	PersonTokens map[string]string `json:"person_tokens,omitempty"`
}

func NewFileMissionIssuanceStore(path string) (*FileMissionIssuanceStore, error) {
	file, err := NewFileGovernanceStore(path)
	if err != nil {
		return nil, err
	}
	body, err := file.Load()
	if err != nil {
		return nil, fmt.Errorf("reference: load mission issuance state: %w", err)
	}
	records, err := decodeMissionIssuanceState(body)
	if err != nil {
		return nil, err
	}
	return &FileMissionIssuanceStore{file: file, records: records}, nil
}

func (store *FileMissionIssuanceStore) Commit(
	_ context.Context,
	record MissionIssuanceRecord,
) error {
	if store == nil || store.file == nil {
		return errors.New("reference: mission issuance file store is not initialized")
	}
	if err := validateMissionIssuanceRecord(record); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.records[record.ReplayKey]; ok {
		if reflect.DeepEqual(existing, record) {
			return nil
		}
		if !validMissionIssuanceTransition(existing, record) {
			return ErrMissionIssuanceConflict
		}
	}
	next := make(map[string]MissionIssuanceRecord, len(store.records)+1)
	for key, existing := range store.records {
		next[key] = copyMissionIssuanceRecord(existing)
	}
	next[record.ReplayKey] = copyMissionIssuanceRecord(record)
	body, err := encodeMissionIssuanceState(next)
	if err != nil {
		return err
	}
	if err := store.file.Save(body); err != nil {
		if errors.Is(err, ErrGovernanceStateUncertain) {
			store.records = next
		}
		return fmt.Errorf("reference: save mission issuance state: %w", err)
	}
	store.records = next
	return nil
}

func (store *FileMissionIssuanceStore) Load(
	_ context.Context,
	replayKey string,
) (MissionIssuanceRecord, error) {
	if store == nil || store.file == nil {
		return MissionIssuanceRecord{}, errors.New("reference: mission issuance file store is not initialized")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[replayKey]
	if !ok {
		return MissionIssuanceRecord{}, ErrMissionIssuanceNotFound
	}
	return copyMissionIssuanceRecord(record), nil
}

func validMissionIssuanceTransition(existing, candidate MissionIssuanceRecord) bool {
	if existing.State != MissionIssuancePrepared || candidate.State != MissionIssuanceComplete {
		return false
	}
	candidate.State = MissionIssuancePrepared
	return reflect.DeepEqual(existing, candidate)
}

func validateMissionIssuanceRecord(record MissionIssuanceRecord) error {
	replayKey, err := base64.RawURLEncoding.DecodeString(record.ReplayKey)
	if err != nil || len(replayKey) != sha256.Size || record.ReplayExpiresAt.IsZero() {
		return errors.New("reference: mission issuance replay identity is invalid")
	}
	if record.State != MissionIssuancePrepared && record.State != MissionIssuanceComplete {
		return errors.New("reference: mission issuance state is invalid")
	}
	if err := aauth.ValidateAgentIdentifier(record.Agent); err != nil {
		return err
	}
	if err := record.Reference.Validate(); err != nil ||
		aauth.S256(record.MissionBytes) != record.Reference.S256 {
		return errors.New("reference: mission issuance reference does not bind its exact bytes")
	}
	var blob missionBlob
	if err := decodeJSONBytes(bytes.NewReader(record.MissionBytes), &blob); err != nil {
		return fmt.Errorf("reference: decode mission issuance blob: %w", err)
	}
	if blob.Approver != record.Reference.Approver || blob.Agent != record.Agent ||
		blob.Description != record.Description ||
		!reflect.DeepEqual(blob.ApprovedTools, record.ApprovedTools) ||
		!reflect.DeepEqual(blob.ApprovedResources, record.ApprovedResources) {
		return errors.New("reference: mission issuance fields do not match the exact mission bytes")
	}
	if formatOptionalTime(record.ExpiresAt) != blob.ExpiresAt {
		return errors.New("reference: mission issuance expiry does not match the exact mission bytes")
	}
	var approval currentMissionApproval
	if err := decodeJSONBytes(bytes.NewReader(record.ResponseBody), &approval); err != nil {
		return fmt.Errorf("reference: decode mission issuance response: %w", err)
	}
	missionBytes, err := base64.RawURLEncoding.DecodeString(approval.Mission)
	if err != nil || approval.S256 != record.Reference.S256 ||
		!bytes.Equal(missionBytes, record.MissionBytes) ||
		!reflect.DeepEqual(approval.Capabilities, record.Capabilities) {
		return errors.New("reference: mission issuance response does not bind its exact mission")
	}
	if len(record.PersonTokens) != len(record.ApprovedResources) ||
		len(approval.PersonTokens) != len(record.PersonTokens) {
		return errors.New("reference: mission issuance person-token set is incomplete")
	}
	resources := make(map[string]bool, len(record.PersonTokens))
	for _, prepared := range record.PersonTokens {
		if resources[prepared.Resource] || approval.PersonTokens[prepared.Resource] != prepared.Compact {
			return errors.New("reference: mission issuance contains a duplicate or mismatched person token")
		}
		resources[prepared.Resource] = true
		if err := validatePersonTokenRecord(prepared.Record); err != nil ||
			prepared.Record.PersonServer != record.Reference.Approver ||
			prepared.Record.Resource != prepared.Resource ||
			prepared.Record.MissionS256 != record.Reference.S256 ||
			prepared.Record.TokenSHA256 != aauth.S256([]byte(prepared.Compact)) {
			return errors.New("reference: mission issuance person-token custody is invalid")
		}
	}
	for _, resource := range record.ApprovedResources {
		if !resources[resource] {
			return errors.New("reference: mission issuance omitted an approved resource")
		}
	}
	return nil
}

func encodeMissionIssuanceState(records map[string]MissionIssuanceRecord) ([]byte, error) {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	state := missionIssuanceState{Schema: missionIssuanceStateSchema}
	for _, key := range keys {
		state.Records = append(state.Records, copyMissionIssuanceRecord(records[key]))
	}
	stateBody, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("reference: encode mission issuance state: %w", err)
	}
	digest := sha256.Sum256(stateBody)
	body, err := json.Marshal(missionIssuanceEnvelope{
		Schema:      missionIssuanceEnvelopeSchema,
		StateSHA256: hex.EncodeToString(digest[:]),
		State:       stateBody,
	})
	if err != nil {
		return nil, fmt.Errorf("reference: encode mission issuance envelope: %w", err)
	}
	return body, nil
}

func decodeMissionIssuanceState(body []byte) (map[string]MissionIssuanceRecord, error) {
	records := make(map[string]MissionIssuanceRecord)
	if len(body) == 0 {
		return records, nil
	}
	var envelope missionIssuanceEnvelope
	if err := decodeJSONBytesWithLimit(bytes.NewReader(body), &envelope, maxGovernanceStateBytes); err != nil {
		return nil, fmt.Errorf("reference: decode mission issuance envelope: %w", err)
	}
	if envelope.Schema != missionIssuanceEnvelopeSchema {
		return nil, errors.New("reference: mission issuance envelope schema is unsupported")
	}
	digest := sha256.Sum256(envelope.State)
	if hex.EncodeToString(digest[:]) != envelope.StateSHA256 {
		return nil, errors.New("reference: mission issuance state checksum does not match")
	}
	var state missionIssuanceState
	if err := decodeJSONBytesWithLimit(bytes.NewReader(envelope.State), &state, maxGovernanceStateBytes); err != nil {
		return nil, fmt.Errorf("reference: decode mission issuance state: %w", err)
	}
	if state.Schema != missionIssuanceStateSchema {
		return nil, errors.New("reference: mission issuance state schema is unsupported")
	}
	for _, record := range state.Records {
		if err := validateMissionIssuanceRecord(record); err != nil {
			return nil, err
		}
		if _, duplicate := records[record.ReplayKey]; duplicate {
			return nil, errors.New("reference: mission issuance state contains a duplicate record")
		}
		records[record.ReplayKey] = copyMissionIssuanceRecord(record)
	}
	return records, nil
}

func copyMissionIssuanceRecord(record MissionIssuanceRecord) MissionIssuanceRecord {
	record.MissionBytes = append([]byte(nil), record.MissionBytes...)
	record.ApprovedTools = append([]aauth.Tool(nil), record.ApprovedTools...)
	record.ApprovedResources = append([]string(nil), record.ApprovedResources...)
	record.ExpiresAt = copyTimePointer(record.ExpiresAt)
	record.Capabilities = append([]string(nil), record.Capabilities...)
	record.ResponseBody = append([]byte(nil), record.ResponseBody...)
	record.PersonTokens = append([]MissionIssuancePersonToken(nil), record.PersonTokens...)
	return record
}

var _ MissionIssuanceStore = (*FileMissionIssuanceStore)(nil)
