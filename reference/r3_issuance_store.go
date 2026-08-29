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
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

const (
	r3IssuanceEnvelopeSchema = "aauth.reference.r3-issuance-envelope.v0"
	r3IssuanceStateSchema    = "aauth.reference.r3-issuance-state.v0"
)

var (
	ErrR3IssuanceNotFound = errors.New("reference: R3 issuance was not found")
	ErrR3IssuanceConflict = errors.New("reference: R3 issuance conflicts with retained custody")
)

// R3IssuanceRecord is one atomic audit-and-response record. RequestKey is
// derived from the authenticated PS identity and exact signed request body.
type R3IssuanceRecord struct {
	RequestKey        string           `json:"request_key"`
	RequestBodySHA256 string           `json:"request_body_sha256"`
	Signer            string           `json:"signer"`
	AuthToken         string           `json:"auth_token"`
	ResponseBody      []byte           `json:"response_body"`
	Audit             r3.IssuanceAudit `json:"audit"`
}

// R3IssuanceStore commits the exact direct grant and its audit atomically.
// Recommitting an exact record is idempotent; any different record under the
// same request identity conflicts.
type R3IssuanceStore interface {
	Commit(context.Context, R3IssuanceRecord) error
	Load(context.Context, string) (R3IssuanceRecord, error)
}

// FileR3IssuanceStore is a private, single-writer reference adapter.
type FileR3IssuanceStore struct {
	file    *FileGovernanceStore
	mu      sync.Mutex
	records map[string]R3IssuanceRecord
}

type r3IssuanceEnvelope struct {
	Schema      string          `json:"schema"`
	StateSHA256 string          `json:"state_sha256"`
	State       json.RawMessage `json:"state"`
}

type r3IssuanceState struct {
	Schema  string             `json:"schema"`
	Records []R3IssuanceRecord `json:"records"`
}

func NewFileR3IssuanceStore(path string) (*FileR3IssuanceStore, error) {
	file, err := NewFileGovernanceStore(path)
	if err != nil {
		return nil, err
	}
	body, err := file.Load()
	if err != nil {
		return nil, fmt.Errorf("reference: load R3 issuance state: %w", err)
	}
	records, err := decodeR3IssuanceState(body)
	if err != nil {
		return nil, err
	}
	return &FileR3IssuanceStore{file: file, records: records}, nil
}

func (store *FileR3IssuanceStore) Commit(_ context.Context, record R3IssuanceRecord) error {
	if store == nil || store.file == nil {
		return errors.New("reference: R3 issuance file store is not initialized")
	}
	if err := validateR3IssuanceRecord(record); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.records[record.RequestKey]; found {
		if reflect.DeepEqual(existing, record) {
			return nil
		}
		return ErrR3IssuanceConflict
	}
	next := make(map[string]R3IssuanceRecord, len(store.records)+1)
	for key, existing := range store.records {
		next[key] = copyR3IssuanceRecord(existing)
	}
	next[record.RequestKey] = copyR3IssuanceRecord(record)
	body, err := encodeR3IssuanceState(next)
	if err != nil {
		return err
	}
	if err := store.file.Save(body); err != nil {
		if errors.Is(err, ErrGovernanceStateUncertain) {
			store.records = next
		}
		return fmt.Errorf("reference: save R3 issuance state: %w", err)
	}
	store.records = next
	return nil
}

func (store *FileR3IssuanceStore) Load(_ context.Context, requestKey string) (R3IssuanceRecord, error) {
	if store == nil || store.file == nil {
		return R3IssuanceRecord{}, errors.New("reference: R3 issuance file store is not initialized")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.records[requestKey]
	if !found {
		return R3IssuanceRecord{}, ErrR3IssuanceNotFound
	}
	return copyR3IssuanceRecord(record), nil
}

func r3IssuanceRequestKey(signer string, requestBody []byte) (string, string) {
	bodyDigest := sha256.Sum256(requestBody)
	bodySHA256 := base64.RawURLEncoding.EncodeToString(bodyDigest[:])
	identity := sha256.Sum256([]byte("gitlab.com/sidecat-dev/aauth-go/r3-issuance-request/v1\x00" + signer + "\x00" + bodySHA256))
	return base64.RawURLEncoding.EncodeToString(identity[:]), bodySHA256
}

func validateR3IssuanceRecord(record R3IssuanceRecord) error {
	requestKey, requestErr := base64.RawURLEncoding.DecodeString(record.RequestKey)
	bodyDigest, bodyErr := base64.RawURLEncoding.DecodeString(record.RequestBodySHA256)
	// Reconstruct the domain-separated request identity from the retained body
	// hash rather than retaining credential-bearing request bytes.
	identity := sha256.Sum256([]byte("gitlab.com/sidecat-dev/aauth-go/r3-issuance-request/v1\x00" + record.Signer + "\x00" + record.RequestBodySHA256))
	wantKey := base64.RawURLEncoding.EncodeToString(identity[:])
	if requestErr != nil || len(requestKey) != sha256.Size || bodyErr != nil || len(bodyDigest) != sha256.Size || wantKey != record.RequestKey {
		return errors.New("reference: R3 issuance request identity is invalid")
	}
	if err := aauth.ValidateServerIdentifier(record.Signer); err != nil || record.Signer != record.Audit.PersonServer {
		return errors.New("reference: R3 issuance signer does not match the audited person server")
	}
	if err := validateR3IssuanceAudit(record.Audit); err != nil {
		return err
	}
	var response struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := decodeJSONBytes(bytes.NewReader(record.ResponseBody), &response); err != nil ||
		response.AuthToken == "" || response.AuthToken != record.AuthToken || response.ExpiresIn <= 0 {
		return errors.New("reference: R3 issuance response body is invalid")
	}
	return validateR3IssuanceToken(record, response.ExpiresIn)
}

func validateR3IssuanceAudit(audit r3.IssuanceAudit) error {
	for _, identifier := range []string{audit.AccessServer, audit.PersonServer, audit.Resource} {
		if err := aauth.ValidateServerIdentifier(identifier); err != nil {
			return errors.New("reference: R3 issuance audit contains an invalid server identifier")
		}
	}
	if err := aauth.ValidateAgentIdentifier(audit.Agent); err != nil {
		return errors.New("reference: R3 issuance audit contains an invalid agent")
	}
	if audit.ParentAgent != "" {
		if err := aauth.ValidateAgentIdentifier(audit.ParentAgent); err != nil {
			return errors.New("reference: R3 issuance audit contains an invalid parent agent")
		}
	}
	thumbprint, err := base64.RawURLEncoding.DecodeString(audit.AgentJKT)
	digest, digestErr := base64.RawURLEncoding.DecodeString(audit.Digest)
	if err != nil || len(thumbprint) != sha256.Size || audit.Subject == "" ||
		audit.ResourceTokenID == "" || audit.AuthTokenID == "" || audit.URI == "" ||
		digestErr != nil || len(digest) != sha256.Size || audit.IssuedAt.IsZero() {
		return errors.New("reference: R3 issuance audit is incomplete")
	}
	return nil
}

func validateR3IssuanceToken(record R3IssuanceRecord, expiresIn int64) error {
	parsed, err := jose.ParseCompact(record.AuthToken)
	if err != nil || parsed.Header().Type != aauth.AuthTokenType {
		return errors.New("reference: R3 issuance auth token is invalid")
	}
	var claims aauth.AuthTokenClaims
	var members map[string]json.RawMessage
	if err := json.Unmarshal(parsed.Payload(), &claims); err != nil || json.Unmarshal(parsed.Payload(), &members) != nil {
		return errors.New("reference: R3 issuance auth-token claims are invalid")
	}
	var uri, digest string
	_ = json.Unmarshal(members["r3_uri"], &uri)
	_ = json.Unmarshal(members["r3_s256"], &digest)
	if claims.Issuer != record.Audit.AccessServer || claims.PersonServer != record.Audit.PersonServer ||
		claims.Subject != record.Audit.Subject || claims.Audience != record.Audit.Resource ||
		claims.JTI != record.Audit.AuthTokenID || claims.IssuedAt != record.Audit.IssuedAt.Unix() ||
		claims.ExpiresAt-claims.IssuedAt != expiresIn || uri != record.Audit.URI || digest != record.Audit.Digest {
		return errors.New("reference: R3 issuance auth token does not match its audit")
	}
	if _, err := r3.ParseOperationSet(members["r3_granted"]); err != nil {
		return errors.New("reference: R3 issuance auth token has an invalid direct grant")
	}
	if _, perCall := members["r3_per_call"]; perCall {
		return errors.New("reference: R3 direct issuance contains r3_per_call")
	}
	return nil
}

func encodeR3IssuanceState(records map[string]R3IssuanceRecord) ([]byte, error) {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	state := r3IssuanceState{Schema: r3IssuanceStateSchema}
	for _, key := range keys {
		state.Records = append(state.Records, copyR3IssuanceRecord(records[key]))
	}
	stateBody, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(stateBody)
	return json.Marshal(r3IssuanceEnvelope{
		Schema: r3IssuanceEnvelopeSchema, StateSHA256: hex.EncodeToString(digest[:]), State: stateBody,
	})
}

func decodeR3IssuanceState(body []byte) (map[string]R3IssuanceRecord, error) {
	records := make(map[string]R3IssuanceRecord)
	if len(body) == 0 {
		return records, nil
	}
	var envelope r3IssuanceEnvelope
	if err := decodeJSONBytesWithLimit(bytes.NewReader(body), &envelope, maxGovernanceStateBytes); err != nil {
		return nil, err
	}
	if envelope.Schema != r3IssuanceEnvelopeSchema {
		return nil, errors.New("reference: R3 issuance envelope schema is unsupported")
	}
	digest := sha256.Sum256(envelope.State)
	if hex.EncodeToString(digest[:]) != envelope.StateSHA256 {
		return nil, errors.New("reference: R3 issuance state checksum does not match")
	}
	var state r3IssuanceState
	if err := decodeJSONBytesWithLimit(bytes.NewReader(envelope.State), &state, maxGovernanceStateBytes); err != nil || state.Schema != r3IssuanceStateSchema {
		return nil, errors.New("reference: R3 issuance state is invalid")
	}
	for _, record := range state.Records {
		if err := validateR3IssuanceRecord(record); err != nil {
			return nil, err
		}
		if _, duplicate := records[record.RequestKey]; duplicate {
			return nil, errors.New("reference: R3 issuance state contains a duplicate record")
		}
		records[record.RequestKey] = copyR3IssuanceRecord(record)
	}
	return records, nil
}

func copyR3IssuanceRecord(record R3IssuanceRecord) R3IssuanceRecord {
	record.ResponseBody = append([]byte(nil), record.ResponseBody...)
	return record
}

var _ R3IssuanceStore = (*FileR3IssuanceStore)(nil)
