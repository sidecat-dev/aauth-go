package reference

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type DeferredProtectedState string

const (
	DeferredProtectedPending  DeferredProtectedState = "pending"
	DeferredProtectedClaimed  DeferredProtectedState = "claimed"
	DeferredProtectedComplete DeferredProtectedState = "complete"

	deferredProtectedEnvelopeSchema = "aauth.reference.deferred-protected-envelope.v0"
	deferredProtectedStateSchema    = "aauth.reference.deferred-protected-state.v0"
)

var (
	ErrDeferredProtectedNotFound = errors.New("reference: deferred protected call was not found")
	ErrDeferredProtectedConflict = errors.New("reference: deferred protected call conflicts with retained custody")
)

// DeferredProtectedResult is the exact terminal HTTP response retained before
// release to the agent.
type DeferredProtectedResult struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        []byte `json:"body"`
}

// DeferredProtectedCallRecord retains one exact protected invocation, its
// sensitive signed request proof, and the auth-token identity that first
// claimed its consequence.
type DeferredProtectedCallRecord struct {
	ID              string                   `json:"id"`
	Resource        string                   `json:"resource"`
	ResourceToken   string                   `json:"resource_token"`
	RequestProofKey string                   `json:"request_proof_key"`
	RequestProof    *aauth.RequestProof      `json:"request_proof"`
	PersonIssuerKey jose.JWK                 `json:"person_issuer_key"`
	Method          string                   `json:"method"`
	Target          string                   `json:"target"`
	Body            []byte                   `json:"body,omitempty"`
	ContentType     string                   `json:"content_type,omitempty"`
	RequiredScopes  []string                 `json:"required_scopes"`
	ExpiresAt       time.Time                `json:"expires_at"`
	State           DeferredProtectedState   `json:"state"`
	AuthTokenIssuer string                   `json:"auth_token_issuer,omitempty"`
	AuthTokenID     string                   `json:"auth_token_id,omitempty"`
	Result          *DeferredProtectedResult `json:"result,omitempty"`
}

// DeferredProtectedCallStore atomically retains, claims, and settles held
// protected invocations.
type DeferredProtectedCallStore interface {
	Create(context.Context, DeferredProtectedCallRecord) error
	Load(context.Context, string) (DeferredProtectedCallRecord, error)
	Claim(context.Context, string, string, string) (DeferredProtectedCallRecord, bool, error)
	Complete(context.Context, string, DeferredProtectedResult) (DeferredProtectedCallRecord, error)
	Release(string)
}

func (store *FileDeferredProtectedCallStore) Load(_ context.Context, id string) (DeferredProtectedCallRecord, error) {
	if store == nil || store.file == nil {
		return DeferredProtectedCallRecord{}, errors.New("reference: deferred protected-call store is not initialized")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.records[id]
	if !found {
		return DeferredProtectedCallRecord{}, ErrDeferredProtectedNotFound
	}
	return copyDeferredProtectedRecord(record), nil
}

// FileDeferredProtectedCallStore is a private bounded single-writer reference
// adapter. An in-process claim is transient; a claimed durable record is
// reclaimable after reconstruction with the same auth-token identity.
type FileDeferredProtectedCallStore struct {
	file    *FileGovernanceStore
	mu      sync.Mutex
	records map[string]DeferredProtectedCallRecord
	active  map[string]struct{}
}

type deferredProtectedEnvelope struct {
	Schema      string          `json:"schema"`
	StateSHA256 string          `json:"state_sha256"`
	State       json.RawMessage `json:"state"`
}

type deferredProtectedState struct {
	Schema  string                        `json:"schema"`
	Records []DeferredProtectedCallRecord `json:"records"`
}

func NewFileDeferredProtectedCallStore(path string) (*FileDeferredProtectedCallStore, error) {
	file, err := NewFileGovernanceStore(path)
	if err != nil {
		return nil, err
	}
	body, err := file.Load()
	if err != nil {
		return nil, fmt.Errorf("reference: load deferred protected-call state: %w", err)
	}
	records, err := decodeDeferredProtectedState(body)
	if err != nil {
		return nil, err
	}
	return &FileDeferredProtectedCallStore{file: file, records: records, active: make(map[string]struct{})}, nil
}

func (store *FileDeferredProtectedCallStore) Create(_ context.Context, record DeferredProtectedCallRecord) error {
	if store == nil || store.file == nil {
		return errors.New("reference: deferred protected-call store is not initialized")
	}
	if err := validateDeferredProtectedRecord(record); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.records[record.ID]; found {
		if reflect.DeepEqual(existing, record) {
			return nil
		}
		return ErrDeferredProtectedConflict
	}
	return store.saveLocked(record)
}

func (store *FileDeferredProtectedCallStore) Claim(
	_ context.Context,
	id, authTokenIssuer, authTokenID string,
) (DeferredProtectedCallRecord, bool, error) {
	if store == nil || store.file == nil {
		return DeferredProtectedCallRecord{}, false, errors.New("reference: deferred protected-call store is not initialized")
	}
	if aauth.ValidateServerIdentifier(authTokenIssuer) != nil || authTokenID == "" {
		return DeferredProtectedCallRecord{}, false, errors.New("reference: deferred protected-call auth-token identity is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.records[id]
	if !found {
		return DeferredProtectedCallRecord{}, false, ErrDeferredProtectedNotFound
	}
	if record.State == DeferredProtectedPending {
		record.State = DeferredProtectedClaimed
		record.AuthTokenIssuer, record.AuthTokenID = authTokenIssuer, authTokenID
		if err := store.saveLocked(record); err != nil {
			return DeferredProtectedCallRecord{}, false, err
		}
	} else if record.AuthTokenIssuer != authTokenIssuer || record.AuthTokenID != authTokenID {
		return DeferredProtectedCallRecord{}, false, ErrDeferredProtectedConflict
	}
	if record.State == DeferredProtectedComplete {
		return copyDeferredProtectedRecord(record), false, nil
	}
	if _, active := store.active[id]; active {
		return copyDeferredProtectedRecord(record), false, nil
	}
	store.active[id] = struct{}{}
	return copyDeferredProtectedRecord(record), true, nil
}

func (store *FileDeferredProtectedCallStore) Complete(
	_ context.Context,
	id string,
	result DeferredProtectedResult,
) (DeferredProtectedCallRecord, error) {
	if store == nil || store.file == nil {
		return DeferredProtectedCallRecord{}, errors.New("reference: deferred protected-call store is not initialized")
	}
	if err := validateDeferredProtectedResult(result); err != nil {
		return DeferredProtectedCallRecord{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	defer delete(store.active, id)
	record, found := store.records[id]
	if !found {
		return DeferredProtectedCallRecord{}, ErrDeferredProtectedNotFound
	}
	if record.State == DeferredProtectedComplete {
		if record.Result == nil || !reflect.DeepEqual(*record.Result, result) {
			return DeferredProtectedCallRecord{}, ErrDeferredProtectedConflict
		}
		return copyDeferredProtectedRecord(record), nil
	}
	if record.State != DeferredProtectedClaimed {
		return DeferredProtectedCallRecord{}, ErrDeferredProtectedConflict
	}
	next := copyDeferredProtectedRecord(record)
	next.State = DeferredProtectedComplete
	copyResult := result
	copyResult.Body = append([]byte(nil), result.Body...)
	next.Result = &copyResult
	if err := store.saveLocked(next); err != nil {
		return DeferredProtectedCallRecord{}, err
	}
	return copyDeferredProtectedRecord(next), nil
}

func (store *FileDeferredProtectedCallStore) Release(id string) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.active, id)
}

func (store *FileDeferredProtectedCallStore) saveLocked(record DeferredProtectedCallRecord) error {
	if err := validateDeferredProtectedRecord(record); err != nil {
		return err
	}
	next := make(map[string]DeferredProtectedCallRecord, len(store.records)+1)
	for id, existing := range store.records {
		next[id] = copyDeferredProtectedRecord(existing)
	}
	next[record.ID] = copyDeferredProtectedRecord(record)
	body, err := encodeDeferredProtectedState(next)
	if err != nil {
		return err
	}
	if err := store.file.Save(body); err != nil {
		if errors.Is(err, ErrGovernanceStateUncertain) {
			store.records = next
		}
		return fmt.Errorf("reference: save deferred protected-call state: %w", err)
	}
	store.records = next
	return nil
}

func validateDeferredProtectedRecord(record DeferredProtectedCallRecord) error {
	if record.ID == "" || record.ResourceToken == "" || record.RequestProofKey == "" ||
		aauth.ValidateServerIdentifier(record.Resource) != nil || strings.TrimSpace(record.Method) == "" ||
		record.Target == "" || record.Target[0] != '/' || record.ExpiresAt.IsZero() || len(record.Body) > maxJSONBody {
		return errors.New("reference: deferred protected-call record is incomplete")
	}
	if len(record.Body) == 0 && record.ContentType != "" || len(record.Body) != 0 && strings.TrimSpace(record.ContentType) == "" {
		return errors.New("reference: deferred protected-call content metadata is invalid")
	}
	if _, err := canonicalRequiredScopes(record.RequiredScopes, record.RequiredScopes); err != nil {
		return errors.New("reference: deferred protected-call scope set is invalid")
	}
	if err := validateDeferredProtectedRequestEvidence(record); err != nil {
		return err
	}
	switch record.State {
	case DeferredProtectedPending:
		if record.AuthTokenIssuer != "" || record.AuthTokenID != "" || record.Result != nil {
			return errors.New("reference: pending deferred call carries terminal custody")
		}
	case DeferredProtectedClaimed:
		if aauth.ValidateServerIdentifier(record.AuthTokenIssuer) != nil || record.AuthTokenID == "" || record.Result != nil {
			return errors.New("reference: claimed deferred call has invalid auth-token custody")
		}
	case DeferredProtectedComplete:
		if aauth.ValidateServerIdentifier(record.AuthTokenIssuer) != nil || record.AuthTokenID == "" || record.Result == nil || validateDeferredProtectedResult(*record.Result) != nil {
			return errors.New("reference: complete deferred call lacks a valid result")
		}
	default:
		return errors.New("reference: deferred protected-call state is invalid")
	}
	return nil
}

func validateDeferredProtectedRequestEvidence(record DeferredProtectedCallRecord) error {
	proof := record.RequestProof
	if proof == nil || proof.ReplayKey != record.RequestProofKey || proof.Method != record.Method || proof.Target != record.Target ||
		proof.CredentialType != aauth.PersonTokenType || proof.SignatureKeyType != string(signaturekey.SchemeJWT) ||
		proof.CredentialIssuer == "" || proof.VerifiedAt.IsZero() || record.PersonIssuerKey.Kid == "" {
		return errors.New("reference: deferred protected-call request proof is invalid")
	}
	if _, err := proof.PublicKey.PublicKey(); err != nil {
		return errors.New("reference: deferred protected-call request proof key is invalid")
	}
	request, err := http.NewRequest(record.Method, record.Resource+record.Target, bytes.NewReader(record.Body))
	if err != nil {
		return errors.New("reference: deferred protected-call target is invalid")
	}
	request.Host = proof.Authority
	request.Header.Set("Content-Digest", proof.ContentDigest)
	if record.ContentType != "" {
		request.Header.Set("Content-Type", record.ContentType)
	}
	request.Header.Set("Signature-Input", proof.SignatureInput)
	request.Header.Set("Signature", proof.Signature)
	request.Header.Set("Signature-Key", proof.SignatureKey)
	required := []string(nil)
	if len(record.Body) != 0 {
		required = append(required, "content-type")
	}
	verified, err := aauth.VerifyRequest(
		context.Background(), request,
		signaturekey.StaticKeyResolver{proof.CredentialIssuer: {record.PersonIssuerKey.Kid: record.PersonIssuerKey}},
		aauth.ClockFunc(func() time.Time { return proof.VerifiedAt.UTC() }),
		aauth.VerifyRequestOptions{
			RequiredComponents: required, RequireExactComponents: true,
			AllowedCredentialTypes: []string{aauth.PersonTokenType},
		},
	)
	if err != nil || verified.ReplayKey != proof.ReplayKey || !verified.PublicKey.Equal(proof.PublicKey) {
		return errors.New("reference: deferred protected-call request proof does not verify")
	}
	return nil
}

func validateDeferredProtectedResult(result DeferredProtectedResult) error {
	if result.Status < 200 || result.Status > 599 || strings.TrimSpace(result.ContentType) == "" || len(result.Body) == 0 {
		return errors.New("reference: deferred protected-call result is invalid")
	}
	return nil
}

func copyDeferredProtectedRecord(record DeferredProtectedCallRecord) DeferredProtectedCallRecord {
	record.Body = append([]byte(nil), record.Body...)
	record.RequiredScopes = append([]string(nil), record.RequiredScopes...)
	record.RequestProof = copyRequestProof(record.RequestProof)
	if record.Result != nil {
		result := *record.Result
		result.Body = append([]byte(nil), record.Result.Body...)
		record.Result = &result
	}
	return record
}

func encodeDeferredProtectedState(records map[string]DeferredProtectedCallRecord) ([]byte, error) {
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	state := deferredProtectedState{Schema: deferredProtectedStateSchema}
	for _, id := range ids {
		state.Records = append(state.Records, copyDeferredProtectedRecord(records[id]))
	}
	body, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	return json.Marshal(deferredProtectedEnvelope{Schema: deferredProtectedEnvelopeSchema, StateSHA256: hex.EncodeToString(digest[:]), State: body})
}

func decodeDeferredProtectedState(body []byte) (map[string]DeferredProtectedCallRecord, error) {
	records := make(map[string]DeferredProtectedCallRecord)
	if len(body) == 0 {
		return records, nil
	}
	var envelope deferredProtectedEnvelope
	if err := decodeJSONBytesWithLimit(bytes.NewReader(body), &envelope, maxGovernanceStateBytes); err != nil || envelope.Schema != deferredProtectedEnvelopeSchema {
		return nil, errors.New("reference: deferred protected-call envelope is invalid")
	}
	digest := sha256.Sum256(envelope.State)
	if envelope.StateSHA256 != hex.EncodeToString(digest[:]) {
		return nil, errors.New("reference: deferred protected-call checksum does not match")
	}
	var state deferredProtectedState
	if err := decodeJSONBytesWithLimit(bytes.NewReader(envelope.State), &state, maxGovernanceStateBytes); err != nil || state.Schema != deferredProtectedStateSchema {
		return nil, errors.New("reference: deferred protected-call state is invalid")
	}
	previous := ""
	for _, record := range state.Records {
		if record.ID <= previous || validateDeferredProtectedRecord(record) != nil {
			return nil, errors.New("reference: deferred protected-call state contains an invalid record")
		}
		previous = record.ID
		records[record.ID] = copyDeferredProtectedRecord(record)
	}
	return records, nil
}

func writeDeferredProtectedResult(response http.ResponseWriter, result DeferredProtectedResult) {
	response.Header().Set("Content-Type", result.ContentType)
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(result.Status)
	_, _ = response.Write(result.Body)
}

var _ DeferredProtectedCallStore = (*FileDeferredProtectedCallStore)(nil)
