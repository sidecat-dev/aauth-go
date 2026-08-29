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
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

const (
	r3ResourceTokenEnvelopeSchema = "aauth.reference.r3-resource-token-envelope.v0"
	r3ResourceTokenStateSchema    = "aauth.reference.r3-resource-token-state.v0"
)

var (
	ErrR3ResourceTokenNotFound = errors.New("reference: R3 resource token was not found")
	ErrR3ResourceTokenConflict = errors.New("reference: R3 resource token conflicts with retained custody")
)

// R3ResourceTokenRecord retains the exact resource token and the person-token
// JTI that established its subject. LineageKey contains only context visible in
// the later auth token. ContextKey additionally carries PresentedJTI and the
// resource-token scope so distinct bindings can never silently converge.
type R3ResourceTokenRecord struct {
	LineageKey    string `json:"lineage_key"`
	ContextKey    string `json:"context_key"`
	ResourceToken string `json:"resource_token"`
	Resource      string `json:"resource"`
	AccessServer  string `json:"access_server"`
	PersonServer  string `json:"person_server"`
	Subject       string `json:"subject"`
	PresentedJTI  string `json:"presented_jti"`
	AgentJKT      string `json:"agent_jkt"`
	Scope         string `json:"scope"`
	MissionS256   string `json:"mission_s256,omitempty"`
	Tenant        string `json:"tenant,omitempty"`
	Account       string `json:"account,omitempty"`
	URI           string `json:"r3_uri"`
	Digest        string `json:"r3_s256"`
	IssuedAt      int64  `json:"issued_at"`
	ExpiresAt     int64  `json:"expires_at"`
}

// R3ResourceTokenStore is the resource deployment's exact authorization-
// lineage boundary. Exact replay is idempotent; a changed token under the same
// context conflicts.
type R3ResourceTokenStore interface {
	Commit(context.Context, R3ResourceTokenRecord) error
	Load(context.Context, string) (R3ResourceTokenRecord, error)
	Resolve(context.Context, string, int64) (R3ResourceTokenRecord, error)
}

// NewR3ResourceTokenRecord binds one compact token to the claims and R3
// document reference used to mint it.
func NewR3ResourceTokenRecord(
	compact string,
	claims aauth.ResourceTokenClaims,
	reference r3.DocumentReference,
) (R3ResourceTokenRecord, error) {
	if !reference.Valid() {
		return R3ResourceTokenRecord{}, errors.New("reference: R3 resource-token document is invalid")
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil || parsed.Header().Type != aauth.ResourceTokenType {
		return R3ResourceTokenRecord{}, errors.New("reference: R3 compact resource token is invalid")
	}
	var retained aauth.ResourceTokenClaims
	var members map[string]json.RawMessage
	if json.Unmarshal(parsed.Payload(), &retained) != nil || json.Unmarshal(parsed.Payload(), &members) != nil ||
		!reflect.DeepEqual(retained, claims) {
		return R3ResourceTokenRecord{}, errors.New("reference: R3 resource token does not match its retained claims")
	}
	var uri, digest string
	if json.Unmarshal(members["r3_uri"], &uri) != nil || json.Unmarshal(members["r3_s256"], &digest) != nil ||
		uri != reference.URI() || digest != reference.Digest() {
		return R3ResourceTokenRecord{}, errors.New("reference: R3 resource token does not match its document")
	}
	record := R3ResourceTokenRecord{
		ResourceToken: compact, Resource: claims.Issuer, AccessServer: claims.Audience,
		PersonServer: claims.PersonServer, Subject: claims.Subject, PresentedJTI: claims.PresentedJTI,
		AgentJKT: claims.AgentJKT, Scope: claims.Scope, MissionS256: claims.MissionS256,
		Tenant: claims.Tenant, Account: claims.Account, URI: uri, Digest: digest,
		IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt,
	}
	record.LineageKey, err = r3ResourceAuthorizationLineageKey(record)
	if err == nil {
		record.ContextKey, err = r3ResourceAuthorizationContextKey(record.LineageKey, record.PresentedJTI, record.Scope, record.IssuedAt)
	}
	if err != nil {
		return R3ResourceTokenRecord{}, err
	}
	if err := validateR3ResourceTokenRecord(record); err != nil {
		return R3ResourceTokenRecord{}, err
	}
	return record, nil
}

// R3ResourceAuthorizationLineageKey derives the lookup key available from an
// R3 auth token at a resource. It deliberately accepts no presented_jti; the
// store resolves the exact earlier resource-token generation at the auth
// token's trusted issuance instant.
func R3ResourceAuthorizationLineageKey(
	resource, accessServer, personServer, subject, agentJKT,
	missionS256, tenant, account, uri, digest string,
) (string, error) {
	record := R3ResourceTokenRecord{
		Resource: resource, AccessServer: accessServer, PersonServer: personServer,
		Subject: subject, AgentJKT: agentJKT, MissionS256: missionS256,
		Tenant: tenant, Account: account, URI: uri, Digest: digest,
	}
	return r3ResourceAuthorizationLineageKey(record)
}

func r3ResourceAuthorizationLineageKey(record R3ResourceTokenRecord) (string, error) {
	material, err := json.Marshal(struct {
		Domain       string `json:"domain"`
		Resource     string `json:"resource"`
		AccessServer string `json:"access_server"`
		PersonServer string `json:"person_server"`
		Subject      string `json:"subject"`
		AgentJKT     string `json:"agent_jkt"`
		MissionS256  string `json:"mission_s256,omitempty"`
		Tenant       string `json:"tenant,omitempty"`
		Account      string `json:"account,omitempty"`
		URI          string `json:"r3_uri"`
		Digest       string `json:"r3_s256"`
	}{
		Domain:   "gitlab.com/sidecat-dev/aauth-go/r3-resource-authorization-context/v1",
		Resource: record.Resource, AccessServer: record.AccessServer,
		PersonServer: record.PersonServer, Subject: record.Subject, AgentJKT: record.AgentJKT,
		MissionS256: record.MissionS256, Tenant: record.Tenant,
		Account: record.Account, URI: record.URI, Digest: record.Digest,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(material)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func r3ResourceAuthorizationContextKey(lineageKey, presentedJTI, scope string, issuedAt int64) (string, error) {
	lineage, err := base64.RawURLEncoding.DecodeString(lineageKey)
	if err != nil || len(lineage) != sha256.Size || presentedJTI == "" || scope == "" || issuedAt <= 0 {
		return "", errors.New("reference: R3 resource-token lineage identity is invalid")
	}
	material, err := json.Marshal(struct {
		Domain       string `json:"domain"`
		LineageKey   string `json:"lineage_key"`
		PresentedJTI string `json:"presented_jti"`
		Scope        string `json:"scope"`
		IssuedAt     int64  `json:"issued_at"`
	}{"gitlab.com/sidecat-dev/aauth-go/r3-resource-authorization-generation/v1", lineageKey, presentedJTI, scope, issuedAt})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(material)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

// FileR3ResourceTokenStore is a private, single-writer reference adapter.
type FileR3ResourceTokenStore struct {
	file    *FileGovernanceStore
	mu      sync.Mutex
	records map[string]R3ResourceTokenRecord
}

type r3ResourceTokenEnvelope struct {
	Schema      string          `json:"schema"`
	StateSHA256 string          `json:"state_sha256"`
	State       json.RawMessage `json:"state"`
}

type r3ResourceTokenState struct {
	Schema  string                  `json:"schema"`
	Records []R3ResourceTokenRecord `json:"records"`
}

func NewFileR3ResourceTokenStore(path string) (*FileR3ResourceTokenStore, error) {
	file, err := NewFileGovernanceStore(path)
	if err != nil {
		return nil, err
	}
	body, err := file.Load()
	if err != nil {
		return nil, fmt.Errorf("reference: load R3 resource-token state: %w", err)
	}
	records, err := decodeR3ResourceTokenState(body)
	if err != nil {
		return nil, err
	}
	return &FileR3ResourceTokenStore{file: file, records: records}, nil
}

func (store *FileR3ResourceTokenStore) Commit(_ context.Context, record R3ResourceTokenRecord) error {
	if store == nil || store.file == nil {
		return errors.New("reference: R3 resource-token file store is not initialized")
	}
	if err := validateR3ResourceTokenRecord(record); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.records[record.ContextKey]; found {
		if reflect.DeepEqual(existing, record) {
			return nil
		}
		return ErrR3ResourceTokenConflict
	}
	next := make(map[string]R3ResourceTokenRecord, len(store.records)+1)
	for key, existing := range store.records {
		next[key] = existing
	}
	next[record.ContextKey] = record
	body, err := encodeR3ResourceTokenState(next)
	if err != nil {
		return err
	}
	if err := store.file.Save(body); err != nil {
		if errors.Is(err, ErrGovernanceStateUncertain) {
			store.records = next
		}
		return fmt.Errorf("reference: save R3 resource-token state: %w", err)
	}
	store.records = next
	return nil
}

func (store *FileR3ResourceTokenStore) Load(_ context.Context, contextKey string) (R3ResourceTokenRecord, error) {
	if store == nil || store.file == nil {
		return R3ResourceTokenRecord{}, errors.New("reference: R3 resource-token file store is not initialized")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.records[contextKey]
	if !found {
		return R3ResourceTokenRecord{}, ErrR3ResourceTokenNotFound
	}
	return record, nil
}

func (store *FileR3ResourceTokenStore) Resolve(_ context.Context, lineageKey string, authIssuedAt int64) (R3ResourceTokenRecord, error) {
	if store == nil || store.file == nil {
		return R3ResourceTokenRecord{}, errors.New("reference: R3 resource-token file store is not initialized")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var selected R3ResourceTokenRecord
	found := false
	for _, record := range store.records {
		if record.LineageKey != lineageKey || record.IssuedAt > authIssuedAt || record.ExpiresAt < authIssuedAt {
			continue
		}
		if !found || record.IssuedAt > selected.IssuedAt {
			selected, found = record, true
			continue
		}
		if record.IssuedAt == selected.IssuedAt && record.ContextKey != selected.ContextKey {
			return R3ResourceTokenRecord{}, ErrR3ResourceTokenConflict
		}
	}
	if !found {
		return R3ResourceTokenRecord{}, ErrR3ResourceTokenNotFound
	}
	return selected, nil
}

func validateR3ResourceTokenRecord(record R3ResourceTokenRecord) error {
	lineageKey, err := r3ResourceAuthorizationLineageKey(record)
	contextKey, contextErr := r3ResourceAuthorizationContextKey(lineageKey, record.PresentedJTI, record.Scope, record.IssuedAt)
	if err != nil || contextErr != nil || lineageKey != record.LineageKey || contextKey != record.ContextKey {
		return errors.New("reference: R3 resource-token context key is invalid")
	}
	if record.ResourceToken == "" || record.PresentedJTI == "" || record.IssuedAt <= 0 || record.ExpiresAt <= record.IssuedAt {
		return errors.New("reference: R3 resource-token record is incomplete")
	}
	for _, identifier := range []string{record.Resource, record.AccessServer, record.PersonServer} {
		if aauth.ValidateServerIdentifier(identifier) != nil {
			return errors.New("reference: R3 resource-token record has an invalid server identifier")
		}
	}
	thumbprint, thumbprintErr := base64.RawURLEncoding.DecodeString(record.AgentJKT)
	digest, digestErr := base64.RawURLEncoding.DecodeString(record.Digest)
	if record.Subject == "" || len(thumbprint) != sha256.Size || thumbprintErr != nil ||
		len(digest) != sha256.Size || digestErr != nil {
		return errors.New("reference: R3 resource-token record has invalid authorization context")
	}
	parsed, err := jose.ParseCompact(record.ResourceToken)
	if err != nil || parsed.Header().Type != aauth.ResourceTokenType {
		return errors.New("reference: retained R3 resource token is invalid")
	}
	var claims aauth.ResourceTokenClaims
	var members map[string]json.RawMessage
	if json.Unmarshal(parsed.Payload(), &claims) != nil || json.Unmarshal(parsed.Payload(), &members) != nil {
		return errors.New("reference: retained R3 resource-token claims are invalid")
	}
	var uri, retainedDigest string
	_ = json.Unmarshal(members["r3_uri"], &uri)
	_ = json.Unmarshal(members["r3_s256"], &retainedDigest)
	if claims.Issuer != record.Resource || claims.Audience != record.AccessServer ||
		claims.PersonServer != record.PersonServer || claims.Subject != record.Subject ||
		claims.PresentedJTI != record.PresentedJTI || claims.AgentJKT != record.AgentJKT ||
		claims.Scope != record.Scope || claims.MissionS256 != record.MissionS256 ||
		claims.Tenant != record.Tenant || claims.Account != record.Account ||
		claims.IssuedAt != record.IssuedAt || claims.ExpiresAt != record.ExpiresAt ||
		uri != record.URI || retainedDigest != record.Digest {
		return errors.New("reference: retained R3 resource token differs from its context")
	}
	return nil
}

func encodeR3ResourceTokenState(records map[string]R3ResourceTokenRecord) ([]byte, error) {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	state := r3ResourceTokenState{Schema: r3ResourceTokenStateSchema}
	for _, key := range keys {
		state.Records = append(state.Records, records[key])
	}
	stateBody, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(stateBody)
	return json.Marshal(r3ResourceTokenEnvelope{
		Schema: r3ResourceTokenEnvelopeSchema, StateSHA256: hex.EncodeToString(digest[:]), State: stateBody,
	})
}

func decodeR3ResourceTokenState(body []byte) (map[string]R3ResourceTokenRecord, error) {
	records := make(map[string]R3ResourceTokenRecord)
	if len(body) == 0 {
		return records, nil
	}
	var envelope r3ResourceTokenEnvelope
	if err := decodeJSONBytesWithLimit(bytes.NewReader(body), &envelope, maxGovernanceStateBytes); err != nil || envelope.Schema != r3ResourceTokenEnvelopeSchema {
		return nil, errors.New("reference: R3 resource-token envelope is invalid")
	}
	digest := sha256.Sum256(envelope.State)
	if hex.EncodeToString(digest[:]) != envelope.StateSHA256 {
		return nil, errors.New("reference: R3 resource-token state checksum does not match")
	}
	var state r3ResourceTokenState
	if err := decodeJSONBytesWithLimit(bytes.NewReader(envelope.State), &state, maxGovernanceStateBytes); err != nil || state.Schema != r3ResourceTokenStateSchema {
		return nil, errors.New("reference: R3 resource-token state is invalid")
	}
	previous := ""
	for _, record := range state.Records {
		if record.ContextKey <= previous || validateR3ResourceTokenRecord(record) != nil {
			return nil, errors.New("reference: R3 resource-token state contains an invalid record")
		}
		previous = record.ContextKey
		records[record.ContextKey] = record
	}
	return records, nil
}

var _ R3ResourceTokenStore = (*FileR3ResourceTokenStore)(nil)

// Keep the record's absolute lifetime explicit at the API boundary.
func (record R3ResourceTokenRecord) Active(at time.Time) bool {
	return record.IssuedAt <= at.Unix() && at.Unix() < record.ExpiresAt
}
