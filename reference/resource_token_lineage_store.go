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
)

const (
	resourceTokenLineageEnvelopeSchema = "aauth.reference.resource-token-lineage-envelope.v0"
	resourceTokenLineageStateSchema    = "aauth.reference.resource-token-lineage-state.v0"
)

var (
	ErrResourceTokenLineageNotFound = errors.New("reference: resource token lineage was not found")
	ErrResourceTokenLineageConflict = errors.New("reference: resource token lineage conflicts with retained custody")
)

// ResourceTokenLineageRecord retains the exact resource token and the person-token
// JTI that established its subject. LineageKey contains only context visible in
// the later auth token. ContextKey additionally carries PresentedJTI and the
// resource-token scope so distinct bindings can never silently converge.
type ResourceTokenLineageRecord struct {
	LineageKey           string `json:"lineage_key"`
	ContextKey           string `json:"context_key"`
	ResourceToken        string `json:"resource_token"`
	Resource             string `json:"resource"`
	AccessServer         string `json:"access_server"`
	PersonServer         string `json:"person_server"`
	Subject              string `json:"subject"`
	PresentedJTI         string `json:"presented_jti"`
	AgentJKT             string `json:"agent_jkt"`
	Scope                string `json:"scope"`
	AuthorizationVariant string `json:"authorization_variant,omitempty"`
	MissionS256          string `json:"mission_s256,omitempty"`
	Tenant               string `json:"tenant,omitempty"`
	Account              string `json:"account,omitempty"`
	URI                  string `json:"r3_uri"`
	Digest               string `json:"r3_s256"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
}

// ResourceTokenLineageStore is the resource deployment's exact authorization-
// lineage boundary. Exact replay is idempotent; a changed token under the same
// context conflicts.
type ResourceTokenLineageStore interface {
	Commit(context.Context, ResourceTokenLineageRecord) error
	Load(context.Context, string) (ResourceTokenLineageRecord, error)
	Resolve(context.Context, string, int64) (ResourceTokenLineageRecord, error)
}

// NewResourceTokenLineageRecord binds one exact compact token to its Core
// claims and recognized authorization-member variant.
func NewResourceTokenLineageRecord(
	compact string,
	claims aauth.ResourceTokenClaims,
) (ResourceTokenLineageRecord, error) {
	parsed, err := jose.ParseCompact(compact)
	if err != nil || parsed.Header().Type != aauth.ResourceTokenType {
		return ResourceTokenLineageRecord{}, errors.New("reference: compact resource token is invalid")
	}
	var retained aauth.ResourceTokenClaims
	var members map[string]json.RawMessage
	if json.Unmarshal(parsed.Payload(), &retained) != nil || json.Unmarshal(parsed.Payload(), &members) != nil ||
		!reflect.DeepEqual(retained, claims) {
		return ResourceTokenLineageRecord{}, errors.New("reference: resource token lineage does not match its retained claims")
	}
	var uri, digest string
	if members["r3_uri"] != nil {
		if json.Unmarshal(members["r3_uri"], &uri) != nil || json.Unmarshal(members["r3_s256"], &digest) != nil || uri == "" || digest == "" {
			return ResourceTokenLineageRecord{}, errors.New("reference: resource-token lineage has invalid R3 identity")
		}
	}
	record := ResourceTokenLineageRecord{
		ResourceToken: compact, Resource: claims.Issuer, AccessServer: claims.Audience,
		PersonServer: claims.PersonServer, Subject: claims.Subject, PresentedJTI: claims.PresentedJTI,
		AgentJKT: claims.AgentJKT, Scope: claims.Scope, MissionS256: claims.MissionS256,
		Tenant: claims.Tenant, Account: claims.Account, URI: uri, Digest: digest,
		IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt,
	}
	record.AuthorizationVariant, err = resourceAuthorizationVariant(members)
	if err != nil {
		return ResourceTokenLineageRecord{}, err
	}
	record.LineageKey, err = resourceAuthorizationLineageKey(record)
	if err == nil {
		record.ContextKey, err = resourceAuthorizationContextKey(record.LineageKey, record.PresentedJTI, record.Scope, record.AuthorizationVariant, record.IssuedAt)
	}
	if err != nil {
		return ResourceTokenLineageRecord{}, err
	}
	if err := validateResourceTokenLineageRecord(record); err != nil {
		return ResourceTokenLineageRecord{}, err
	}
	return record, nil
}

// ResourceAuthorizationLineageKey derives the lookup key available from an
// auth token at a resource. It deliberately accepts no presented_jti; the
// store resolves the exact earlier resource-token generation at the auth
// token's trusted issuance instant.
func ResourceAuthorizationLineageKey(
	resource, accessServer, personServer, subject, agentJKT,
	missionS256, tenant, account, uri, digest string,
) (string, error) {
	record := ResourceTokenLineageRecord{
		Resource: resource, AccessServer: accessServer, PersonServer: personServer,
		Subject: subject, AgentJKT: agentJKT, MissionS256: missionS256,
		Tenant: tenant, Account: account, URI: uri, Digest: digest,
	}
	return resourceAuthorizationLineageKey(record)
}

func resourceAuthorizationLineageKey(record ResourceTokenLineageRecord) (string, error) {
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
		Domain:   "gitlab.com/sidecat-dev/aauth-go/resource-token-lineage/v1",
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

func resourceAuthorizationContextKey(lineageKey, presentedJTI, scope, authorizationVariant string, issuedAt int64) (string, error) {
	lineage, err := base64.RawURLEncoding.DecodeString(lineageKey)
	if err != nil || len(lineage) != sha256.Size || presentedJTI == "" || scope == "" || issuedAt <= 0 {
		return "", errors.New("reference: resource-token lineage identity is invalid")
	}
	material, err := json.Marshal(struct {
		Domain               string `json:"domain"`
		LineageKey           string `json:"lineage_key"`
		PresentedJTI         string `json:"presented_jti"`
		Scope                string `json:"scope"`
		AuthorizationVariant string `json:"authorization_variant,omitempty"`
		IssuedAt             int64  `json:"issued_at"`
	}{"gitlab.com/sidecat-dev/aauth-go/resource-token-generation/v1", lineageKey, presentedJTI, scope, authorizationVariant, issuedAt})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(material)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

// FileResourceTokenLineageStore is a private, single-writer reference adapter.
type FileResourceTokenLineageStore struct {
	file    *FileGovernanceStore
	mu      sync.Mutex
	records map[string]ResourceTokenLineageRecord
}

type resourceTokenLineageEnvelope struct {
	Schema      string          `json:"schema"`
	StateSHA256 string          `json:"state_sha256"`
	State       json.RawMessage `json:"state"`
}

type resourceTokenLineageState struct {
	Schema  string                       `json:"schema"`
	Records []ResourceTokenLineageRecord `json:"records"`
}

func NewFileResourceTokenLineageStore(path string) (*FileResourceTokenLineageStore, error) {
	file, err := NewFileGovernanceStore(path)
	if err != nil {
		return nil, err
	}
	body, err := file.Load()
	if err != nil {
		return nil, fmt.Errorf("reference: load resource-token lineage state: %w", err)
	}
	records, err := decodeResourceTokenLineageState(body)
	if err != nil {
		return nil, err
	}
	return &FileResourceTokenLineageStore{file: file, records: records}, nil
}

func (store *FileResourceTokenLineageStore) Commit(_ context.Context, record ResourceTokenLineageRecord) error {
	if store == nil || store.file == nil {
		return errors.New("reference: resource-token lineage file store is not initialized")
	}
	if err := validateResourceTokenLineageRecord(record); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.records[record.ContextKey]; found {
		if reflect.DeepEqual(existing, record) {
			return nil
		}
		return ErrResourceTokenLineageConflict
	}
	next := make(map[string]ResourceTokenLineageRecord, len(store.records)+1)
	for key, existing := range store.records {
		next[key] = existing
	}
	next[record.ContextKey] = record
	body, err := encodeResourceTokenLineageState(next)
	if err != nil {
		return err
	}
	if err := store.file.Save(body); err != nil {
		if errors.Is(err, ErrGovernanceStateUncertain) {
			store.records = next
		}
		return fmt.Errorf("reference: save resource-token lineage state: %w", err)
	}
	store.records = next
	return nil
}

func (store *FileResourceTokenLineageStore) Load(_ context.Context, contextKey string) (ResourceTokenLineageRecord, error) {
	if store == nil || store.file == nil {
		return ResourceTokenLineageRecord{}, errors.New("reference: resource-token lineage file store is not initialized")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.records[contextKey]
	if !found {
		return ResourceTokenLineageRecord{}, ErrResourceTokenLineageNotFound
	}
	return record, nil
}

func (store *FileResourceTokenLineageStore) Resolve(_ context.Context, lineageKey string, authIssuedAt int64) (ResourceTokenLineageRecord, error) {
	if store == nil || store.file == nil {
		return ResourceTokenLineageRecord{}, errors.New("reference: resource-token lineage file store is not initialized")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var selected ResourceTokenLineageRecord
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
			return ResourceTokenLineageRecord{}, ErrResourceTokenLineageConflict
		}
	}
	if !found {
		return ResourceTokenLineageRecord{}, ErrResourceTokenLineageNotFound
	}
	return selected, nil
}

func validateResourceTokenLineageRecord(record ResourceTokenLineageRecord) error {
	lineageKey, err := resourceAuthorizationLineageKey(record)
	contextKey, contextErr := resourceAuthorizationContextKey(lineageKey, record.PresentedJTI, record.Scope, record.AuthorizationVariant, record.IssuedAt)
	if err != nil || contextErr != nil || lineageKey != record.LineageKey || contextKey != record.ContextKey {
		return errors.New("reference: resource-token lineage context key is invalid")
	}
	if record.ResourceToken == "" || record.PresentedJTI == "" || record.IssuedAt <= 0 || record.ExpiresAt <= record.IssuedAt {
		return errors.New("reference: resource-token lineage record is incomplete")
	}
	for _, identifier := range []string{record.Resource, record.AccessServer, record.PersonServer} {
		if aauth.ValidateServerIdentifier(identifier) != nil {
			return errors.New("reference: resource-token lineage record has an invalid server identifier")
		}
	}
	thumbprint, thumbprintErr := base64.RawURLEncoding.DecodeString(record.AgentJKT)
	var digest []byte
	var digestErr error
	if record.Digest != "" {
		digest, digestErr = base64.RawURLEncoding.DecodeString(record.Digest)
	}
	if record.Subject == "" || len(thumbprint) != sha256.Size || thumbprintErr != nil ||
		(record.URI == "") != (record.Digest == "") ||
		(record.Digest != "" && (len(digest) != sha256.Size || digestErr != nil)) {
		return errors.New("reference: resource-token lineage record has invalid authorization context")
	}
	parsed, err := jose.ParseCompact(record.ResourceToken)
	if err != nil || parsed.Header().Type != aauth.ResourceTokenType {
		return errors.New("reference: retained resource token lineage is invalid")
	}
	var claims aauth.ResourceTokenClaims
	var members map[string]json.RawMessage
	if json.Unmarshal(parsed.Payload(), &claims) != nil || json.Unmarshal(parsed.Payload(), &members) != nil {
		return errors.New("reference: retained resource-token lineage claims are invalid")
	}
	var uri, retainedDigest string
	_ = json.Unmarshal(members["r3_uri"], &uri)
	_ = json.Unmarshal(members["r3_s256"], &retainedDigest)
	variant, variantErr := resourceAuthorizationVariant(members)
	if variantErr != nil || variant != record.AuthorizationVariant ||
		claims.Issuer != record.Resource || claims.Audience != record.AccessServer ||
		claims.PersonServer != record.PersonServer || claims.Subject != record.Subject ||
		claims.PresentedJTI != record.PresentedJTI || claims.AgentJKT != record.AgentJKT ||
		claims.Scope != record.Scope || claims.MissionS256 != record.MissionS256 ||
		claims.Tenant != record.Tenant || claims.Account != record.Account ||
		claims.IssuedAt != record.IssuedAt || claims.ExpiresAt != record.ExpiresAt ||
		uri != record.URI || retainedDigest != record.Digest {
		return errors.New("reference: retained resource token lineage differs from its context")
	}
	return nil
}

func resourceAuthorizationVariant(members map[string]json.RawMessage) (string, error) {
	variantMembers := make(map[string]json.RawMessage)
	for _, name := range []string{"budget", "budget_consumed"} {
		if raw, present := members[name]; present {
			variantMembers[name] = append(json.RawMessage(nil), raw...)
		}
	}
	if len(variantMembers) == 0 {
		return "", nil
	}
	variantJSON, err := json.Marshal(variantMembers)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(variantJSON)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func encodeResourceTokenLineageState(records map[string]ResourceTokenLineageRecord) ([]byte, error) {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	state := resourceTokenLineageState{Schema: resourceTokenLineageStateSchema}
	for _, key := range keys {
		state.Records = append(state.Records, records[key])
	}
	stateBody, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(stateBody)
	return json.Marshal(resourceTokenLineageEnvelope{
		Schema: resourceTokenLineageEnvelopeSchema, StateSHA256: hex.EncodeToString(digest[:]), State: stateBody,
	})
}

func decodeResourceTokenLineageState(body []byte) (map[string]ResourceTokenLineageRecord, error) {
	records := make(map[string]ResourceTokenLineageRecord)
	if len(body) == 0 {
		return records, nil
	}
	var envelope resourceTokenLineageEnvelope
	if err := decodeJSONBytesWithLimit(bytes.NewReader(body), &envelope, maxGovernanceStateBytes); err != nil || envelope.Schema != resourceTokenLineageEnvelopeSchema {
		return nil, errors.New("reference: resource-token lineage envelope is invalid")
	}
	digest := sha256.Sum256(envelope.State)
	if hex.EncodeToString(digest[:]) != envelope.StateSHA256 {
		return nil, errors.New("reference: resource-token lineage state checksum does not match")
	}
	var state resourceTokenLineageState
	if err := decodeJSONBytesWithLimit(bytes.NewReader(envelope.State), &state, maxGovernanceStateBytes); err != nil || state.Schema != resourceTokenLineageStateSchema {
		return nil, errors.New("reference: resource-token lineage state is invalid")
	}
	previous := ""
	for _, record := range state.Records {
		if record.ContextKey <= previous || validateResourceTokenLineageRecord(record) != nil {
			return nil, errors.New("reference: resource-token lineage state contains an invalid record")
		}
		previous = record.ContextKey
		records[record.ContextKey] = record
	}
	return records, nil
}

var _ ResourceTokenLineageStore = (*FileResourceTokenLineageStore)(nil)

// Keep the record's absolute lifetime explicit at the API boundary.
func (record ResourceTokenLineageRecord) Active(at time.Time) bool {
	return record.IssuedAt <= at.Unix() && at.Unix() < record.ExpiresAt
}
