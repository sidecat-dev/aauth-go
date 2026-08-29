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
	"sort"
	"sync"
	"time"

	aa "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

var (
	ErrTokenRevocationNotFound  = errors.New("reference: token revocation target was not observed")
	ErrTokenRevocationReplay    = errors.New("reference: token revocation proof was replayed")
	ErrTokenRevocationConflict  = errors.New("reference: token revocation target conflicts with the existing observation")
	ErrTokenRevocationStore     = errors.New("reference: token revocation store is not initialized")
	ErrTokenRevocationIntegrity = errors.New("reference: token revocation state integrity check failed")
)

const (
	tokenRevocationEnvelopeSchema = "aauth.reference.token-revocation-envelope.v0"
	tokenRevocationStateSchema    = "aauth.reference.token-revocation-state.v0"
	maxTokenRevocationStateBytes  = 16 << 20
)

// TokenRevocationObservation records that a server has seen one token
// identity and its expiry. The issuer/JTI pair is the only lookup key.
type TokenRevocationObservation struct {
	Request   aa.TokenRevocationRequest
	ExpiresAt time.Time
}

type tokenRevocationRecord struct {
	Request   aa.TokenRevocationRequest `json:"request"`
	ExpiresAt time.Time                 `json:"expires_at"`
	RevokedAt *time.Time                `json:"revoked_at,omitempty"`
}

type tokenRevocationReplay struct {
	Key       string    `json:"key"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TokenRevocationStore retains observed token identities and their revocation
// state. Revoke is idempotent for a known target and a new proof, while the
// same proof is rejected as a replay. Implementations must retain both pieces
// atomically before reporting success.
type TokenRevocationStore interface {
	Observe(context.Context, TokenRevocationObservation) error
	Revoke(context.Context, aa.TokenRevocationRequest, string, time.Time, time.Time) error
	IsRevoked(context.Context, aa.TokenRevocationRequest) (bool, error)
}

// MemoryTokenRevocationStore is a process-local adapter for tests and
// deployments that do not claim restart recovery.
type MemoryTokenRevocationStore struct {
	mu      sync.Mutex
	records map[string]tokenRevocationRecord
	replays map[string]time.Time
}

func NewMemoryTokenRevocationStore() *MemoryTokenRevocationStore {
	return &MemoryTokenRevocationStore{
		records: make(map[string]tokenRevocationRecord),
		replays: make(map[string]time.Time),
	}
}

func (store *MemoryTokenRevocationStore) Observe(
	ctx context.Context,
	observation TokenRevocationObservation,
) error {
	if err := validateTokenRevocationContext(ctx); err != nil {
		return err
	}
	if err := validateTokenRevocationObservation(observation); err != nil {
		return err
	}
	if store == nil {
		return ErrTokenRevocationStore
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.records == nil {
		store.records = make(map[string]tokenRevocationRecord)
	}
	key := tokenRevocationKey(observation.Request)
	if existing, ok := store.records[key]; ok {
		if !existing.ExpiresAt.Equal(observation.ExpiresAt.UTC()) {
			return ErrTokenRevocationConflict
		}
		return nil
	}
	store.records[key] = tokenRevocationRecord{
		Request:   observation.Request,
		ExpiresAt: observation.ExpiresAt.UTC(),
	}
	return nil
}

func (store *MemoryTokenRevocationStore) Revoke(
	ctx context.Context,
	request aa.TokenRevocationRequest,
	replayKey string,
	replayExpiresAt time.Time,
	now time.Time,
) error {
	if err := validateTokenRevocationContext(ctx); err != nil {
		return err
	}
	if err := validateTokenRevocationRequest(request); err != nil {
		return err
	}
	if err := validateTokenRevocationReplay(replayKey, replayExpiresAt, now); err != nil {
		return err
	}
	if store == nil {
		return ErrTokenRevocationStore
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return revokeTokenRevocationMaps(store.records, store.replays, request, replayKey, replayExpiresAt, now)
}

func (store *MemoryTokenRevocationStore) IsRevoked(
	ctx context.Context,
	request aa.TokenRevocationRequest,
) (bool, error) {
	if err := validateTokenRevocationContext(ctx); err != nil {
		return false, err
	}
	if err := validateTokenRevocationRequest(request); err != nil {
		return false, err
	}
	if store == nil {
		return false, ErrTokenRevocationStore
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[tokenRevocationKey(request)]
	return ok && record.RevokedAt != nil, nil
}

// FileTokenRevocationStore is a restart-safe single-writer adapter. Its
// snapshot is checksum-bound and stores observations, revocations, and live
// request-proof replay keys together.
type FileTokenRevocationStore struct {
	file    *FileGovernanceStore
	mu      sync.Mutex
	records map[string]tokenRevocationRecord
	replays map[string]time.Time
}

type tokenRevocationEnvelope struct {
	Schema      string          `json:"schema"`
	StateSHA256 string          `json:"state_sha256"`
	State       json.RawMessage `json:"state"`
}

type tokenRevocationState struct {
	Schema  string                  `json:"schema"`
	Records []tokenRevocationRecord `json:"records"`
	Replays []tokenRevocationReplay `json:"replays"`
}

// OpenFileTokenRevocationStore opens one checksum-verified revocation
// snapshot, or an empty store when the path has not been written yet.
func OpenFileTokenRevocationStore(path string) (*FileTokenRevocationStore, error) {
	file, err := NewFileGovernanceStore(path)
	if err != nil {
		return nil, err
	}
	body, err := file.Load()
	if err != nil {
		return nil, fmt.Errorf("reference: load token revocation state: %w", err)
	}
	records, replays, err := decodeTokenRevocationState(body)
	if err != nil {
		return nil, err
	}
	return &FileTokenRevocationStore{file: file, records: records, replays: replays}, nil
}

func (store *FileTokenRevocationStore) Observe(
	ctx context.Context,
	observation TokenRevocationObservation,
) error {
	if err := validateTokenRevocationContext(ctx); err != nil {
		return err
	}
	if err := validateTokenRevocationObservation(observation); err != nil {
		return err
	}
	if store == nil || store.file == nil {
		return ErrTokenRevocationStore
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := tokenRevocationKey(observation.Request)
	if existing, ok := store.records[key]; ok {
		if !existing.ExpiresAt.Equal(observation.ExpiresAt.UTC()) {
			return ErrTokenRevocationConflict
		}
		return nil
	}
	nextRecords := cloneTokenRevocationRecords(store.records)
	nextRecords[key] = tokenRevocationRecord{Request: observation.Request, ExpiresAt: observation.ExpiresAt.UTC()}
	if err := store.persistLocked(nextRecords, store.replays); err != nil {
		if errors.Is(err, ErrGovernanceStateUncertain) {
			store.records = nextRecords
		}
		return err
	}
	store.records = nextRecords
	return nil
}

func (store *FileTokenRevocationStore) Revoke(
	ctx context.Context,
	request aa.TokenRevocationRequest,
	replayKey string,
	replayExpiresAt time.Time,
	now time.Time,
) error {
	if err := validateTokenRevocationContext(ctx); err != nil {
		return err
	}
	if err := validateTokenRevocationRequest(request); err != nil {
		return err
	}
	if err := validateTokenRevocationReplay(replayKey, replayExpiresAt, now); err != nil {
		return err
	}
	if store == nil || store.file == nil {
		return ErrTokenRevocationStore
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	nextRecords := cloneTokenRevocationRecords(store.records)
	nextReplays := cloneTokenRevocationReplays(store.replays)
	if err := revokeTokenRevocationMaps(nextRecords, nextReplays, request, replayKey, replayExpiresAt, now); err != nil {
		return err
	}
	if err := store.persistLocked(nextRecords, nextReplays); err != nil {
		if errors.Is(err, ErrGovernanceStateUncertain) {
			store.records = nextRecords
			store.replays = nextReplays
		}
		return err
	}
	store.records = nextRecords
	store.replays = nextReplays
	return nil
}

func (store *FileTokenRevocationStore) IsRevoked(
	ctx context.Context,
	request aa.TokenRevocationRequest,
) (bool, error) {
	if err := validateTokenRevocationContext(ctx); err != nil {
		return false, err
	}
	if err := validateTokenRevocationRequest(request); err != nil {
		return false, err
	}
	if store == nil || store.file == nil {
		return false, ErrTokenRevocationStore
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[tokenRevocationKey(request)]
	return ok && record.RevokedAt != nil, nil
}

func (store *FileTokenRevocationStore) persistLocked(
	records map[string]tokenRevocationRecord,
	replays map[string]time.Time,
) error {
	body, err := encodeTokenRevocationState(records, replays)
	if err != nil {
		return err
	}
	if err := store.file.Save(body); err != nil {
		return fmt.Errorf("reference: save token revocation state: %w", err)
	}
	return nil
}

func validateTokenRevocationContext(ctx context.Context) error {
	if ctx == nil {
		return ErrTokenRevocationStore
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func validateTokenRevocationRequest(request aa.TokenRevocationRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	return nil
}

func validateTokenRevocationObservation(observation TokenRevocationObservation) error {
	if err := validateTokenRevocationRequest(observation.Request); err != nil {
		return err
	}
	if observation.ExpiresAt.IsZero() {
		return errors.New("reference: token revocation observation expiry is required")
	}
	return nil
}

func validateTokenRevocationReplay(replayKey string, replayExpiresAt, now time.Time) error {
	if !validReplayKey(replayKey) || replayExpiresAt.IsZero() || now.IsZero() || !replayExpiresAt.After(now) {
		return errors.New("reference: token revocation replay proof is invalid")
	}
	return nil
}

func revokeTokenRevocationMaps(
	records map[string]tokenRevocationRecord,
	replays map[string]time.Time,
	request aa.TokenRevocationRequest,
	replayKey string,
	replayExpiresAt time.Time,
	now time.Time,
) error {
	if records == nil || replays == nil {
		return ErrTokenRevocationStore
	}
	for key, expiry := range replays {
		if !expiry.After(now) {
			delete(replays, key)
		}
	}
	if _, exists := replays[replayKey]; exists {
		return ErrTokenRevocationReplay
	}
	key := tokenRevocationKey(request)
	record, exists := records[key]
	if !exists {
		return ErrTokenRevocationNotFound
	}
	if record.RevokedAt == nil {
		revokedAt := now.UTC()
		record.RevokedAt = &revokedAt
		records[key] = record
	}
	replays[replayKey] = replayExpiresAt.UTC()
	return nil
}

func tokenRevocationKey(request aa.TokenRevocationRequest) string {
	return request.Issuer + "\x00" + request.JTI
}

func cloneTokenRevocationRecords(records map[string]tokenRevocationRecord) map[string]tokenRevocationRecord {
	cloned := make(map[string]tokenRevocationRecord, len(records))
	for key, record := range records {
		clonedRecord := record
		if record.RevokedAt != nil {
			revokedAt := record.RevokedAt.UTC()
			clonedRecord.RevokedAt = &revokedAt
		}
		cloned[key] = clonedRecord
	}
	return cloned
}

func cloneTokenRevocationReplays(replays map[string]time.Time) map[string]time.Time {
	cloned := make(map[string]time.Time, len(replays))
	for key, expiry := range replays {
		cloned[key] = expiry.UTC()
	}
	return cloned
}

func encodeTokenRevocationState(
	records map[string]tokenRevocationRecord,
	replays map[string]time.Time,
) ([]byte, error) {
	recordKeys := make([]string, 0, len(records))
	for key := range records {
		recordKeys = append(recordKeys, key)
	}
	sort.Strings(recordKeys)
	replayKeys := make([]string, 0, len(replays))
	for key := range replays {
		replayKeys = append(replayKeys, key)
	}
	sort.Strings(replayKeys)
	state := tokenRevocationState{Schema: tokenRevocationStateSchema}
	for _, key := range recordKeys {
		state.Records = append(state.Records, records[key])
	}
	for _, key := range replayKeys {
		state.Replays = append(state.Replays, tokenRevocationReplay{Key: key, ExpiresAt: replays[key].UTC()})
	}
	stateBody, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("reference: encode token revocation state: %w", err)
	}
	digest := sha256.Sum256(stateBody)
	body, err := json.Marshal(tokenRevocationEnvelope{
		Schema:      tokenRevocationEnvelopeSchema,
		StateSHA256: hex.EncodeToString(digest[:]),
		State:       stateBody,
	})
	if err != nil {
		return nil, fmt.Errorf("reference: encode token revocation envelope: %w", err)
	}
	return body, nil
}

func decodeTokenRevocationState(body []byte) (map[string]tokenRevocationRecord, map[string]time.Time, error) {
	records := make(map[string]tokenRevocationRecord)
	replays := make(map[string]time.Time)
	if len(body) == 0 {
		return records, replays, nil
	}
	if len(body) > maxTokenRevocationStateBytes {
		return nil, nil, ErrTokenRevocationIntegrity
	}
	var envelope tokenRevocationEnvelope
	if err := decodeJSONBytesWithLimit(bytes.NewReader(body), &envelope, maxTokenRevocationStateBytes); err != nil {
		return nil, nil, errors.Join(ErrTokenRevocationIntegrity, err)
	}
	if envelope.Schema != tokenRevocationEnvelopeSchema {
		return nil, nil, ErrTokenRevocationIntegrity
	}
	digest := sha256.Sum256(envelope.State)
	if hex.EncodeToString(digest[:]) != envelope.StateSHA256 {
		return nil, nil, ErrTokenRevocationIntegrity
	}
	var state tokenRevocationState
	if err := decodeJSONBytesWithLimit(bytes.NewReader(envelope.State), &state, maxTokenRevocationStateBytes); err != nil {
		return nil, nil, errors.Join(ErrTokenRevocationIntegrity, err)
	}
	if state.Schema != tokenRevocationStateSchema {
		return nil, nil, ErrTokenRevocationIntegrity
	}
	for _, record := range state.Records {
		if err := validateTokenRevocationObservation(TokenRevocationObservation{Request: record.Request, ExpiresAt: record.ExpiresAt}); err != nil {
			return nil, nil, errors.Join(ErrTokenRevocationIntegrity, err)
		}
		if record.RevokedAt != nil && record.RevokedAt.IsZero() {
			return nil, nil, ErrTokenRevocationIntegrity
		}
		key := tokenRevocationKey(record.Request)
		if _, duplicate := records[key]; duplicate {
			return nil, nil, ErrTokenRevocationIntegrity
		}
		records[key] = record
	}
	previous := ""
	for _, replay := range state.Replays {
		if !validReplayKey(replay.Key) || replay.ExpiresAt.IsZero() || replay.Key <= previous {
			return nil, nil, ErrTokenRevocationIntegrity
		}
		previous = replay.Key
		replays[replay.Key] = replay.ExpiresAt.UTC()
	}
	canonical, err := encodeTokenRevocationState(records, replays)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, nil, ErrTokenRevocationIntegrity
	}
	return records, replays, nil
}

var _ TokenRevocationStore = (*MemoryTokenRevocationStore)(nil)
var _ TokenRevocationStore = (*FileTokenRevocationStore)(nil)

func (server *PersonServer) checkAgentToken(
	response http.ResponseWriter,
	ctx context.Context,
	verified aa.VerifiedRequest,
) bool {
	if server.tokenRevocationStore == nil {
		return true
	}
	claims, err := verified.AgentClaims()
	if err != nil {
		writeSignatureFailure(response, err)
		return false
	}
	request := aa.TokenRevocationRequest{Issuer: claims.Issuer, JTI: claims.JTI}
	revoked, err := server.tokenRevocationStore.IsRevoked(ctx, request)
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "token_revocation_unavailable", err)
		return false
	}
	if revoked {
		writeProblem(response, http.StatusForbidden, "token_revoked", errors.New("agent token has been revoked"))
		return false
	}
	if err := server.tokenRevocationStore.Observe(ctx, TokenRevocationObservation{
		Request: request, ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	}); err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "token_revocation_unavailable", err)
		return false
	}
	return true
}

func (server *PersonServer) handleTokenRevocation(
	response http.ResponseWriter,
	request *http.Request,
) {
	if request.URL.RawQuery != "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("revocation endpoint does not accept query parameters"))
		return
	}
	body, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	verified, err := aa.VerifyRequest(
		request.Context(),
		request,
		server.keyResolver,
		server.clock,
		aa.VerifyRequestOptions{
			RequiredComponents:       []string{"content-digest"},
			AllowedCredentialTypes:   []string{aa.AgentTokenType},
			AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeJWT, signaturekey.SchemeJWKSURI},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	var input aa.TokenRevocationRequest
	if err := decodeJSONBytes(bytes.NewReader(body), &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := input.Validate(); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	callerIssuer := verified.Signer
	callerAgent := ""
	callerJTI := ""
	if verified.AgentToken != nil {
		if !server.checkAgentToken(response, request.Context(), verified) {
			return
		}
		claims, claimsErr := verified.AgentClaims()
		if claimsErr != nil {
			writeSignatureFailure(response, claimsErr)
			return
		}
		callerIssuer = claims.Issuer
		callerAgent = claims.Subject
		callerJTI = claims.JTI
	}
	if server.tokenRevocationPolicy != nil {
		err = server.tokenRevocationPolicy(request.Context(), aa.TokenRevocationEvaluation{
			Request: input, CallerIssuer: callerIssuer, CallerAgent: callerAgent, CallerJTI: callerJTI,
		})
	} else if callerIssuer != input.Issuer {
		err = errors.New("caller is not the token issuer")
	}
	if err != nil {
		writeProblem(response, http.StatusForbidden, "revocation_denied", errors.New("revocation policy denied the request"))
		return
	}
	if err := server.tokenRevocationStore.Revoke(
		request.Context(), input, verified.ReplayKey,
		verified.Created.Add(signaturekey.DefaultSignatureWindow), verified.VerifiedAt,
	); err != nil {
		switch {
		case errors.Is(err, ErrTokenRevocationNotFound):
			writeProblem(response, http.StatusNotFound, "token_not_found", errors.New("token revocation target was not observed"))
		case errors.Is(err, ErrTokenRevocationReplay):
			writeProblem(response, http.StatusBadRequest, "request_replayed", errors.New("revocation request proof was replayed"))
		default:
			writeProblem(response, http.StatusServiceUnavailable, "token_revocation_unavailable", err)
		}
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
}

func (server *AccessServer) observeIssuedAuthToken(ctx context.Context, compact string) error {
	if server.tokenRevocationStore == nil {
		return nil
	}
	evidence, err := aa.VerifyAuthToken(
		ctx,
		compact,
		signaturekey.StaticKeyResolver{server.identifier: {server.signingKey.ID(): server.signingKey.PublicJWK()}},
		server.clock,
	)
	if err != nil {
		return fmt.Errorf("reference: issued auth-token does not verify for revocation custody: %w", err)
	}
	claims, err := evidence.Claims()
	if err != nil {
		return fmt.Errorf("reference: read issued auth-token claims for revocation custody: %w", err)
	}
	return server.tokenRevocationStore.Observe(ctx, TokenRevocationObservation{
		Request:   aa.TokenRevocationRequest{Issuer: claims.Issuer, JTI: claims.JTI},
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	})
}

func (server *PersonServer) observeIssuedAuthToken(ctx context.Context, compact string) error {
	if server.tokenRevocationStore == nil {
		return nil
	}
	evidence, err := aa.VerifyAuthToken(
		ctx,
		compact,
		signaturekey.StaticKeyResolver{server.identifier: {server.signingKey.ID(): server.signingKey.PublicJWK()}},
		server.clock,
	)
	if err != nil {
		return fmt.Errorf("reference: issued auth-token does not verify for revocation custody: %w", err)
	}
	claims, err := evidence.Claims()
	if err != nil {
		return fmt.Errorf("reference: read issued auth-token claims for revocation custody: %w", err)
	}
	return server.tokenRevocationStore.Observe(ctx, TokenRevocationObservation{
		Request:   aa.TokenRevocationRequest{Issuer: claims.Issuer, JTI: claims.JTI},
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	})
}

func (server *AccessServer) handleTokenRevocation(
	response http.ResponseWriter,
	request *http.Request,
) {
	if request.URL.RawQuery != "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("revocation endpoint does not accept query parameters"))
		return
	}
	body, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	verified, err := aa.VerifyRequest(
		request.Context(),
		request,
		server.keyResolver,
		server.clock,
		aa.VerifyRequestOptions{
			RequiredComponents:       []string{"content-type", "content-digest"},
			AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	var input aa.TokenRevocationRequest
	if err := decodeJSONBytes(bytes.NewReader(body), &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := input.Validate(); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	evaluation := aa.TokenRevocationEvaluation{Request: input, CallerIssuer: verified.Signer}
	if server.tokenRevocationPolicy != nil {
		err = server.tokenRevocationPolicy(request.Context(), evaluation)
	} else if verified.Signer != input.Issuer {
		err = server.trustedPersonServer(request.Context(), verified.Signer)
	}
	if err != nil {
		writeProblem(response, http.StatusForbidden, "revocation_denied", errors.New("revocation policy denied the request"))
		return
	}
	if err := server.tokenRevocationStore.Revoke(
		request.Context(), input, verified.ReplayKey,
		verified.Created.Add(signaturekey.DefaultSignatureWindow), verified.VerifiedAt,
	); err != nil {
		switch {
		case errors.Is(err, ErrTokenRevocationNotFound):
			writeProblem(response, http.StatusNotFound, "token_not_found", errors.New("token revocation target was not observed"))
		case errors.Is(err, ErrTokenRevocationReplay):
			writeProblem(response, http.StatusBadRequest, "request_replayed", errors.New("revocation request proof was replayed"))
		default:
			writeProblem(response, http.StatusServiceUnavailable, "token_revocation_unavailable", err)
		}
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
}

func (resource *Resource) checkAuthToken(
	response http.ResponseWriter,
	ctx context.Context,
	claims aa.AuthTokenClaims,
) bool {
	if resource.tokenRevocationStore == nil {
		return true
	}
	request := aa.TokenRevocationRequest{Issuer: claims.Issuer, JTI: claims.JTI}
	revoked, err := resource.tokenRevocationStore.IsRevoked(ctx, request)
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "token_revocation_unavailable", err)
		return false
	}
	if revoked {
		writeProblem(response, http.StatusForbidden, "token_revoked", errors.New("auth token has been revoked"))
		return false
	}
	if err := resource.tokenRevocationStore.Observe(ctx, TokenRevocationObservation{
		Request: request, ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	}); err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "token_revocation_unavailable", err)
		return false
	}
	return true
}

func (resource *Resource) handleTokenRevocation(
	response http.ResponseWriter,
	request *http.Request,
) {
	if request.URL.RawQuery != "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("revocation endpoint does not accept query parameters"))
		return
	}
	body, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	verified, err := aa.VerifyRequest(
		request.Context(),
		request,
		resource.keyResolver,
		resource.clock,
		aa.VerifyRequestOptions{
			RequiredComponents:       []string{"content-type", "content-digest"},
			AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	var input aa.TokenRevocationRequest
	if err := decodeJSONBytes(bytes.NewReader(body), &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := input.Validate(); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	callerIssuer := verified.Signer
	if resource.tokenRevocationPolicy != nil {
		err = resource.tokenRevocationPolicy(request.Context(), aa.TokenRevocationEvaluation{
			Request: input, CallerIssuer: callerIssuer,
		})
	} else if callerIssuer != input.Issuer {
		err = errors.New("caller is not the token issuer")
	}
	if err != nil {
		writeProblem(response, http.StatusForbidden, "revocation_denied", errors.New("revocation policy denied the request"))
		return
	}
	if err := resource.tokenRevocationStore.Revoke(
		request.Context(), input, verified.ReplayKey,
		verified.Created.Add(signaturekey.DefaultSignatureWindow), verified.VerifiedAt,
	); err != nil {
		switch {
		case errors.Is(err, ErrTokenRevocationNotFound):
			writeProblem(response, http.StatusNotFound, "token_not_found", errors.New("token revocation target was not observed"))
		case errors.Is(err, ErrTokenRevocationReplay):
			writeProblem(response, http.StatusBadRequest, "request_replayed", errors.New("revocation request proof was replayed"))
		default:
			writeProblem(response, http.StatusServiceUnavailable, "token_revocation_unavailable", err)
		}
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
}
