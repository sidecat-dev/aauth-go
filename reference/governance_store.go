package reference

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

const (
	governanceEnvelopeSchema = "aauth.reference.governance-envelope.v0"
	governanceStateSchema    = "aauth.reference.person-governance-state.v0"
	maxGovernanceStateBytes  = 16 << 20
)

// ErrGovernanceStateUncertain means a store published the replacement but
// could not prove its crash durability. Callers must retain the candidate
// in-memory state and reconcile instead of rolling back to a known-stale value.
var ErrGovernanceStateUncertain = errors.New("reference: governance state commit is uncertain")

// GovernanceStore holds an opaque, checksum-verified person-server snapshot.
// Save errors mean the previous snapshot remains authoritative unless the
// error wraps ErrGovernanceStateUncertain.
type GovernanceStore interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// FileGovernanceStore is a single-writer, restart-safe reference adapter. The
// snapshot contains credentials and interaction codes and is therefore stored
// as a private file.
type FileGovernanceStore struct {
	path string
	mu   sync.Mutex
}

func NewFileGovernanceStore(path string) (*FileGovernanceStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("reference: governance state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("reference: create governance state directory: %w", err)
	}
	return &FileGovernanceStore{path: filepath.Clean(path)}, nil
}

func (store *FileGovernanceStore) Load() ([]byte, error) {
	if store == nil || store.path == "" {
		return nil, errors.New("reference: governance file store is not initialized")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	info, err := os.Lstat(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reference: inspect governance state: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("reference: governance state must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("reference: governance state permissions must not allow group or other access")
	}
	if info.Size() > maxGovernanceStateBytes {
		return nil, errors.New("reference: governance state is too large")
	}
	body, err := os.ReadFile(store.path)
	if err != nil {
		return nil, fmt.Errorf("reference: read governance state: %w", err)
	}
	return body, nil
}

func (store *FileGovernanceStore) Save(body []byte) error {
	if store == nil || store.path == "" {
		return errors.New("reference: governance file store is not initialized")
	}
	if len(body) == 0 || len(body) > maxGovernanceStateBytes {
		return errors.New("reference: governance state size is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("reference: create governance state directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".aauth-governance-*")
	if err != nil {
		return fmt.Errorf("reference: create governance state temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("reference: protect governance state temporary file: %w", err)
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("reference: write governance state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("reference: sync governance state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("reference: close governance state: %w", err)
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return fmt.Errorf("reference: publish governance state: %w", err)
	}
	cleanup = false
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf(
			"%w: sync governance state directory: %v",
			ErrGovernanceStateUncertain,
			err,
		)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

type governanceEnvelope struct {
	Schema      string          `json:"schema"`
	StateSHA256 string          `json:"state_sha256"`
	State       json.RawMessage `json:"state"`
}

type governanceState struct {
	Schema             string                        `json:"schema"`
	PersonServer       string                        `json:"person_server"`
	Missions           []governanceMission           `json:"missions"`
	Permissions        []aauth.PermissionRecord      `json:"permissions"`
	Interactions       []aauth.InteractionRecord     `json:"interactions"`
	PendingPermissions []governancePendingPermission `json:"pending_permissions"`
	PendingCompletions []governancePendingCompletion `json:"pending_completions"`
	Replays            []governanceReplay            `json:"replays,omitempty"`
}

type governanceReplay struct {
	Key       string `json:"key"`
	ExpiresAt string `json:"expires_at"`
}

type governanceMission struct {
	Reference         aauth.MissionReference  `json:"reference"`
	Agent             string                  `json:"agent"`
	Bytes             []byte                  `json:"bytes"`
	Description       string                  `json:"description"`
	ApprovedTools     []aauth.Tool            `json:"approved_tools,omitempty"`
	ApprovedResources []string                `json:"approved_resources,omitempty"`
	Capabilities      []string                `json:"capabilities,omitempty"`
	ExpiresAt         string                  `json:"expires_at,omitempty"`
	Status            aauth.MissionStatus     `json:"status"`
	Log               []aauth.MissionLogEntry `json:"log,omitempty"`
}

type governancePendingPermission struct {
	ID                     string                       `json:"id"`
	Code                   string                       `json:"code"`
	CodeConsumed           bool                         `json:"code_consumed"`
	FailedCodeAttempts     int                          `json:"failed_code_attempts"`
	State                  string                       `json:"state"`
	PollingError           aauth.PollingErrorCode       `json:"polling_error,omitempty"`
	ExpiresAt              string                       `json:"expires_at"`
	Agent                  string                       `json:"agent"`
	PollingAgentThumbprint string                       `json:"polling_agent_thumbprint"`
	RequestReplayKey       string                       `json:"request_replay_key"`
	RequestBody            []byte                       `json:"request_body"`
	Decision               governancePermissionDecision `json:"decision"`
}

type governancePermissionDecision struct {
	Permission aauth.Permission `json:"permission,omitempty"`
	Reason     string           `json:"reason,omitempty"`
	DecidedBy  string           `json:"decided_by,omitempty"`
}

type governancePendingCompletion struct {
	ID                     string          `json:"id"`
	Agent                  string          `json:"agent"`
	PollingAgentThumbprint string          `json:"polling_agent_thumbprint"`
	ExpiresAt              string          `json:"expires_at"`
	RequestReplayKey       string          `json:"request_replay_key"`
	RequestBody            []byte          `json:"request_body"`
	State                  completionState `json:"state"`
	Clarification          string          `json:"clarification,omitempty"`
	ClarificationRounds    int             `json:"clarification_rounds"`
	DecidedBy              string          `json:"decided_by,omitempty"`
	DecidedAt              string          `json:"decided_at,omitempty"`
	ResponseBody           []byte          `json:"response_body,omitempty"`
}

func encodeGovernanceState(
	personServer string,
	missions map[string]storedMission,
	permissions []aauth.PermissionRecord,
	interactions []aauth.InteractionRecord,
	pendingPermissions map[string]pendingPersonPermission,
	pendingCompletions map[string]pendingCompletion,
	replays map[string]time.Time,
) ([]byte, error) {
	state := governanceState{
		Schema:       governanceStateSchema,
		PersonServer: personServer,
	}
	missionIDs := make([]string, 0, len(missions))
	for id := range missions {
		missionIDs = append(missionIDs, id)
	}
	sort.Strings(missionIDs)
	for _, id := range missionIDs {
		mission := missions[id]
		state.Missions = append(state.Missions, governanceMission{
			Reference:         mission.reference,
			Agent:             mission.agent,
			Bytes:             append([]byte(nil), mission.bytes...),
			Description:       mission.description,
			ApprovedTools:     append([]aauth.Tool(nil), mission.approvedTools...),
			ApprovedResources: append([]string(nil), mission.approvedResources...),
			Capabilities:      append([]string(nil), mission.capabilities...),
			ExpiresAt:         formatOptionalTime(mission.expiresAt),
			Status:            mission.status,
			Log:               copyMissionLog(mission.log),
		})
	}
	state.Permissions = copyPermissionHistory(permissions)
	state.Interactions = copyInteractionHistory(interactions)
	pendingIDs := make([]string, 0, len(pendingPermissions))
	for id := range pendingPermissions {
		pendingIDs = append(pendingIDs, id)
	}
	sort.Strings(pendingIDs)
	for _, id := range pendingIDs {
		pending := pendingPermissions[id]
		state.PendingPermissions = append(
			state.PendingPermissions,
			governancePendingPermission{
				ID:                     pending.id,
				Code:                   pending.code,
				CodeConsumed:           pending.codeConsumed,
				FailedCodeAttempts:     pending.failedCodeAttempts,
				State:                  string(pending.state),
				PollingError:           pending.pollingError,
				ExpiresAt:              pending.expiresAt.UTC().Format(time.RFC3339Nano),
				Agent:                  pending.agent,
				PollingAgentThumbprint: pending.pollingAgentThumbprint,
				RequestReplayKey:       pending.requestReplayKey,
				RequestBody:            append([]byte(nil), pending.requestBody...),
				Decision: governancePermissionDecision{
					Permission: pending.decision.Permission,
					Reason:     pending.decision.Reason,
					DecidedBy:  pending.decision.DecidedBy,
				},
			},
		)
	}
	completionIDs := make([]string, 0, len(pendingCompletions))
	for id := range pendingCompletions {
		completionIDs = append(completionIDs, id)
	}
	sort.Strings(completionIDs)
	for _, id := range completionIDs {
		pending := pendingCompletions[id]
		decidedAt := ""
		if !pending.decidedAt.IsZero() {
			decidedAt = pending.decidedAt.UTC().Format(time.RFC3339Nano)
		}
		state.PendingCompletions = append(
			state.PendingCompletions,
			governancePendingCompletion{
				ID:                     pending.id,
				Agent:                  pending.agent,
				PollingAgentThumbprint: pending.pollingAgentThumbprint,
				ExpiresAt:              pending.expiresAt.UTC().Format(time.RFC3339Nano),
				RequestReplayKey:       pending.requestReplayKey,
				RequestBody:            append([]byte(nil), pending.requestBody...),
				State:                  pending.state,
				Clarification:          pending.clarification,
				ClarificationRounds:    pending.clarificationRounds,
				DecidedBy:              pending.decidedBy,
				DecidedAt:              decidedAt,
				ResponseBody:           append([]byte(nil), pending.responseBody...),
			},
		)
	}
	replayKeys := make([]string, 0, len(replays))
	for key := range replays {
		replayKeys = append(replayKeys, key)
	}
	sort.Strings(replayKeys)
	for _, key := range replayKeys {
		state.Replays = append(state.Replays, governanceReplay{
			Key:       key,
			ExpiresAt: replays[key].UTC().Format(time.RFC3339Nano),
		})
	}
	stateBody, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("reference: encode governance state: %w", err)
	}
	digest := sha256.Sum256(stateBody)
	envelopeBody, err := json.Marshal(governanceEnvelope{
		Schema:      governanceEnvelopeSchema,
		StateSHA256: hex.EncodeToString(digest[:]),
		State:       stateBody,
	})
	if err != nil {
		return nil, fmt.Errorf("reference: encode governance envelope: %w", err)
	}
	return envelopeBody, nil
}

func decodeGovernanceState(
	body []byte,
	personServer string,
) (
	map[string]storedMission,
	[]aauth.PermissionRecord,
	[]aauth.InteractionRecord,
	map[string]pendingPersonPermission,
	map[string]pendingCompletion,
	map[string]time.Time,
	error,
) {
	missions := make(map[string]storedMission)
	var permissions []aauth.PermissionRecord
	var interactions []aauth.InteractionRecord
	pendingPermissions := make(map[string]pendingPersonPermission)
	pendingCompletions := make(map[string]pendingCompletion)
	replays := make(map[string]time.Time)
	if body == nil {
		return missions, permissions, interactions, pendingPermissions, pendingCompletions, replays, nil
	}
	if len(body) == 0 {
		return nil, nil, nil, nil, nil, nil, errors.New("reference: governance state is empty")
	}
	if len(body) > maxGovernanceStateBytes {
		return nil, nil, nil, nil, nil, nil, errors.New("reference: governance state is too large")
	}
	var envelope governanceEnvelope
	if err := decodeJSONBytesWithLimit(bytes.NewReader(body), &envelope, maxGovernanceStateBytes); err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("reference: decode governance envelope: %w", err)
	}
	if envelope.Schema != governanceEnvelopeSchema {
		return nil, nil, nil, nil, nil, nil, errors.New("reference: governance envelope schema is unsupported")
	}
	expected, err := hex.DecodeString(envelope.StateSHA256)
	if err != nil || len(expected) != sha256.Size {
		return nil, nil, nil, nil, nil, nil, errors.New("reference: governance state digest is invalid")
	}
	actual := sha256.Sum256(envelope.State)
	if !bytes.Equal(expected, actual[:]) {
		return nil, nil, nil, nil, nil, nil, errors.New("reference: governance state digest does not match")
	}
	var state governanceState
	if err := decodeJSONBytesWithLimit(bytes.NewReader(envelope.State), &state, maxGovernanceStateBytes); err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("reference: decode governance state: %w", err)
	}
	if state.Schema != governanceStateSchema || state.PersonServer != personServer {
		return nil, nil, nil, nil, nil, nil, errors.New("reference: governance state does not belong to this person server")
	}
	for index, encoded := range state.Missions {
		mission, err := decodeGovernanceMission(encoded, personServer)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("reference: governance mission %d: %w", index, err)
		}
		if _, duplicate := missions[mission.reference.S256]; duplicate {
			return nil, nil, nil, nil, nil, nil, errors.New("reference: governance state contains duplicate missions")
		}
		missions[mission.reference.S256] = mission
	}
	for index, encoded := range state.Permissions {
		record, err := decodeGovernancePermissionRecord(
			encoded,
			uint64(index+1),
			personServer,
			missions,
		)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("reference: permission record %d: %w", index, err)
		}
		permissions = append(permissions, record)
	}
	for index, encoded := range state.Interactions {
		record, err := decodeGovernanceInteractionRecord(
			encoded,
			uint64(index+1),
			personServer,
			missions,
		)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("reference: interaction record %d: %w", index, err)
		}
		interactions = append(interactions, record)
	}
	for index, encoded := range state.PendingPermissions {
		pending, err := decodeGovernancePendingPermission(
			encoded,
			personServer,
			missions,
			permissions,
		)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("reference: pending permission %d: %w", index, err)
		}
		if _, duplicate := pendingPermissions[pending.id]; duplicate {
			return nil, nil, nil, nil, nil, nil, errors.New("reference: governance state contains duplicate pending permissions")
		}
		pendingPermissions[pending.id] = pending
	}
	for index, encoded := range state.PendingCompletions {
		pending, err := decodeGovernancePendingCompletion(
			encoded,
			personServer,
			missions,
			interactions,
		)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("reference: pending completion %d: %w", index, err)
		}
		if _, duplicate := pendingCompletions[pending.id]; duplicate {
			return nil, nil, nil, nil, nil, nil, errors.New("reference: governance state contains duplicate pending completions")
		}
		pendingCompletions[pending.id] = pending
	}
	for index, encoded := range state.Replays {
		key, err := base64.RawURLEncoding.DecodeString(encoded.Key)
		if err != nil || len(key) != sha256.Size {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("reference: governance replay %d key is invalid", index)
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, encoded.ExpiresAt)
		if err != nil || expiresAt.IsZero() {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("reference: governance replay %d expiry is invalid", index)
		}
		if _, duplicate := replays[encoded.Key]; duplicate {
			return nil, nil, nil, nil, nil, nil, errors.New("reference: governance state contains duplicate replay proofs")
		}
		replays[encoded.Key] = expiresAt
	}
	if err := validateGovernanceRelationships(
		missions,
		permissions,
		interactions,
		pendingPermissions,
		pendingCompletions,
		replays,
	); err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	return missions, permissions, interactions, pendingPermissions, pendingCompletions, replays, nil
}

func decodeGovernanceMission(
	encoded governanceMission,
	personServer string,
) (storedMission, error) {
	var mission storedMission
	if err := encoded.Reference.Validate(); err != nil ||
		encoded.Reference.Approver != personServer ||
		aauth.S256(encoded.Bytes) != encoded.Reference.S256 {
		return mission, errors.New("mission reference does not bind the retained bytes")
	}
	if err := aauth.ValidateAgentIdentifier(encoded.Agent); err != nil {
		return mission, err
	}
	if encoded.Status != aauth.MissionActive && encoded.Status != aauth.MissionTerminated {
		return mission, errors.New("mission status is invalid")
	}
	var blob missionBlob
	if err := decodeJSONBytes(bytes.NewReader(encoded.Bytes), &blob); err != nil {
		return mission, err
	}
	if blob.Approver != encoded.Reference.Approver ||
		blob.Agent != encoded.Agent ||
		blob.Description != encoded.Description ||
		!reflect.DeepEqual(blob.ApprovedTools, encoded.ApprovedTools) ||
		!reflect.DeepEqual(blob.ApprovedResources, encoded.ApprovedResources) ||
		!reflect.DeepEqual(blob.Capabilities, encoded.Capabilities) {
		return mission, errors.New("mission fields do not match exact approved bytes")
	}
	if _, err := time.Parse(time.RFC3339Nano, blob.ApprovedAt); err != nil ||
		strings.TrimSpace(blob.Description) == "" {
		return mission, errors.New("approved mission time or description is invalid")
	}
	var expiresAt *time.Time
	if encoded.ExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, encoded.ExpiresAt)
		if err != nil || blob.ExpiresAt != encoded.ExpiresAt {
			return mission, errors.New("mission expiry is invalid")
		}
		expiresAt = &parsed
	} else if blob.ExpiresAt != "" {
		return mission, errors.New("mission expiry does not match exact approved bytes")
	}
	for index, entry := range encoded.Log {
		if err := validateMissionLogEntry(entry, uint64(index+1), encoded.Reference, encoded.Agent); err != nil {
			return mission, fmt.Errorf("mission log entry %d: %w", index, err)
		}
		if entry.Kind == aauth.MissionLogTermination && index != len(encoded.Log)-1 {
			return mission, errors.New("mission termination must be the final log entry")
		}
	}
	terminatedInLog := len(encoded.Log) > 0 &&
		encoded.Log[len(encoded.Log)-1].Kind == aauth.MissionLogTermination
	if (encoded.Status == aauth.MissionTerminated) != terminatedInLog {
		return mission, errors.New("mission status does not match its termination log")
	}
	return storedMission{
		reference:         encoded.Reference,
		agent:             encoded.Agent,
		bytes:             append([]byte(nil), encoded.Bytes...),
		description:       encoded.Description,
		approvedTools:     append([]aauth.Tool(nil), encoded.ApprovedTools...),
		approvedResources: append([]string(nil), encoded.ApprovedResources...),
		capabilities:      append([]string(nil), encoded.Capabilities...),
		expiresAt:         expiresAt,
		status:            encoded.Status,
		log:               copyMissionLog(encoded.Log),
	}, nil
}

func decodeGovernancePermissionRecord(
	encoded aauth.PermissionRecord,
	sequence uint64,
	personServer string,
	missions map[string]storedMission,
) (aauth.PermissionRecord, error) {
	if encoded.Sequence != sequence ||
		encoded.RecordedAt.IsZero() ||
		encoded.Proof == nil {
		return aauth.PermissionRecord{}, errors.New("permission record ordering or evidence is invalid")
	}
	if err := aauth.ValidateAgentIdentifier(encoded.Agent); err != nil {
		return aauth.PermissionRecord{}, err
	}
	var request aauth.PermissionRequest
	if err := decodeJSONBytes(bytes.NewReader(encoded.Request), &request); err != nil {
		return aauth.PermissionRecord{}, err
	}
	if err := request.Validate(); err != nil {
		return aauth.PermissionRecord{}, err
	}
	if request.Mission != nil {
		if request.Mission.Approver != personServer {
			return aauth.PermissionRecord{}, errors.New("permission record mission has the wrong approver")
		}
		mission, exists := missions[request.Mission.S256]
		if !exists || mission.reference != *request.Mission || mission.agent != encoded.Agent {
			return aauth.PermissionRecord{}, errors.New("permission record mission is absent or has the wrong owner")
		}
	}
	if err := validateStoredRequestProof(
		encoded.Proof,
		encoded.Request,
		encoded.Agent,
		personServer,
		"/permission",
	); err != nil {
		return aauth.PermissionRecord{}, err
	}
	if encoded.PendingID != "" {
		decodedID, err := base64.RawURLEncoding.DecodeString(encoded.PendingID)
		if err != nil || len(decodedID) != 16 {
			return aauth.PermissionRecord{}, errors.New("permission record pending id is invalid")
		}
	}
	if len(encoded.Response) == 0 {
		if encoded.PendingID == "" ||
			!encoded.DecidedAt.IsZero() ||
			encoded.DecidedBy != "" {
			return aauth.PermissionRecord{}, errors.New("unterminated permission record is inconsistent")
		}
	} else {
		if encoded.DecidedAt.IsZero() ||
			encoded.DecidedAt.Before(encoded.RecordedAt) {
			return aauth.PermissionRecord{}, errors.New("permission decision time is invalid")
		}
		if err := validatePermissionDecisionBody(encoded.Response); err != nil {
			return aauth.PermissionRecord{}, err
		}
	}
	return copyPermissionRecord(encoded), nil
}

func decodeGovernancePendingPermission(
	encoded governancePendingPermission,
	personServer string,
	missions map[string]storedMission,
	permissions []aauth.PermissionRecord,
) (pendingPersonPermission, error) {
	var pending pendingPersonPermission
	decodedID, err := base64.RawURLEncoding.DecodeString(encoded.ID)
	if err != nil || len(decodedID) != 16 {
		return pending, errors.New("pending id is invalid")
	}
	normalizedCode, err := aauth.NormalizeInteractionCode(encoded.Code)
	if err != nil {
		return pending, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, encoded.ExpiresAt)
	if err != nil || expiresAt.IsZero() {
		return pending, errors.New("pending expiry is invalid")
	}
	state := pendingAuthorizationState(encoded.State)
	switch state {
	case pendingAuthorizationWaiting,
		pendingAuthorizationInteracting,
		pendingAuthorizationApproved,
		pendingAuthorizationRejected,
		pendingAuthorizationExpired,
		pendingAuthorizationInvalidCode,
		pendingAuthorizationServed:
	default:
		return pending, errors.New("pending state is invalid")
	}
	if err := aauth.ValidateAgentIdentifier(encoded.Agent); err != nil {
		return pending, err
	}
	if encoded.PollingAgentThumbprint == "" ||
		encoded.RequestReplayKey == "" ||
		encoded.FailedCodeAttempts < 0 ||
		encoded.FailedCodeAttempts > maxInteractionCodeAttempts {
		return pending, errors.New("pending ownership or code-attempt state is invalid")
	}
	thumbprint, err := base64.RawURLEncoding.DecodeString(encoded.PollingAgentThumbprint)
	if err != nil || len(thumbprint) != sha256.Size {
		return pending, errors.New("pending agent-key thumbprint is invalid")
	}
	var request aauth.PermissionRequest
	if err := decodeJSONBytes(bytes.NewReader(encoded.RequestBody), &request); err != nil {
		return pending, err
	}
	if err := request.Validate(); err != nil {
		return pending, err
	}
	if request.Mission != nil {
		if request.Mission.Approver != personServer {
			return pending, errors.New("pending permission mission has the wrong approver")
		}
		mission, exists := missions[request.Mission.S256]
		if !exists || mission.reference != *request.Mission || mission.agent != encoded.Agent {
			return pending, errors.New("pending permission mission is absent or has the wrong owner")
		}
	}
	var permissionRecord *aauth.PermissionRecord
	for index := range permissions {
		if permissions[index].Proof != nil &&
			permissions[index].Proof.ReplayKey == encoded.RequestReplayKey {
			permissionRecord = &permissions[index]
			break
		}
	}
	if permissionRecord == nil ||
		permissionRecord.Agent != encoded.Agent ||
		permissionRecord.PendingID != encoded.ID ||
		!bytes.Equal(permissionRecord.Request, encoded.RequestBody) {
		return pending, errors.New("pending permission does not match its request record")
	}
	if state == pendingAuthorizationApproved {
		result := aauth.PermissionResponse{
			Permission: encoded.Decision.Permission,
			Reason:     encoded.Decision.Reason,
		}
		if err := result.Validate(); err != nil {
			return pending, err
		}
	}
	switch state {
	case pendingAuthorizationWaiting:
		if encoded.CodeConsumed ||
			encoded.PollingError != "" ||
			encoded.Decision.Permission != "" {
			return pending, errors.New("waiting permission state is inconsistent")
		}
	case pendingAuthorizationInteracting:
		if !encoded.CodeConsumed ||
			encoded.PollingError != "" ||
			encoded.Decision.Permission != "" {
			return pending, errors.New("interacting permission state is inconsistent")
		}
	case pendingAuthorizationApproved:
		if !encoded.CodeConsumed || encoded.PollingError != "" {
			return pending, errors.New("approved permission state is inconsistent")
		}
	case pendingAuthorizationRejected:
		if !encoded.CodeConsumed ||
			(encoded.PollingError != aauth.PollingDenied &&
				encoded.PollingError != aauth.PollingAbandoned &&
				encoded.PollingError != aauth.PollingServerError) {
			return pending, errors.New("rejected permission state is inconsistent")
		}
	case pendingAuthorizationInvalidCode:
		if encoded.FailedCodeAttempts != maxInteractionCodeAttempts {
			return pending, errors.New("invalid-code permission state is inconsistent")
		}
	}
	return pendingPersonPermission{
		pendingInteraction: pendingInteraction{
			id:                 encoded.ID,
			code:               encoded.Code,
			normalizedCode:     normalizedCode,
			codeConsumed:       encoded.CodeConsumed,
			failedCodeAttempts: encoded.FailedCodeAttempts,
			state:              state,
			pollingError:       encoded.PollingError,
			expiresAt:          expiresAt,
		},
		agent:                  encoded.Agent,
		pollingAgentThumbprint: encoded.PollingAgentThumbprint,
		requestReplayKey:       encoded.RequestReplayKey,
		requestBody:            append([]byte(nil), encoded.RequestBody...),
		decision: aauth.PermissionDecision{
			Permission: encoded.Decision.Permission,
			Reason:     encoded.Decision.Reason,
			DecidedBy:  encoded.Decision.DecidedBy,
		},
	}, nil
}

func validateGovernanceRelationships(
	missions map[string]storedMission,
	permissions []aauth.PermissionRecord,
	interactions []aauth.InteractionRecord,
	pendingPermissions map[string]pendingPersonPermission,
	pendingCompletions map[string]pendingCompletion,
	replays map[string]time.Time,
) error {
	permissionProofs := make(map[string]aauth.PermissionRecord, len(permissions))
	for _, record := range permissions {
		key := record.Proof.ReplayKey
		if _, duplicate := permissionProofs[key]; duplicate {
			return errors.New("reference: governance state contains duplicate permission proofs")
		}
		permissionProofs[key] = record
	}
	for _, pending := range pendingPermissions {
		record, exists := permissionProofs[pending.requestReplayKey]
		if !exists || record.PendingID != pending.id {
			return errors.New("reference: pending permission has no request record")
		}
		terminal := pending.state == pendingAuthorizationServed
		if terminal != (len(record.Response) != 0) {
			return errors.New("reference: pending permission terminal state does not match its request record")
		}
	}
	interactionProofs := make(map[string]aauth.InteractionRecord, len(interactions))
	for _, record := range interactions {
		key := record.Proof.ReplayKey
		if _, duplicate := interactionProofs[key]; duplicate {
			return errors.New("reference: governance state contains duplicate interaction proofs")
		}
		interactionProofs[key] = record
	}
	for _, pending := range pendingCompletions {
		record, exists := interactionProofs[pending.requestReplayKey]
		if !exists || record.PendingID != pending.id {
			return errors.New("reference: pending completion has no interaction record")
		}
		terminal := pending.state == completionAccepted ||
			pending.state == completionServed
		if terminal != (len(record.Response) != 0) {
			return errors.New("reference: pending completion terminal state does not match its interaction record")
		}
	}
	for _, mission := range missions {
		for index, entry := range mission.log {
			switch entry.Kind {
			case aauth.MissionLogPermissionRequest:
				record, exists := permissionProofs[entry.RequestProofID]
				if !exists ||
					record.Agent != mission.agent ||
					!bytes.Equal(record.Request, entry.Request) {
					return errors.New("reference: mission permission request has no global request record")
				}
				if recordMission(record) != mission.reference {
					return errors.New("reference: mission permission request record has the wrong mission")
				}
				if len(record.Response) != 0 {
					if permissionResponseIsMissionTerminated(record.Response) &&
						mission.status == aauth.MissionTerminated {
						continue
					}
					matched := false
					for _, decision := range mission.log[index+1:] {
						if decision.Kind == aauth.MissionLogPermissionDecision &&
							decision.RequestProofID == entry.RequestProofID &&
							bytes.Equal(decision.Response, record.Response) {
							matched = true
							break
						}
					}
					if !matched {
						return errors.New("reference: permission response does not match the mission log")
					}
				}
			case aauth.MissionLogInteractionRequest:
				record, exists := interactionProofs[entry.RequestProofID]
				if !exists ||
					record.Agent != mission.agent ||
					!bytes.Equal(record.Request, entry.Request) {
					return errors.New("reference: mission interaction request has no global interaction record")
				}
				if interactionRecordMission(record) != mission.reference {
					return errors.New("reference: mission interaction request has the wrong mission")
				}
				if len(record.Response) != 0 {
					kind, err := interactionResponseKind(record.Response)
					if err != nil {
						return err
					}
					if kind == "mission_terminated" &&
						mission.status == aauth.MissionTerminated {
						continue
					}
					matched := false
					for _, decision := range mission.log[index+1:] {
						if decision.Kind == aauth.MissionLogInteractionResponse &&
							decision.RequestProofID == entry.RequestProofID &&
							bytes.Equal(decision.Response, record.Response) {
							matched = true
							break
						}
					}
					if !matched {
						return errors.New("reference: interaction response does not match the mission log")
					}
				}
			}
		}
	}
	for key := range replays {
		if _, err := base64.RawURLEncoding.DecodeString(key); err != nil {
			return errors.New("reference: governance replay key is invalid")
		}
	}
	return nil
}

func recordMission(record aauth.PermissionRecord) aauth.MissionReference {
	var request aauth.PermissionRequest
	if err := json.Unmarshal(record.Request, &request); err != nil || request.Mission == nil {
		return aauth.MissionReference{}
	}
	return *request.Mission
}

func permissionResponseIsMissionTerminated(body []byte) bool {
	var wire struct {
		Status int    `json:"status"`
		Code   string `json:"error"`
	}
	return json.Unmarshal(body, &wire) == nil &&
		wire.Status == http.StatusForbidden &&
		wire.Code == "mission_terminated"
}

func validateMissionLogEntry(
	entry aauth.MissionLogEntry,
	sequence uint64,
	mission aauth.MissionReference,
	agent string,
) error {
	if entry.Sequence != sequence || entry.RecordedAt.IsZero() || entry.Agent != agent {
		return errors.New("mission log ordering or ownership is invalid")
	}
	switch entry.Kind {
	case aauth.MissionLogPermissionRequest:
		var request aauth.PermissionRequest
		if err := decodeJSONBytes(bytes.NewReader(entry.Request), &request); err != nil {
			return err
		}
		if err := request.Validate(); err != nil ||
			request.Mission == nil ||
			*request.Mission != mission ||
			entry.Proof == nil ||
			entry.RequestProofID != entry.Proof.ReplayKey {
			return errors.New("permission request log entry is invalid")
		}
		if err := validateStoredRequestProof(
			entry.Proof,
			entry.Request,
			agent,
			mission.Approver,
			"/permission",
		); err != nil {
			return err
		}
	case aauth.MissionLogPermissionDecision:
		if len(entry.Response) == 0 ||
			!json.Valid(entry.Response) ||
			entry.Proof != nil ||
			!validReplayKey(entry.RequestProofID) {
			return errors.New("permission decision log entry is invalid")
		}
		if err := validatePermissionDecisionBody(entry.Response); err != nil {
			return err
		}
	case aauth.MissionLogAudit:
		var request aauth.AuditRequest
		if err := decodeJSONBytes(bytes.NewReader(entry.Request), &request); err != nil {
			return err
		}
		if err := request.Validate(); err != nil ||
			request.Mission != mission ||
			entry.Proof == nil ||
			entry.RequestProofID != entry.Proof.ReplayKey {
			return errors.New("audit log entry is invalid")
		}
		if err := validateStoredRequestProof(
			entry.Proof,
			entry.Request,
			agent,
			mission.Approver,
			"/audit",
		); err != nil {
			return err
		}
	case aauth.MissionLogInteractionRequest:
		var request aauth.InteractionRequest
		if err := decodeJSONBytes(bytes.NewReader(entry.Request), &request); err != nil {
			return err
		}
		if err := request.Validate(); err != nil ||
			request.Type != aauth.InteractionTypeCompletion ||
			request.Mission == nil ||
			*request.Mission != mission ||
			len(entry.Response) != 0 ||
			entry.Proof == nil ||
			entry.RequestProofID != entry.Proof.ReplayKey {
			return errors.New("interaction request log entry is invalid")
		}
		if err := validateStoredRequestProof(
			entry.Proof,
			entry.Request,
			agent,
			mission.Approver,
			"/interaction",
		); err != nil {
			return err
		}
	case aauth.MissionLogClarification:
		if len(entry.Request) != 0 {
			var request aauth.ClarificationResponse
			if err := decodeJSONBytes(bytes.NewReader(entry.Request), &request); err != nil {
				return err
			}
			if request.Action != "clarification_response" ||
				strings.TrimSpace(request.ClarificationResponse) == "" ||
				len(entry.Response) != 0 ||
				entry.DecidedBy != "" ||
				entry.Proof == nil ||
				entry.RequestProofID != entry.Proof.ReplayKey ||
				!validPendingInteractionTarget(entry.Proof.Target) {
				return errors.New("clarification response log entry is invalid")
			}
			if err := validateStoredRequestProof(
				entry.Proof,
				entry.Request,
				agent,
				mission.Approver,
				entry.Proof.Target,
			); err != nil {
				return err
			}
			break
		}
		var response struct {
			Clarification string `json:"clarification"`
		}
		if err := decodeJSONBytes(bytes.NewReader(entry.Response), &response); err != nil {
			return err
		}
		if strings.TrimSpace(response.Clarification) == "" ||
			entry.Proof != nil ||
			!validReplayKey(entry.RequestProofID) ||
			strings.TrimSpace(entry.DecidedBy) == "" {
			return errors.New("clarification question log entry is invalid")
		}
	case aauth.MissionLogInteractionResponse:
		if len(entry.Request) != 0 ||
			len(entry.Response) == 0 ||
			entry.Proof != nil ||
			!validReplayKey(entry.RequestProofID) {
			return errors.New("interaction response log entry is invalid")
		}
		kind, err := interactionResponseKind(entry.Response)
		if err != nil {
			return err
		}
		if kind == "completed" && strings.TrimSpace(entry.DecidedBy) == "" {
			return errors.New("completion response log entry requires a decision actor")
		}
	case aauth.MissionLogTermination:
		if len(entry.Request) != 0 ||
			len(entry.Response) != 0 ||
			entry.Proof != nil ||
			entry.RequestProofID != "" {
			return errors.New("mission termination log entry is invalid")
		}
	default:
		return errors.New("mission log kind is invalid")
	}
	return nil
}

func validReplayKey(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validatePermissionDecisionBody(body []byte) error {
	var decision aauth.PermissionResponse
	if err := decodeJSONBytes(bytes.NewReader(body), &decision); err == nil {
		if err := decision.Validate(); err == nil {
			return nil
		}
	}
	var wire struct {
		Status int `json:"status"`
	}
	if err := json.Unmarshal(body, &wire); err != nil || wire.Status == 0 {
		return errors.New("permission decision response is invalid")
	}
	response := &http.Response{
		StatusCode: wire.Status,
		Header: http.Header{
			"Content-Type": {"application/problem+json"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}
	problem, err := aauth.DecodeProblemResponse(response)
	if err != nil {
		return errors.New("permission decision problem response is invalid")
	}
	switch problem.Code {
	case aauth.PollingDenied, aauth.PollingAbandoned:
		if problem.Status == http.StatusForbidden {
			return nil
		}
	case aauth.PollingExpired:
		if problem.Status == http.StatusRequestTimeout {
			return nil
		}
	case aauth.PollingInvalidCode:
		if problem.Status == http.StatusGone {
			return nil
		}
	case aauth.PollingServerError:
		if problem.Status == http.StatusInternalServerError {
			return nil
		}
	case "mission_terminated":
		if problem.Status == http.StatusForbidden &&
			problem.MissionStatus == string(aauth.MissionTerminated) {
			return nil
		}
	default:
	}
	return errors.New("permission decision problem code or status is invalid")
}

func validateStoredRequestProof(
	proof *aauth.RequestProof,
	body []byte,
	agent string,
	personServer string,
	target string,
) error {
	identifier, err := url.Parse(personServer)
	if err != nil {
		return errors.New("mission log person-server identifier is invalid")
	}
	if proof.Method != http.MethodPost ||
		proof.Authority != identifier.Host ||
		proof.Target != target ||
		proof.SignatureInput == "" ||
		proof.SignatureKey == "" ||
		proof.SignatureKeyType != string(signaturekey.SchemeJWT) ||
		proof.CredentialType != aauth.AgentTokenType ||
		proof.Signer != agent ||
		proof.Agent != agent ||
		proof.Created.IsZero() ||
		proof.VerifiedAt.IsZero() {
		return errors.New("mission log request proof context is invalid")
	}
	age := proof.VerifiedAt.Sub(proof.Created)
	if age < -signaturekey.DefaultSignatureWindow || age > signaturekey.DefaultSignatureWindow {
		return errors.New("mission log request proof verification time is invalid")
	}
	if _, err := proof.PublicKey.PublicKey(); err != nil {
		return errors.New("mission log request proof key is invalid")
	}
	const digestPrefix = "sha-256=:"
	if !strings.HasPrefix(proof.ContentDigest, digestPrefix) ||
		!strings.HasSuffix(proof.ContentDigest, ":") {
		return errors.New("mission log request proof content digest is invalid")
	}
	expectedDigest, err := base64.StdEncoding.DecodeString(
		strings.TrimSuffix(strings.TrimPrefix(proof.ContentDigest, digestPrefix), ":"),
	)
	if err != nil || len(expectedDigest) != sha256.Size {
		return errors.New("mission log request proof content digest is invalid")
	}
	actualDigest := sha256.Sum256(body)
	if !bytes.Equal(expectedDigest, actualDigest[:]) {
		return errors.New("mission log request body does not match its verified digest")
	}
	const signaturePrefix = "sig=:"
	if !strings.HasPrefix(proof.Signature, signaturePrefix) ||
		!strings.HasSuffix(proof.Signature, ":") {
		return errors.New("mission log request proof signature is invalid")
	}
	signature, err := base64.StdEncoding.DecodeString(
		strings.TrimSuffix(strings.TrimPrefix(proof.Signature, signaturePrefix), ":"),
	)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("mission log request proof signature is invalid")
	}
	replayKey, err := base64.RawURLEncoding.DecodeString(proof.ReplayKey)
	if err != nil || len(replayKey) != sha256.Size {
		return errors.New("mission log request proof replay key is invalid")
	}
	return nil
}

func copyMissionLog(entries []aauth.MissionLogEntry) []aauth.MissionLogEntry {
	copied := make([]aauth.MissionLogEntry, len(entries))
	for index, entry := range entries {
		copied[index] = entry
		copied[index].Request = append([]byte(nil), entry.Request...)
		copied[index].Response = append([]byte(nil), entry.Response...)
		copied[index].Proof = copyRequestProof(entry.Proof)
	}
	return copied
}

func copyPermissionRecord(record aauth.PermissionRecord) aauth.PermissionRecord {
	copied := record
	copied.Request = append([]byte(nil), record.Request...)
	copied.Response = append([]byte(nil), record.Response...)
	copied.Proof = copyRequestProof(record.Proof)
	return copied
}

func copyPermissionHistory(records []aauth.PermissionRecord) []aauth.PermissionRecord {
	copied := make([]aauth.PermissionRecord, len(records))
	for index, record := range records {
		copied[index] = copyPermissionRecord(record)
	}
	return copied
}

var _ GovernanceStore = (*FileGovernanceStore)(nil)
