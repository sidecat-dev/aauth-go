package aauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Permission is the terminal result of a person-server permission request.
type Permission string

const (
	PermissionGranted Permission = "granted"
	PermissionDenied  Permission = "denied"
)

// PermissionRequest asks a person server to govern a local action. Mission is
// optional because local-action governance is also available outside missions.
type PermissionRequest struct {
	Action      string            `json:"action"`
	Description string            `json:"description,omitempty"`
	Parameters  map[string]any    `json:"parameters,omitempty"`
	Mission     *MissionReference `json:"mission,omitempty"`
}

// Validate checks the protocol-level permission request shape.
func (request PermissionRequest) Validate() error {
	if strings.TrimSpace(request.Action) == "" {
		return errors.New("aauth: permission action is required")
	}
	if request.Mission != nil {
		if err := request.Mission.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// PermissionResponse is the terminal person-server response.
type PermissionResponse struct {
	Permission Permission `json:"permission"`
	Reason     string     `json:"reason,omitempty"`
}

// Validate checks that a permission response is terminal and well formed.
func (response PermissionResponse) Validate() error {
	switch response.Permission {
	case PermissionGranted:
		if response.Reason != "" {
			return errors.New("aauth: a granted permission response must not include a denial reason")
		}
	case PermissionDenied:
	default:
		return errors.New("aauth: permission must be granted or denied")
	}
	return nil
}

// PermissionDecision is returned by deployment policy after protocol checks.
// DecidedBy is retained in the mission log but is not disclosed on the wire.
type PermissionDecision struct {
	Permission Permission
	Reason     string
	DecidedBy  string
}

// PermissionEvaluation gives deployment policy the verified agent, request,
// exact approved mission, approved tools, and prior ordered mission history.
type PermissionEvaluation struct {
	Agent   string
	Request PermissionRequest
	Mission *MissionSnapshot
}

// PermissionPolicy is intentionally caller-owned.
type PermissionPolicy func(context.Context, PermissionEvaluation) (PermissionDecision, error)

// AuditRequest records a completed local action. Audit is always mission-bound.
type AuditRequest struct {
	Mission     MissionReference `json:"mission"`
	Action      string           `json:"action"`
	Description string           `json:"description,omitempty"`
	Parameters  map[string]any   `json:"parameters,omitempty"`
	Result      map[string]any   `json:"result,omitempty"`
}

// Validate checks the protocol-level audit request shape.
func (request AuditRequest) Validate() error {
	if err := request.Mission.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(request.Action) == "" {
		return errors.New("aauth: audit action is required")
	}
	return nil
}

// MissionStatus is the two-state mission lifecycle from the core draft.
type MissionStatus string

const (
	MissionActive     MissionStatus = "active"
	MissionTerminated MissionStatus = "terminated"
)

// MissionLogKind identifies an ordered person-server governance event.
type MissionLogKind string

const (
	MissionLogPermissionRequest   MissionLogKind = "permission_request"
	MissionLogPermissionDecision  MissionLogKind = "permission_decision"
	MissionLogAudit               MissionLogKind = "audit"
	MissionLogInteractionRequest  MissionLogKind = "interaction_request"
	MissionLogClarification       MissionLogKind = "clarification"
	MissionLogInteractionResponse MissionLogKind = "interaction_response"
	MissionLogTermination         MissionLogKind = "termination"
)

// MissionLogEntry retains the exact request body and, when applicable, the
// terminal response body. Sequence is strictly increasing within one mission.
type MissionLogEntry struct {
	Sequence   uint64         `json:"sequence"`
	Kind       MissionLogKind `json:"kind"`
	RecordedAt time.Time      `json:"recorded_at"`
	Agent      string         `json:"agent"`
	DecidedBy  string         `json:"decided_by,omitempty"`
	// RequestProofID correlates a permission decision with the verified request
	// proof that caused it. It is not an AAuth idempotency identifier.
	RequestProofID string          `json:"request_proof_id,omitempty"`
	Request        json.RawMessage `json:"request,omitempty"`
	Response       json.RawMessage `json:"response,omitempty"`
	Proof          *RequestProof   `json:"proof,omitempty"`
}

// RequestProof archives the artifacts needed to attribute a request after the
// issuer rotates its live JWKS. SignatureKey can contain a credential and is
// sensitive custody, not presentation data.
type RequestProof struct {
	Method           string    `json:"method"`
	Authority        string    `json:"authority"`
	Target           string    `json:"target"`
	ContentDigest    string    `json:"content_digest,omitempty"`
	SignatureInput   string    `json:"signature_input"`
	Signature        string    `json:"signature"`
	SignatureKey     string    `json:"signature_key"`
	AAuthMission     string    `json:"aauth_mission,omitempty"`
	Authorization    string    `json:"authorization,omitempty"`
	SignatureKeyType string    `json:"signature_key_type"`
	CredentialType   string    `json:"credential_type,omitempty"`
	Signer           string    `json:"signer"`
	Agent            string    `json:"agent,omitempty"`
	PublicKey        JWK       `json:"public_key"`
	Created          time.Time `json:"created"`
	VerifiedAt       time.Time `json:"verified_at"`
	ReplayKey        string    `json:"replay_key"`
}

// PermissionRecord is the person server's ordered custody for every permission
// request, including requests made outside a mission. Request and Proof are
// immutable verification evidence; Response is populated only after a terminal
// decision. PendingID links a deferred request to its private continuation.
type PermissionRecord struct {
	Sequence   uint64          `json:"sequence"`
	RecordedAt time.Time       `json:"recorded_at"`
	Agent      string          `json:"agent"`
	Request    json.RawMessage `json:"request"`
	Proof      *RequestProof   `json:"proof"`
	PendingID  string          `json:"pending_id,omitempty"`
	DecidedAt  time.Time       `json:"decided_at,omitempty"`
	DecidedBy  string          `json:"decided_by,omitempty"`
	Response   json.RawMessage `json:"response,omitempty"`
}

// MissionSnapshot is an immutable caller copy of retained mission custody.
// Bytes are the exact approved response bytes bound by Reference.S256.
type MissionSnapshot struct {
	Reference         MissionReference
	Bytes             []byte
	Description       string
	ApprovedTools     []Tool
	ApprovedResources []string
	Capabilities      []string
	ExpiresAt         *time.Time
	Status            MissionStatus
	Log               []MissionLogEntry
}
