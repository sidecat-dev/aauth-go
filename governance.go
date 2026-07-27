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
	MissionLogPermissionRequest  MissionLogKind = "permission_request"
	MissionLogPermissionDecision MissionLogKind = "permission_decision"
	MissionLogAudit              MissionLogKind = "audit"
	MissionLogTermination        MissionLogKind = "termination"
)

// MissionLogEntry retains the exact request body and, when applicable, the
// terminal response body. Sequence is strictly increasing within one mission.
type MissionLogEntry struct {
	Sequence   uint64          `json:"sequence"`
	Kind       MissionLogKind  `json:"kind"`
	RecordedAt time.Time       `json:"recorded_at"`
	Agent      string          `json:"agent"`
	DecidedBy  string          `json:"decided_by,omitempty"`
	Request    json.RawMessage `json:"request,omitempty"`
	Response   json.RawMessage `json:"response,omitempty"`
}

// MissionSnapshot is an immutable caller copy of retained mission custody.
// Bytes are the exact approved response bytes bound by Reference.S256.
type MissionSnapshot struct {
	Reference     MissionReference
	Bytes         []byte
	Description   string
	ApprovedTools []Tool
	Capabilities  []string
	Status        MissionStatus
	Log           []MissionLogEntry
}
