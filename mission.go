package aauth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Tool is a human-readable tool declaration in a mission proposal or approval.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// MissionProposal is the agent's requested mission.
type MissionProposal struct {
	Description string   `json:"description"`
	Tools       []Tool   `json:"tools,omitempty"`
	Resources   []string `json:"resources,omitempty"`
}

// MissionUpdate records one accepted change in the work represented by an
// approved mission. The mission blob remains immutable; the update is part of
// the ordered mission log.
type MissionUpdate struct {
	Action      string `json:"action"`
	Description string `json:"description"`
}

// Validate checks the current mission-endpoint update request shape.
func (update MissionUpdate) Validate() error {
	if update.Action != "update" {
		return errors.New("aauth: mission update action must be update")
	}
	if strings.TrimSpace(update.Description) == "" {
		return errors.New("aauth: mission update description is required")
	}
	return nil
}

// MissionUpdateResult is the digest of the exact update bytes retained by the
// person server.
type MissionUpdateResult struct {
	S256 string `json:"s256"`
}

// Validate checks the digest returned for one accepted mission update.
func (result MissionUpdateResult) Validate() error {
	return validateS256("mission update s256", result.S256)
}

// MissionCompletion is the current mission-endpoint request that proposes
// completion of an approved mission. The person still decides whether to
// terminate the mission.
type MissionCompletion struct {
	Action  string `json:"action"`
	Summary string `json:"summary"`
}

// Validate checks the current mission-endpoint completion request shape.
func (completion MissionCompletion) Validate() error {
	if completion.Action != "completion" {
		return errors.New("aauth: mission completion action must be completion")
	}
	if strings.TrimSpace(completion.Summary) == "" {
		return errors.New("aauth: mission completion summary is required")
	}
	return nil
}

// Validate rejects protocol-invalid mission material before a deployment
// presents it to a person or policy engine.
func (proposal MissionProposal) Validate() error {
	if strings.TrimSpace(proposal.Description) == "" {
		return errors.New("aauth: mission description is required")
	}
	toolNames := make(map[string]bool, len(proposal.Tools))
	for _, tool := range proposal.Tools {
		name := strings.TrimSpace(tool.Name)
		if name == "" || strings.TrimSpace(tool.Description) == "" {
			return errors.New("aauth: mission tools require name and description")
		}
		if toolNames[name] {
			return fmt.Errorf("aauth: mission tools contain duplicate name %q", name)
		}
		toolNames[name] = true
	}
	resources := make(map[string]bool, len(proposal.Resources))
	for _, resource := range proposal.Resources {
		if err := ValidateServerIdentifier(resource); err != nil {
			return fmt.Errorf("aauth: mission resource: %w", err)
		}
		if resources[resource] {
			return fmt.Errorf("aauth: mission resources contain duplicate %q", resource)
		}
		resources[resource] = true
	}
	return nil
}

// MissionDecision is the deployment-owned result of approving a proposal.
type MissionDecision struct {
	Description       string
	Tools             []Tool
	Capabilities      []string
	ApprovedResources []string
	ExpiresAt         *time.Time
}

// MissionReference binds later protocol messages to exact approved bytes.
type MissionReference struct {
	Approver string `json:"approver"`
	S256     string `json:"s256"`
}

// ApprovedMission retains the exact bytes returned by the person server.
type ApprovedMission struct {
	Reference    MissionReference
	Bytes        []byte
	Capabilities []string
	PersonTokens map[string]string
}

// S256 returns the unpadded base64url SHA-256 digest of exact bytes.
func S256(value []byte) string {
	digest := sha256.Sum256(value)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// Validate verifies the mission reference without dereferencing it.
func (reference MissionReference) Validate() error {
	if err := ValidateServerIdentifier(reference.Approver); err != nil {
		return fmt.Errorf("aauth: mission approver: %w", err)
	}
	return validateS256("mission s256", reference.S256)
}

func validateS256(name string, value string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("aauth: %s must be an unpadded base64url SHA-256 digest", name)
	}
	return nil
}

// ValidateExactBytes checks that the retained mission bytes match the reference.
func (mission ApprovedMission) ValidateExactBytes() error {
	if err := mission.Reference.Validate(); err != nil {
		return err
	}
	if S256(mission.Bytes) != mission.Reference.S256 {
		return errors.New("aauth: mission bytes do not match s256")
	}
	return nil
}
