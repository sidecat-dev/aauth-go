package aauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

// MissionTool is one tool named in a mission proposal or approved mission.
// Description is untrusted Markdown and must be sanitized before rendering.
// The protocol records this declaration; it does not make the declaration an
// enforceable permission at a remote Resource.
type MissionTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// MissionProposal is the Agent-authored request body sent to a Person
// Server's mission endpoint. Description and tool descriptions are untrusted
// Markdown and must be sanitized before rendering.
type MissionProposal struct {
	Description string        `json:"description"`
	Tools       []MissionTool `json:"tools,omitempty"`
	Resources   []string      `json:"resources,omitempty"`
}

// MissionUpdate is the Agent-authored body that records changed work without
// changing the approved mission blob or its identifier.
type MissionUpdate struct {
	Action      string `json:"action"`
	Description string `json:"description"`
}

// MissionUpdateDocument keeps a parsed update beside the exact JSON bytes its
// S256 identifies. Unknown additive members remain intact in ExactJSON.
type MissionUpdateDocument struct {
	S256      string
	ExactJSON []byte
	Update    MissionUpdate
}

// MissionUpdateResponse is the successful mission-update response.
type MissionUpdateResponse struct {
	S256 string `json:"s256"`
}

// MissionCompletion is the Agent-authored proposal that a mission is finished.
type MissionCompletion struct {
	Action  string `json:"action"`
	Summary string `json:"summary"`
}

// MissionCompletionDocument keeps a parsed completion proposal beside its
// exact JSON bytes. Unknown additive members remain intact in ExactJSON. Core
// does not define a digest identifier for a completion proposal.
type MissionCompletionDocument struct {
	ExactJSON  []byte
	Completion MissionCompletion
}

// Validate checks the protocol-defined shape of a mission proposal.
func (proposal MissionProposal) Validate() error {
	if proposal.Description == "" {
		return errors.New("aauth: mission proposal description is required")
	}
	for index, resource := range proposal.Resources {
		if err := ValidateServerIdentifier(resource); err != nil {
			return fmt.Errorf("aauth: mission proposal resource %d: %w", index, err)
		}
	}
	return nil
}

// MissionBlob is the Person Server-approved mission content. Its encoded JSON
// bytes, rather than a re-encoding of this value, are the object identified by
// s256. The blob carries no approver member: the approver is always the Person
// Server that returns or serves the mission, named beside s256 by the iss of a
// person token, the ps claim of a resource or auth token, or the Person Server
// a request is made to.
type MissionBlob struct {
	Agent             string        `json:"agent"`
	ApprovedAt        time.Time     `json:"approved_at"`
	ExpiresAt         *time.Time    `json:"expires_at,omitempty"`
	Description       string        `json:"description"`
	ApprovedTools     []MissionTool `json:"approved_tools,omitempty"`
	ApprovedResources []string      `json:"approved_resources,omitempty"`
}

// MissionApproval is the successful mission-endpoint response. Mission is the
// unpadded base64url encoding of the exact approved mission JSON.
type MissionApproval struct {
	S256         string            `json:"s256"`
	Mission      string            `json:"mission"`
	Capabilities []string          `json:"capabilities,omitempty"`
	PersonTokens map[string]string `json:"person_tokens,omitempty"`
}

// ApprovedMission keeps the parsed mission beside the exact bytes its s256
// identifies. Unknown mission-blob members remain intact in ExactJSON.
type ApprovedMission struct {
	S256      string
	Encoded   string
	ExactJSON []byte
	Blob      MissionBlob
}

// ApprovesTool reports whether name exactly matches a tool recorded in the
// approved mission. The protocol defines no tool-name normalization and does
// not make this local planning aid an enforceable permission at a Resource.
func (mission ApprovedMission) ApprovesTool(name string) bool {
	if name == "" {
		return false
	}
	for _, tool := range mission.Blob.ApprovedTools {
		if tool.Name == name {
			return true
		}
	}
	return false
}

// MissionS256 returns the unpadded base64url SHA-256 identifier used for exact
// mission-blob and accepted-update bytes.
func MissionS256(exactJSON []byte) string {
	digest := sha256.Sum256(exactJSON)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// ValidateMissionS256 checks the exact unpadded base64url SHA-256 syntax used
// by mission references.
func ValidateMissionS256(value string) error {
	return validateS256("mission_s256", value)
}

// EncodeMissionUpdate validates and deterministically encodes an update.
func EncodeMissionUpdate(update MissionUpdate) (MissionUpdateDocument, error) {
	if err := validateMissionUpdate(update); err != nil {
		return MissionUpdateDocument{}, err
	}
	exactJSON, err := json.Marshal(update)
	if err != nil {
		return MissionUpdateDocument{}, fmt.Errorf("aauth: encode mission update: %w", err)
	}
	return MissionUpdateDocument{
		S256: MissionS256(exactJSON), ExactJSON: append([]byte(nil), exactJSON...), Update: update,
	}, nil
}

// DecodeMissionUpdate verifies an update's identifier, preserves its exact
// bytes, and decodes its protocol-defined members.
func DecodeMissionUpdate(s256 string, exactJSON []byte) (MissionUpdateDocument, error) {
	if err := validateS256("mission update s256", s256); err != nil {
		return MissionUpdateDocument{}, err
	}
	if MissionS256(exactJSON) != s256 {
		return MissionUpdateDocument{}, errors.New("aauth: mission update bytes do not match s256")
	}
	var update MissionUpdate
	if err := jsonstrict.RejectCaseVariants(exactJSON, &update); err != nil {
		return MissionUpdateDocument{}, fmt.Errorf("aauth: decode mission update: %w", err)
	}
	if err := json.Unmarshal(exactJSON, &update); err != nil {
		return MissionUpdateDocument{}, fmt.Errorf("aauth: decode mission update: %w", err)
	}
	if err := validateMissionUpdate(update); err != nil {
		return MissionUpdateDocument{}, err
	}
	return MissionUpdateDocument{
		S256: s256, ExactJSON: append([]byte(nil), exactJSON...), Update: update,
	}, nil
}

func validateMissionUpdate(update MissionUpdate) error {
	if update.Action != "update" {
		return errors.New("aauth: mission update action must be update")
	}
	if update.Description == "" {
		return errors.New("aauth: mission update description is required")
	}
	return nil
}

// EncodeMissionCompletion validates and deterministically encodes a completion
// proposal.
func EncodeMissionCompletion(completion MissionCompletion) (MissionCompletionDocument, error) {
	if err := validateMissionCompletion(completion); err != nil {
		return MissionCompletionDocument{}, err
	}
	exactJSON, err := json.Marshal(completion)
	if err != nil {
		return MissionCompletionDocument{}, fmt.Errorf("aauth: encode mission completion: %w", err)
	}
	return MissionCompletionDocument{
		ExactJSON: append([]byte(nil), exactJSON...), Completion: completion,
	}, nil
}

// DecodeMissionCompletion preserves a completion proposal's exact bytes and
// decodes its protocol-defined members.
func DecodeMissionCompletion(exactJSON []byte) (MissionCompletionDocument, error) {
	var completion MissionCompletion
	if err := jsonstrict.RejectCaseVariants(exactJSON, &completion); err != nil {
		return MissionCompletionDocument{}, fmt.Errorf("aauth: decode mission completion: %w", err)
	}
	if err := json.Unmarshal(exactJSON, &completion); err != nil {
		return MissionCompletionDocument{}, fmt.Errorf("aauth: decode mission completion: %w", err)
	}
	if err := validateMissionCompletion(completion); err != nil {
		return MissionCompletionDocument{}, err
	}
	return MissionCompletionDocument{
		ExactJSON: append([]byte(nil), exactJSON...), Completion: completion,
	}, nil
}

func validateMissionCompletion(completion MissionCompletion) error {
	if completion.Action != "completion" {
		return errors.New("aauth: mission completion action must be completion")
	}
	if completion.Summary == "" {
		return errors.New("aauth: mission completion summary is required")
	}
	return nil
}

// EncodeMission validates and deterministically encodes a mission blob.
func EncodeMission(blob MissionBlob) (ApprovedMission, error) {
	blob = cloneMissionBlob(blob)
	if err := validateMissionBlob(blob); err != nil {
		return ApprovedMission{}, err
	}
	exactJSON, err := json.Marshal(blob)
	if err != nil {
		return ApprovedMission{}, fmt.Errorf("aauth: encode mission blob: %w", err)
	}
	return ApprovedMission{
		S256: MissionS256(exactJSON), Encoded: base64.RawURLEncoding.EncodeToString(exactJSON),
		ExactJSON: append([]byte(nil), exactJSON...), Blob: blob,
	}, nil
}

func cloneMissionBlob(blob MissionBlob) MissionBlob {
	blob.ApprovedTools = append([]MissionTool(nil), blob.ApprovedTools...)
	blob.ApprovedResources = append([]string(nil), blob.ApprovedResources...)
	if blob.ExpiresAt != nil {
		expiresAt := *blob.ExpiresAt
		blob.ExpiresAt = &expiresAt
	}
	return blob
}

// DecodeMission verifies an approval's s256 and decodes its exact mission
// bytes. Unknown members are ignored semantically and retained byte-for-byte.
func DecodeMission(s256, encoded string) (ApprovedMission, error) {
	if err := validateS256("mission s256", s256); err != nil {
		return ApprovedMission{}, err
	}
	exactJSON, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(exactJSON) != encoded {
		return ApprovedMission{}, errors.New("aauth: mission must be unpadded canonical base64url")
	}
	if MissionS256(exactJSON) != s256 {
		return ApprovedMission{}, errors.New("aauth: mission bytes do not match s256")
	}
	var blob MissionBlob
	if err := jsonstrict.RejectCaseVariants(exactJSON, &blob); err != nil {
		return ApprovedMission{}, fmt.Errorf("aauth: decode mission blob: %w", err)
	}
	if err := json.Unmarshal(exactJSON, &blob); err != nil {
		return ApprovedMission{}, fmt.Errorf("aauth: decode mission blob: %w", err)
	}
	if err := validateMissionBlob(blob); err != nil {
		return ApprovedMission{}, err
	}
	return ApprovedMission{
		S256: s256, Encoded: encoded, ExactJSON: append([]byte(nil), exactJSON...), Blob: blob,
	}, nil
}

func validateMissionBlob(blob MissionBlob) error {
	if err := ValidateAgentIdentifier(blob.Agent); err != nil {
		return fmt.Errorf("aauth: mission agent: %w", err)
	}
	if blob.ApprovedAt.IsZero() {
		return errors.New("aauth: mission approved_at is required")
	}
	if blob.Description == "" {
		return errors.New("aauth: mission description is required")
	}
	for index, resource := range blob.ApprovedResources {
		if err := ValidateServerIdentifier(resource); err != nil {
			return fmt.Errorf("aauth: mission approved resource %d: %w", index, err)
		}
	}
	return nil
}

// MissionReadUpdate is one accepted update as a mission read serves it: the
// update's s256 and the unpadded base64url of the exact bytes it names.
type MissionReadUpdate struct {
	S256    string `json:"s256"`
	Encoded string `json:"encoded"`
}

// MissionReadResponse is a Person Server's answer to the owning Agent's
// signed GET of its mission's own URL, {mission_endpoint}/{mission_s256}.
// Mission carries the same bytes the approval returned (Core, Mission
// Identifier), and Updates the accepted updates in the order they were
// accepted, since a party auditing a mission reads both (Core, Mission
// Update).
type MissionReadResponse struct {
	S256    string              `json:"s256"`
	Mission string              `json:"mission"`
	Updates []MissionReadUpdate `json:"updates"`
}

// MissionRead is a verified mission read: the approved mission and its
// accepted updates, each checked against the s256 that names it.
type MissionRead struct {
	Mission ApprovedMission
	Updates []MissionUpdateDocument
}

// NewMissionReadResponse builds the answer to a mission read from the
// approved mission and its accepted updates, in acceptance order.
func NewMissionReadResponse(mission ApprovedMission, updates []MissionUpdateDocument) MissionReadResponse {
	response := MissionReadResponse{S256: mission.S256, Mission: mission.Encoded, Updates: []MissionReadUpdate{}}
	for _, update := range updates {
		response.Updates = append(response.Updates, MissionReadUpdate{
			S256: update.S256, Encoded: base64.RawURLEncoding.EncodeToString(update.ExactJSON),
		})
	}
	return response
}

// DecodeMissionRead verifies one exact mission-read response for the mission
// named s256: the response names that mission, its mission bytes hash to it,
// and each update's bytes hash to the update's own s256. Unknown members are
// ignored.
func DecodeMissionRead(exactJSON []byte, s256 string) (MissionRead, error) {
	if err := validateS256("mission s256", s256); err != nil {
		return MissionRead{}, err
	}
	var response MissionReadResponse
	if err := jsonstrict.RejectAmbiguousNames(exactJSON); err != nil {
		return MissionRead{}, fmt.Errorf("aauth: decode mission read: %w", err)
	}
	if err := jsonstrict.RejectCaseVariants(exactJSON, &response); err != nil {
		return MissionRead{}, fmt.Errorf("aauth: decode mission read: %w", err)
	}
	if err := json.Unmarshal(exactJSON, &response); err != nil {
		return MissionRead{}, fmt.Errorf("aauth: decode mission read: %w", err)
	}
	if response.S256 != s256 {
		return MissionRead{}, errors.New("aauth: mission read names a different mission")
	}
	mission, err := DecodeMission(response.S256, response.Mission)
	if err != nil {
		return MissionRead{}, err
	}
	read := MissionRead{Mission: mission}
	for index, update := range response.Updates {
		exact, err := base64.RawURLEncoding.Strict().DecodeString(update.Encoded)
		if err != nil || base64.RawURLEncoding.EncodeToString(exact) != update.Encoded {
			return MissionRead{}, fmt.Errorf("aauth: mission read update %d must be unpadded canonical base64url", index)
		}
		document, err := DecodeMissionUpdate(update.S256, exact)
		if err != nil {
			return MissionRead{}, fmt.Errorf("aauth: mission read update %d: %w", index, err)
		}
		read.Updates = append(read.Updates, document)
	}
	return read, nil
}
