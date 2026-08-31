package aauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

// AuditEntry is the source-defined record of one action already performed
// within a mission. Parameters and Result are absent or JSON objects.
// Description is untrusted raw Markdown and must be sanitized before display.
// Action, Parameters, and Result are also untrusted Agent input; a host must
// validate them before application-specific processing or rendering.
type AuditEntry struct {
	MissionS256 string          `json:"mission_s256"`
	Action      string          `json:"action"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
}

// AuditDocument keeps a parsed audit entry beside its exact JSON bytes.
// Unknown additive members remain intact in ExactJSON and are untrusted.
type AuditDocument struct {
	ExactJSON []byte
	Entry     AuditEntry
}

// Validate checks the Core Audit Endpoint request shape.
func (entry AuditEntry) Validate() error {
	if err := ValidateMissionS256(entry.MissionS256); err != nil {
		return fmt.Errorf("aauth: audit entry: %w", err)
	}
	if strings.TrimSpace(entry.Action) == "" {
		return errors.New("aauth: audit entry action is required")
	}
	if !utf8.ValidString(entry.Action) {
		return errors.New("aauth: audit entry action must be valid UTF-8")
	}
	if !utf8.ValidString(entry.Description) {
		return errors.New("aauth: audit entry description must be valid UTF-8")
	}
	if err := validateAuditObject("parameters", entry.Parameters); err != nil {
		return err
	}
	if err := validateAuditObject("result", entry.Result); err != nil {
		return err
	}
	return nil
}

// EncodeAudit validates and deterministically encodes an audit entry. The
// returned document does not alias caller-owned raw JSON.
func EncodeAudit(entry AuditEntry) (AuditDocument, error) {
	entry = cloneAuditEntry(entry)
	if err := entry.Validate(); err != nil {
		return AuditDocument{}, err
	}
	exactJSON, err := json.Marshal(entry)
	if err != nil {
		return AuditDocument{}, fmt.Errorf("aauth: encode audit entry: %w", err)
	}
	var encodedEntry AuditEntry
	if err := json.Unmarshal(exactJSON, &encodedEntry); err != nil {
		return AuditDocument{}, fmt.Errorf("aauth: encode audit entry: %w", err)
	}
	return AuditDocument{
		ExactJSON: append([]byte(nil), exactJSON...), Entry: cloneAuditEntry(encodedEntry),
	}, nil
}

// DecodeAudit preserves exact request bytes and decodes the source-defined
// members. Unknown additive members remain available in ExactJSON.
func DecodeAudit(exactJSON []byte) (AuditDocument, error) {
	if !utf8.Valid(exactJSON) {
		return AuditDocument{}, errors.New("aauth: decode audit entry: JSON input must be valid UTF-8")
	}
	var entry AuditEntry
	if err := jsonstrict.RejectCaseVariants(exactJSON, &entry); err != nil {
		return AuditDocument{}, fmt.Errorf("aauth: decode audit entry: %w", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(exactJSON, &members); err != nil || members == nil {
		return AuditDocument{}, errors.New("aauth: decode audit entry: JSON input must be an object")
	}
	if description, present := members["description"]; present && bytes.Equal(bytes.TrimSpace(description), []byte("null")) {
		return AuditDocument{}, errors.New("aauth: audit entry description must be a string when present")
	}
	if err := json.Unmarshal(exactJSON, &entry); err != nil {
		return AuditDocument{}, fmt.Errorf("aauth: decode audit entry: %w", err)
	}
	if err := entry.Validate(); err != nil {
		return AuditDocument{}, err
	}
	return AuditDocument{
		ExactJSON: append([]byte(nil), exactJSON...),
		Entry:     cloneAuditEntry(entry),
	}, nil
}

func validateAuditObject(name string, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	value := bytes.TrimSpace(raw)
	if len(value) == 0 || value[0] != '{' {
		return fmt.Errorf("aauth: audit entry %s must be a JSON object when present", name)
	}
	if err := jsonstrict.RejectAmbiguousNames(value); err != nil {
		return fmt.Errorf("aauth: audit entry %s: %w", name, err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(value, &object); err != nil {
		return fmt.Errorf("aauth: audit entry %s must be a JSON object: %w", name, err)
	}
	if object == nil {
		return fmt.Errorf("aauth: audit entry %s must be a JSON object when present", name)
	}
	return nil
}

func cloneAuditEntry(entry AuditEntry) AuditEntry {
	entry.Parameters = append(json.RawMessage(nil), entry.Parameters...)
	entry.Result = append(json.RawMessage(nil), entry.Result...)
	return entry
}
