package aauth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Tool is a human-readable tool declaration in a mission proposal or approval.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// MissionProposal is the agent's requested mission.
type MissionProposal struct {
	Description string `json:"description"`
	Tools       []Tool `json:"tools,omitempty"`
}

// MissionDecision is the deployment-owned result of approving a proposal.
type MissionDecision struct {
	Description  string
	Tools        []Tool
	Capabilities []string
}

// MissionReference binds later protocol messages to exact approved bytes.
type MissionReference struct {
	Approver string `json:"approver"`
	S256     string `json:"s256"`
}

// ApprovedMission retains the exact bytes returned by the person server.
type ApprovedMission struct {
	Reference MissionReference
	Bytes     []byte
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
	decoded, err := base64.RawURLEncoding.DecodeString(reference.S256)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("aauth: mission s256 must be an unpadded base64url SHA-256 digest")
	}
	return nil
}

// Header serializes the AAuth-Mission profile used by the current draft.
func (reference MissionReference) Header() (string, error) {
	if err := reference.Validate(); err != nil {
		return "", err
	}
	return `approver=` + strconv.Quote(reference.Approver) + `; s256=` + strconv.Quote(reference.S256), nil
}

var missionParameterPattern = regexp.MustCompile(`(?i)(approver|s256)\s*=\s*("(?:[^"\\]|\\.)*")`)

// ParseMissionHeader parses the two required mission parameters, accepting
// folding whitespace while rejecting duplicates and unknown residue.
func ParseMissionHeader(header string) (MissionReference, error) {
	var reference MissionReference
	seen := map[string]bool{}
	matches := missionParameterPattern.FindAllStringSubmatchIndex(header, -1)
	if len(matches) != 2 {
		return reference, errors.New("aauth: AAuth-Mission must contain approver and s256")
	}
	residue := header
	for _, match := range matches {
		name := strings.ToLower(header[match[2]:match[3]])
		if seen[name] {
			return reference, fmt.Errorf("aauth: duplicate AAuth-Mission parameter %q", name)
		}
		seen[name] = true
		quoted := header[match[4]:match[5]]
		value, err := strconv.Unquote(quoted)
		if err != nil {
			return reference, fmt.Errorf("aauth: decode AAuth-Mission %s: %w", name, err)
		}
		switch name {
		case "approver":
			reference.Approver = value
		case "s256":
			reference.S256 = value
		}
		residue = strings.Replace(residue, header[match[0]:match[1]], "", 1)
	}
	residue = strings.Map(func(character rune) rune {
		switch character {
		case ';', ' ', '\t', '\r', '\n':
			return -1
		default:
			return character
		}
	}, residue)
	if residue != "" {
		return reference, errors.New("aauth: AAuth-Mission contains unsupported syntax")
	}
	if !seen["approver"] || !seen["s256"] {
		return reference, errors.New("aauth: AAuth-Mission must contain approver and s256")
	}
	return reference, reference.Validate()
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
