package aauth

import (
	"errors"
	"fmt"

	"github.com/dunglas/httpsfv"
)

// Requirement is an extension-friendly AAuth requirement token.
type Requirement string

const (
	RequirementInteraction   Requirement = "interaction"
	RequirementApproval      Requirement = "approval"
	RequirementClarification Requirement = "clarification"
	RequirementClaims        Requirement = "claims"
	RequirementAgentToken    Requirement = "agent-token"
	RequirementPersonToken   Requirement = "person-token"
	RequirementAuthToken     Requirement = "auth-token"
)

// ParseRequirement returns the generic requirement token while leaving
// requirement-specific parameters to the corresponding focused parser.
func ParseRequirement(values []string) (Requirement, error) {
	dictionary, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return "", fmt.Errorf("aauth: parse AAuth-Requirement: %w", err)
	}
	member, ok := dictionary.Get("requirement")
	if !ok {
		return "", errors.New("aauth: AAuth-Requirement requires a requirement member")
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return "", errors.New("aauth: AAuth-Requirement requirement member must be an item")
	}
	value, ok := item.Value.(httpsfv.Token)
	if !ok || value == "" {
		return "", errors.New("aauth: AAuth-Requirement requirement value must be a token")
	}
	return Requirement(value), nil
}
