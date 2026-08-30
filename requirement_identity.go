package aauth

import (
	"errors"
	"fmt"

	"github.com/dunglas/httpsfv"
)

const (
	agentTokenRequirementToken  = httpsfv.Token("agent-token")
	personTokenRequirementToken = httpsfv.Token("person-token")
)

// FormatAgentTokenRequirement returns the canonical parameterless
// agent-token AAuth-Requirement field value.
func FormatAgentTokenRequirement() string { return "requirement=agent-token" }

// ParseAgentTokenRequirement verifies an agent-token AAuth-Requirement field.
// Unknown parameters are ignored as required by AAuth Core.
func ParseAgentTokenRequirement(values []string) error {
	return parseIdentityTokenRequirement(values, agentTokenRequirementToken)
}

// FormatPersonTokenRequirement returns the canonical parameterless
// person-token AAuth-Requirement field value.
func FormatPersonTokenRequirement() string { return "requirement=person-token" }

// ParsePersonTokenRequirement verifies a person-token AAuth-Requirement field.
// Unknown parameters are ignored as required by AAuth Core.
func ParsePersonTokenRequirement(values []string) error {
	return parseIdentityTokenRequirement(values, personTokenRequirementToken)
}

func parseIdentityTokenRequirement(values []string, expected httpsfv.Token) error {
	dictionary, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return fmt.Errorf("aauth: parse AAuth-Requirement: %w", err)
	}
	member, ok := dictionary.Get("requirement")
	if !ok {
		return errors.New("aauth: AAuth-Requirement requires a requirement member")
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return errors.New("aauth: AAuth-Requirement requirement member must be an item")
	}
	requirement, ok := item.Value.(httpsfv.Token)
	if !ok {
		return errors.New("aauth: AAuth-Requirement requirement value must be a token")
	}
	if requirement != expected {
		return fmt.Errorf("aauth: AAuth-Requirement requirement is %q, not %s", requirement, expected)
	}
	return nil
}
