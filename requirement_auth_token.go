package aauth

import (
	"errors"
	"fmt"

	"github.com/dunglas/httpsfv"
)

const authTokenRequirementToken = httpsfv.Token("auth-token")

// AuthTokenRequirement is the Core requirement that carries a resource token
// for obtaining an auth token.
type AuthTokenRequirement struct {
	ResourceToken string
}

// ParseAuthTokenRequirement parses one or more AAuth-Requirement field lines
// containing the Core auth-token requirement.
func ParseAuthTokenRequirement(values []string) (AuthTokenRequirement, error) {
	dictionary, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return AuthTokenRequirement{}, fmt.Errorf("aauth: parse AAuth-Requirement: %w", err)
	}
	member, ok := dictionary.Get("requirement")
	if !ok {
		return AuthTokenRequirement{}, errors.New("aauth: AAuth-Requirement requires a requirement member")
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return AuthTokenRequirement{}, errors.New("aauth: AAuth-Requirement requirement member must be an item")
	}
	requirement, ok := item.Value.(httpsfv.Token)
	if !ok {
		return AuthTokenRequirement{}, errors.New("aauth: AAuth-Requirement requirement value must be a token")
	}
	if requirement != authTokenRequirementToken {
		return AuthTokenRequirement{}, fmt.Errorf("aauth: AAuth-Requirement requirement is %q, not auth-token", requirement)
	}

	resourceTokenValue, ok := item.Params.Get("resource-token")
	if !ok {
		return AuthTokenRequirement{}, errors.New("aauth: auth-token requirement requires resource-token")
	}
	resourceToken, ok := resourceTokenValue.(string)
	if !ok || resourceToken == "" {
		return AuthTokenRequirement{}, errors.New("aauth: auth-token requirement resource-token must be a non-empty string")
	}

	return AuthTokenRequirement{ResourceToken: resourceToken}, nil
}

// FormatAuthTokenRequirement returns the canonical AAuth-Requirement field
// value for a Core auth-token requirement.
func FormatAuthTokenRequirement(value AuthTokenRequirement) (string, error) {
	if value.ResourceToken == "" {
		return "", errors.New("aauth: auth-token requirement resource-token is required")
	}

	requirement := httpsfv.NewItem(authTokenRequirementToken)
	requirement.Params.Add("resource-token", value.ResourceToken)
	dictionary := httpsfv.NewDictionary()
	dictionary.Add("requirement", requirement)

	formatted, err := httpsfv.Marshal(dictionary)
	if err != nil {
		return "", fmt.Errorf("aauth: format AAuth-Requirement: %w", err)
	}
	return formatted, nil
}
