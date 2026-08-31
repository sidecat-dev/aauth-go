package budgets

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dunglas/httpsfv"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// ParseAuthTokenRequirement parses the Core auth-token requirement and its
// required Budget reason parameter. Unrelated extension parameters remain
// ignored as required by the base extension model.
func ParseAuthTokenRequirement(values []string) (aauth.AuthTokenRequirement, Reason, error) {
	core, reason, present, err := ParseOptionalAuthTokenRequirement(values)
	if err != nil {
		return aauth.AuthTokenRequirement{}, "", err
	}
	if !present {
		return aauth.AuthTokenRequirement{}, "", errors.New("budgets: Budget auth-token requirement requires reason")
	}
	return core, reason, nil
}

// ParseOptionalAuthTokenRequirement parses the Core auth-token requirement
// and, when present, one typed Budget reason. A missing reason is the ordinary
// Core step-up shape; an unknown or malformed present reason fails.
func ParseOptionalAuthTokenRequirement(values []string) (aauth.AuthTokenRequirement, Reason, bool, error) {
	core, err := aauth.ParseAuthTokenRequirement(values)
	if err != nil {
		return aauth.AuthTokenRequirement{}, "", false, err
	}
	dictionary, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return aauth.AuthTokenRequirement{}, "", false, fmt.Errorf("budgets: parse AAuth-Requirement: %w", err)
	}
	member, present := dictionary.Get("requirement")
	if !present {
		return aauth.AuthTokenRequirement{}, "", false, errors.New("budgets: AAuth-Requirement requires a requirement member")
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return aauth.AuthTokenRequirement{}, "", false, errors.New("budgets: AAuth-Requirement requirement member must be an item")
	}
	for _, name := range item.Params.Names() {
		for _, canonical := range []string{"resource-token", "reason"} {
			if name != canonical && strings.EqualFold(name, canonical) {
				return aauth.AuthTokenRequirement{}, "", false, fmt.Errorf(
					"budgets: AAuth-Requirement parameter %q is a case variant of %q", name, canonical,
				)
			}
		}
	}
	rawReason, present := item.Params.Get("reason")
	if !present {
		return core, "", false, nil
	}
	reasonToken, ok := rawReason.(httpsfv.Token)
	if !ok {
		return aauth.AuthTokenRequirement{}, "", false, errors.New("budgets: Budget auth-token requirement reason must be a token")
	}
	reason, err := ParseReason(string(reasonToken))
	if err != nil {
		return aauth.AuthTokenRequirement{}, "", false, err
	}
	return core, reason, true, nil
}

// FormatAuthTokenRequirement formats the Core auth-token requirement with one
// typed Budget reason parameter.
func FormatAuthTokenRequirement(value aauth.AuthTokenRequirement, reason Reason) (string, error) {
	parsedReason, err := ParseReason(reason.String())
	if err != nil {
		return "", err
	}
	core, err := aauth.FormatAuthTokenRequirement(value)
	if err != nil {
		return "", err
	}
	dictionary, err := httpsfv.UnmarshalDictionary([]string{core})
	if err != nil {
		return "", fmt.Errorf("budgets: parse formatted Core requirement: %w", err)
	}
	member, present := dictionary.Get("requirement")
	if !present {
		return "", errors.New("budgets: formatted Core requirement omitted requirement")
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return "", errors.New("budgets: formatted Core requirement is not an item")
	}
	item.Params.Add("reason", httpsfv.Token(parsedReason.String()))
	dictionary.Add("requirement", item)
	formatted, err := httpsfv.Marshal(dictionary)
	if err != nil {
		return "", fmt.Errorf("budgets: format AAuth-Requirement: %w", err)
	}
	return formatted, nil
}
