package aauth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/dunglas/httpsfv"
)

const interactionRequirementToken = httpsfv.Token("interaction")

const crockfordInteractionAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// InteractionRequirement tells an agent where a person can complete an
// interaction and which human-readable code correlates that interaction with
// the pending request. The code is not an authorization credential.
type InteractionRequirement struct {
	URL  string
	Code string
}

// ParseInteractionRequirement parses one or more AAuth-Requirement field lines
// containing the Core interaction requirement.
func ParseInteractionRequirement(values []string) (InteractionRequirement, error) {
	dictionary, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return InteractionRequirement{}, fmt.Errorf("aauth: parse AAuth-Requirement: %w", err)
	}
	member, ok := dictionary.Get("requirement")
	if !ok {
		return InteractionRequirement{}, errors.New("aauth: AAuth-Requirement requires a requirement member")
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return InteractionRequirement{}, errors.New("aauth: AAuth-Requirement requirement member must be an item")
	}
	requirement, ok := item.Value.(httpsfv.Token)
	if !ok {
		return InteractionRequirement{}, errors.New("aauth: AAuth-Requirement requirement value must be a token")
	}
	if requirement != interactionRequirementToken {
		return InteractionRequirement{}, fmt.Errorf("aauth: AAuth-Requirement requirement is %q, not interaction", requirement)
	}

	interactionURL, err := interactionStringParameter(item, "url")
	if err != nil {
		return InteractionRequirement{}, err
	}
	if err := validateInteractionURL(interactionURL); err != nil {
		return InteractionRequirement{}, fmt.Errorf("aauth: interaction requirement url: %w", err)
	}
	code, err := interactionStringParameter(item, "code")
	if err != nil {
		return InteractionRequirement{}, err
	}
	if err := validateEmittedInteractionCode(code); err != nil {
		return InteractionRequirement{}, err
	}
	return InteractionRequirement{URL: interactionURL, Code: code}, nil
}

// FormatInteractionRequirement returns the canonical AAuth-Requirement field
// value for a Core interaction requirement.
func FormatInteractionRequirement(value InteractionRequirement) (string, error) {
	if err := validateInteractionURL(value.URL); err != nil {
		return "", fmt.Errorf("aauth: interaction requirement url: %w", err)
	}
	if err := validateEmittedInteractionCode(value.Code); err != nil {
		return "", err
	}
	requirement := httpsfv.NewItem(interactionRequirementToken)
	requirement.Params.Add("url", value.URL)
	requirement.Params.Add("code", value.Code)
	dictionary := httpsfv.NewDictionary()
	dictionary.Add("requirement", requirement)
	formatted, err := httpsfv.Marshal(dictionary)
	if err != nil {
		return "", fmt.Errorf("aauth: format AAuth-Requirement: %w", err)
	}
	return formatted, nil
}

// MatchInteractionCode compares an emitted interaction code with human input.
// Input comparison is case-insensitive, ignores grouping hyphens, and accepts
// the Crockford transcription aliases I/L for 1 and O for 0.
func MatchInteractionCode(expected, entered string) bool {
	if err := validateEmittedInteractionCode(expected); err != nil {
		return false
	}
	want := normalizeInteractionCode(expected, false)
	got, err := NormalizeInteractionCode(entered)
	if err != nil || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// NormalizeInteractionCode prepares human-entered Crockford base32 for
// comparison. It removes grouping hyphens, folds case, and accepts I/L for 1
// and O for 0. The returned value contains at least eight canonical symbols.
func NormalizeInteractionCode(code string) (string, error) {
	normalized := normalizeInteractionCode(code, true)
	if len(normalized) < 8 {
		return "", errors.New("aauth: interaction code must contain at least eight Crockford base32 symbols")
	}
	for index := 0; index < len(normalized); index++ {
		if !strings.ContainsRune(crockfordInteractionAlphabet, rune(normalized[index])) {
			return "", errors.New("aauth: interaction code must use Crockford base32")
		}
	}
	return normalized, nil
}

func interactionStringParameter(item httpsfv.Item, name string) (string, error) {
	value, ok := item.Params.Get(name)
	if !ok {
		return "", fmt.Errorf("aauth: interaction requirement requires %s", name)
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return "", fmt.Errorf("aauth: interaction requirement %s must be a non-empty string", name)
	}
	return text, nil
}

func validateInteractionURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("parse interaction URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("interaction URL must be absolute and use https")
	}
	if parsed.User != nil {
		return errors.New("interaction URL must not contain userinfo")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return errors.New("interaction URL must not contain a query or fragment")
	}
	return nil
}

func validateEmittedInteractionCode(code string) error {
	normalized := normalizeInteractionCode(code, false)
	if len(normalized) < 8 {
		return errors.New("aauth: interaction requirement code must contain at least eight Crockford base32 symbols")
	}
	for index := 0; index < len(normalized); index++ {
		if !strings.ContainsRune(crockfordInteractionAlphabet, rune(normalized[index])) {
			return errors.New("aauth: interaction requirement code must use uppercase Crockford base32")
		}
	}
	return nil
}

func normalizeInteractionCode(code string, acceptAliases bool) string {
	code = strings.ReplaceAll(code, "-", "")
	if acceptAliases {
		code = strings.ToUpper(code)
		code = strings.NewReplacer("I", "1", "L", "1", "O", "0").Replace(code)
	}
	return code
}
