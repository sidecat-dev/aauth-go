package aauth

import (
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode"
)

const maxRequirementHeaderBytes = 16 << 10

type RequirementType string

const (
	RequirementAgentToken    RequirementType = "agent-token"
	RequirementPersonToken   RequirementType = "person-token"
	RequirementAuthToken     RequirementType = "auth-token"
	RequirementInteraction   RequirementType = "interaction"
	RequirementApproval      RequirementType = "approval"
	RequirementClarification RequirementType = "clarification"
	RequirementClaims        RequirementType = "claims"
)

var ErrRequirementInvalid = errors.New("aauth: requirement is invalid")

// Requirement is the understood projection of an AAuth-Requirement
// Structured Field Dictionary. Unknown requirement values remain parseable so
// callers can surface or poll an extension they do not implement.
type Requirement struct {
	Type            RequirementType
	ResourceToken   string
	InteractionURL  string
	InteractionCode string
}

// FormatRequirementHeader serializes one AAuth-Requirement dictionary member.
func FormatRequirementHeader(requirement Requirement) (string, error) {
	if err := validateRequirement(requirement); err != nil {
		return "", err
	}
	header := "requirement=" + string(requirement.Type)
	switch requirement.Type {
	case RequirementAuthToken:
		header += `; resource-token=` + quoteStructuredString(requirement.ResourceToken)
	case RequirementInteraction:
		header += `; url=` + quoteStructuredString(requirement.InteractionURL)
		header += `; code=` + quoteStructuredString(requirement.InteractionCode)
	}
	return header, nil
}

// ParseRequirementHeader parses the AAuth-Requirement dictionary. Unknown
// parameters on the requirement member are ignored.
func ParseRequirementHeader(header string) (Requirement, error) {
	if header == "" || len(header) > maxRequirementHeaderBytes {
		return Requirement{}, fmt.Errorf("%w: header size", ErrRequirementInvalid)
	}
	members, err := parseRequirementDictionary(header)
	if err != nil {
		return Requirement{}, err
	}
	item, ok := members["requirement"]
	if !ok || item.quoted || item.value == "" {
		return Requirement{}, fmt.Errorf("%w: requirement member", ErrRequirementInvalid)
	}
	if len(members) != 1 {
		return Requirement{}, fmt.Errorf("%w: unexpected dictionary member", ErrRequirementInvalid)
	}

	requirement := Requirement{Type: RequirementType(item.value)}
	switch requirement.Type {
	case RequirementAuthToken:
		requirement.ResourceToken, err = requiredStringParameter(item.params, "resource-token")
	case RequirementInteraction:
		requirement.InteractionURL, err = requiredStringParameter(item.params, "url")
		if err == nil {
			requirement.InteractionCode, err = requiredStringParameter(item.params, "code")
		}
	}
	if err != nil {
		return Requirement{}, err
	}
	if err := validateRequirement(requirement); err != nil {
		return Requirement{}, err
	}
	return requirement, nil
}

func validateRequirement(requirement Requirement) error {
	if !isStructuredToken(string(requirement.Type)) {
		return fmt.Errorf("%w: requirement type", ErrRequirementInvalid)
	}
	switch requirement.Type {
	case RequirementAuthToken:
		if requirement.ResourceToken == "" {
			return fmt.Errorf("%w: resource-token", ErrRequirementInvalid)
		}
	case RequirementInteraction:
		if err := validateInteractionURL(requirement.InteractionURL); err != nil {
			return err
		}
		if err := validateEmittedInteractionCode(requirement.InteractionCode); err != nil {
			return err
		}
	}
	return nil
}

func validateInteractionURL(raw string) error {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return fmt.Errorf("%w: interaction url", ErrRequirementInvalid)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%w: interaction url", ErrRequirementInvalid)
	}
	return nil
}

func validateEmittedInteractionCode(code string) error {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	symbols := 0
	for _, character := range code {
		if character == '-' {
			continue
		}
		if !strings.ContainsRune(alphabet, character) {
			return fmt.Errorf("%w: interaction code", ErrRequirementInvalid)
		}
		symbols++
	}
	if symbols < 8 {
		return fmt.Errorf("%w: interaction code entropy", ErrRequirementInvalid)
	}
	return nil
}

// GenerateInteractionCode reads 40 random bits and emits eight grouped
// Crockford base32 symbols.
func GenerateInteractionCode(random io.Reader) (string, error) {
	if random == nil {
		return "", errors.New("aauth: interaction-code randomness is required")
	}
	var entropy [5]byte
	if _, err := io.ReadFull(random, entropy[:]); err != nil {
		return "", fmt.Errorf("aauth: generate interaction code: %w", err)
	}
	encoding := base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)
	raw := encoding.EncodeToString(entropy[:])
	return raw[:4] + "-" + raw[4:], nil
}

// NormalizeInteractionCode prepares human-entered code text for comparison.
// Hyphens and case are ignored, and Crockford I/L/O aliases are folded.
func NormalizeInteractionCode(code string) (string, error) {
	var normalized strings.Builder
	for _, character := range code {
		switch character {
		case '-':
			continue
		case 'i', 'I', 'l', 'L':
			character = '1'
		case 'o', 'O':
			character = '0'
		default:
			character = unicode.ToUpper(character)
		}
		if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", character) {
			return "", fmt.Errorf("%w: interaction code character", ErrRequirementInvalid)
		}
		normalized.WriteRune(character)
	}
	if normalized.Len() < 8 {
		return "", fmt.Errorf("%w: interaction code entropy", ErrRequirementInvalid)
	}
	return normalized.String(), nil
}

type structuredValue struct {
	value  string
	quoted bool
	params map[string]structuredValue
}

func requiredStringParameter(parameters map[string]structuredValue, name string) (string, error) {
	value, ok := parameters[name]
	if !ok || !value.quoted || value.value == "" {
		return "", fmt.Errorf("%w: %s parameter", ErrRequirementInvalid, name)
	}
	return value.value, nil
}

func parseRequirementDictionary(header string) (map[string]structuredValue, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil, fmt.Errorf("%w: empty header", ErrRequirementInvalid)
	}
	members := make(map[string]structuredValue)
	for _, rawMember := range splitStructured(header, ',') {
		parts := splitStructured(strings.TrimSpace(rawMember), ';')
		item, err := parseStructuredItem(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, err
		}
		item.params = make(map[string]structuredValue)
		for _, rawParameter := range parts[1:] {
			parameter, err := parseStructuredItem(strings.TrimSpace(rawParameter))
			if err != nil {
				return nil, err
			}
			if _, exists := item.params[parameter.name]; exists {
				return nil, fmt.Errorf("%w: duplicate parameter", ErrRequirementInvalid)
			}
			item.params[parameter.name] = structuredValue{
				value:  parameter.value,
				quoted: parameter.quoted,
			}
		}
		if _, exists := members[item.name]; exists {
			return nil, fmt.Errorf("%w: duplicate member", ErrRequirementInvalid)
		}
		members[item.name] = structuredValue{
			value:  item.value,
			quoted: item.quoted,
			params: item.params,
		}
	}
	return members, nil
}

type structuredItem struct {
	name   string
	value  string
	quoted bool
	params map[string]structuredValue
}

func parseStructuredItem(input string) (structuredItem, error) {
	name, rawValue, found := strings.Cut(input, "=")
	name = strings.TrimSpace(name)
	if !isStructuredKey(name) {
		return structuredItem{}, fmt.Errorf("%w: member name", ErrRequirementInvalid)
	}
	if !found {
		return structuredItem{name: name, value: "?1"}, nil
	}
	rawValue = strings.TrimSpace(rawValue)
	if rawValue == "" {
		return structuredItem{}, fmt.Errorf("%w: empty value", ErrRequirementInvalid)
	}
	if strings.HasPrefix(rawValue, `"`) {
		value, err := parseStructuredString(rawValue)
		if err != nil {
			return structuredItem{}, err
		}
		return structuredItem{name: name, value: value, quoted: true}, nil
	}
	if !isStructuredToken(rawValue) {
		if !isOtherStructuredBareItem(rawValue) {
			return structuredItem{}, fmt.Errorf("%w: invalid bare item", ErrRequirementInvalid)
		}
	}
	return structuredItem{name: name, value: rawValue}, nil
}

func isOtherStructuredBareItem(value string) bool {
	if value == "?0" || value == "?1" {
		return true
	}
	if len(value) >= 2 && value[0] == ':' && value[len(value)-1] == ':' {
		_, err := base64.StdEncoding.DecodeString(value[1 : len(value)-1])
		return err == nil
	}
	number := value
	if strings.HasPrefix(number, "-") {
		number = number[1:]
	}
	if number == "" {
		return false
	}
	integer, fraction, decimal := strings.Cut(number, ".")
	if integer == "" || len(integer) > 15 || !allASCIIDigits(integer) {
		return false
	}
	if !decimal {
		return true
	}
	return fraction != "" && len(integer) <= 12 && len(fraction) <= 3 &&
		allASCIIDigits(fraction)
}

func allASCIIDigits(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func parseStructuredString(input string) (string, error) {
	if len(input) < 2 || input[0] != '"' || input[len(input)-1] != '"' {
		return "", fmt.Errorf("%w: string", ErrRequirementInvalid)
	}
	var output strings.Builder
	escaped := false
	for _, character := range input[1 : len(input)-1] {
		if escaped {
			if character != '"' && character != '\\' {
				return "", fmt.Errorf("%w: string escape", ErrRequirementInvalid)
			}
			output.WriteRune(character)
			escaped = false
			continue
		}
		switch character {
		case '\\':
			escaped = true
		case '"':
			return "", fmt.Errorf("%w: string quote", ErrRequirementInvalid)
		default:
			if character < 0x20 || character == 0x7f {
				return "", fmt.Errorf("%w: string control", ErrRequirementInvalid)
			}
			output.WriteRune(character)
		}
	}
	if escaped {
		return "", fmt.Errorf("%w: trailing escape", ErrRequirementInvalid)
	}
	return output.String(), nil
}

func quoteStructuredString(value string) string {
	var output strings.Builder
	output.WriteByte('"')
	for _, character := range value {
		if character == '\\' || character == '"' {
			output.WriteByte('\\')
		}
		output.WriteRune(character)
	}
	output.WriteByte('"')
	return output.String()
}

func splitStructured(input string, separator rune) []string {
	var parts []string
	start := 0
	quoted := false
	escaped := false
	for index, character := range input {
		if escaped {
			escaped = false
			continue
		}
		if quoted && character == '\\' {
			escaped = true
			continue
		}
		if character == '"' {
			quoted = !quoted
			continue
		}
		if !quoted && character == separator {
			parts = append(parts, input[start:index])
			start = index + 1
		}
	}
	return append(parts, input[start:])
}

func isStructuredToken(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' {
			continue
		}
		if character >= '0' && character <= '9' {
			if index == 0 {
				return false
			}
			continue
		}
		switch character {
		case '*', '/', '-', '_', '.', ':':
			if index == 0 && character != '*' {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func isStructuredKey(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character == '*' {
			continue
		}
		if index > 0 && (character >= '0' && character <= '9' ||
			character == '_' || character == '-' || character == '.') {
			continue
		}
		return false
	}
	return true
}
