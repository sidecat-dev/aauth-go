package aauth

import (
	"errors"
	"fmt"
	"strings"
)

// ValidateScopeValue validates one OAuth scope-token value. Scope values are
// visible ASCII other than quotation mark and backslash.
func ValidateScopeValue(value string) error {
	if value == "" {
		return errors.New("aauth: scope value is required")
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
			return fmt.Errorf("aauth: scope value %q is invalid", value)
		}
	}
	return nil
}

// ParseScope validates and splits one space-delimited OAuth scope value.
func ParseScope(value string) ([]string, error) {
	values := strings.Fields(value)
	if len(values) == 0 || strings.Join(values, " ") != value {
		return nil, errors.New("aauth: scope must contain space-delimited scope values")
	}
	seen := make(map[string]struct{}, len(values))
	for _, item := range values {
		if err := ValidateScopeValue(item); err != nil {
			return nil, err
		}
		if _, duplicate := seen[item]; duplicate {
			return nil, fmt.Errorf("aauth: scope value %q is duplicated", item)
		}
		seen[item] = struct{}{}
	}
	return values, nil
}
