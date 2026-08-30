package aauth

import (
	"errors"
	"fmt"
	"time"

	"github.com/dunglas/httpsfv"
)

// ParseCapabilities parses the AAuth-Capabilities field as an RFC 8941 List
// of Tokens. Parameters on capability items are extension data and are
// ignored. An absent field means that the Agent declared no capabilities.
func ParseCapabilities(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	list, err := httpsfv.UnmarshalList(values)
	if err != nil {
		return nil, fmt.Errorf("aauth: parse AAuth-Capabilities: %w", err)
	}
	if len(list) == 0 {
		return nil, errors.New("aauth: AAuth-Capabilities must not be empty")
	}
	capabilities := make([]string, 0, len(list))
	for _, member := range list {
		item, ok := member.(httpsfv.Item)
		if !ok {
			return nil, errors.New("aauth: AAuth-Capabilities members must be tokens")
		}
		value, ok := item.Value.(httpsfv.Token)
		if !ok || value == "" {
			return nil, errors.New("aauth: AAuth-Capabilities members must be non-empty tokens")
		}
		for _, name := range item.Params.Names() {
			parameter, _ := item.Params.Get(name)
			switch parameter.(type) {
			case time.Time, httpsfv.DisplayString:
				return nil, fmt.Errorf("aauth: AAuth-Capabilities parameter %q uses a type outside RFC 8941", name)
			}
		}
		capabilities = append(capabilities, string(value))
	}
	return capabilities, nil
}

// FormatCapabilities returns one canonical AAuth-Capabilities field value.
func FormatCapabilities(capabilities []string) (string, error) {
	if len(capabilities) == 0 {
		return "", errors.New("aauth: AAuth-Capabilities requires at least one value")
	}
	list := make(httpsfv.List, 0, len(capabilities))
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if capability == "" {
			return "", errors.New("aauth: AAuth-Capabilities contains an empty value")
		}
		if _, duplicate := seen[capability]; duplicate {
			return "", fmt.Errorf("aauth: AAuth-Capabilities repeats %q", capability)
		}
		seen[capability] = struct{}{}
		list = append(list, httpsfv.NewItem(httpsfv.Token(capability)))
	}
	formatted, err := httpsfv.Marshal(list)
	if err != nil {
		return "", fmt.Errorf("aauth: format AAuth-Capabilities: %w", err)
	}
	return formatted, nil
}
