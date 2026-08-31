// Package discoveryendpoint contains the shared discovery-endpoint profile
// used by the seven standard R3 vocabularies.
package discoveryendpoint

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// ValidateStandard accepts a trimmed absolute HTTPS URI without userinfo or a
// fragment. Queries are vocabulary input and remain allowed. This validates
// endpoint syntax only; it does not retrieve or inspect the definition.
func ValidateStandard(endpoint string) error {
	if endpoint == "" || !utf8.ValidString(endpoint) || strings.TrimSpace(endpoint) != endpoint {
		return errors.New("discovery endpoint must be non-empty, trimmed UTF-8")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("parse discovery endpoint: %w", err)
	}
	if !parsed.IsAbs() || !strings.EqualFold(parsed.Scheme, "https") ||
		parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return errors.New("discovery endpoint must be an absolute HTTPS URI with an authority")
	}
	if parsed.User != nil {
		return errors.New("discovery endpoint must not contain userinfo")
	}
	if parsed.Fragment != "" || parsed.RawFragment != "" || strings.Contains(endpoint, "#") {
		return errors.New("discovery endpoint must not contain a fragment")
	}
	return nil
}

// ValidateGRPC applies the current bounded gRPC discovery profile. The R3
// draft permits either server reflection or a hosted .proto file but does not
// define a portable reflection-target URI grammar, so this implementation
// currently admits only HTTPS URLs selected by the host application.
func ValidateGRPC(endpoint string) error {
	if err := ValidateStandard(endpoint); err != nil {
		return fmt.Errorf("current gRPC discovery profile: %w", err)
	}
	return nil
}
