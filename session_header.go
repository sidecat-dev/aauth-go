package aauth

import (
	"errors"
	"fmt"
	"strings"
)

// ParseAAuthAccess validates one AAuth-Access field value and returns its
// opaque session token.
func ParseAAuthAccess(values []string) (string, error) {
	if len(values) != 1 {
		return "", errors.New("aauth: AAuth-Access requires exactly one credential")
	}
	if err := validateSessionToken(values[0]); err != nil {
		return "", fmt.Errorf("aauth: AAuth-Access: %w", err)
	}
	return values[0], nil
}

// FormatAAuthAccess validates an opaque session token for use as an
// AAuth-Access field value.
func FormatAAuthAccess(token string) (string, error) {
	if err := validateSessionToken(token); err != nil {
		return "", fmt.Errorf("aauth: AAuth-Access: %w", err)
	}
	return token, nil
}

// ParseSessionAuthorization validates one Authorization field carrying the
// AAuth scheme and returns its opaque session token.
func ParseSessionAuthorization(values []string) (string, error) {
	if len(values) != 1 {
		return "", errors.New("aauth: session Authorization requires exactly one credential")
	}
	value := values[0]
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\t\r\n") {
		return "", errors.New("aauth: session Authorization is invalid")
	}
	separator := strings.IndexByte(value, ' ')
	if separator <= 0 || !strings.EqualFold(value[:separator], "AAuth") {
		return "", errors.New("aauth: session Authorization requires the AAuth scheme")
	}
	token := strings.TrimLeft(value[separator:], " ")
	if err := validateSessionToken(token); err != nil {
		return "", fmt.Errorf("aauth: session Authorization: %w", err)
	}
	return token, nil
}

// FormatSessionAuthorization validates an opaque session token and formats an
// Authorization field value using the AAuth scheme.
func FormatSessionAuthorization(token string) (string, error) {
	if err := validateSessionToken(token); err != nil {
		return "", fmt.Errorf("aauth: session Authorization: %w", err)
	}
	return "AAuth " + token, nil
}

func validateSessionToken(token string) error {
	if token == "" {
		return errors.New("session token is empty")
	}
	padding := false
	for _, character := range token {
		if character == '=' {
			padding = true
			continue
		}
		if padding {
			return errors.New("session token has embedded padding")
		}
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("-._~+/", character) {
			continue
		}
		return errors.New("session token is not token68")
	}
	if token[0] == '=' {
		return errors.New("session token has no value before padding")
	}
	return nil
}
