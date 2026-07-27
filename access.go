package aauth

import (
	"errors"
	"regexp"
	"strings"
)

var accessTokenPattern = regexp.MustCompile(`^[A-Za-z0-9\-._~+/]+={0,}$`)

// ValidateAccessToken enforces the RFC 9110 token68 shape used by
// AAuth-Access and Authorization: AAuth.
func ValidateAccessToken(token string) error {
	if token == "" || !accessTokenPattern.MatchString(token) {
		return errors.New("aauth: access token must be a non-empty token68")
	}
	if padding := strings.IndexByte(token, '='); padding >= 0 &&
		strings.Trim(token[padding:], "=") != "" {
		return errors.New("aauth: access-token padding is invalid")
	}
	return nil
}

// AccessAuthorization formats the proof-bound Authorization field.
func AccessAuthorization(token string) (string, error) {
	if err := ValidateAccessToken(token); err != nil {
		return "", err
	}
	return "AAuth " + token, nil
}

// ParseAccessAuthorization parses one AAuth credential.
func ParseAccessAuthorization(header string) (string, error) {
	separator := strings.IndexByte(header, ' ')
	if separator < 0 || !strings.EqualFold(header[:separator], "AAuth") {
		return "", errors.New("aauth: Authorization does not use the AAuth scheme")
	}
	token := header[separator+1:]
	if strings.ContainsAny(token, " \t\r\n,") {
		return "", errors.New("aauth: Authorization contains multiple or malformed credentials")
	}
	if err := ValidateAccessToken(token); err != nil {
		return "", err
	}
	return token, nil
}
