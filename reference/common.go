// Package reference provides small, deployable AAuth role handlers and an
// agent client built exclusively on the public aauth package.
package reference

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

const maxJSONBody = 1 << 20

func decodeJSON(response http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(response, request.Body, maxJSONBody)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("decode JSON: multiple values")
		}
		return fmt.Errorf("decode JSON trailing data: %w", err)
	}
	return nil
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeProblem(response http.ResponseWriter, status int, code string, err error) {
	response.Header().Set("Content-Type", "application/problem+json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	detail := code
	if err != nil {
		detail = err.Error()
	}
	_ = json.NewEncoder(response).Encode(map[string]any{
		"type":   "about:blank",
		"title":  http.StatusText(status),
		"status": status,
		"error":  code,
		"detail": detail,
	})
}

func parseScopes(scope string) ([]string, error) {
	values := strings.Fields(scope)
	if len(values) == 0 {
		return nil, errors.New("scope is required")
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return nil, fmt.Errorf("duplicate scope %q", value)
		}
		seen[value] = true
	}
	return values, nil
}

func scopesContained(granted, requested []string) bool {
	allowed := make(map[string]bool, len(requested))
	for _, value := range requested {
		allowed[value] = true
	}
	for _, value := range granted {
		if !allowed[value] {
			return false
		}
	}
	return true
}

func endpointIdentifier(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse endpoint: %w", err)
	}
	identifier := parsed.Scheme + "://" + parsed.Host
	if err := aauth.ValidateServerIdentifier(identifier); err != nil {
		return "", err
	}
	return identifier, nil
}
