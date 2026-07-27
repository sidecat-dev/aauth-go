package aauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxDeferredResponseBytes = 1 << 20

type PollingErrorCode string

const (
	PollingDenied      PollingErrorCode = "denied"
	PollingAbandoned   PollingErrorCode = "abandoned"
	PollingExpired     PollingErrorCode = "expired"
	PollingInvalidCode PollingErrorCode = "invalid_code"
	PollingSlowDown    PollingErrorCode = "slow_down"
	PollingServerError PollingErrorCode = "server_error"
)

// GeneratePendingID reads 128 random bits and returns an unguessable URL-safe
// identifier suitable for a pending continuation path.
func GeneratePendingID(random io.Reader) (string, error) {
	if random == nil {
		return "", errors.New("aauth: pending-id randomness is required")
	}
	var entropy [16]byte
	if _, err := io.ReadFull(random, entropy[:]); err != nil {
		return "", fmt.Errorf("aauth: generate pending id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(entropy[:]), nil
}

// DeferredResponse is the validated continuation state from an AAuth 202.
type DeferredResponse struct {
	Location    string
	RetryAfter  time.Duration
	Status      string
	Requirement *Requirement
}

// ParseDeferredResponse validates an AAuth 202 response and consumes its JSON
// body. The pending URL is resolved against the responding request and must
// remain on that HTTPS origin.
func ParseDeferredResponse(response *http.Response) (DeferredResponse, error) {
	var deferred DeferredResponse
	if response == nil || response.Request == nil || response.Request.URL == nil || response.Body == nil {
		return deferred, errors.New("aauth: deferred response and originating request are required")
	}
	if response.StatusCode != http.StatusAccepted {
		return deferred, fmt.Errorf("aauth: deferred response status is %d, not 202", response.StatusCode)
	}
	locationValues := response.Header.Values("Location")
	if len(locationValues) != 1 {
		return deferred, errors.New("aauth: deferred response requires exactly one Location")
	}
	location, err := resolvePendingLocation(response.Request.URL, locationValues[0])
	if err != nil {
		return deferred, err
	}
	retryValues := response.Header.Values("Retry-After")
	if len(retryValues) != 1 {
		return deferred, errors.New("aauth: deferred response requires exactly one Retry-After")
	}
	retrySeconds, err := strconv.ParseUint(strings.TrimSpace(retryValues[0]), 10, 31)
	if err != nil {
		return deferred, errors.New("aauth: deferred Retry-After must be non-negative seconds")
	}
	if !cacheControlNoStore(response.Header.Values("Cache-Control")) {
		return deferred, errors.New("aauth: deferred response must use Cache-Control: no-store")
	}

	requirementValues := response.Header.Values("AAuth-Requirement")
	if len(requirementValues) > 1 {
		return deferred, errors.New("aauth: deferred response carries more than one AAuth-Requirement")
	}
	var requirement *Requirement
	if len(requirementValues) == 1 {
		parsed, err := ParseRequirementHeader(requirementValues[0])
		if err != nil {
			return deferred, err
		}
		requirement = &parsed
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxDeferredResponseBytes+1))
	if err != nil {
		return deferred, fmt.Errorf("aauth: read deferred response: %w", err)
	}
	if len(body) > maxDeferredResponseBytes {
		return deferred, errors.New("aauth: deferred response is too large")
	}
	var result struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return deferred, fmt.Errorf("aauth: decode deferred response: %w", err)
	}
	if result.Status == "" {
		return deferred, errors.New("aauth: deferred response status is required")
	}
	if result.Status != "pending" && result.Status != "interacting" {
		result.Status = "pending"
	}
	return DeferredResponse{
		Location:    location.String(),
		RetryAfter:  time.Duration(retrySeconds) * time.Second,
		Status:      result.Status,
		Requirement: requirement,
	}, nil
}

func resolvePendingLocation(origin *url.URL, raw string) (*url.URL, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return nil, errors.New("aauth: pending Location is invalid")
	}
	reference, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("aauth: parse pending Location: %w", err)
	}
	resolved := origin.ResolveReference(reference)
	if err := ValidatePollingEndpoint(resolved.String()); err != nil {
		return nil, err
	}
	if !sameOrigin(origin, resolved) {
		return nil, errors.New("aauth: pending Location must use the responding server origin")
	}
	return resolved, nil
}

// ValidatePollingEndpoint validates an absolute HTTPS continuation URL. Query
// parameters are permitted because Location is server-selected.
func ValidatePollingEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("aauth: parse polling endpoint: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("aauth: polling endpoint must be an HTTPS URL without userinfo or fragment")
	}
	if parsed.Hostname() != strings.ToLower(parsed.Hostname()) {
		return errors.New("aauth: polling endpoint host must be lowercase")
	}
	return nil
}

func sameOrigin(left, right *url.URL) bool {
	if !strings.EqualFold(left.Scheme, right.Scheme) ||
		!strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	return effectivePort(left) == effectivePort(right)
}

func effectivePort(parsed *url.URL) string {
	if port := parsed.Port(); port != "" {
		return port
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

func cacheControlNoStore(values []string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
				return true
			}
		}
	}
	return false
}
