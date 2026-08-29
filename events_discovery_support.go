package aauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maximumDiscoveryRetention = 24 * time.Hour
	defaultDiscoveryFreshness = 5 * time.Minute
)

// EgressAdmitter owns the current Events discovery egress decision. The
// Signature-Key resolver has its own identically shaped package contract.
type EgressAdmitter func(ctx context.Context, endpoint string) error

func validateDiscoveryURL(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("URL must be absolute https")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return errors.New("URL must not contain userinfo or fragment")
	}
	return nil
}

func cacheFreshness(cacheControl string) time.Duration {
	directives := strings.Split(cacheControl, ",")
	for _, directive := range directives {
		name, _, _ := strings.Cut(strings.TrimSpace(strings.ToLower(directive)), "=")
		if name == "no-store" || name == "no-cache" {
			return 0
		}
	}
	for _, directive := range directives {
		name, value, found := strings.Cut(strings.TrimSpace(strings.ToLower(directive)), "=")
		if !found || name != "max-age" {
			continue
		}
		seconds, err := strconv.ParseInt(strings.Trim(value, `"`), 10, 64)
		if err != nil || seconds < 0 {
			break
		}
		duration := time.Duration(seconds) * time.Second
		if duration > maximumDiscoveryRetention {
			return maximumDiscoveryRetention
		}
		return duration
	}
	return defaultDiscoveryFreshness
}
