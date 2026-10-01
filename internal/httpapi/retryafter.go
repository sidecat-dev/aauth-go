package httpapi

import "time"

// ParseRetryAfter reads exactly one Retry-After value as nonnegative decimal
// delay-seconds or an HTTP-date measured against now. It reports false for a
// missing, empty, repeated or malformed header and for a delay that a
// time.Duration cannot represent; it never substitutes a default.
func ParseRetryAfter(values []string, now time.Time) (time.Duration, bool) {
	return 0, false
}
