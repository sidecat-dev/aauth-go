package httpapi

import (
	"math"
	"net/http"
	"strconv"
	"time"
)

// ParseRetryAfter reads exactly one Retry-After value as nonnegative decimal
// delay-seconds or an HTTP-date measured against now. It reports false for a
// missing, empty, repeated or malformed header and for a delay that a
// time.Duration cannot represent; it never substitutes a default.
func ParseRetryAfter(values []string, now time.Time) (time.Duration, bool) {
	if len(values) != 1 || values[0] == "" {
		return 0, false
	}
	value := values[0]
	digits := true
	for _, character := range value {
		if character < '0' || character > '9' {
			digits = false
			break
		}
	}
	if digits {
		seconds, err := strconv.ParseUint(value, 10, 64)
		if err != nil || seconds > uint64(math.MaxInt64/int64(time.Second)) {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	date, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	if !date.After(now) {
		return 0, true
	}
	// Sub saturates at the largest Duration; that is not an exact delay.
	delay := date.Sub(now)
	if delay == math.MaxInt64 {
		return 0, false
	}
	return delay, true
}
