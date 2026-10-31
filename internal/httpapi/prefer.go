package httpapi

import (
	"math"
	"strconv"
	"strings"
	"time"
)

// ParsePreferWait reads the RFC 7240 wait preference from Prefer field
// values. It reports false when no value names wait or the first one that
// does is not nonnegative decimal seconds. Preference names compare
// case-insensitively; other preferences and their parameters are ignored.
func ParsePreferWait(values []string) (time.Duration, bool) {
	for _, value := range values {
		for _, preference := range strings.Split(value, ",") {
			token, _, _ := strings.Cut(preference, ";")
			name, raw, hasValue := strings.Cut(strings.TrimSpace(token), "=")
			if !strings.EqualFold(strings.TrimSpace(name), "wait") {
				continue
			}
			raw = strings.Trim(strings.TrimSpace(raw), `"`)
			if !hasValue || raw == "" {
				return 0, false
			}
			seconds, err := strconv.ParseUint(raw, 10, 64)
			if err != nil || seconds > uint64(math.MaxInt64/int64(time.Second)) {
				return 0, false
			}
			return time.Duration(seconds) * time.Second, true
		}
	}
	return 0, false
}
