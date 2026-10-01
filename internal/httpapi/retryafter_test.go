package httpapi_test

import (
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
)

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for name, test := range map[string]struct {
		values []string
		want   time.Duration
		ok     bool
	}{
		"seconds":              {[]string{"120"}, 120 * time.Second, true},
		"zero":                 {[]string{"0"}, 0, true},
		"future date":          {[]string{"Thu, 01 Oct 2026 12:01:30 GMT"}, 90 * time.Second, true},
		"past date":            {[]string{"Thu, 01 Oct 2026 11:00:00 GMT"}, 0, true},
		"date equal to now":    {[]string{"Thu, 01 Oct 2026 12:00:00 GMT"}, 0, true},
		"missing":              {nil, 0, false},
		"empty":                {[]string{""}, 0, false},
		"repeated":             {[]string{"1", "2"}, 0, false},
		"negative":             {[]string{"-1"}, 0, false},
		"signed":               {[]string{"+1"}, 0, false},
		"fraction":             {[]string{"1.5"}, 0, false},
		"spaced":               {[]string{" 1"}, 0, false},
		"seconds overflow":     {[]string{"9223372037"}, 0, false},
		"huge seconds":         {[]string{"99999999999999999999"}, 0, false},
		"not a date":           {[]string{"soon"}, 0, false},
		"unrepresentable date": {[]string{"Fri, 31 Dec 9999 23:59:59 GMT"}, 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := httpapi.ParseRetryAfter(test.values, now)
			if ok != test.ok || got != test.want {
				t.Fatalf("ParseRetryAfter(%q) = %v, %t; want %v, %t", test.values, got, ok, test.want, test.ok)
			}
		})
	}
}
