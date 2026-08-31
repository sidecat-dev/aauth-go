package aauth_test

import (
	"testing"

	auth "gitlab.com/sidecat-dev/aauth-go"
)

func TestParsePermissionAcceptsRegisteredValues(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		value string
		want  auth.Permission
	}{
		{value: "granted", want: auth.PermissionGranted},
		{value: "denied", want: auth.PermissionDenied},
	} {
		got, err := auth.ParsePermission(test.value)
		if err != nil {
			t.Fatalf("ParsePermission(%q) = %q, %v", test.value, got, err)
		}
		if got != test.want {
			t.Fatalf("ParsePermission(%q) = %q, want %q", test.value, got, test.want)
		}
	}
}

func TestParsePermissionRejectsUnsupportedValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "unknown"} {
		got, err := auth.ParsePermission(value)
		if err == nil {
			t.Fatalf("ParsePermission(%q) = %q, nil", value, got)
		}
		if got != "" {
			t.Fatalf("ParsePermission(%q) failure returned %q, want zero value", value, got)
		}
	}
}

func TestPermissionZeroValueIsSafe(t *testing.T) {
	t.Parallel()

	var permission auth.Permission
	if permission != "" {
		t.Fatalf("zero Permission = %q", permission)
	}
	if permission == auth.PermissionGranted || permission == auth.PermissionDenied {
		t.Fatalf("zero Permission matched a registered value: %q", permission)
	}
}
