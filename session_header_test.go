package aauth_test

import (
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestAAuthAccessHeaderRoundTripsToken68(t *testing.T) {
	t.Parallel()

	for _, token := range []string{
		"opaque-session-token",
		"AbC012._~+/==",
	} {
		formatted, err := aauth.FormatAAuthAccess(token)
		if err != nil {
			t.Fatalf("FormatAAuthAccess(%q): %v", token, err)
		}
		if formatted != token {
			t.Fatalf("FormatAAuthAccess(%q) = %q", token, formatted)
		}
		parsed, err := aauth.ParseAAuthAccess([]string{formatted})
		if err != nil {
			t.Fatalf("ParseAAuthAccess(%q): %v", formatted, err)
		}
		if parsed != token {
			t.Fatalf("ParseAAuthAccess(%q) = %q", formatted, parsed)
		}
	}
}

func TestAAuthAccessHeaderRejectsInvalidOrAmbiguousCredentials(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "missing"},
		{name: "empty", values: []string{""}},
		{name: "multiple", values: []string{"first", "second"}},
		{name: "leading whitespace", values: []string{" token"}},
		{name: "embedded whitespace", values: []string{"opaque token"}},
		{name: "control", values: []string{"opaque\ttoken"}},
		{name: "invalid character", values: []string{"opaque?token"}},
		{name: "leading padding", values: []string{"=opaque"}},
		{name: "embedded padding", values: []string{"opaque=token"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := aauth.ParseAAuthAccess(test.values); err == nil {
				t.Fatalf("ParseAAuthAccess(%q) succeeded", test.values)
			}
		})
	}
}

func TestSessionAuthorizationRoundTripsAAuthCredential(t *testing.T) {
	t.Parallel()

	formatted, err := aauth.FormatSessionAuthorization("opaque-session-token")
	if err != nil {
		t.Fatal(err)
	}
	if formatted != "AAuth opaque-session-token" {
		t.Fatalf("FormatSessionAuthorization = %q", formatted)
	}
	for _, value := range []string{
		formatted,
		"aauth opaque-session-token",
		"AAuth   opaque-session-token",
		"AAuth AbC012._~+/==",
	} {
		parsed, err := aauth.ParseSessionAuthorization([]string{value})
		if err != nil {
			t.Fatalf("ParseSessionAuthorization(%q): %v", value, err)
		}
		want := "opaque-session-token"
		if value == "AAuth AbC012._~+/==" {
			want = "AbC012._~+/=="
		}
		if parsed != want {
			t.Fatalf("ParseSessionAuthorization(%q) = %q", value, parsed)
		}
	}
}

func TestSessionAuthorizationRejectsWrongSchemeAndAmbiguity(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "missing"},
		{name: "empty", values: []string{""}},
		{name: "multiple", values: []string{"AAuth first", "AAuth second"}},
		{name: "missing credential", values: []string{"AAuth"}},
		{name: "wrong scheme", values: []string{"Bearer opaque-session-token"}},
		{name: "extra credential", values: []string{"AAuth first second"}},
		{name: "leading whitespace", values: []string{" AAuth opaque-session-token"}},
		{name: "trailing whitespace", values: []string{"AAuth opaque-session-token "}},
		{name: "credential whitespace", values: []string{"AAuth opaque token"}},
		{name: "credential control", values: []string{"AAuth opaque\ttoken"}},
		{name: "invalid token", values: []string{"AAuth opaque?token"}},
		{name: "tab separator", values: []string{"AAuth\topaque-session-token"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := aauth.ParseSessionAuthorization(test.values); err == nil {
				t.Fatalf("ParseSessionAuthorization(%q) succeeded", test.values)
			}
		})
	}
}
