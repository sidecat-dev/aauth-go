package aauth_test

import (
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestAAuthAccessToken68RoundTrip(t *testing.T) {
	t.Parallel()

	valid := []string{
		"opaque-token",
		"abc.DEF_123~+/==",
	}
	for _, token := range valid {
		token := token
		t.Run(token, func(t *testing.T) {
			authorization, err := aauth.AccessAuthorization(token)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := aauth.ParseAccessAuthorization(authorization)
			if err != nil {
				t.Fatal(err)
			}
			if parsed != token {
				t.Fatalf("parsed token = %q", parsed)
			}
		})
	}
}

func TestAAuthAccessRejectsMalformedCredentials(t *testing.T) {
	t.Parallel()

	invalidTokens := []string{
		"",
		" ",
		"abc def",
		"abc,def",
		"=abc",
		"abc=def",
		"abc\r\ndef",
	}
	for _, token := range invalidTokens {
		token := token
		t.Run(strings.ReplaceAll(token, " ", "_"), func(t *testing.T) {
			if _, err := aauth.AccessAuthorization(token); err == nil {
				t.Fatalf("AccessAuthorization(%q) succeeded", token)
			}
		})
	}

	invalidHeaders := []string{
		"",
		"AAuth",
		"AAuth ",
		"AAuth one two",
		"AAuth one,two",
		"Bearer opaque-token",
	}
	for _, header := range invalidHeaders {
		header := header
		t.Run(strings.ReplaceAll(header, " ", "_"), func(t *testing.T) {
			if _, err := aauth.ParseAccessAuthorization(header); err == nil {
				t.Fatalf("ParseAccessAuthorization(%q) succeeded", header)
			}
		})
	}
}

func TestAAuthAccessSchemeIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	token, err := aauth.ParseAccessAuthorization("aauth opaque-token")
	if err != nil {
		t.Fatal(err)
	}
	if token != "opaque-token" {
		t.Fatalf("parsed token = %q", token)
	}
}
