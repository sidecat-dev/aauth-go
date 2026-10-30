package aauth_test

import (
	"errors"
	"net/url"
	"testing"

	auth "gitlab.com/sidecat-dev/aauth-go"
)

func TestInteractionVisitURLRoundTripsCodeAndCallback(t *testing.T) {
	t.Parallel()

	target, err := auth.FormatInteractionVisitURL("https://person.example/interact/ref-1", "A1B2-C3D4", "https://agent.example/callback/flow-1")
	if err != nil {
		t.Fatal(err)
	}
	if target != "https://person.example/interact/ref-1?code=A1B2-C3D4&callback=https%3A%2F%2Fagent.example%2Fcallback%2Fflow-1" {
		t.Fatalf("FormatInteractionVisitURL() = %q", target)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	visit, err := auth.ParseInteractionVisit(parsed.RawQuery, auth.InteractionVisitOptions{})
	if err != nil || visit != (auth.InteractionVisit{Code: "A1B2-C3D4", Callback: "https://agent.example/callback/flow-1"}) {
		t.Fatalf("ParseInteractionVisit() = %#v, %v", visit, err)
	}
	if _, err := auth.FormatInteractionVisitURL("https://person.example/interact?x=1", "A1B2-C3D4", ""); err == nil {
		t.Fatal("an interaction URL with a query was accepted")
	}
	withoutCallback, err := auth.FormatInteractionVisitURL("https://person.example/interact", "A1B2-C3D4", "")
	if err != nil || withoutCallback != "https://person.example/interact?code=A1B2-C3D4" {
		t.Fatalf("visit URL without callback = %q, %v", withoutCallback, err)
	}
}

func TestParseInteractionVisitRefusesAmbiguousOrUnsafeQueries(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		query string
	}{
		{"no code", "callback=https%3A%2F%2Fagent.example%2Fcb"},
		{"empty code", "code="},
		{"repeated code", "code=A1B2-C3D4&code=E5F6-G7H8"},
		{"repeated callback", "code=A1B2-C3D4&callback=https%3A%2F%2Fa.example%2Fcb&callback=https%3A%2F%2Fb.example%2Fcb"},
		{"http callback", "code=A1B2-C3D4&callback=http%3A%2F%2Fagent.example%2Fcb"},
		{"callback with a query", "code=A1B2-C3D4&callback=https%3A%2F%2Fagent.example%2Fcb%3Fx%3D1"},
		{"callback with a fragment", "code=A1B2-C3D4&callback=https%3A%2F%2Fagent.example%2Fcb%23x"},
		{"callback with userinfo", "code=A1B2-C3D4&callback=https%3A%2F%2Fu%40agent.example%2Fcb"},
		{"loopback without permission", "code=A1B2-C3D4&callback=http%3A%2F%2Flocalhost%3A8080%2Fcb"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if visit, err := auth.ParseInteractionVisit(test.query, auth.InteractionVisitOptions{}); err == nil {
				t.Fatalf("ParseInteractionVisit(%q) = %#v", test.query, visit)
			}
		})
	}
	// A malformed code is passed on, so the role that issued it counts the attempt.
	visit, err := auth.ParseInteractionVisit("code=not-a-code&other=ignored", auth.InteractionVisitOptions{})
	if err != nil || visit.Code != "not-a-code" {
		t.Fatalf("malformed code visit = %#v, %v", visit, err)
	}
	loopback, err := auth.ParseInteractionVisit(
		"code=A1B2-C3D4&callback=http%3A%2F%2F127.0.0.1%3A8080%2Fcb", auth.InteractionVisitOptions{AllowLoopbackCallback: true},
	)
	if err != nil || loopback.Callback != "http://127.0.0.1:8080/cb" {
		t.Fatalf("permitted loopback visit = %#v, %v", loopback, err)
	}
}

func TestInteractionCallbackErrorsRoundTripAndMapToPollingErrors(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		failure auth.InteractionCallbackError
		polling auth.ErrorCode
	}{
		{auth.InteractionCallbackAccessDenied, "denied"},
		{auth.InteractionCallbackUserAbandoned, "abandoned"},
		{auth.InteractionCallbackInteractionExpired, "expired"},
		{auth.InteractionCallbackServerError, "server_error"},
		{auth.InteractionCallbackTemporarilyUnavailable, "server_error"},
	} {
		target, err := auth.InteractionCallbackURL("https://ps.example/callback/ref/flow", test.failure)
		if err != nil || target != "https://ps.example/callback/ref/flow?error="+string(test.failure) {
			t.Fatalf("InteractionCallbackURL(%s) = %q, %v", test.failure, target, err)
		}
		parsed, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		read := auth.ReadInteractionCallback(parsed.RawQuery)
		var surfaced auth.InteractionCallbackError
		if !errors.As(read, &surfaced) || surfaced != test.failure || surfaced.PollingError() != test.polling {
			t.Fatalf("ReadInteractionCallback(%q) = %v", parsed.RawQuery, read)
		}
	}
	if err := auth.ReadInteractionCallback(""); err != nil {
		t.Fatalf("completed callback = %v", err)
	}
	if err := auth.ReadInteractionCallback("state=xyz"); err != nil {
		t.Fatalf("callback without error = %v", err)
	}
	for _, query := range []string{"error=not_registered", "error=access_denied&error=server_error", "error=%zz"} {
		if err := auth.ReadInteractionCallback(query); !errors.Is(err, auth.InteractionCallbackServerError) {
			t.Fatalf("ReadInteractionCallback(%q) = %v, want server_error", query, err)
		}
	}
	if _, err := auth.InteractionCallbackURL("https://ps.example/callback", "not_registered"); err == nil {
		t.Fatal("an unregistered callback error was formatted")
	}
	completed, err := auth.InteractionCallbackURL("https://ps.example/callback", "")
	if err != nil || completed != "https://ps.example/callback" {
		t.Fatalf("completed callback URL = %q, %v", completed, err)
	}
}
