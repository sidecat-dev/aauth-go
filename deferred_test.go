package aauth_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestParseDeferredResponse(t *testing.T) {
	t.Parallel()

	response := deferredHTTPResponse(
		t,
		"https://resource.example/authorize",
		http.Header{
			"Location":          {"/pending/request-123"},
			"Retry-After":       {"7"},
			"Cache-Control":     {"private, no-store"},
			"Aauth-Requirement": {`requirement=interaction; url="https://resource.example/interaction/request-123"; code="A1B2-C3D4"`},
		},
		`{"status":"interacting","extension":"ignored"}`,
	)
	deferred, err := aauth.ParseDeferredResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if deferred.Location != "https://resource.example/pending/request-123" {
		t.Fatalf("pending location = %q", deferred.Location)
	}
	if deferred.RetryAfter != 7*time.Second || deferred.Status != "interacting" {
		t.Fatalf("deferred response = %#v", deferred)
	}
	if deferred.Requirement == nil ||
		deferred.Requirement.Type != aauth.RequirementInteraction ||
		deferred.Requirement.InteractionCode != "A1B2-C3D4" {
		t.Fatalf("deferred requirement = %#v", deferred.Requirement)
	}
}

func TestParseDeferredResponseTreatsUnknownStatusAsPending(t *testing.T) {
	t.Parallel()

	response := deferredHTTPResponse(
		t,
		"https://resource.example/authorize",
		http.Header{
			"Location":      {"https://resource.example/pending/request-123"},
			"Retry-After":   {"0"},
			"Cache-Control": {"no-store"},
		},
		`{"status":"future-status"}`,
	)
	deferred, err := aauth.ParseDeferredResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if deferred.Status != "pending" {
		t.Fatalf("deferred status = %q", deferred.Status)
	}
}

func TestParseDeferredResponseAllowsSameOriginPollingQuery(t *testing.T) {
	t.Parallel()

	response := deferredHTTPResponse(
		t,
		"https://resource.example/authorize",
		http.Header{
			"Location":      {"/pending?request=request-123"},
			"Retry-After":   {"0"},
			"Cache-Control": {"no-store"},
		},
		`{"status":"pending"}`,
	)
	deferred, err := aauth.ParseDeferredResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if deferred.Location != "https://resource.example/pending?request=request-123" {
		t.Fatalf("pending location = %q", deferred.Location)
	}
}

func TestParseDeferredResponseRejectsInvalidCustody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers http.Header
		body    string
	}{
		{
			name: "cross-origin location",
			headers: http.Header{
				"Location":      {"https://attacker.example/pending/request-123"},
				"Retry-After":   {"0"},
				"Cache-Control": {"no-store"},
			},
			body: `{"status":"pending"}`,
		},
		{
			name: "missing location",
			headers: http.Header{
				"Retry-After":   {"0"},
				"Cache-Control": {"no-store"},
			},
			body: `{"status":"pending"}`,
		},
		{
			name: "missing retry after",
			headers: http.Header{
				"Location":      {"/pending/request-123"},
				"Cache-Control": {"no-store"},
			},
			body: `{"status":"pending"}`,
		},
		{
			name: "negative retry after",
			headers: http.Header{
				"Location":      {"/pending/request-123"},
				"Retry-After":   {"-1"},
				"Cache-Control": {"no-store"},
			},
			body: `{"status":"pending"}`,
		},
		{
			name: "cacheable pending response",
			headers: http.Header{
				"Location":      {"/pending/request-123"},
				"Retry-After":   {"0"},
				"Cache-Control": {"private"},
			},
			body: `{"status":"pending"}`,
		},
		{
			name: "invalid no-store argument",
			headers: http.Header{
				"Location":      {"/pending/request-123"},
				"Retry-After":   {"0"},
				"Cache-Control": {`no-store="field"`},
			},
			body: `{"status":"pending"}`,
		},
		{
			name: "missing status",
			headers: http.Header{
				"Location":      {"/pending/request-123"},
				"Retry-After":   {"0"},
				"Cache-Control": {"no-store"},
			},
			body: `{}`,
		},
		{
			name: "multiple requirements",
			headers: http.Header{
				"Location":          {"/pending/request-123"},
				"Retry-After":       {"0"},
				"Cache-Control":     {"no-store"},
				"Aauth-Requirement": {"requirement=approval", "requirement=clarification"},
			},
			body: `{"status":"pending"}`,
		},
		{
			name: "overflowing clarification timeout",
			headers: http.Header{
				"Location":          {"/pending/request-123"},
				"Retry-After":       {"0"},
				"Cache-Control":     {"no-store"},
				"Aauth-Requirement": {"requirement=clarification"},
			},
			body: `{"status":"pending","clarification":"Provide details.","timeout":9223372036854775807}`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			response := deferredHTTPResponse(
				t,
				"https://resource.example/authorize",
				test.headers,
				test.body,
			)
			if _, err := aauth.ParseDeferredResponse(response); err == nil {
				t.Fatal("ParseDeferredResponse succeeded")
			}
		})
	}
}

func deferredHTTPResponse(
	t *testing.T,
	requestURL string,
	header http.Header,
	body string,
) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, requestURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{
		StatusCode: http.StatusAccepted,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}
