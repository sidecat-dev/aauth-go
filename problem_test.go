package aauth_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestDecodeProblemResponse(t *testing.T) {
	t.Parallel()

	response := &http.Response{
		StatusCode: http.StatusForbidden,
		Header: http.Header{
			"Content-Type": {"application/problem+json"},
		},
		Body: io.NopCloser(strings.NewReader(
			`{"type":"about:blank","title":"Forbidden","status":403,"error":"denied","detail":"The user declined."}`,
		)),
	}
	problem, err := aauth.DecodeProblemResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if problem.Status != http.StatusForbidden ||
		problem.Code != aauth.PollingDenied ||
		problem.Detail != "The user declined." {
		t.Fatalf("decoded problem = %#v", problem)
	}
}

func TestDecodeProblemResponseRejectsInvalidWireValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{
			name:        "wrong media type",
			contentType: "application/json",
			body:        `{"status":403,"error":"denied"}`,
		},
		{
			name:        "missing error",
			contentType: "application/problem+json",
			body:        `{"status":403}`,
		},
		{
			name:        "mismatched status",
			contentType: "application/problem+json",
			body:        `{"status":400,"error":"denied"}`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			response := &http.Response{
				StatusCode: http.StatusForbidden,
				Header:     http.Header{"Content-Type": {test.contentType}},
				Body:       io.NopCloser(strings.NewReader(test.body)),
			}
			if _, err := aauth.DecodeProblemResponse(response); err == nil {
				t.Fatal("DecodeProblemResponse succeeded")
			}
		})
	}
}
