package aauth_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	auth "gitlab.com/sidecat-dev/aauth-go"
)

func TestDecodeProblemResponseReturnsTypedAAuthError(t *testing.T) {
	t.Parallel()

	response := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Content-Type": {"application/problem+json"}},
		Body: io.NopCloser(strings.NewReader(
			`{"type":"about:blank","title":"Forbidden","status":403,"error":"person_token_denied","detail":"policy declined"}`,
		)),
	}
	problem, err := auth.DecodeProblemResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if problem.Status != http.StatusForbidden || problem.Code != "person_token_denied" || problem.Detail != "policy declined" {
		t.Fatalf("problem = %#v", problem)
	}
}

func TestDecodeProblemResponseRetainsMissionTermination(t *testing.T) {
	t.Parallel()

	response := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Content-Type": {"application/problem+json"}},
		Body: io.NopCloser(strings.NewReader(
			`{"status":403,"error":"mission_terminated","mission_status":"terminated","termination_reason":"expired"}`,
		)),
	}
	problem, err := auth.DecodeProblemResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if problem.Code != "mission_terminated" || problem.MissionStatus != "terminated" || problem.TerminationReason != "expired" {
		t.Fatalf("problem = %#v", problem)
	}
	if !strings.Contains(problem.Error(), "termination_reason=expired") {
		t.Fatalf("problem text = %q", problem.Error())
	}
}

func TestDecodeProblemResponseRejectsAmbiguousErrorMembers(t *testing.T) {
	t.Parallel()

	response := &http.Response{
		StatusCode: http.StatusBadRequest,
		Header:     http.Header{"Content-Type": {"application/problem+json"}},
		Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_request","Error":"server_error"}`)),
	}
	if _, err := auth.DecodeProblemResponse(response); err == nil {
		t.Fatal("DecodeProblemResponse accepted ambiguous members")
	}
}

func TestDecodeProblemResponseRejectsLoneCaseVariant(t *testing.T) {
	t.Parallel()

	response := &http.Response{
		StatusCode: http.StatusBadRequest,
		Header:     http.Header{"Content-Type": {"application/problem+json"}},
		Body:       io.NopCloser(strings.NewReader(`{"ERROR":"invalid_request","status":400}`)),
	}
	if _, err := auth.DecodeProblemResponse(response); err == nil || !strings.Contains(err.Error(), "case variant") {
		t.Fatalf("DecodeProblemResponse error = %v", err)
	}
}
