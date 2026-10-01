package agentprovider_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
)

type closeTrackingBody struct {
	io.Reader
	closed *bool
}

func (body closeTrackingBody) Close() error { *body.closed = true; return nil }

func TestRevocationClientPreservesRateLimitedFeedback(t *testing.T) {
	t.Parallel()
	provider := newRevocationTestProvider(t) // provider clock: 2026-09-01T08:00:00Z
	reference := aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: "https://ap.example", JTI: "token-1"},
		ExpiresAt: time.Unix(2000000000, 0),
	}
	const problem = `{"type":"about:blank","title":"Too Many Requests","status":429,"error":"rate_limited"}`
	for name, test := range map[string]struct {
		status      int
		contentType string
		body        string
		retryAfter  []string
		wantDelay   time.Duration
		wantTyped   bool
		wantProblem aauth.ErrorCode
	}{
		"seconds":          {429, "application/problem+json", problem, []string{"30"}, 30 * time.Second, true, "rate_limited"},
		"zero":             {429, "application/problem+json", problem, []string{"0"}, 0, true, "rate_limited"},
		"future date":      {429, "application/problem+json", problem, []string{"Tue, 01 Sep 2026 08:02:00 GMT"}, 2 * time.Minute, true, "rate_limited"},
		"past date":        {429, "application/problem+json", problem, []string{"Tue, 01 Sep 2026 07:00:00 GMT"}, 0, true, "rate_limited"},
		"missing header":   {429, "application/problem+json", problem, nil, 0, false, "rate_limited"},
		"malformed header": {429, "application/problem+json", problem, []string{"soon"}, 0, false, "rate_limited"},
		"repeated header":  {429, "application/problem+json", problem, []string{"1", "2"}, 0, false, "rate_limited"},
		"other 429 code": {429, "application/problem+json",
			`{"status":429,"error":"slow_down"}`, []string{"30"}, 0, false, "slow_down"},
		"retry-after on other status": {403, "application/problem+json",
			`{"status":403,"error":"rate_limited"}`, []string{"30"}, 0, false, "rate_limited"},
	} {
		t.Run(name, func(t *testing.T) {
			posts, closed := 0, false
			client, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
				Provider: provider,
				HTTPClient: &http.Client{Transport: revocationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					if request.Method == http.MethodGet {
						return revocationJSONResponse(request, `{"issuer":"https://resource.example","revocation_endpoint":"https://resource.example/revoke"}`), nil
					}
					posts++
					response := &http.Response{
						StatusCode: test.status, Status: http.StatusText(test.status), Header: make(http.Header),
						Body: closeTrackingBody{strings.NewReader(test.body), &closed}, Request: request,
					}
					response.Header.Set("Content-Type", test.contentType)
					for _, value := range test.retryAfter {
						response.Header.Add("Retry-After", value)
					}
					return response, nil
				})},
				Admit: func(context.Context, string) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			err = client.RevokeAgentTokenAtResource(context.Background(), "https://resource.example", reference)
			var typed *aauth.RateLimitedError
			var plain *aauth.ProblemError
			if !errors.As(err, &plain) || plain.Code != test.wantProblem {
				t.Fatalf("error = %v; want ProblemError code %q", err, test.wantProblem)
			}
			if got := errors.As(err, &typed); got != test.wantTyped {
				t.Fatalf("typed = %t, want %t (%v)", got, test.wantTyped, err)
			}
			if test.wantTyped && (typed.RetryAfter != test.wantDelay || typed.Problem != plain) {
				t.Fatalf("typed = %#v; want delay %v", typed, test.wantDelay)
			}
			if posts != 1 || !closed {
				t.Fatalf("posts = %d, body closed = %t; want one exchange and a closed body", posts, closed)
			}
		})
	}
}

func TestRevocationClientLeavesNonProblem429Untyped(t *testing.T) {
	t.Parallel()
	provider := newRevocationTestProvider(t)
	client, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider: provider,
		HTTPClient: &http.Client{Transport: revocationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodGet {
				return revocationJSONResponse(request, `{"issuer":"https://resource.example","revocation_endpoint":"https://resource.example/revoke"}`), nil
			}
			response := &http.Response{
				StatusCode: 429, Status: "429 Too Many Requests", Header: http.Header{"Retry-After": []string{"30"}},
				Body: io.NopCloser(strings.NewReader("slow down")), Request: request,
			}
			return response, nil
		})},
		Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	err = client.RevokeAgentTokenAtResource(context.Background(), "https://resource.example", aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: "https://ap.example", JTI: "token-1"}, ExpiresAt: time.Unix(2000000000, 0),
	})
	var typed *aauth.RateLimitedError
	var plain *aauth.ProblemError
	if err == nil || errors.As(err, &typed) || errors.As(err, &plain) {
		t.Fatalf("non-problem 429 = %v", err)
	}
}
