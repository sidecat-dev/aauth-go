package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type rateLimitCloseBody struct {
	io.Reader
	closed *bool
}

func (body rateLimitCloseBody) Close() error { *body.closed = true; return nil }

func TestRevokeIssuedAuthTokenPreservesRateLimitedFeedback(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := personServerTestKey(t, "rate-limited-person")
	const (
		personID   = "https://person.example"
		resourceID = "https://resource.example"
	)
	reference := aauth.TokenReference{Issuer: personID, JTI: "rate-limited-token"}
	const problem = `{"status":429,"error":"rate_limited"}`
	for name, test := range map[string]struct {
		status      int
		contentType string
		body        string
		retryAfter  []string
		wantDelay   time.Duration
		wantTyped   bool
		wantProblem bool
	}{
		"seconds":          {429, "application/problem+json", problem, []string{"30"}, 30 * time.Second, true, true},
		"zero":             {429, "application/problem+json", problem, []string{"0"}, 0, true, true},
		"future date":      {429, "application/problem+json", problem, []string{"Thu, 01 Oct 2026 12:02:00 GMT"}, 2 * time.Minute, true, true},
		"past date":        {429, "application/problem+json", problem, []string{"Thu, 01 Oct 2026 11:00:00 GMT"}, 0, true, true},
		"missing header":   {429, "application/problem+json", problem, nil, 0, false, true},
		"malformed header": {429, "application/problem+json", problem, []string{"soon"}, 0, false, true},
		"repeated header":  {429, "application/problem+json", problem, []string{"1", "2"}, 0, false, true},
		"other 429 code":   {429, "application/problem+json", `{"status":429,"error":"slow_down"}`, []string{"30"}, 0, false, true},
		"other status":     {403, "application/problem+json", `{"status":403,"error":"rate_limited"}`, []string{"30"}, 0, false, true},
		"non-problem 429":  {429, "text/plain", `slow down`, []string{"30"}, 0, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			issued := newTestIssuedAuthTokenStore()
			if err := issued.CommitIssuedAuthToken(context.Background(), IssuedAuthTokenRecord{
				Reference: reference, Resource: resourceID, CompactSHA256: [32]byte{1},
				IssuedAt: now, ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				t.Fatal(err)
			}
			posts, closed := 0, false
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet {
					body, _ := json.Marshal(map[string]string{"issuer": resourceID, "revocation_endpoint": resourceID + "/revoke"})
					return &http.Response{
						StatusCode: http.StatusOK, Status: "200 OK", Request: request,
						Header: http.Header{"Content-Type": []string{"application/json"}},
						Body:   io.NopCloser(bytes.NewReader(body)),
					}, nil
				}
				posts++
				response := &http.Response{
					StatusCode: test.status, Status: http.StatusText(test.status), Request: request, Header: make(http.Header),
					Body: rateLimitCloseBody{strings.NewReader(test.body), &closed},
				}
				response.Header.Set("Content-Type", test.contentType)
				for _, value := range test.retryAfter {
					response.Header.Add("Retry-After", value)
				}
				return response, nil
			})}
			server, err := NewPSAuthorization(PSAuthorizationConfig{
				Issuer: personID, SigningKey: personKey, KeyResolver: signaturekey.StaticKeyResolver{},
				Clock: clock, NewID: func() string { return "unused" }, Tokens: newMemoryTokenStore(),
				BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
				Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
					return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}, nil
				},
				Revocation: &AuthTokenRevocationConfig{IssuedTokens: issued, HTTPClient: client, Admit: allowRevocationEgress},
			})
			if err != nil {
				t.Fatal(err)
			}
			err = server.RevokeIssuedAuthToken(context.Background(), reference)
			var typed *aauth.RateLimitedError
			var plain *aauth.ProblemError
			if err == nil || errors.As(err, &plain) != test.wantProblem {
				t.Fatalf("error = %v; ProblemError wanted=%t", err, test.wantProblem)
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
