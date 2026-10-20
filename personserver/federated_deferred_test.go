package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/diagnostics"
)

// Protocol 28e8258, Error Response Format and Token Endpoint Error Codes:
// a local unsupported composition is not an unreachable or invalid AS result.
func TestDeferredCompositionRefusalHasLocalReason(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(map[bool]string{false: "not configured", true: "mission"}[configured], func(t *testing.T) {
			now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
			f := newMissionFederationFixture(t, missionFederationTimes{now: now, resourceExpiresAt: now.Add(time.Minute), missionExpiresAt: now.Add(5 * time.Minute), authExpiresAt: now.Add(time.Minute)})
			if configured {
				f.server.federatedDeferred = &FederatedDeferredConfig{}
			}
			f.server.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 402, Header: http.Header{"Location": {"https://access.example/pending/test"}, "Www-Authenticate": {`Payment secret="private-invoice"`}}, Body: io.NopCloser(strings.NewReader("private-invoice")), Request: r}, nil
			})}
			body := testTokenRequestBody(t, f.resourceToken, f.presentedToken)
			request := httptest.NewRequest("POST", f.protocol.personServerID+"/token", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			if err := signPersonServerTestRequest(request, f.protocol.agentKey, f.protocol.agentToken, f.protocol.clock); err != nil {
				t.Fatal(err)
			}
			var observed diagnostics.Problem
			recorder := httptest.NewRecorder()
			diagnostics.Handler(f.server.Handler(), func(_ context.Context, p diagnostics.Problem) { observed = p }).ServeHTTP(recorder, request)
			problem, err := aauth.DecodeProblemResponse(recorder.Result())
			if err != nil {
				t.Fatal(err)
			}
			if problem.Status != 500 || problem.Code != "server_error" {
				t.Fatalf("local refusal = %v", problem)
			}
			var reason *DeferredCompositionError
			if !errors.As(observed.Cause, &reason) {
				t.Fatalf("untyped composition cause: %T %v", observed.Cause, observed.Cause)
			}
			want := "not_configured"
			if configured {
				want = "mission"
			}
			if reason.Reason() != want || !strings.Contains(problem.Detail, "deferred") || strings.Contains(problem.Detail, "private-invoice") {
				t.Fatalf("reason=%q detail=%q", reason.Reason(), problem.Detail)
			}
			if attempts, _, _ := f.store.observation(); attempts != 0 {
				t.Fatal("unsupported continuation retained a token")
			}
		})
	}
}

func TestPendingFederatedReferencesValidateStoreResults(t *testing.T) {
	now := time.Unix(100, 0)
	valid := FederatedAuthorizationRecord{ID: "request", PersonServer: "https://ps.example", ExpiresAt: now.Add(time.Minute)}
	for _, tc := range []struct {
		name  string
		alter func(*FederatedAuthorizationRecord)
	}{
		{"valid", nil},
		{"foreign", func(r *FederatedAuthorizationRecord) { r.PersonServer = "https://other.example" }},
		{"expired", func(r *FederatedAuthorizationRecord) { r.ExpiresAt = now }},
		{"terminal", func(r *FederatedAuthorizationRecord) { r.Terminal = true }},
		{"gone", func(r *FederatedAuthorizationRecord) { r.Gone = true }},
		{"missing id", func(r *FederatedAuthorizationRecord) { r.ID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			if tc.alter != nil {
				tc.alter(&r)
			}
			store := &federatedQueueProbe{records: []FederatedAuthorizationRecord{r}}
			server := &Server{issuer: valid.PersonServer, clock: aauth.ClockFunc(func() time.Time { return now }), federatedDeferred: &FederatedDeferredConfig{Store: store}}
			queue := server
			refs, err := queue.PendingFederatedAuthorizationReferences(context.Background(), 1)
			if tc.alter != nil {
				if !errors.Is(err, ErrFederatedAuthorizationConflict) || len(refs) != 0 {
					t.Fatalf("corrupt queue = %v %v", refs, err)
				}
				return
			}
			if err != nil || len(refs) != 1 || refs[0] != valid.ID || store.issuer != valid.PersonServer || !store.now.Equal(now) || store.limit != 1 {
				t.Fatalf("queue = %v %v", refs, err)
			}
			store.records = append(store.records, r)
			for _, limit := range []int{1, 2} {
				if refs, err := queue.PendingFederatedAuthorizationReferences(context.Background(), limit); !errors.Is(err, ErrFederatedAuthorizationConflict) || len(refs) != 0 {
					t.Fatalf("excess or duplicate records = %v %v", refs, err)
				}
			}
		})
	}
}

type federatedQueueProbe struct {
	FederatedAuthorizationStore
	records []FederatedAuthorizationRecord
	issuer  string
	now     time.Time
	limit   int
	err     error
	calls   int
}

func (s *federatedQueueProbe) ListPendingFederatedAuthorizations(_ context.Context, issuer string, now time.Time, limit int) ([]FederatedAuthorizationRecord, error) {
	s.issuer, s.now, s.limit = issuer, now, limit
	s.calls++
	return s.records, s.err
}

func TestFederatedWaitingRoundsUpRemainingRetryAfter(t *testing.T) {
	now := time.Unix(100, 0)
	server := &Server{issuer: "https://ps.example", clock: aauth.ClockFunc(func() time.Time { return now })}
	for _, tc := range []struct {
		remaining time.Duration
		want      string
	}{{time.Millisecond, "1"}, {time.Second + time.Nanosecond, "2"}, {0, "0"}, {-time.Second, "0"}} {
		w := httptest.NewRecorder()
		server.writeFederatedWaiting(w, FederatedAuthorizationRecord{ID: "request", NextPollAt: now.Add(tc.remaining)})
		if got := w.Header().Get("Retry-After"); got != tc.want {
			t.Fatalf("remaining %v: Retry-After=%q, want %q", tc.remaining, got, tc.want)
		}
	}
}

func TestFederatedWaitingExposesOnlySafeHint(t *testing.T) {
	now := time.Unix(100, 0)
	server := &Server{issuer: "https://ps.example", clock: aauth.ClockFunc(func() time.Time { return now })}
	for _, tc := range []struct {
		status int
		reason string
	}{{402, "awaiting_payment"}, {202, "awaiting_approval"}, {503, ""}} {
		w := httptest.NewRecorder()
		server.writeFederatedWaiting(w, FederatedAuthorizationRecord{ID: "request", NextPollAt: now, Response: FederatedResponse{Status: tc.status, Body: []byte("private-invoice"), Header: http.Header{"Www-Authenticate": {"private-payment"}}}})
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["status"] != "pending" || body["pending_reason"] != tc.reason {
			t.Fatalf("pending response = %v", body)
		}
		if strings.Contains(w.Body.String(), "private-") || w.Header().Get("WWW-Authenticate") != "" {
			t.Fatal("payment details exposed to Agent")
		}
	}
}
