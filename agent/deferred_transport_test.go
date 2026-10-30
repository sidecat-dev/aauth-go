package agent_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
)

func TestExchangePendingLocationUsesEffectiveHTTPOrigin(t *testing.T) {
	for _, test := range []struct {
		name, endpoint, location, want string
		wantError                      bool
	}{
		{"nondefault port", "https://edge.example:8443/v2/token", "/pending/1", "https://edge.example:8443/pending/1", false},
		{"default port equivalent", "https://edge.example/v2/token", "https://EDGE.example:443/pending/1", "https://EDGE.example:443/pending/1", false},
		{"wrong port", "https://edge.example:8443/v2/token", "https://edge.example:9443/pending/1", "", true},
		{"cross origin", "https://edge.example/v2/token", "https://other.example/pending/1", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newExchangeInteractionHarness(t)
			h.protocol.authTokenEndpoint = test.endpoint
			h.initial = func(r *http.Request) (*http.Response, error) {
				return validExchangePendingResponse(r, test.location, "0", "pending"), nil
			}
			result, err := h.client(t).BeginExchange(context.Background(), agent.ExchangeRequest{PersonServer: h.protocol.personServerID, ResourceToken: h.resourceToken, PresentedToken: h.presentedToken, Capabilities: []string{"interaction"}})
			if test.wantError {
				if err == nil {
					t.Fatal("accepted wrong origin")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			pending, _ := result.Pending()
			if pending.Location() != test.want {
				t.Fatalf("Location = %q, want %q", pending.Location(), test.want)
			}
		})
	}
}

func TestExchangeRetryResponseOwnershipAndHTTPDate(t *testing.T) {
	t.Run("initial 503 HTTP-date uses fixed clock and remains caller owned", func(t *testing.T) {
		h := newExchangeInteractionHarness(t)
		clock := &exchangeCountingClock{now: h.protocol.now}
		h.protocol.clock = clock
		body := newExchangeTrackedBody("initial")
		retryAt := clock.now.Add(13 * time.Second)
		clockCallsAtResponse := 0
		h.initial = func(r *http.Request) (*http.Response, error) {
			clockCallsAtResponse = clock.calls
			return retryResponse(r, http.StatusServiceUnavailable, retryAt.Format(http.TimeFormat), body), nil
		}
		result, err := h.client(t).BeginExchange(context.Background(), agent.ExchangeRequest{PersonServer: h.protocol.personServerID, ResourceToken: h.resourceToken, PresentedToken: h.presentedToken})
		if err != nil {
			t.Fatal(err)
		}
		response, ok := result.Response()
		if !ok || response.Header.Get("Retry-After") != retryAt.Format(http.TimeFormat) {
			t.Fatalf("response=%#v ok=%t", response, ok)
		}
		if clock.calls != clockCallsAtResponse+1 {
			t.Fatalf("clock calls after response = %d, want %d", clock.calls, clockCallsAtResponse+1)
		}
		if body.closed {
			t.Fatal("initial 503 body closed before caller")
		}
		response.Body.Close()
		if !body.closed {
			t.Fatal("caller close not observed")
		}
		if _, ok := result.Pending(); ok {
			t.Fatal("initial 503 exposed pending")
		}
	})

	t.Run("invalid initial 503 closes body", func(t *testing.T) {
		h := newExchangeInteractionHarness(t)
		body := newExchangeTrackedBody("initial")
		h.initial = func(r *http.Request) (*http.Response, error) {
			return retryResponse(r, http.StatusServiceUnavailable, "tomorrow", body), nil
		}
		result, err := h.client(t).BeginExchange(context.Background(), agent.ExchangeRequest{PersonServer: h.protocol.personServerID, ResourceToken: h.resourceToken, PresentedToken: h.presentedToken})
		if err == nil {
			t.Fatal("accepted invalid initial Retry-After")
		}
		if response, ok := result.Response(); ok || response != nil {
			t.Fatalf("Response = %#v, %t", response, ok)
		}
		if !body.closed {
			t.Fatal("invalid initial retry body was not closed")
		}
	})

	for _, test := range []struct {
		name      string
		status    int
		retry     string
		want      time.Duration
		wantError bool
	}{
		{"429", http.StatusTooManyRequests, "", 12 * time.Second, false},
		{"429 longer Retry-After", http.StatusTooManyRequests, "99", 99 * time.Second, false},
		{"429 date", http.StatusTooManyRequests, time.Date(2026, 8, 29, 18, 0, 30, 0, time.UTC).Format(http.TimeFormat), 30 * time.Second, false},
		{"429 invalid", http.StatusTooManyRequests, "tomorrow", 0, true},
		{"503 date", http.StatusServiceUnavailable, time.Date(2026, 8, 29, 18, 0, 13, 0, time.UTC).Format(http.TimeFormat), 13 * time.Second, false},
		{"503 invalid", http.StatusServiceUnavailable, "tomorrow", 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newExchangeInteractionHarness(t)
			h.initial = func(r *http.Request) (*http.Response, error) {
				return validExchangePendingResponse(r, "/pending/exchange-1", "7", "pending"), nil
			}
			body := newExchangeTrackedBody("poll")
			h.poll = []func(*http.Request) (*http.Response, error){func(r *http.Request) (*http.Response, error) {
				return retryResponse(r, test.status, test.retry, body), nil
			}}
			client := h.client(t)
			pending := beginExchangeInteraction(t, client, h)
			result, err := client.PollExchange(context.Background(), pending)
			if test.wantError {
				if err == nil {
					t.Fatal("accepted invalid Retry-After")
				}
				if !body.closed {
					t.Fatal("invalid retry body was not closed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			response, rok := result.Response()
			next, pok := result.Pending()
			if !rok || !pok || next.RetryAfter() != test.want {
				t.Fatalf("response=%t pending=%t retry=%s", rok, pok, next.RetryAfter())
			}
			if body.closed {
				t.Fatal("poll retry body closed before caller")
			}
			response.Body.Close()
			if !body.closed {
				t.Fatal("caller close not observed")
			}
		})
	}
}

func TestExchangeRetryPreservesUnsupportedPendingFailure(t *testing.T) {
	h := newExchangeInteractionHarness(t)
	h.initial = func(r *http.Request) (*http.Response, error) {
		response := validExchangePendingResponse(r, "/pending/exchange-1", "7", "pending")
		response.Header.Set("AAuth-Requirement", "requirement=future-consent")
		response.Body = io.NopCloser(strings.NewReader(`{"status":"pending","extension":{"mode":"later"}}`))
		return response, nil
	}
	body := newExchangeTrackedBody("retry")
	h.poll = []func(*http.Request) (*http.Response, error){func(r *http.Request) (*http.Response, error) {
		return retryResponse(r, http.StatusServiceUnavailable, "11", body), nil
	}}
	client := h.client(t)
	pending := beginExchangeInteraction(t, client, h)
	result, err := client.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	response, responseOK := result.Response()
	next, pendingOK := result.Pending()
	var unsupported *agent.UnsupportedRequirementError
	if !responseOK || !pendingOK || next.Requirement() != aauth.Requirement("future-consent") ||
		!errors.As(result.Failure(), &unsupported) || unsupported.Requirement != aauth.Requirement("future-consent") {
		t.Fatalf("response=%t pending=%t requirement=%q failure=%v", responseOK, pendingOK, next.Requirement(), result.Failure())
	}
	if next.Location() != pending.Location() || next.RetryAfter() != 11*time.Second {
		t.Fatalf("next location=%q retry=%s", next.Location(), next.RetryAfter())
	}
	if body.closed {
		t.Fatal("retry body closed before caller")
	}
	response.Body.Close()
	if !body.closed {
		t.Fatal("caller close not observed")
	}
}

func TestExchangePollUsesTokenEndpointOriginAndClosesSuccessfulResponse(t *testing.T) {
	const (
		tokenEndpoint = "https://token.ps-edge.example:8443/v2/token"
		pollURL       = "https://token.ps-edge.example:8443/pending/exchange-1"
	)
	h := newExchangeInteractionHarness(t)
	h.protocol.authTokenEndpoint = tokenEndpoint
	h.initial = func(r *http.Request) (*http.Response, error) {
		return validExchangePendingResponse(r, "/pending/exchange-1", "0", "pending"), nil
	}
	var pollCalls int
	var responseBody *trackedBody
	transport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.String() != pollURL {
			return h.roundTrip(r)
		}
		pollCalls++
		if r.Body != nil && r.Body != http.NoBody {
			t.Fatal("poll carried a body")
		}
		verified := verifyProof(t, r, h.protocol.resolver, h.protocol.clock, aauth.AgentTokenType)
		if _, err := verified.AgentClaims(); err != nil {
			t.Fatal(err)
		}
		response := h.authTokenResponse(r, nil)
		responseBody = trackDeferredResponseBody(t, response)
		return response, nil
	})
	client := h.protocol.newClientWithHTTPClient(t, &http.Client{Transport: transport})
	pending := beginExchangeInteraction(t, client, h)
	if pending.Location() != pollURL {
		t.Fatalf("Location = %q, want %q", pending.Location(), pollURL)
	}
	result, err := client.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if token, ok := result.Token(); !ok || token == "" {
		t.Fatalf("Token = %q, %t", token, ok)
	}
	if pollCalls != 1 {
		t.Fatalf("poll calls = %d, want 1", pollCalls)
	}
	if responseBody == nil || !responseBody.closed {
		t.Fatalf("successful response body = %#v", responseBody)
	}
}

func TestExchangeConsumedResponseBodiesAreClosed(t *testing.T) {
	t.Run("malformed initial 202", func(t *testing.T) {
		h := newExchangeInteractionHarness(t)
		body := newExchangeTrackedBody(`{"status":`)
		h.initial = func(r *http.Request) (*http.Response, error) {
			response := validExchangePendingResponse(r, "/pending/exchange-1", "0", "pending")
			response.Body = body
			return response, nil
		}
		if _, err := h.client(t).BeginExchange(context.Background(), agent.ExchangeRequest{
			PersonServer: h.protocol.personServerID, ResourceToken: h.resourceToken, PresentedToken: h.presentedToken, Capabilities: []string{"interaction"},
		}); err == nil {
			t.Fatal("accepted malformed pending body")
		}
		if !body.closed {
			t.Fatal("malformed pending body was not closed")
		}
	})

	t.Run("terminal 410", func(t *testing.T) {
		h := newExchangeInteractionHarness(t)
		h.initial = func(r *http.Request) (*http.Response, error) {
			return validExchangePendingResponse(r, "/pending/exchange-1", "0", "pending"), nil
		}
		var body *trackedBody
		h.poll = []func(*http.Request) (*http.Response, error){func(r *http.Request) (*http.Response, error) {
			response := problemResponse(r, &aauth.ProblemError{Status: http.StatusGone, Code: "invalid_code", Detail: "terminal"})
			body = trackDeferredResponseBody(t, response)
			return response, nil
		}}
		client := h.client(t)
		pending := beginExchangeInteraction(t, client, h)
		_, err := client.PollExchange(context.Background(), pending)
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) || problem.Status != http.StatusGone || problem.Code != "invalid_code" {
			t.Fatalf("error = %v, problem = %#v", err, problem)
		}
		if body == nil || !body.closed {
			t.Fatalf("terminal response body = %#v", body)
		}
	})

	t.Run("429 retry overflow", func(t *testing.T) {
		h := newExchangeInteractionHarness(t)
		h.initial = func(r *http.Request) (*http.Response, error) {
			return validExchangePendingResponse(r, "/pending/exchange-1", "9223372036", "pending"), nil
		}
		body := newExchangeTrackedBody("retry")
		h.poll = []func(*http.Request) (*http.Response, error){func(r *http.Request) (*http.Response, error) {
			return retryResponse(r, http.StatusTooManyRequests, "", body), nil
		}}
		client := h.client(t)
		pending := beginExchangeInteraction(t, client, h)
		if _, err := client.PollExchange(context.Background(), pending); err == nil || !strings.Contains(err.Error(), "overflows") {
			t.Fatalf("PollExchange error = %v", err)
		}
		if !body.closed {
			t.Fatal("overflow retry body was not closed")
		}
	})
}

func TestPersonTokenRepeatedInteractionCodeAllowsRegrouping(t *testing.T) {
	p := newTestProtocol(t)
	tr := &personTokenInteractionTransport{protocol: p}
	tr.initial = func(r *http.Request) (*http.Response, error) {
		return validPersonTokenPendingResponse(r, "0", "pending"), nil
	}
	tr.poll = []func(*http.Request) (*http.Response, error){func(r *http.Request) (*http.Response, error) {
		response := validPersonTokenPendingResponse(r, "0", "pending")
		response.Header.Set("AAuth-Requirement", interactionRequirement(interactionURL, "A1B2C3D4"))
		return response, nil
	}}
	client := p.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(tr.roundTrip)})
	pending := beginPersonTokenInteraction(t, client, p)
	result, err := client.PollPersonToken(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	next, _ := result.Pending()
	if next.InteractionCode() != pending.InteractionCode() {
		t.Fatalf("code=%q", next.InteractionCode())
	}
}

func TestResourceSessionRepeatedInteractionCodeAllowsRegrouping(t *testing.T) {
	p := newTestProtocol(t)
	polls := 0
	client := p.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, ".well-known"):
			return resourceSessionMetadataResponseWithComponents(r, p.resourceID, nil), nil
		case r.Method == http.MethodPost:
			return validResourceSessionPendingResponse(r, "0", "pending", true), nil
		default:
			polls++
			response := validResourceSessionPendingResponse(r, "0", "pending", true)
			response.Header.Set("AAuth-Requirement", interactionRequirement(resourceInteractionURL, "R1S2T3V4"))
			return response, nil
		}
	})})
	pending := beginPendingResourceSession(t, client, p)
	result, err := client.PollResourceSession(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	next, _ := result.Pending()
	if polls != 1 || next.InteractionCode() != pending.InteractionCode() {
		t.Fatalf("polls=%d code=%q", polls, next.InteractionCode())
	}
}

type exchangeCountingClock struct {
	now   time.Time
	calls int
}

func (clock *exchangeCountingClock) Now() time.Time {
	clock.calls++
	return clock.now
}

func newExchangeTrackedBody(value string) *trackedBody {
	return &trackedBody{Reader: strings.NewReader(value)}
}

func trackDeferredResponseBody(t *testing.T, response *http.Response) *trackedBody {
	t.Helper()
	encoded, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	body := newExchangeTrackedBody(string(encoded))
	response.Body = body
	return body
}

func retryResponse(r *http.Request, status int, retry string, body io.ReadCloser) *http.Response {
	h := make(http.Header)
	if retry != "" {
		h.Set("Retry-After", retry)
	}
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: h, Body: body, Request: r}
}
