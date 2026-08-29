package aauth_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestAgentEnforcesRetryAfterAndSlowDown(t *testing.T) {
	t.Parallel()

	var polls int
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch {
			case request.Method == http.MethodGet && request.URL.Path == "/documents" && request.Header.Get("Authorization") == "":
				response.Header().Set("Location", "/pending/request-123")
				response.Header().Set("Retry-After", "2")
				response.Header().Set("Cache-Control", "no-store")
				response.Header().Set("Content-Type", "application/json")
				response.WriteHeader(http.StatusAccepted)
				_, _ = io.WriteString(response, `{"status":"pending"}`)
			case request.Method == http.MethodGet && request.URL.Path == "/pending/request-123":
				polls++
				if polls == 1 {
					response.Header().Set("Content-Type", "application/problem+json")
					response.WriteHeader(http.StatusTooManyRequests)
					_, _ = io.WriteString(response, `{"status":429,"error":"slow_down"}`)
					return
				}
				response.Header().Set("AAuth-Access", "opaque-access-token")
				response.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(response, `{"status":"authorized","scope":"documents.read"}`)
			default:
				http.NotFound(response, request)
			}
		}),
	})
	defer gateway.Close()

	now := time.Date(2026, 7, 27, 13, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	agent, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:reader@ap.example",
		SigningKey:         testSigningKey(t, "agent-key"),
		AgentToken:         "agent-token",
		KeyResolver:        signaturekey.StaticKeyResolver{},
		HTTPClient:         gateway.Client(),
		Clock:              clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	authorization, err := agent.RequestResourceManagedAccess(
		context.Background(),
		reference.AuthorizedCall{Method: http.MethodGet, Endpoint: "https://resource.example/documents"},
	)
	if err != nil {
		t.Fatal(err)
	}
	pending := authorization.Pending
	if pending == nil || pending.RetryAfter != 2*time.Second {
		t.Fatalf("pending authorization = %#v", pending)
	}
	if _, err := agent.PollResourceManagedAccess(context.Background(), pending); err == nil {
		t.Fatal("agent polled before Retry-After")
	}
	if polls != 0 {
		t.Fatalf("early network polls = %d", polls)
	}

	now = now.Add(2 * time.Second)
	if _, err := agent.PollResourceManagedAccess(context.Background(), pending); err == nil {
		t.Fatal("slow_down poll succeeded")
	} else {
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) || problem.Code != aauth.PollingSlowDown {
			t.Fatalf("slow_down error = %#v", err)
		}
	}
	if pending.RetryAfter != 7*time.Second ||
		!pending.NotBefore.Equal(now.Add(7*time.Second)) {
		t.Fatalf("slow_down pending state = %#v", pending)
	}
	if _, err := agent.PollResourceManagedAccess(context.Background(), pending); err == nil {
		t.Fatal("agent ignored slow_down interval")
	}
	if polls != 1 {
		t.Fatalf("network polls after local slow_down refusal = %d", polls)
	}

	now = now.Add(7 * time.Second)
	approved, err := agent.PollResourceManagedAccess(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Grant == nil || approved.Grant.Token != "opaque-access-token" {
		t.Fatalf("approved authorization = %#v", approved)
	}
}

func TestAgentBacksOffAfterServiceUnavailable(t *testing.T) {
	t.Parallel()

	var polls int
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch {
			case request.Method == http.MethodGet && request.URL.Path == "/documents" && request.Header.Get("Authorization") == "":
				response.Header().Set("Location", "/pending/request-503")
				response.Header().Set("Retry-After", "0")
				response.Header().Set("Cache-Control", "no-store")
				response.Header().Set("Content-Type", "application/json")
				response.WriteHeader(http.StatusAccepted)
				_, _ = io.WriteString(response, `{"status":"pending"}`)
			case request.Method == http.MethodGet && request.URL.Path == "/pending/request-503":
				polls++
				if polls == 1 {
					response.Header().Set("Retry-After", "3")
					response.Header().Set("Content-Type", "application/problem+json")
					response.WriteHeader(http.StatusServiceUnavailable)
					_, _ = io.WriteString(response, `{"status":503,"error":"server_error"}`)
					return
				}
				response.Header().Set("AAuth-Access", "opaque-access-token")
				response.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(response, `{"status":"authorized","scope":"documents.read"}`)
			default:
				http.NotFound(response, request)
			}
		}),
	})
	defer gateway.Close()

	now := time.Date(2026, 7, 27, 15, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	agent, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:reader@ap.example",
		SigningKey:         testSigningKey(t, "agent-key"),
		AgentToken:         "agent-token",
		KeyResolver:        signaturekey.StaticKeyResolver{},
		HTTPClient:         gateway.Client(),
		Clock:              clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	authorization, err := agent.RequestResourceManagedAccess(
		context.Background(),
		reference.AuthorizedCall{Method: http.MethodGet, Endpoint: "https://resource.example/documents"},
	)
	if err != nil {
		t.Fatal(err)
	}
	pending := authorization.Pending
	if pending == nil {
		t.Fatalf("authorization = %#v", authorization)
	}

	if _, err := agent.PollResourceManagedAccess(context.Background(), pending); err == nil {
		t.Fatal("503 poll succeeded")
	}
	if pending.RetryAfter != 3*time.Second ||
		!pending.NotBefore.Equal(now.Add(3*time.Second)) {
		t.Fatalf("503 pending state = %#v", pending)
	}
	if _, err := agent.PollResourceManagedAccess(context.Background(), pending); err == nil {
		t.Fatal("agent ignored 503 Retry-After")
	}
	if polls != 1 {
		t.Fatalf("network polls before backoff elapsed = %d", polls)
	}

	now = now.Add(3 * time.Second)
	approved, err := agent.PollResourceManagedAccess(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Grant == nil || approved.Grant.Token != "opaque-access-token" {
		t.Fatalf("approved authorization = %#v", approved)
	}
}
