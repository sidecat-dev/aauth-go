package aauth_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestAgentUsesGrantedScopeAndRotatedAAuthAccess(t *testing.T) {
	t.Parallel()

	var calls int
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch {
			case request.Method == http.MethodPost && request.URL.Path == "/authorize":
				response.Header().Set("AAuth-Access", "initial-token")
				response.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(response, `{"status":"authorized","scope":"documents.read"}`)
			case request.Method == http.MethodGet && request.URL.Path == "/documents":
				calls++
				expected := "AAuth initial-token"
				if calls == 2 {
					expected = "AAuth rotated-token"
				}
				if request.Header.Get("Authorization") != expected {
					http.Error(response, "wrong access credential", http.StatusUnauthorized)
					return
				}
				if calls == 1 {
					response.Header().Set("AAuth-Access", "rotated-token")
				}
				response.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(response, `{"ok":true}`)
			default:
				http.NotFound(response, request)
			}
		}),
	})
	defer gateway.Close()

	clock := aauth.ClockFunc(func() time.Time {
		return time.Date(2026, 7, 27, 11, 0, 0, 0, time.UTC)
	})
	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:reader@ap.example",
		SigningKey:  testSigningKey(t, "agent-key"),
		AgentToken:  "agent-token",
		KeyResolver: aauth.StaticKeyResolver{},
		HTTPClient:  gateway.Client(),
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	grant, err := agent.AuthorizeResourceManaged(
		context.Background(),
		"https://resource.example/authorize",
		[]string{"documents.read", "documents.write"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(grant.Scope, " ") != "documents.read" {
		t.Fatalf("granted scope = %q", grant.Scope)
	}

	first, err := agent.DoWithAccess(
		context.Background(),
		http.MethodGet,
		"https://resource.example/documents",
		&grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	first.Body.Close()
	if grant.Token != "rotated-token" {
		t.Fatalf("rotated access token = %q", grant.Token)
	}

	second, err := agent.DoWithAccess(
		context.Background(),
		http.MethodGet,
		"https://resource.example/documents",
		&grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("second access status = %d", second.StatusCode)
	}
}
