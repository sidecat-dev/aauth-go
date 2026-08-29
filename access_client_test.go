package aauth_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

type capturedRequestTransport struct {
	base     http.RoundTripper
	requests []*http.Request
}

func (transport *capturedRequestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.requests = append(transport.requests, request.Clone(context.Background()))
	return transport.base.RoundTrip(request)
}

func TestAgentUsesGrantedScopeAndRotatedAAuthAccess(t *testing.T) {
	t.Parallel()

	var calls int
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch {
			case request.Method == http.MethodGet && request.URL.Path == "/documents" && request.Header.Get("Authorization") == "":
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
	if authorization.Grant == nil || authorization.Pending != nil {
		t.Fatalf("immediate authorization = %#v", authorization)
	}
	grant := *authorization.Grant
	if strings.Join(grant.Scope, " ") != "documents.read" {
		t.Fatalf("granted scope = %q", grant.Scope)
	}

	first, err := agent.DoWithAccess(
		context.Background(),
		reference.AuthorizedCall{Method: http.MethodGet, Endpoint: "https://resource.example/documents"},
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
		reference.AuthorizedCall{Method: http.MethodGet, Endpoint: "https://resource.example/documents"},
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

func TestPublicAgentUsesUniqueProofsForIndependentSameSecondProtectedCalls(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 9, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "person-key")
	agentKey := testSigningKey(t, "agent-key")
	resourceKey := testSigningKey(t, "resource-key")
	resolver := signaturekey.StaticKeyResolver{
		"https://ps.example": {personKey.ID(): personKey.PublicJWK()},
	}
	authToken, err := aauth.MintAuthToken(personKey, aauth.AuthTokenClaims{
		Issuer:       "https://ps.example",
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     "https://resource.example",
		JTI:          "same-second-auth-token",
		PersonServer: "https://ps.example",
		Subject:      "pairwise-person",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		Scope:        "documents.read",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	operationCalls := 0
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier:                   "https://resource.example",
		AccessMode:                   aauth.AccessModeAuthToken,
		PersonServer:                 "https://ps.example",
		SigningKey:                   resourceKey,
		KeyResolver:                  resolver,
		Clock:                        clock,
		NewID:                        sequentialIDs("unused-resource-token"),
		Scopes:                       []string{"documents.read"},
		ScopeDescriptions:            map[string]string{"documents.read": "Read documents"},
		RequiredScopesForRequest:     testRequiredResourceScopes("documents.read"),
		ReplayStore:                  testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error { return nil },
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) {
			operationCalls++
			return map[string]bool{"ok": true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := newLogicalGateway(t, map[string]http.Handler{"resource.example": resource.Handler()})
	defer gateway.Close()
	transport := &capturedRequestTransport{base: gateway.Client().Transport}
	client := gateway.Client()
	client.Transport = transport
	agent, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:reader@ap.example",
		SigningKey:         agentKey,
		AgentToken:         "unused-agent-token",
		KeyResolver:        resolver,
		HTTPClient:         client,
		Clock:              clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := reference.Grant{
		Resource:  "https://resource.example",
		AuthToken: authToken,
		Claims:    mustVerifyAuthToken(t, authToken, resolver, clock),
	}
	call := reference.AuthorizedCall{Method: http.MethodGet, Endpoint: "https://resource.example/documents"}
	for attempt := 1; attempt <= 2; attempt++ {
		response, err := agent.DoAuthorizedRequest(context.Background(), call, grant)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("independent same-second call %d status = %d", attempt, response.StatusCode)
		}
	}
	if operationCalls != 2 {
		t.Fatalf("independent operation calls = %d, want 2", operationCalls)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("captured request count = %d", len(transport.requests))
	}
	replayed, err := client.Do(transport.requests[0].Clone(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Body.Close()
	if replayed.StatusCode != http.StatusUnauthorized {
		t.Fatalf("captured retransmission status = %d", replayed.StatusCode)
	}
	if operationCalls != 2 {
		t.Fatalf("captured retransmission operation calls = %d", operationCalls)
	}
}

func mustVerifyAuthToken(t *testing.T, compact string, resolver signaturekey.KeyResolver, clock aauth.Clock) aauth.AuthTokenClaims {
	t.Helper()
	evidence, err := aauth.VerifyAuthToken(context.Background(), compact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := evidence.Claims()
	if err != nil {
		t.Fatal(err)
	}
	return claims
}
