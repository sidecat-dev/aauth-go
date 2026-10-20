package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestRunVerifiesTokenAndRequest(t *testing.T) {
	var output bytes.Buffer
	if err := run(&output); err != nil {
		t.Fatal(err)
	}
	want := "Token verified: aauth:reader@agents.example\n" +
		"Request verified: aauth:reader@agents.example\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}

func TestServiceVerificationRejectsInvalidCredentials(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey, agentKey := signingKey("provider-key"), signingKey("agent-key")
	token, err := aauth.MintAgentToken("https://agents.example", providerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:reader@agents.example", PublicKey: agentKey.PublicJWK(),
			Lifetime: time.Hour,
		}, now, "example-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	keys := providerKeys(providerKey.PublicJWK())
	parts := strings.Split(token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature)
	for _, test := range []struct {
		name  string
		token string
		keys  signaturekey.KeyResolver
		clock aauth.Clock
	}{
		{"tampered token", tampered, keys, clock},
		{"untrusted issuer key", token, providerKeys(signingKey("provider-key").PublicJWK()), clock},
		{"expired token", token, keys, aauth.ClockFunc(func() time.Time { return now.Add(2 * time.Hour) })},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := aauth.VerifyAgentToken(context.Background(), test.token, test.keys, test.clock); err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}

	calls := 0
	handler, err := agentResource(keys, clock, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		principal, ok := resource.AgentPrincipalFromContext(r.Context())
		if !ok || principal.Agent != "aauth:reader@agents.example" {
			t.Fatalf("principal = %#v, present = %t", principal, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "missing proof", "wrong proof key", "changed method", "tampered token"} {
		t.Run(mode, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://resource.example/records", nil)
			key, compact := agentKey, token
			if mode == "wrong proof key" {
				key = signingKey("other-agent-key")
			}
			if mode == "tampered token" {
				compact = tampered
			}
			if mode != "missing proof" {
				if err := signaturekey.SignJWTRequest(request, key, compact, clock); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "changed method" {
				request.Method = http.MethodDelete
			}
			before := calls
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if mode == "valid" {
				if recorder.Code != http.StatusNoContent || calls != before+1 {
					t.Fatalf("valid request: status=%d, calls=%d", recorder.Code, calls-before)
				}
			} else if recorder.Code != http.StatusUnauthorized || calls != before {
				t.Fatalf("invalid request: status=%d, calls=%d", recorder.Code, calls-before)
			}
		})
	}
}
