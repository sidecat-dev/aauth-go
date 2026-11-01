package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
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

// Core Covered Components permits Resources to require content-digest in
// addition to the mandatory target and credential fields.
func TestServiceVerificationProtectsRequestBodies(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey, agentKey := signingKey("provider-key"), signingKey("agent-key")
	token, err := aauth.MintAgentToken("https://agents.example", providerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:reader@agents.example", PublicKey: agentKey.PublicJWK(),
			Lifetime: time.Hour,
		}, now, "example-body-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		digest  bool
		replace bool
		want    int
	}{
		{"covered body", true, false, http.StatusCreated},
		{"missing body coverage", false, false, http.StatusUnauthorized},
		{"uncovered body replaced", false, true, http.StatusUnauthorized},
		{"covered body replaced", true, true, http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			const original = `{"note":"approved"}`
			calls := 0
			handler, err := agentResource(providerKeys(providerKey.PublicJWK()), clock,
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					body, err := io.ReadAll(r.Body)
					if err != nil || string(body) != original {
						t.Errorf("application received body %q, error %v", body, err)
					}
					w.WriteHeader(http.StatusCreated)
				}))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "https://resource.example/notes", strings.NewReader(original))
			if test.digest {
				err = signAgentRequest(request, agentKey, token, clock)
			} else {
				body, length := request.Body, request.ContentLength
				request.Body, request.ContentLength = http.NoBody, 0
				err = signaturekey.SignJWTRequest(request, agentKey, token, clock)
				request.Body, request.ContentLength = body, length
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.replace {
				request.Body = io.NopCloser(strings.NewReader(`{"note":"tampered"}`))
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d; application calls = %d", response.Code, test.want, calls)
			}
			if test.want == http.StatusUnauthorized && calls != 0 {
				t.Fatalf("refused body reached application %d times", calls)
			}
			if test.want == http.StatusCreated && calls != 1 {
				t.Fatalf("verified body reached application %d times, want 1", calls)
			}
		})
	}
}

// Core a99d353 Resource Metadata requires advertised additional components on
// requests to the Resource, including requests with empty content.
func TestServiceVerificationRequiresExplicitDigestOnEmptyRequests(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey, agentKey := signingKey("provider-key"), signingKey("agent-key")
	token, err := aauth.MintAgentToken("https://agents.example", providerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:reader@agents.example", PublicKey: agentKey.PublicJWK(),
			Lifetime: time.Hour,
		}, now, "example-empty-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, digest := range []bool{false, true} {
			name := method + "/missing digest"
			if digest {
				name = method + "/covered empty digest"
			}
			t.Run(name, func(t *testing.T) {
				calls := 0
				handler, err := digestEverywhereResource(providerKeys(providerKey.PublicJWK()), clock,
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls++
						w.WriteHeader(http.StatusNoContent)
					}))
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(method, "https://resource.example/notes", nil)
				if digest {
					err = signAgentRequest(request, agentKey, token, clock)
				} else {
					err = signaturekey.SignJWTRequest(request, agentKey, token, clock)
				}
				if err != nil {
					t.Fatal(err)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if digest {
					if response.Code != http.StatusNoContent || calls != 1 {
						t.Fatalf("covered empty digest: status=%d calls=%d", response.Code, calls)
					}
				} else {
					if response.Code != http.StatusUnauthorized || calls != 0 {
						t.Fatalf("missing empty digest: status=%d calls=%d", response.Code, calls)
					}
					problem := response.Header().Get("Signature-Error")
					for _, required := range []string{"invalid_input", "required_input", "content-digest"} {
						if !strings.Contains(problem, required) {
							t.Fatalf("Signature-Error = %q, missing %q", problem, required)
						}
					}
				}
			})
		}
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
				if err := signAgentRequest(request, key, compact, clock); err != nil {
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
