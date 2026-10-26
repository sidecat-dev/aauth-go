package resource

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Core a99d353 Covered Components permits Resource requirements. This profile
// requires integrity of nonempty content before application policy runs.
func TestResourceDefaultBodyCoverageBeforePolicy(t *testing.T) {
	for _, mode := range []string{"agent", "person", "PS auth", "AS auth"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
			clock := aauth.ClockFunc(func() time.Time { return now })
			providerKey := testSigningKey(t, "body-ap", 71)
			personKey := testSigningKey(t, "body-ps", 72)
			accessKey := testSigningKey(t, "body-as", 73)
			resourceKey := testSigningKey(t, "body-resource", 74)
			agentKey := testSigningKey(t, "body-agent", 75)
			resolver := signaturekey.StaticKeyResolver{
				{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
				{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:          personKey.PublicJWK(),
				{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:          accessKey.PublicJWK(),
			}
			applicationCalls, policyCalls := 0, 0
			var received []byte
			protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				applicationCalls++
				body, readErr := io.ReadAll(r.Body)
				received = body
				if readErr != nil {
					t.Error(readErr)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			resolvePerson := func(context.Context, PersonIdentity, PersonContext) error {
				policyCalls++
				return nil
			}
			requiredScopes := func(*http.Request) []string {
				policyCalls++
				return []string{"records.read"}
			}
			var server *Server
			var token string
			var err error
			switch mode {
			case "agent":
				server, err = NewAgentIdentity(AgentIdentityConfig{
					Issuer: resourceIssuer, KeyResolver: resolver, Clock: clock, Protected: protected,
				})
				if err != nil {
					t.Fatal(err)
				}
				token, err = aauth.MintAgentToken("https://ap.example", providerKey, aauth.AgentTokenRequest{
					Agent: "aauth:reader@ap.example", PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
				}, now, "body-agent-token")
			case "person":
				server, err = NewPersonIdentity(PersonIdentityConfig{
					Issuer: resourceIssuer, KeyResolver: resolver, Clock: clock,
					ResolvePerson: resolvePerson, Protected: protected,
				})
				token = mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "body-person-token")
			case "PS auth":
				server, err = NewPSAuthorization(PSAuthorizationConfig{
					Issuer: resourceIssuer, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
					NewID:             func() string { return "body-resource-token" },
					ScopeDescriptions: map[string]string{"records.read": "Read records"},
					RequiredScopes:    requiredScopes, ResolvePerson: resolvePerson, Protected: protected,
				})
				token = mintAuthToken(t, personKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
					Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
					JTI: "body-auth-token", PersonServer: personIssuer, Subject: "person-1", Scope: "records.read",
				})
			case "AS auth":
				config := validConfigWithKey(resourceKey, protected)
				config.Clock, config.KeyResolver = clock, resolver
				config.AdditionalSignatureComponents = nil
				config.RequiredScopes, config.ResolvePerson = requiredScopes, resolvePerson
				server, err = NewFederatedAuthorization(config)
				token = mintAuthToken(t, accessKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
					Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: resourceIssuer,
					JTI: "body-auth-token", PersonServer: personIssuer, Subject: "person-1", Scope: "records.read",
				})
			}
			if err != nil {
				t.Fatal(err)
			}

			server.maxSignedBodyBytes = 64
			for _, test := range []struct {
				name           string
				body           string
				contentType    string
				explicitDigest bool
				after          func(*http.Request)
				want           int
				code           signaturekey.ErrorCode
			}{
				{name: "bodyless POST", want: 204},
				{name: "empty transport reader", after: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("")) }, want: 204},
				{name: "original body", body: `{"value":1}`, want: 204},
				{name: "content at the bound", body: strings.Repeat("x", 64), want: 204},
				{name: "original JSON", body: `{"value":1}`, contentType: "application/json", want: 204},
				{name: "changed media type", body: `{"value":1}`, contentType: "application/json", after: func(r *http.Request) {
					r.Header.Set("Content-Type", "text/plain")
				}, want: 401, code: signaturekey.ErrorInvalidSignature},
				{name: "removed media type", body: `{"value":1}`, contentType: "application/json", after: func(r *http.Request) {
					r.Header.Del("Content-Type")
				}, want: 401, code: signaturekey.ErrorInvalidSignature},
				{name: "added media type", body: `{"value":1}`, after: func(r *http.Request) {
					r.Header.Set("Content-Type", "text/plain")
				}, want: 401, code: signaturekey.ErrorInvalidInput},
				{name: "swapped body", body: `{"value":1}`, after: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"value":2}`)) }, want: 401, code: signaturekey.ErrorInvalidSignature},
				{name: "swapped body and recomputed digest", body: `{"value":1}`, after: func(r *http.Request) {
					body := `{"value":2}`
					r.Body = io.NopCloser(strings.NewReader(body))
					digest := sha256.Sum256([]byte(body))
					r.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
				}, want: 401, code: signaturekey.ErrorInvalidSignature},
				{name: "removed body", body: `{"value":1}`, after: func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 0 }, want: 401, code: signaturekey.ErrorInvalidSignature},
				{name: "added body with positive length", after: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("added")); r.ContentLength = 5 }, want: 401, code: signaturekey.ErrorInvalidInput},
				{name: "added body with unknown length", after: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("added")); r.ContentLength = -1 }, want: 401, code: signaturekey.ErrorInvalidInput},
				{name: "added body with unspecified length", after: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("added")); r.ContentLength = 0 }, want: 401, code: signaturekey.ErrorInvalidInput},
				{name: "empty digest then added body", explicitDigest: true, after: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("added")); r.ContentLength = 0 }, want: 401, code: signaturekey.ErrorInvalidSignature},
				{name: "missing digest field", body: `{"value":1}`, after: func(r *http.Request) { r.Header.Del("Content-Digest") }, want: 401, code: signaturekey.ErrorInvalidSignature},
				{name: "body read failure", body: `{"value":1}`, after: func(r *http.Request) {
					r.Body = &bytesThenErrorBody{reader: strings.NewReader(`{"value":1}`), err: errors.New("body stream failed")}
				}, want: 401, code: signaturekey.ErrorInvalidSignature},
				{name: "oversize content", body: strings.Repeat("x", 65), want: 401, code: signaturekey.ErrorInvalidInput},
			} {
				t.Run(test.name, func(t *testing.T) {
					request := httptest.NewRequest(http.MethodPost, resourceIssuer+"/records", strings.NewReader(test.body))
					if test.contentType != "" {
						request.Header.Set("Content-Type", test.contentType)
					}
					options := signaturekey.SignOptions{}
					if test.explicitDigest {
						options.AdditionalComponents = []string{"content-digest"}
					}
					if err := signaturekey.SignJWTRequestWithOptions(request, agentKey, token, clock, options); err != nil {
						t.Fatal(err)
					}
					if test.after != nil {
						test.after(request)
					}
					applicationCalls, policyCalls = 0, 0
					received = nil
					response := httptest.NewRecorder()
					server.Handler().ServeHTTP(response, request)
					if response.Code != test.want {
						t.Fatalf("status=%d want=%d; application=%d policy=%d body=%s", response.Code, test.want, applicationCalls, policyCalls, response.Body.String())
					}
					if test.want == 204 {
						if applicationCalls != 1 || string(received) != test.body {
							t.Fatalf("application calls=%d body=%q", applicationCalls, received)
						}
					} else {
						if applicationCalls != 0 || policyCalls != 0 {
							t.Fatalf("refused body reached application=%d policy=%d", applicationCalls, policyCalls)
						}
						assertSignatureError(t, response, test.code)
						requiredComponent := "content-digest"
						if test.name == "added media type" {
							requiredComponent = "content-type"
						}
						if test.code == signaturekey.ErrorInvalidInput && test.name != "oversize content" && !strings.Contains(response.Header().Get("Signature-Error"), requiredComponent) {
							t.Fatalf("missing required_input: %v", response.Header())
						}
					}
				})
			}
		})
	}
}
