package resource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Core a99d353, Covered Components, binds @authority to the target host and
// @path to the endpoint. RFC 9110 §7.4 and §15.5.20 permit rejecting a request
// directed to an origin the server is not configured to serve.
func TestResourceBindsRequestAuthorityToIssuer(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"agent", "person", "PS auth", "AS auth"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
			clock := aauth.ClockFunc(func() time.Time { return now })
			providerKey := testSigningKey(t, "authority-ap", 71)
			personKey := testSigningKey(t, "authority-ps", 72)
			accessKey := testSigningKey(t, "authority-as", 73)
			resourceKey := testSigningKey(t, "authority-resource", 74)
			agentKey := testSigningKey(t, "authority-agent", 75)
			resolver := signaturekey.StaticKeyResolver{
				{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
				{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:          personKey.PublicJWK(),
				{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:          accessKey.PublicJWK(),
			}
			applicationCalls, policyCalls := 0, 0
			protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				applicationCalls++
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
				}, now, "authority-agent-token")
			case "person":
				server, err = NewPersonIdentity(PersonIdentityConfig{
					Issuer: resourceIssuer, KeyResolver: resolver, Clock: clock,
					ResolvePerson: resolvePerson, Protected: protected,
				})
				token = mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "authority-person-token")
			case "PS auth":
				server, err = NewPSAuthorization(PSAuthorizationConfig{
					Issuer: resourceIssuer, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
					NewID:             func() string { return "authority-resource-token" },
					ScopeDescriptions: map[string]string{"records.read": "Read records"},
					RequiredScopes:    requiredScopes, ResolvePerson: resolvePerson, Protected: protected,
				})
				token = mintAuthToken(t, personKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
					Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
					JTI: "authority-auth-token", PersonServer: personIssuer, Subject: "person-1", Scope: "records.read",
				})
			case "AS auth":
				config := validConfigWithKey(resourceKey, protected)
				config.Clock, config.KeyResolver = clock, resolver
				config.AdditionalSignatureComponents = nil
				config.RequiredScopes, config.ResolvePerson = requiredScopes, resolvePerson
				server, err = NewFederatedAuthorization(config)
				token = mintAuthToken(t, accessKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
					Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: resourceIssuer,
					JTI: "authority-auth-token", PersonServer: personIssuer, Subject: "person-1", Scope: "records.read",
				})
			}
			if err != nil {
				t.Fatal(err)
			}

			for _, test := range []struct {
				name   string
				target string
				before func(*http.Request)
				after  func(*http.Request)
				want   int
			}{
				{name: "own host", target: resourceIssuer + "/records", want: http.StatusNoContent},
				{name: "normalized authority", target: "https://RESOURCE.example:443/records", want: http.StatusNoContent},
				{name: "another signed path", target: resourceIssuer + "/other-records", want: http.StatusNoContent},
				{name: "foreign host", target: "https://other.example/records", want: http.StatusMisdirectedRequest},
				{name: "foreign port", target: resourceIssuer + ":8443/records", want: http.StatusMisdirectedRequest},
				{name: "foreign Host overrides URL", target: resourceIssuer + "/records",
					before: func(r *http.Request) { r.Host = "other.example" }, want: http.StatusMisdirectedRequest},
				{name: "Unicode case fold is not a DNS alias", target: resourceIssuer + "/records",
					before: func(r *http.Request) { r.Host = "re\u017fource.example" }, want: http.StatusMisdirectedRequest},
				{name: "forwarding headers cannot select issuer", target: "https://other.example/records",
					before: func(r *http.Request) {
						r.Header.Set("Forwarded", "host=resource.example;proto=https")
						r.Header.Set("X-Forwarded-Host", "resource.example")
					}, want: http.StatusMisdirectedRequest},
				{name: "origin form", target: resourceIssuer + "/records",
					after: func(r *http.Request) { r.URL.Scheme, r.URL.Host = "", "" }, want: http.StatusNoContent},
				{name: "foreign origin form", target: "https://other.example/records",
					after: func(r *http.Request) { r.URL.Scheme, r.URL.Host = "", "" }, want: http.StatusMisdirectedRequest},
				{name: "URL authority fallback", target: resourceIssuer + "/records",
					before: func(r *http.Request) { r.Host = "" }, want: http.StatusNoContent},
				{name: "foreign URL authority fallback", target: "https://other.example/records",
					before: func(r *http.Request) { r.Host = "" }, want: http.StatusMisdirectedRequest},
				{name: "host rewritten after signing", target: "https://other.example/records",
					after: func(r *http.Request) { r.Host = "resource.example" }, want: http.StatusUnauthorized},
				{name: "path rewritten after signing", target: resourceIssuer + "/records",
					after: func(r *http.Request) { r.URL.Path = "/admin" }, want: http.StatusUnauthorized},
			} {
				t.Run(test.name, func(t *testing.T) {
					request := httptest.NewRequest(http.MethodGet, test.target, nil)
					if test.before != nil {
						test.before(request)
					}
					if err := signaturekey.SignJWTRequest(request, agentKey, token, clock); err != nil {
						t.Fatal(err)
					}
					if test.after != nil {
						test.after(request)
					}
					applicationCalls, policyCalls = 0, 0
					response := httptest.NewRecorder()
					server.Handler().ServeHTTP(response, request)
					if response.Code != test.want {
						t.Fatalf("status = %d, want %d; application=%d policy=%d; body=%s",
							response.Code, test.want, applicationCalls, policyCalls, response.Body.String())
					}
					if test.want == http.StatusNoContent {
						if applicationCalls != 1 {
							t.Fatalf("application calls = %d, want 1", applicationCalls)
						}
					} else if applicationCalls != 0 || policyCalls != 0 {
						t.Fatalf("refused request reached application=%d policy=%d", applicationCalls, policyCalls)
					}
					if test.want == http.StatusMisdirectedRequest && response.Header().Get("Signature-Error") != "" {
						t.Fatalf("wrong authority was reported as a signature failure: %v", response.Header())
					}
					if test.want == http.StatusMisdirectedRequest && response.Header().Get("Cache-Control") != "private, no-store, no-transform" {
						t.Fatalf("wrong authority response permits caching: %v", response.Header())
					}
					if test.want == http.StatusUnauthorized {
						assertSignatureError(t, response, signaturekey.ErrorInvalidSignature)
					}
				})
			}
		})
	}
}
