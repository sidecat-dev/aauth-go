package personserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// A Person Server must not present an expired token to an Access Server. Consent
// can take as long as the person needs, so a presented or Resource token that
// expires while consent runs is refused and nothing is sent to the Access
// Server.
func TestFederatedAuthorizationRechecksExpiryAfterConsent(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name           string
		presentedLife  time.Duration
		resourceLife   time.Duration
		consentReturns time.Duration
		wantProblem    string
	}{
		{
			name: "presented token expires during consent", presentedLife: 2 * time.Minute,
			resourceLife: 5 * time.Minute, consentReturns: 2 * time.Minute,
			wantProblem: "expired_presented_token",
		},
		{
			name: "Resource token expires during consent", presentedLife: 20 * time.Minute,
			resourceLife: 5 * time.Minute, consentReturns: 5 * time.Minute,
			wantProblem: "expired_resource_token",
		},
		{
			name: "tokens still current after consent", presentedLife: 2 * time.Minute,
			resourceLife: 5 * time.Minute, consentReturns: 2*time.Minute - time.Second,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var mu sync.Mutex
			current := start
			clock := aauth.ClockFunc(func() time.Time {
				mu.Lock()
				defer mu.Unlock()
				return current
			})
			providerKey := personServerTestKey(t, "expiry-provider")
			personKey := personServerTestKey(t, "expiry-person")
			resourceKey := personServerTestKey(t, "expiry-resource")
			accessKey := personServerTestKey(t, "expiry-access")
			agentKey := personServerTestKey(t, "expiry-agent")
			const (
				providerID = "https://provider.example"
				personID   = "https://person.example"
				resourceID = "https://resource.example"
				accessID   = "https://access.example"
				agentID    = "aauth:planner@provider.example"
			)
			resolver := signaturekey.StaticKeyResolver{
				{Issuer: providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
				{Issuer: personID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
				{Issuer: resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
				{Issuer: accessID, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
			}
			agentToken, err := aauth.MintAgentToken(providerID, providerKey, aauth.AgentTokenRequest{
				Agent: agentID, PersonServer: personID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
			}, start, "expiry-agent-token")
			if err != nil {
				t.Fatal(err)
			}
			agentJKT, err := agentKey.PublicJWK().Thumbprint()
			if err != nil {
				t.Fatal(err)
			}
			resourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
				Issuer: resourceID, DWK: aauth.ResourceDiscoveryDocument, Audience: accessID,
				JTI: "expiry-resource-token", AgentJKT: agentJKT,
				IssuedAt: start.Unix(), ExpiresAt: start.Add(test.resourceLife).Unix(),
				Scope: "records.read", PersonServer: personID, Subject: "person-123",
				PresentedJTI: "expiry-person-token", Tenant: "tenant-1",
			})
			if err != nil {
				t.Fatal(err)
			}
			presentedToken := testPresentedPersonToken(
				t, personKey, resourceToken, agentKey.PublicJWK(), start, start.Add(test.presentedLife),
			)
			accessCalls := 0
			httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				mu.Lock()
				accessCalls++
				mu.Unlock()
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Status:     "403 Forbidden",
					Header:     http.Header{"Content-Type": []string{"application/problem+json"}},
					Body:       io.NopCloser(strings.NewReader(`{"status":403,"error":"access_denied"}`)),
					Request:    request,
				}, nil
			})}
			consents := 0
			server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
				Issuer: personID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
				NewID:      func() string { return "unused" },
				HTTPClient: httpClient,
				AccessServerEndpoint: func(context.Context, string) (string, error) {
					return "https://api.access.example/token", nil
				},
				Tokens: newMemoryTokenStore(),
				BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
					return Person{}, errors.New("not used")
				},
				Consent: func(context.Context, AuthorizationRequest) error {
					mu.Lock()
					defer mu.Unlock()
					consents++
					current = start.Add(test.consentReturns)
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, personID+"/token",
				bytes.NewReader(testTokenRequestBody(t, resourceToken, presentedToken)))
			request.Header.Set("Content-Type", "application/json")
			if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)

			mu.Lock()
			calls, consented := accessCalls, consents
			mu.Unlock()
			if consented != 1 {
				t.Fatalf("consent calls = %d, want 1", consented)
			}
			if test.wantProblem == "" {
				// The Access Server was reached and its refusal relayed.
				if calls != 1 || response.Code != http.StatusForbidden {
					t.Fatalf("access calls = %d, response = %d %s", calls, response.Code, response.Body.String())
				}
				return
			}
			if calls != 0 {
				t.Fatalf("an expired token was presented to the Access Server (%d calls)", calls)
			}
			assertPersonServerProblem(t, response, test.wantProblem)
		})
	}
}
