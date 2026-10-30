package resource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// A request to the authorization endpoint that carries no person token is
// answered with 401 and requirement=person-token, and no resource token is
// issued from any other credential.
func TestAuthorizationEndpointChallengesRequestsWithoutPersonToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 16, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const provider = "https://provider.example"
	providerKey := testSigningKey(t, "authorize-provider-key", 0x61)
	accessKey := testSigningKey(t, "authorize-access-key", 0x62)
	resourceKey := testSigningKey(t, "authorize-resource-key", 0x63)
	agentKey := testSigningKey(t, "authorize-agent-key", 0x64)
	wrongKey := testSigningKey(t, "authorize-wrong-key", 0x65)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: provider, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:          providerKey.PublicJWK(),
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	issued := 0
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer:       resourceIssuer,
		AccessServer: accessIssuer,
		SigningKey:   resourceKey,
		KeyResolver:  resolver,
		Clock:        clock,
		NewID: func() string {
			issued++
			return "resource-token-unexpected"
		},
		ScopeDescriptions:             map[string]string{"records.read": "Read records"},
		AdditionalSignatureComponents: []string{"content-type", "content-digest"},
		MaxSignedBodyBytes:            64 << 10,
		RequiredScopes:                func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:                 func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected:                     http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := aauth.MintAgentToken(provider, providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:assistant@provider.example", PersonServer: personIssuer,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}, now, "authorize-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	authToken := mintAuthToken(t, accessKey, agentKey.PublicJWK(), now, authClaims())
	const body = `{"scope":"records.read"}`

	assertPersonTokenChallenge := func(t *testing.T, response *httptest.ResponseRecorder) {
		t.Helper()
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body = %s", response.Code, response.Body.String())
		}
		if err := aauth.ParsePersonTokenRequirement(response.Header().Values("AAuth-Requirement")); err != nil {
			t.Fatalf("AAuth-Requirement = %q: %v", response.Header().Values("AAuth-Requirement"), err)
		}
		if header := response.Header().Get("Signature-Error"); header != "" {
			t.Fatalf("Signature-Error = %q on a challenge", header)
		}
		if strings.Contains(response.Body.String(), "resource_token") || issued != 0 {
			t.Fatalf("challenge issued a resource token: body=%s issued=%d", response.Body.String(), issued)
		}
	}

	t.Run("agent token", func(t *testing.T) {
		request := signedRequest(t, clock, agentKey, agentToken, http.MethodPost, resourceIssuer+"/authorize", body)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		assertPersonTokenChallenge(t, response)
	})

	t.Run("auth token", func(t *testing.T) {
		request := signedRequest(t, clock, agentKey, authToken, http.MethodPost, resourceIssuer+"/authorize", body)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		assertPersonTokenChallenge(t, response)
	})

	t.Run("no request proof", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, resourceIssuer+"/authorize", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		assertPersonTokenChallenge(t, response)
	})

	// A request missing one of Signature, Signature-Input, or Signature-Key
	// fails verification step 1 with invalid_signature.
	for _, missing := range []string{"Signature", "Signature-Input", "Signature-Key"} {
		t.Run("missing "+missing, func(t *testing.T) {
			request := signedRequest(t, clock, agentKey, agentToken, http.MethodPost, resourceIssuer+"/authorize", body)
			request.Header.Del(missing)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			assertSignatureError(t, response, signaturekey.ErrorInvalidSignature)
			if issued != 0 {
				t.Fatalf("partial proof issued a resource token")
			}
		})
	}

	// The challenge follows verification of the credential the request does
	// carry: an agent-token request whose signature fails is a verification
	// failure, not a person-token requirement.
	t.Run("agent token with a failing signature", func(t *testing.T) {
		request := signedRequest(t, clock, wrongKey, agentToken, http.MethodPost, resourceIssuer+"/authorize", body)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		assertSignatureError(t, response, signaturekey.ErrorInvalidSignature)
		if response.Header().Get("AAuth-Requirement") != "" || issued != 0 {
			t.Fatalf("failed proof = headers %v, issued %d", response.Header(), issued)
		}
	})
}
