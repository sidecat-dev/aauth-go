package reference

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestTokenAuthoritiesRejectUnsupportedResourceTokenClaimBeforeProofReplay(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 23, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := referenceTestSigningKey(t, "person-key")
	providerKey := referenceTestSigningKey(t, "provider-key")
	agentKey := referenceTestSigningKey(t, "agent-key")
	resourceKey, resourcePrivate := preflightTestSigningMaterial(t, "resource-key")
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := aauth.MintAgentToken(
		"https://ap.example",
		providerKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:agent@ap.example",
			PersonServer: "https://ps.example",
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		now,
		"agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}

	newRawResourceToken := func(audience string) string {
		t.Helper()
		return signRawPreflightResourceToken(t, resourceKey, resourcePrivate, aauth.ResourceTokenClaims{
			Issuer:       "https://resource.example",
			DWK:          aauth.ResourceDiscoveryDocument,
			Audience:     audience,
			JTI:          "resource-token",
			AgentJKT:     agentJKT,
			IssuedAt:     now.Unix(),
			ExpiresAt:    now.Add(5 * time.Minute).Unix(),
			Scope:        "records.read",
			PersonServer: "https://ps.example",
			Subject:      "person-1",
			PresentedJTI: "person-token-1",
		}, "r3_uri", `"https://resource.example/r3/document"`)
	}

	for _, test := range []struct {
		name       string
		newServer  func(t *testing.T, policyCalls *int) http.Handler
		newRequest func(t *testing.T) *http.Request
	}{
		{
			name: "person server",
			newServer: func(t *testing.T, policyCalls *int) http.Handler {
				t.Helper()
				personTokens, err := NewFilePersonTokenStore(t.TempDir() + "/person-tokens.json")
				if err != nil {
					t.Fatal(err)
				}
				missionIssuance, err := NewFileMissionIssuanceStore(t.TempDir() + "/mission-issuance.json")
				if err != nil {
					t.Fatal(err)
				}
				authorizationStore, err := NewMemoryAuthorizationStateStore(16, 1<<20)
				if err != nil {
					t.Fatal(err)
				}
				server, err := NewPersonServer(PersonServerConfig{
					Identifier: "https://ps.example",
					SigningKey: personKey,
					KeyResolver: aauth.StaticKeyResolver{
						"https://ap.example":       {providerKey.ID(): providerKey.PublicJWK()},
						"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
					},
					Clock:                clock,
					NewID:                func() string { return "unused" },
					AuthorizationStore:   authorizationStore,
					PersonTokenStore:     personTokens,
					MissionIssuanceStore: missionIssuance,
					PersonTokenPolicy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
						return aauth.PersonTokenDecision{}, errors.New("unused")
					},
					CurrentMissionPolicy: func(context.Context, aauth.MissionEvaluation) (aauth.MissionDecision, error) {
						return aauth.MissionDecision{}, errors.New("unused")
					},
					AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
						(*policyCalls)++
						return aauth.AuthorizationDecision{}, errors.New("policy reached")
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				return server.Handler()
			},
			newRequest: func(t *testing.T) *http.Request {
				t.Helper()
				body, err := json.Marshal(personAuthorizationTokenInput{ResourceToken: newRawResourceToken("https://ps.example")})
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(http.MethodPost, "https://ps.example/token", bytes.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				if err := aauth.SignRequest(request, agentKey, agentToken, clock); err != nil {
					t.Fatal(err)
				}
				return request
			},
		},
		{
			name: "access server",
			newServer: func(t *testing.T, policyCalls *int) http.Handler {
				t.Helper()
				authorizationStore, err := NewMemoryAuthorizationStateStore(16, 1<<20)
				if err != nil {
					t.Fatal(err)
				}
				server, err := NewAccessServer(AccessServerConfig{
					Identifier: "https://as.example",
					SigningKey: referenceTestSigningKey(t, "access-key"),
					KeyResolver: aauth.StaticKeyResolver{
						"https://ps.example":       {personKey.ID(): personKey.PublicJWK()},
						"https://ap.example":       {providerKey.ID(): providerKey.PublicJWK()},
						"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
					},
					Clock:              clock,
					NewID:              func() string { return "unused" },
					AuthorizationStore: authorizationStore,
					TrustedPersonServer: func(context.Context, string) error {
						return nil
					},
					AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
						(*policyCalls)++
						return aauth.AuthorizationDecision{}, errors.New("policy reached")
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				return server.Handler()
			},
			newRequest: func(t *testing.T) *http.Request {
				t.Helper()
				body, err := json.Marshal(accessAuthorizationTokenInput{
					ResourceToken: newRawResourceToken("https://as.example"),
					AgentToken:    agentToken,
				})
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(http.MethodPost, "https://as.example/token", bytes.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				if err := aauth.SignRequestWithJWKSURI(
					request,
					personKey,
					"https://ps.example",
					aauth.PersonDiscoveryDocument,
					clock,
				); err != nil {
					t.Fatal(err)
				}
				return request
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			policyCalls := 0
			handler := test.newServer(t, &policyCalls)
			request := test.newRequest(t)
			for attempt := 0; attempt < 2; attempt++ {
				clone := request.Clone(context.Background())
				clone.Body, err = request.GetBody()
				if err != nil {
					t.Fatal(err)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, clone)
				if response.Code != http.StatusBadRequest ||
					!strings.Contains(response.Body.String(), `"error":"invalid_resource_token"`) ||
					!strings.Contains(response.Body.String(), "r3_uri") {
					t.Fatalf("attempt %d = %d: %s", attempt+1, response.Code, response.Body.String())
				}
			}
			if policyCalls != 0 {
				t.Fatalf("unsupported ResourceToken reached policy %d times", policyCalls)
			}
		})
	}
}

func TestAccessServerTrustPolicyRefusalDoesNotLeakHostDetail(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 23, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := referenceTestSigningKey(t, "person-key")
	authorizationStore, err := NewMemoryAuthorizationStateStore(16, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewAccessServer(AccessServerConfig{
		Identifier: "https://as.example",
		SigningKey: referenceTestSigningKey(t, "access-key"),
		KeyResolver: aauth.StaticKeyResolver{
			"https://ps.example": {personKey.ID(): personKey.PublicJWK()},
		},
		Clock:              clock,
		NewID:              func() string { return "unused" },
		AuthorizationStore: authorizationStore,
		TrustedPersonServer: func(context.Context, string) error {
			return errors.New("secret trust database /srv/tenants.db")
		},
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			t.Fatal("authorization policy ran after trust refusal")
			return aauth.AuthorizationDecision{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://as.example/token", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequestWithJWKSURI(
		request,
		personKey,
		"https://ps.example",
		aauth.PersonDiscoveryDocument,
		clock,
	); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden ||
		!strings.Contains(response.Body.String(), `"error":"untrusted_person_server"`) ||
		!strings.Contains(response.Body.String(), `"detail":"person server is not trusted"`) ||
		strings.Contains(response.Body.String(), "secret trust") {
		t.Fatalf("trust-policy refusal = %d: %s", response.Code, response.Body.String())
	}
}

func preflightTestSigningMaterial(t *testing.T, id string) (aauth.SigningKey, ed25519.PrivateKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := aauth.NewEd25519SigningKey(id, private)
	if err != nil {
		t.Fatal(err)
	}
	return key, private
}

func signRawPreflightResourceToken(
	t *testing.T,
	key aauth.SigningKey,
	private ed25519.PrivateKey,
	claims aauth.ResourceTokenClaims,
	claimName string,
	claimValue string,
) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload[:len(payload)-1], []byte(`,"`+claimName+`":`+claimValue)...)
	payload = append(payload, '}')
	header, err := json.Marshal(aauth.TokenHeader{
		Algorithm: aauth.Ed25519Algorithm,
		Type:      aauth.ResourceTokenType,
		KeyID:     key.ID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(signingInput)))
}
