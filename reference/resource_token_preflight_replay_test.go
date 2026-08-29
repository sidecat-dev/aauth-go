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

	newRawResourceToken := func(audience, member, value string) string {
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
		}, member, value)
	}

	for _, extension := range []struct {
		name, member, value string
	}{
		{name: "r3", member: "r3_uri", value: `"https://resource.example/r3/document"`},
		{name: "budget", member: "budget", value: `{"amount":100,"unit":"USD","decimals":2}`},
		{name: "budget consumed", member: "budget_consumed", value: `[{"jti":"auth-1","consumed":10}]`},
	} {
		for _, test := range []struct {
			name       string
			newServer  func(t *testing.T, authorizationPolicyCalls *int) http.Handler
			newRequest func(t *testing.T) *http.Request
		}{
			{
				name: "person server",
				newServer: func(t *testing.T, authorizationPolicyCalls *int) http.Handler {
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
							(*authorizationPolicyCalls)++
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
					body, err := json.Marshal(personAuthorizationTokenInput{ResourceToken: newRawResourceToken("https://ps.example", extension.member, extension.value)})
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
				newServer: func(t *testing.T, authorizationPolicyCalls *int) http.Handler {
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
							(*authorizationPolicyCalls)++
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
						ResourceToken: newRawResourceToken("https://as.example", extension.member, extension.value),
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
			t.Run(extension.name+"/"+test.name, func(t *testing.T) {
				authorizationPolicyCalls := 0
				handler := test.newServer(t, &authorizationPolicyCalls)
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
						!strings.Contains(response.Body.String(), extension.member) {
						t.Fatalf("attempt %d = %d: %s", attempt+1, response.Code, response.Body.String())
					}
				}
				if authorizationPolicyCalls != 0 {
					t.Fatalf("unsupported ResourceToken reached authorization policy %d times", authorizationPolicyCalls)
				}
			})
		}
	}
}

func TestPersonTokenAuthorityRejectsUnsupportedUpstreamClaimBeforeProofReplay(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 23, 20, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := referenceTestSigningKey(t, "provider-key")
	serverKey := referenceTestSigningKey(t, "person-server-key")
	agentKey := referenceTestSigningKey(t, "agent-key")
	upstreamKey, upstreamPrivate := preflightTestSigningMaterial(t, "upstream-key")
	agentToken, err := aauth.MintAgentToken(
		"https://ap.example",
		providerKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:agent@ap.example",
			PersonServer: "https://upstream-ps.example",
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		now,
		"agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, extension := range []struct {
		member, value string
	}{
		{member: "budget", value: `{"amount":100,"unit":"USD","decimals":2}`},
		{member: "budget_consumed", value: `[{"jti":"auth-1","consumed":10}]`},
	} {
		t.Run(extension.member, func(t *testing.T) {
			personTokens := &preflightPersonTokenStore{}
			missionIssuance := &preflightMissionIssuanceStore{}
			authorizationStore, err := NewMemoryAuthorizationStateStore(16, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			personPolicyCalls := 0
			server, err := NewPersonServer(PersonServerConfig{
				Identifier: "https://ps.example",
				SigningKey: serverKey,
				KeyResolver: aauth.StaticKeyResolver{
					"https://ap.example":          {providerKey.ID(): providerKey.PublicJWK()},
					"https://upstream-ps.example": {upstreamKey.ID(): upstreamKey.PublicJWK()},
				},
				Clock:                clock,
				NewID:                func() string { return "unused" },
				AuthorizationStore:   authorizationStore,
				PersonTokenStore:     personTokens,
				MissionIssuanceStore: missionIssuance,
				PersonTokenPolicy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
					personPolicyCalls++
					return aauth.PersonTokenDecision{}, errors.New("person-token policy reached")
				},
				CurrentMissionPolicy: func(context.Context, aauth.MissionEvaluation) (aauth.MissionDecision, error) {
					return aauth.MissionDecision{}, errors.New("mission policy must not run")
				},
				AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
					return aauth.AuthorizationDecision{}, errors.New("authorization policy must not run")
				},
				TrustedUpstreamIssuer: func(context.Context, string) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			upstreamToken := signRawPreflightAuthToken(t, upstreamKey, upstreamPrivate, aauth.AuthTokenClaims{
				Issuer:       "https://upstream-ps.example",
				DWK:          aauth.PersonDiscoveryDocument,
				Audience:     "https://ap.example",
				JTI:          "upstream-auth-token",
				Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
				IssuedAt:     now.Unix(),
				ExpiresAt:    now.Add(time.Hour).Unix(),
				Subject:      "upstream-person",
				Scope:        "records.read",
				PersonServer: "https://ps.example",
			}, extension.member, extension.value)
			body, err := json.Marshal(map[string]string{
				"resource":       "https://resource.example",
				"upstream_token": upstreamToken,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "https://ps.example/person", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			if err := aauth.SignRequest(request, agentKey, agentToken, clock); err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				clone := request.Clone(context.Background())
				clone.Body, err = request.GetBody()
				if err != nil {
					t.Fatal(err)
				}
				response := httptest.NewRecorder()
				server.Handler().ServeHTTP(response, clone)
				if response.Code != http.StatusBadRequest ||
					!strings.Contains(response.Body.String(), `"error":"invalid_upstream_token"`) ||
					!strings.Contains(response.Body.String(), extension.member) {
					t.Fatalf("attempt %d = %d: %s", attempt+1, response.Code, response.Body.String())
				}
			}
			if personPolicyCalls != 0 || personTokens.commits != 0 || personTokens.loads != 0 ||
				missionIssuance.commits != 0 || missionIssuance.loads != 0 {
				t.Fatalf(
					"unsupported upstream token reached policy/person/mission custody = %d/%d,%d/%d,%d",
					personPolicyCalls,
					personTokens.commits,
					personTokens.loads,
					missionIssuance.commits,
					missionIssuance.loads,
				)
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

func signRawPreflightAuthToken(
	t *testing.T,
	key aauth.SigningKey,
	private ed25519.PrivateKey,
	claims aauth.AuthTokenClaims,
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
		Type:      aauth.AuthTokenType,
		KeyID:     key.ID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(signingInput)))
}

type preflightPersonTokenStore struct {
	commits int
	loads   int
}

func (store *preflightPersonTokenStore) Commit(context.Context, PersonTokenRecord) error {
	store.commits++
	return errors.New("person-token custody must not run")
}

func (store *preflightPersonTokenStore) Load(context.Context, string, string) (PersonTokenRecord, error) {
	store.loads++
	return PersonTokenRecord{}, errors.New("person-token custody must not run")
}

type preflightMissionIssuanceStore struct {
	commits int
	loads   int
}

func (store *preflightMissionIssuanceStore) Commit(context.Context, MissionIssuanceRecord) error {
	store.commits++
	return errors.New("mission-issuance custody must not run")
}

func (store *preflightMissionIssuanceStore) Load(context.Context, string) (MissionIssuanceRecord, error) {
	store.loads++
	return MissionIssuanceRecord{}, errors.New("mission-issuance custody must not run")
}
