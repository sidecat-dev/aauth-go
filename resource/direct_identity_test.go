package resource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestDirectIdentityConstructorsRequireOnlyTheirModeDependencies(t *testing.T) {
	t.Parallel()

	clock := aauth.ClockFunc(func() time.Time { return time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC) })
	valid := AgentIdentityConfig{
		Issuer: resourceIssuer, KeyResolver: signaturekey.StaticKeyResolver{}, Clock: clock,
		Protected: http.NotFoundHandler(),
	}
	for _, test := range []struct {
		name   string
		change func(*AgentIdentityConfig)
	}{
		{name: "issuer", change: func(config *AgentIdentityConfig) { config.Issuer = "" }},
		{name: "resolver", change: func(config *AgentIdentityConfig) { config.KeyResolver = nil }},
		{name: "clock", change: func(config *AgentIdentityConfig) { config.Clock = nil }},
		{name: "handler", change: func(config *AgentIdentityConfig) { config.Protected = nil }},
		{name: "body limit", change: func(config *AgentIdentityConfig) { config.MaxSignedBodyBytes = -1 }},
		{name: "component", change: func(config *AgentIdentityConfig) { config.AdditionalSignatureComponents = []string{"Content-Type"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			if _, err := NewAgentIdentity(config); err == nil {
				t.Fatal("NewAgentIdentity accepted incomplete configuration")
			}
		})
	}
	if _, err := NewPersonIdentity(PersonIdentityConfig{
		Issuer: resourceIssuer, KeyResolver: signaturekey.StaticKeyResolver{}, Clock: clock,
		Protected: http.NotFoundHandler(),
	}); err == nil {
		t.Fatal("NewPersonIdentity accepted a missing person resolver")
	}
}

func TestDirectIdentityResourcesAdvertiseAndChallengeForTheirExactCredential(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	issuerKey := testSigningKey(t, "wrong-mode-issuer", 21)
	proofKey := testSigningKey(t, "wrong-mode-proof", 22)
	for _, test := range []struct {
		name        string
		mode        aauth.AccessMode
		newResource func(http.Handler) (*Server, error)
		parse       func([]string) error
	}{
		{
			name: "agent", mode: aauth.AccessModeAgentToken, parse: aauth.ParseAgentTokenRequirement,
			newResource: func(protected http.Handler) (*Server, error) {
				return NewAgentIdentity(AgentIdentityConfig{
					Issuer: resourceIssuer, KeyResolver: signaturekey.StaticKeyResolver{}, Clock: clock,
					AdditionalSignatureComponents: []string{"x-request-id"}, Protected: protected,
				})
			},
		},
		{
			name: "person", mode: aauth.AccessModePersonToken, parse: aauth.ParsePersonTokenRequirement,
			newResource: func(protected http.Handler) (*Server, error) {
				return NewPersonIdentity(PersonIdentityConfig{
					Issuer: resourceIssuer, KeyResolver: signaturekey.StaticKeyResolver{}, Clock: clock,
					AdditionalSignatureComponents: []string{"x-request-id"},
					ResolvePerson:                 func(context.Context, PersonIdentity, PersonContext) error { return nil },
					Protected:                     protected,
				})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := 0
			server, err := test.newResource(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called++ }))
			if err != nil {
				t.Fatal(err)
			}
			metadataResponse := httptest.NewRecorder()
			server.Handler().ServeHTTP(metadataResponse, httptest.NewRequest(http.MethodGet, resourceIssuer+"/.well-known/aauth-resource.json", nil))
			var metadata map[string]json.RawMessage
			if err := json.Unmarshal(metadataResponse.Body.Bytes(), &metadata); err != nil {
				t.Fatal(err)
			}
			if metadataResponse.Code != http.StatusOK || len(metadata) != 3 || string(metadata["access_mode"]) != `"`+string(test.mode)+`"` ||
				string(metadata["issuer"]) != `"`+resourceIssuer+`"` || string(metadata["additional_signature_components"]) != `["x-request-id"]` {
				t.Fatalf("metadata status = %d, body = %s", metadataResponse.Code, metadataResponse.Body.String())
			}

			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, resourceIssuer+"/records", nil))
			if response.Code != http.StatusUnauthorized || response.Header().Get("Signature-Error") != "" ||
				test.parse(response.Header().Values("AAuth-Requirement")) != nil || called != 0 {
				t.Fatalf("challenge = %d headers=%v body=%s called=%d", response.Code, response.Header(), response.Body.String(), called)
			}

			partial := httptest.NewRequest(http.MethodGet, resourceIssuer+"/records", nil)
			partial.Header.Set("Signature-Input", `sig=("@method")`)
			response = httptest.NewRecorder()
			server.Handler().ServeHTTP(response, partial)
			if response.Code != http.StatusUnauthorized || response.Header().Get("Signature-Error") == "" ||
				response.Header().Get("AAuth-Requirement") != "" || called != 0 {
				t.Fatalf("partial proof = %d headers=%v body=%s called=%d", response.Code, response.Header(), response.Body.String(), called)
			}

			authToken, err := aauth.MintAuthToken(issuerKey, aauth.AuthTokenClaims{
				Issuer: "https://as.example", DWK: aauth.AccessDiscoveryDocument,
				Audience: resourceIssuer, JTI: "wrong-mode-auth",
				PersonServer: "https://ps.example", Subject: "direct-person",
				Confirmation: aauth.Confirmation{JWK: proofKey.PublicJWK()},
				IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
			})
			if err != nil {
				t.Fatal(err)
			}
			wrongModeTokens := []string{authToken}
			switch test.mode {
			case aauth.AccessModeAgentToken:
				wrongModeToken, err := aauth.MintPersonToken(issuerKey, aauth.PersonTokenClaims{
					Issuer: "https://ps.example", DWK: aauth.PersonDiscoveryDocument,
					Audience: resourceIssuer, Subject: "direct-person",
					Confirmation: aauth.Confirmation{JWK: proofKey.PublicJWK()},
					JTI:          "wrong-mode-person", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
				})
				if err != nil {
					t.Fatal(err)
				}
				wrongModeTokens = append(wrongModeTokens, wrongModeToken)
			case aauth.AccessModePersonToken:
				wrongModeToken, err := aauth.MintAgentToken("https://ap.example", issuerKey, aauth.AgentTokenRequest{
					Agent: "aauth:reader@ap.example", PublicKey: proofKey.PublicJWK(), Lifetime: time.Hour,
				}, now, "wrong-mode-agent")
				if err != nil {
					t.Fatal(err)
				}
				wrongModeTokens = append(wrongModeTokens, wrongModeToken)
			}
			for index, wrongModeToken := range wrongModeTokens {
				wrongMode := httptest.NewRequest(http.MethodGet, resourceIssuer+"/records", nil)
				wrongMode.Header.Set("X-Request-ID", "wrong-mode")
				if err := signaturekey.SignJWTRequestWithOptions(wrongMode, proofKey, wrongModeToken, clock, signaturekey.SignOptions{
					AdditionalComponents: []string{"x-request-id"},
				}); err != nil {
					t.Fatal(err)
				}
				response = httptest.NewRecorder()
				server.Handler().ServeHTTP(response, wrongMode)
				if response.Code != http.StatusUnauthorized || response.Header().Get("Signature-Error") != "" ||
					test.parse(response.Header().Values("AAuth-Requirement")) != nil || called != 0 {
					t.Fatalf("wrong mode %d = %d headers=%v body=%s called=%d", index, response.Code, response.Header(), response.Body.String(), called)
				}
			}
		})
	}
}

func TestAgentIdentityResourceVerifiesAgentAndProofBeforeApplication(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := testSigningKey(t, "direct-provider", 31)
	agentKey := testSigningKey(t, "direct-agent", 32)
	otherKey := testSigningKey(t, "direct-other", 33)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}
	var principals []AgentPrincipal
	server, err := NewAgentIdentity(AgentIdentityConfig{
		Issuer: resourceIssuer, KeyResolver: resolver, Clock: clock,
		Protected: http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			principal, ok := AgentPrincipalFromContext(request.Context())
			if !ok {
				t.Errorf("principal = %#v, present = %v", principal, ok)
				return
			}
			principal.AdditionalClaims["platform_attestation"][0] = 'x'
			again, _ := AgentPrincipalFromContext(request.Context())
			if string(again.AdditionalClaims["platform_attestation"]) != `{"level":"example"}` {
				t.Fatalf("principal accessor exposed mutable claims: %s", again.AdditionalClaims["platform_attestation"])
			}
			principals = append(principals, again)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	mint := func(agent, parent string, key jose.JWK, issued time.Time, lifetime time.Duration, jti string) string {
		t.Helper()
		compact, err := aauth.MintAgentToken("https://ap.example", providerKey, aauth.AgentTokenRequest{
			Agent: agent, ParentAgent: parent, PersonServer: personIssuer,
			PublicKey: key, Lifetime: lifetime,
			AdditionalClaims: map[string]json.RawMessage{
				"platform_attestation": json.RawMessage(`{"level":"example"}`),
			},
		}, issued, jti)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	valid := mint("aauth:reader@ap.example", "", agentKey.PublicJWK(), now, time.Hour, "direct-agent-token")
	request := httptest.NewRequest(http.MethodGet, resourceIssuer+"/records", nil)
	if err := signaturekey.SignJWTRequest(request, agentKey, valid, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(principals) != 1 {
		t.Fatalf("valid request = %d body=%s principals=%d", response.Code, response.Body.String(), len(principals))
	}
	if principal := principals[0]; principal.AgentProvider != "https://ap.example" || principal.Agent != "aauth:reader@ap.example" ||
		principal.ParentAgent != "" || principal.PersonServer != personIssuer || !principal.Confirmation.Equal(agentKey.PublicJWK()) ||
		string(principal.AdditionalClaims["platform_attestation"]) != `{"level":"example"}` {
		t.Fatalf("top-level principal = %#v", principal)
	}

	subAgent := mint("aauth:reader+child@ap.example", "aauth:reader@ap.example", agentKey.PublicJWK(), now, time.Hour, "sub-agent")
	request = httptest.NewRequest(http.MethodGet, resourceIssuer+"/records", nil)
	if err := signaturekey.SignJWTRequest(request, agentKey, subAgent, clock); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(principals) != 2 {
		t.Fatalf("sub-agent request = %d body=%s principals=%d", response.Code, response.Body.String(), len(principals))
	}
	if principal := principals[1]; principal.Agent != "aauth:reader+child@ap.example" ||
		principal.ParentAgent != "aauth:reader@ap.example" {
		t.Fatalf("sub-agent principal = %#v", principal)
	}

	for _, test := range []struct {
		name  string
		token string
		key   jose.SigningKey
	}{
		{name: "wrong request key", token: valid, key: otherKey},
		{name: "expired token", token: mint("aauth:reader@ap.example", "", agentKey.PublicJWK(), now.Add(-2*time.Hour), time.Hour, "expired-agent"), key: agentKey},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, resourceIssuer+"/records", nil)
			if err := signaturekey.SignJWTRequest(request, test.key, test.token, clock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code == http.StatusOK || len(principals) != 2 {
				t.Fatalf("response = %d body=%s principals=%d", response.Code, response.Body.String(), len(principals))
			}
		})
	}
}

func TestPersonIdentityResourceKeepsPersonServerInIdentity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	agentKey := testSigningKey(t, "direct-person-agent", 41)
	psA := testSigningKey(t, "direct-ps-a", 42)
	psB := testSigningKey(t, "direct-ps-b", 43)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://ps-a.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: psA.ID()}: psA.PublicJWK(),
		{Issuer: "https://ps-b.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: psB.ID()}: psB.PublicJWK(),
	}
	var identities []PersonIdentity
	called := 0
	server, err := NewPersonIdentity(PersonIdentityConfig{
		Issuer: resourceIssuer, KeyResolver: resolver, Clock: clock,
		ResolvePerson: func(_ context.Context, identity PersonIdentity, _ PersonContext) error {
			identities = append(identities, identity)
			return nil
		},
		Protected: http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			called++
			principal, ok := PersonPrincipalFromContext(request.Context())
			if !ok {
				t.Errorf("principal = %#v, present = %v", principal, ok)
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	mint := func(issuer string, key jose.SigningKey, audience, mission, jti string) string {
		t.Helper()
		compact, err := aauth.MintPersonToken(key, aauth.PersonTokenClaims{
			Issuer: issuer, DWK: aauth.PersonDiscoveryDocument, Audience: audience,
			Subject: "same-directed-subject", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			JTI: jti, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), MissionS256: mission,
		})
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	for _, issuer := range []struct {
		id  string
		key jose.SigningKey
	}{{"https://ps-a.example", psA}, {"https://ps-b.example", psB}} {
		request := httptest.NewRequest(http.MethodGet, resourceIssuer+"/profile", nil)
		token := mint(issuer.id, issuer.key, resourceIssuer, "", issuer.id)
		if err := signaturekey.SignJWTRequest(request, agentKey, token, clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s response = %d %s", issuer.id, response.Code, response.Body.String())
		}
	}
	if called != 2 || len(identities) != 2 || identities[0] == identities[1] ||
		identities[0].Subject != identities[1].Subject {
		t.Fatalf("identities = %#v, called = %d", identities, called)
	}

	mission := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, test := range []struct {
		name     string
		token    string
		proofKey jose.SigningKey
	}{
		{name: "wrong audience", token: mint("https://ps-a.example", psA, "https://other-resource.example", "", "wrong-audience"), proofKey: agentKey},
		{name: "wrong proof key", token: mint("https://ps-a.example", psA, resourceIssuer, "", "wrong-key"), proofKey: testSigningKey(t, "direct-person-other", 44)},
		{name: "mission requires mission flow", token: mint("https://ps-a.example", psA, resourceIssuer, mission, "mission"), proofKey: agentKey},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, resourceIssuer+"/profile", nil)
			if err := signaturekey.SignJWTRequest(request, test.proofKey, test.token, clock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code == http.StatusOK || called != 2 || len(identities) != 2 {
				t.Fatalf("response = %d body=%s identities=%d called=%d", response.Code, response.Body.String(), len(identities), called)
			}
		})
	}
}
