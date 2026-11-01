package aauth_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCoreTokenVerificationReturnsTypedClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := coreTokenKey(t, "provider-key")
	personKey := coreTokenKey(t, "person-key")
	resourceKey := coreTokenKey(t, "resource-key")
	accessKey := coreTokenKey(t, "access-key")
	agentKey := coreTokenKey(t, "agent-key")

	const (
		provider = "https://agents.example"
		person   = "https://person.example"
		resource = "https://resource.example"
		access   = "https://access.example"
		agent    = "aauth:reader@agents.example"
	)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: provider, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
		{Issuer: person, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: resource, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: access, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}

	agentToken, err := aauth.MintAgentToken(provider, providerKey, aauth.AgentTokenRequest{
		Agent: agent, PersonServer: person, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		AdditionalClaims: map[string]json.RawMessage{
			"platform_attestation": json.RawMessage(`{"level":"example"}`),
		},
	}, now, "agent-token-1")
	if err != nil {
		t.Fatal(err)
	}
	agentClaims, err := aauth.VerifyAgentToken(context.Background(), agentToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if agentClaims.Subject != agent || !agentClaims.Confirmation.JWK.Equal(agentKey.PublicJWK()) {
		t.Fatalf("agent claims = %#v", agentClaims)
	}
	if string(agentClaims.AdditionalClaims["platform_attestation"]) != `{"level":"example"}` {
		t.Fatalf("agent additional claims = %#v", agentClaims.AdditionalClaims)
	}

	personToken, err := aauth.MintPersonToken(personKey, aauth.PersonTokenClaims{
		Issuer: person, DWK: aauth.PersonDiscoveryDocument, Audience: resource,
		Subject: "person-123", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		JTI: "person-token-1", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	personClaims, err := aauth.VerifyPersonToken(context.Background(), personToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if personClaims.Audience != resource || personClaims.Subject != "person-123" {
		t.Fatalf("person claims = %#v", personClaims)
	}

	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	missionS256 := coreTokenS256("approved mission")
	account := "account-123"
	resourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: resource, DWK: aauth.ResourceDiscoveryDocument, Audience: access,
		JTI: "resource-token-1", PersonServer: person, Subject: personClaims.Subject,
		PresentedJTI: personClaims.JTI, AgentJKT: agentJKT, Scope: "records.read",
		Account: &account, MissionS256: missionS256, Tenant: "tenant-123",
		Interaction: &aauth.ResourceInteraction{
			URL: "https://resource.example/interaction", Code: "A1B2-C3D4",
		},
		AdditionalClaims: map[string]json.RawMessage{
			"resource_profile": json.RawMessage(`{"tier":"example"}`),
		},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims, err := aauth.VerifyResourceToken(context.Background(), resourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if resourceClaims.PresentedJTI != personClaims.JTI || resourceClaims.AgentJKT != agentJKT {
		t.Fatalf("resource claims = %#v", resourceClaims)
	}
	if resourceClaims.Account == nil || *resourceClaims.Account != account || resourceClaims.MissionS256 != missionS256 ||
		resourceClaims.Tenant != "tenant-123" || resourceClaims.Interaction == nil ||
		resourceClaims.Interaction.URL != "https://resource.example/interaction" ||
		resourceClaims.Interaction.Code != "A1B2-C3D4" {
		t.Fatalf("resource optional claims = %#v", resourceClaims)
	}
	if string(resourceClaims.AdditionalClaims["resource_profile"]) != `{"tier":"example"}` {
		t.Fatalf("resource additional claims = %#v", resourceClaims.AdditionalClaims)
	}

	authToken, err := aauth.MintAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: access, DWK: aauth.AccessDiscoveryDocument, Audience: resource,
		JTI: "auth-token-1", PersonServer: person, Subject: personClaims.Subject,
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()}, Scope: "records.read",
		Account: &account, MissionS256: missionS256, Tenant: "tenant-123",
		AdditionalClaims: map[string]json.RawMessage{
			"email":  json.RawMessage(`"person@example.com"`),
			"groups": json.RawMessage(`["engineering"]`),
		},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	authClaims, err := aauth.VerifyAuthToken(context.Background(), authToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.PersonServer != person || authClaims.Subject != personClaims.Subject {
		t.Fatalf("auth claims = %#v", authClaims)
	}
	if authClaims.Account == nil || *authClaims.Account != account || authClaims.MissionS256 != missionS256 || authClaims.Tenant != "tenant-123" {
		t.Fatalf("auth optional claims = %#v", authClaims)
	}
	if string(authClaims.AdditionalClaims["email"]) != `"person@example.com"` ||
		string(authClaims.AdditionalClaims["groups"]) != `["engineering"]` {
		t.Fatalf("auth additional claims = %#v", authClaims.AdditionalClaims)
	}
}

func TestMintAuthTokenRejectsAdditionalClaimCollision(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	key := coreTokenKey(t, "access-key")
	requestKey := coreTokenKey(t, "request-key")
	base := aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-token-1",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Scope: "records.read",
	}
	for _, name := range []string{"scope", "SCOPE", "r3_per_call"} {
		claims := base
		claims.AdditionalClaims = map[string]json.RawMessage{name: json.RawMessage(`true`)}
		if _, err := aauth.MintAuthToken(key, claims); err == nil {
			t.Fatalf("MintAuthToken accepted additional claim %q", name)
		}
	}
}

func TestMintResourceTokenRejectsAdditionalClaimCollision(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	key := coreTokenKey(t, "resource-key")
	base := aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-token-1",
		PersonServer: "https://person.example", Subject: "person-1", PresentedJTI: "person-token-1",
		AgentJKT: coreTokenS256("agent-key"), Scope: "records.read",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
	for _, name := range []string{"scope", "SCOPE", "r3_per_call"} {
		claims := base
		claims.AdditionalClaims = map[string]json.RawMessage{name: json.RawMessage(`true`)}
		if _, err := aauth.MintResourceToken(key, claims); err == nil {
			t.Fatalf("MintResourceToken accepted additional claim %q", name)
		}
	}
}

func TestResourceTokenAdditionalClaimsAreCopied(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	key := coreTokenKey(t, "resource-key")
	raw := json.RawMessage(`{"tier":"original"}`)
	additional := map[string]json.RawMessage{"resource_profile": raw}
	compact, err := aauth.MintResourceToken(key, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-token-1",
		PersonServer: "https://person.example", Subject: "person-1", PresentedJTI: "person-token-1",
		AgentJKT: coreTokenS256("agent-key"), Scope: "records.read",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		AdditionalClaims: additional,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = '['
	additional["resource_profile"] = json.RawMessage(`null`)

	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	first, err := aauth.VerifyResourceToken(context.Background(), compact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(first.AdditionalClaims["resource_profile"]); got != `{"tier":"original"}` {
		t.Fatalf("first verified additional claim = %s", got)
	}
	first.AdditionalClaims["resource_profile"][0] = '['
	first.AdditionalClaims["resource_profile"] = json.RawMessage(`null`)

	second, err := aauth.VerifyResourceToken(context.Background(), compact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(second.AdditionalClaims["resource_profile"]); got != `{"tier":"original"}` {
		t.Fatalf("second verified additional claim = %s", got)
	}
}

func TestTokenMintersRejectAmbiguousAdditionalClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	issuerKey := coreTokenKey(t, "issuer-key")
	requestKey := coreTokenKey(t, "request-key")
	ambiguous := map[string]json.RawMessage{
		"extension": json.RawMessage(`{"nested":{"value":1,"value":2}}`),
	}
	if _, err := aauth.MintAgentToken(
		"https://agents.example", issuerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:reader@agents.example", PersonServer: "https://person.example",
			PublicKey: requestKey.PublicJWK(), Lifetime: time.Hour, AdditionalClaims: ambiguous,
		}, now, "agent-token-1",
	); err == nil {
		t.Fatal("MintAgentToken accepted an ambiguous nested extension")
	}
	if _, err := aauth.MintAuthToken(issuerKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-token-1",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()}, Scope: "records.read",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), AdditionalClaims: ambiguous,
	}); err == nil {
		t.Fatal("MintAuthToken accepted an ambiguous nested extension")
	}
}

func TestCurrentAuthTokenContextBindsTheExpectedIssuerRole(t *testing.T) {
	t.Parallel()

	requestKey := coreTokenKey(t, "request-key").PublicJWK()
	claims := aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", PersonServer: "https://person.example",
		Subject: "person-1", Scope: "records.read",
		Confirmation: aauth.Confirmation{JWK: requestKey},
	}
	context := aauth.AuthTokenContext{
		Issuer: "https://attacker.example", DiscoveryDocument: aauth.AccessDiscoveryDocument,
		Resource: "https://resource.example", PersonServer: "https://person.example", Subject: "person-1",
		RequestKey: requestKey, RequiredScopes: []string{"records.read"},
	}
	if err := aauth.ValidateCurrentAuthTokenContext(claims, context); err == nil {
		t.Fatal("context accepted an auth token from another issuer")
	}
	context.Issuer = "https://access.example"
	context.DiscoveryDocument = aauth.PersonDiscoveryDocument
	if err := aauth.ValidateCurrentAuthTokenContext(claims, context); err == nil {
		t.Fatal("context accepted the wrong issuer role")
	}
	context.DiscoveryDocument = aauth.AccessDiscoveryDocument
	if err := aauth.ValidateCurrentAuthTokenContext(claims, context); err != nil {
		t.Fatal(err)
	}
}

func TestCoreTokenVerificationRejectsFutureNotBefore(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	providerKey := coreTokenKey(t, "provider-key")
	personKey := coreTokenKey(t, "person-key")
	resourceKey := coreTokenKey(t, "resource-key")
	accessKey := coreTokenKey(t, "access-key")
	requestKey := coreTokenKey(t, "request-key")
	requestJKT, err := requestKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://agents.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:      providerKey.PublicJWK(),
		{Issuer: "https://person.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	tests := []struct {
		name      string
		tokenType string
		key       jose.SigningKey
		claims    any
		verify    func(string) error
	}{
		{
			name: "agent", tokenType: aauth.AgentTokenType, key: providerKey,
			claims: aauth.AgentTokenClaims{
				Issuer: "https://agents.example", DWK: aauth.AgentDiscoveryDocument,
				Subject: "aauth:reader@agents.example", JTI: "agent-token-1",
				Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
				IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), PersonServer: "https://person.example",
			},
			verify: func(compact string) error {
				_, err := aauth.VerifyAgentToken(context.Background(), compact, resolver, clock)
				return err
			},
		},
		{
			name: "person", tokenType: aauth.PersonTokenType, key: personKey,
			claims: aauth.PersonTokenClaims{
				Issuer: "https://person.example", DWK: aauth.PersonDiscoveryDocument,
				Audience: "https://resource.example", Subject: "person-1", JTI: "person-token-1",
				Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
				IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
			},
			verify: func(compact string) error {
				_, err := aauth.VerifyPersonToken(context.Background(), compact, resolver, clock)
				return err
			},
		},
		{
			name: "resource", tokenType: aauth.ResourceTokenType, key: resourceKey,
			claims: aauth.ResourceTokenClaims{
				Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
				Audience: "https://access.example", JTI: "resource-token-1",
				PersonServer: "https://person.example", Subject: "person-1", PresentedJTI: "person-token-1",
				AgentJKT: requestJKT, Scope: "records.read", IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(),
			},
			verify: func(compact string) error {
				_, err := aauth.VerifyResourceToken(context.Background(), compact, resolver, clock)
				return err
			},
		},
		{
			name: "auth", tokenType: aauth.AuthTokenType, key: accessKey,
			claims: aauth.AuthTokenClaims{
				Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
				Audience: "https://resource.example", JTI: "auth-token-1",
				PersonServer: "https://person.example", Subject: "person-1", Scope: "records.read",
				Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
				IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
			},
			verify: func(compact string) error {
				_, err := aauth.VerifyAuthToken(context.Background(), compact, resolver, clock)
				return err
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.claims)
			if err != nil {
				t.Fatal(err)
			}
			var members map[string]any
			if err := json.Unmarshal(encoded, &members); err != nil {
				t.Fatal(err)
			}
			members["nbf"] = now.Add(time.Minute).Unix()
			compact := signCoreTokenPayload(t, test.key, test.tokenType, members)
			err = test.verify(compact)
			var validation *aauth.TokenValidationError
			if !errors.As(err, &validation) || validation.Code != aauth.TokenValidationNotYetValid {
				t.Fatalf("verify error = %T %v", err, err)
			}
		})
	}
}

func TestMintedTokenCanActivateAfterItsIssueTime(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	issuerKey := coreTokenKey(t, "access-key")
	requestKey := coreTokenKey(t, "request-key")
	claims := aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-token-1",
		PersonServer: "https://person.example", Subject: "person-1", Scope: "records.read",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		IssuedAt:     now.Unix(), NotBefore: now.Add(time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	compact, err := aauth.MintAuthToken(issuerKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: claims.Issuer, DiscoveryDocument: claims.DWK, KeyID: issuerKey.ID()}: issuerKey.PublicJWK(),
	}
	if _, err := aauth.VerifyAuthToken(
		context.Background(), compact, resolver, aauth.ClockFunc(func() time.Time { return now }),
	); err == nil {
		t.Fatal("token verified before nbf")
	}
	if _, err := aauth.VerifyAuthToken(
		context.Background(), compact, resolver,
		aauth.ClockFunc(func() time.Time { return now.Add(time.Minute) }),
	); err != nil {
		t.Fatal(err)
	}
}

func TestMintedAgentTokenCanActivateAfterItsIssueTime(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	issuerKey := coreTokenKey(t, "issuer-key")
	agentKey := coreTokenKey(t, "agent-key")
	compact, err := aauth.MintAgentToken(
		"https://agents.example",
		issuerKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:reader@agents.example",
			PersonServer: "https://person.example",
			PublicKey:    agentKey.PublicJWK(),
			NotBefore:    now.Add(time.Minute),
			Lifetime:     time.Hour,
		},
		now,
		"agent-token-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://agents.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: issuerKey.ID()}: issuerKey.PublicJWK(),
	}
	if _, err := aauth.VerifyAgentToken(
		context.Background(), compact, resolver, aauth.ClockFunc(func() time.Time { return now }),
	); err == nil {
		t.Fatal("agent token verified before nbf")
	}
	claims, err := aauth.VerifyAgentToken(
		context.Background(), compact, resolver,
		aauth.ClockFunc(func() time.Time { return now.Add(time.Minute) }),
	)
	if err != nil {
		t.Fatal(err)
	}
	if claims.NotBefore != now.Add(time.Minute).Unix() {
		t.Fatalf("nbf = %d, want %d", claims.NotBefore, now.Add(time.Minute).Unix())
	}
}

func TestTokenVerificationClassifiesUnsupportedHeaderAlgorithm(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	issuerKey := coreTokenKey(t, "issuer-key")
	payload := mustCoreTokenJSON(t, map[string]any{
		"iss": "https://agents.example", "dwk": aauth.AgentDiscoveryDocument,
		"sub": "aauth:reader@agents.example", "jti": "agent-token-1",
		"cnf": map[string]any{"jwk": coreTokenKey(t, "agent-key").PublicJWK()},
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	header, err := json.Marshal(jose.Header{Algorithm: "PS256", Type: aauth.AgentTokenType, KeyID: issuerKey.ID()})
	if err != nil {
		t.Fatal(err)
	}
	encoding := base64.RawURLEncoding
	compact := encoding.EncodeToString(header) + "." + encoding.EncodeToString([]byte(payload)) + "." + encoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	_, err = aauth.VerifyAgentToken(
		context.Background(), compact, signaturekey.StaticKeyResolver{},
		aauth.ClockFunc(func() time.Time { return now }),
	)
	var validation *aauth.TokenValidationError
	if !errors.As(err, &validation) || validation.Code != aauth.TokenValidationUnsupportedAlgorithm {
		t.Fatalf("VerifyAgentToken error = %T %v", err, err)
	}
}

func TestTokenVerificationClassifiesUnsupportedResolvedKeyAlgorithm(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	issuerKey := coreTokenKey(t, "issuer-key")
	agentKey := coreTokenKey(t, "agent-key")
	compact, err := aauth.MintAgentToken(
		"https://agents.example", issuerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:reader@agents.example", PersonServer: "https://person.example",
			PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		}, now, "agent-token-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	unsupported := issuerKey.PublicJWK()
	unsupported.Alg = "EdDSA"
	_, err = aauth.VerifyAgentToken(
		context.Background(), compact,
		coreTokenResolverFunc(func(context.Context, string, string, string) (jose.JWK, error) {
			return unsupported, nil
		}),
		aauth.ClockFunc(func() time.Time { return now }),
	)
	var validation *aauth.TokenValidationError
	if !errors.As(err, &validation) || validation.Code != aauth.TokenValidationUnsupportedAlgorithm {
		t.Fatalf("VerifyAgentToken error = %T %v", err, err)
	}
}

func TestTokenVerificationClassifiesUnsupportedRefreshedKeyAlgorithm(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	oldKey := coreTokenKey(t, "issuer-key")
	newKey := coreTokenKey(t, "issuer-key")
	agentKey := coreTokenKey(t, "agent-key")
	compact, err := aauth.MintAgentToken(
		"https://agents.example", newKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:reader@agents.example", PersonServer: "https://person.example",
			PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		}, now, "agent-token-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	unsupported := newKey.PublicJWK()
	unsupported.Alg = "EdDSA"
	_, err = aauth.VerifyAgentToken(
		context.Background(), compact,
		coreRefreshingResolver{initial: oldKey.PublicJWK(), refreshed: unsupported},
		aauth.ClockFunc(func() time.Time { return now }),
	)
	var validation *aauth.TokenValidationError
	if !errors.As(err, &validation) || validation.Code != aauth.TokenValidationUnsupportedAlgorithm {
		t.Fatalf("VerifyAgentToken error = %T %v", err, err)
	}
}

func TestAgentTokenVerifierAcceptsIssuerExceptionsToRecommendedLifetime(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	issuerKey := coreTokenKey(t, "issuer-key")
	agentKey := coreTokenKey(t, "agent-key")
	compact, err := aauth.MintAgentToken(
		"https://agents.example", issuerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:reader@agents.example", PersonServer: "https://person.example",
			PublicKey: agentKey.PublicJWK(), Lifetime: 25 * time.Hour,
		},
		now, "long-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://agents.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: issuerKey.ID()}: issuerKey.PublicJWK(),
	}
	if _, err := aauth.VerifyAgentToken(
		context.Background(), compact, resolver, aauth.ClockFunc(func() time.Time { return now }),
	); err != nil {
		t.Fatal(err)
	}
}

func TestCoreTokenVerificationRejectsUnhandledAuthorizationClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	key := coreTokenKey(t, "resource-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: key.ID()}:     key.PublicJWK(),
	}
	resourceBase := map[string]any{
		"iss": "https://resource.example", "dwk": aauth.ResourceDiscoveryDocument,
		"aud": "https://access.example", "jti": "resource-token-1",
		"ps": "https://person.example", "sub": "person-123", "presented_jti": "person-token-1",
		"agent_jkt": strings.Repeat("a", 43), "scope": "records.read",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	authBase := map[string]any{
		"iss": "https://access.example", "dwk": aauth.AccessDiscoveryDocument,
		"aud": "https://resource.example", "jti": "auth-token-1",
		"ps": "https://person.example", "sub": "person-123",
		"cnf": map[string]any{"jwk": key.PublicJWK()}, "scope": "records.read",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	for _, token := range []struct {
		name      string
		tokenType string
		base      map[string]any
		verify    func(string) error
	}{
		{name: "resource", tokenType: aauth.ResourceTokenType, base: resourceBase, verify: func(compact string) error {
			_, err := aauth.VerifyResourceToken(context.Background(), compact, resolver, aauth.ClockFunc(func() time.Time { return now }))
			return err
		}},
		{name: "auth", tokenType: aauth.AuthTokenType, base: authBase, verify: func(compact string) error {
			_, err := aauth.VerifyAuthToken(context.Background(), compact, resolver, aauth.ClockFunc(func() time.Time { return now }))
			return err
		}},
	} {
		for _, claim := range []string{"r3_uri", "r3_s256", "r3_granted", "r3_per_call", "budget", "budget_consumed"} {
			t.Run(token.name+"/"+claim, func(t *testing.T) {
				members := cloneCoreTokenMembers(token.base)
				members[claim] = map[string]any{"unsupported": true}
				compact := signCoreTokenPayload(t, key, token.tokenType, members)
				err := token.verify(compact)
				if err == nil || !strings.Contains(err.Error(), "unsupported") || !strings.Contains(err.Error(), claim) {
					t.Fatalf("verify error = %v", err)
				}
			})
		}
	}
}

// RFC 7519 lets a single audience be written as a string or as an array of
// one string; other implementations write the array. Person, Resource and
// auth tokens are read in either form and still name exactly one audience.
func TestCoreTokenVerificationReadsAudAsAStringOrAnArrayOfOne(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 31, 12, 15, 0, 0, time.UTC)
	key := coreTokenKey(t, "issuer-key")
	clock := aauth.ClockFunc(func() time.Time { return now })
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://person.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: key.ID()}:     key.PublicJWK(),
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: key.ID()}:     key.PublicJWK(),
	}
	for _, token := range []struct {
		name      string
		tokenType string
		audience  string
		base      map[string]any
		verify    func(string) (string, error)
	}{
		{
			name: "person", tokenType: aauth.PersonTokenType, audience: "https://resource.example",
			base: map[string]any{
				"iss": "https://person.example", "dwk": aauth.PersonDiscoveryDocument, "sub": "person-123",
				"cnf": map[string]any{"jwk": key.PublicJWK()}, "jti": "person-token-1",
				"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			},
			verify: func(compact string) (string, error) {
				claims, err := aauth.VerifyPersonToken(context.Background(), compact, resolver, clock)
				return claims.Audience, err
			},
		},
		{
			name: "resource", tokenType: aauth.ResourceTokenType, audience: "https://access.example",
			base: map[string]any{
				"iss": "https://resource.example", "dwk": aauth.ResourceDiscoveryDocument, "jti": "resource-token-1",
				"ps": "https://person.example", "sub": "person-123", "presented_jti": "person-token-1",
				"agent_jkt": coreTokenS256("agent-key"), "scope": "records.read",
				"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			},
			verify: func(compact string) (string, error) {
				claims, err := aauth.VerifyResourceToken(context.Background(), compact, resolver, clock)
				return claims.Audience, err
			},
		},
		{
			name: "auth", tokenType: aauth.AuthTokenType, audience: "https://resource.example",
			base: map[string]any{
				"iss": "https://access.example", "dwk": aauth.AccessDiscoveryDocument, "jti": "auth-token-1",
				"ps": "https://person.example", "sub": "person-123",
				"cnf": map[string]any{"jwk": key.PublicJWK()}, "scope": "records.read",
				"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			},
			verify: func(compact string) (string, error) {
				claims, err := aauth.VerifyAuthToken(context.Background(), compact, resolver, clock)
				return claims.Audience, err
			},
		},
	} {
		for _, form := range []struct {
			name     string
			audience any
			accepted bool
		}{
			{name: "string", audience: token.audience, accepted: true},
			{name: "array of one", audience: []string{token.audience}, accepted: true},
			{name: "empty array", audience: []string{}},
			{name: "array of two", audience: []string{token.audience, "https://other.example"}},
			{name: "array of a number", audience: []any{7}},
		} {
			t.Run(token.name+"/"+form.name, func(t *testing.T) {
				members := cloneCoreTokenMembers(token.base)
				members["aud"] = form.audience
				audience, err := token.verify(signCoreTokenPayload(t, key, token.tokenType, members))
				if form.accepted && (err != nil || audience != token.audience) {
					t.Fatalf("verify = %q, %v; want %q", audience, err, token.audience)
				}
				if !form.accepted && err == nil {
					t.Fatalf("aud %v was accepted", form.audience)
				}
			})
		}
	}
}

func TestCoreTokenVerificationRejectsObsoleteClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	key := coreTokenKey(t, "issuer-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: key.ID()}:     key.PublicJWK(),
	}
	resourceBase := map[string]any{
		"iss": "https://resource.example", "dwk": aauth.ResourceDiscoveryDocument,
		"aud": "https://access.example", "jti": "resource-token-1",
		"ps": "https://person.example", "sub": "person-123", "presented_jti": "person-token-1",
		"agent_jkt": strings.Repeat("a", 43), "scope": "records.read",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	authBase := map[string]any{
		"iss": "https://access.example", "dwk": aauth.AccessDiscoveryDocument,
		"aud": "https://resource.example", "jti": "auth-token-1",
		"ps": "https://person.example", "sub": "person-123",
		"cnf": map[string]any{"jwk": key.PublicJWK()}, "scope": "records.read",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	tests := []struct {
		name      string
		tokenType string
		base      map[string]any
		claim     string
		value     any
	}{
		{name: "resource agent", tokenType: aauth.ResourceTokenType, base: resourceBase, claim: "agent", value: "aauth:old@provider.example"},
		{name: "resource mission", tokenType: aauth.ResourceTokenType, base: resourceBase, claim: "mission", value: map[string]any{"old": true}},
		{name: "auth agent", tokenType: aauth.AuthTokenType, base: authBase, claim: "agent", value: "aauth:old@provider.example"},
		{name: "auth act", tokenType: aauth.AuthTokenType, base: authBase, claim: "act", value: map[string]any{"agent": "aauth:old@provider.example"}},
		{name: "auth mission", tokenType: aauth.AuthTokenType, base: authBase, claim: "mission", value: map[string]any{"old": true}},
		{name: "removed r3_conditional", tokenType: aauth.ResourceTokenType, base: resourceBase, claim: "r3_conditional", value: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			members := cloneCoreTokenMembers(test.base)
			members[test.claim] = test.value
			compact := signCoreTokenPayload(t, key, test.tokenType, members)
			var err error
			switch test.tokenType {
			case aauth.ResourceTokenType:
				_, err = aauth.VerifyResourceToken(context.Background(), compact, resolver, aauth.ClockFunc(func() time.Time { return now }))
			case aauth.AuthTokenType:
				_, err = aauth.VerifyAuthToken(context.Background(), compact, resolver, aauth.ClockFunc(func() time.Time { return now }))
			}
			if err == nil || !strings.Contains(err.Error(), "unsupported") || !strings.Contains(err.Error(), test.claim) {
				t.Fatalf("verify error = %v", err)
			}
		})
	}
}

func TestCoreTokenVerificationRejectsAmbiguousPayloadNames(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	issuerKey := coreTokenKey(t, "provider-key")
	agentKey := coreTokenKey(t, "agent-key")
	for name, ambiguous := range map[string]string{
		"duplicate":    `"sub":"aauth:other@agents.example",`,
		"case variant": `"SUB":"aauth:other@agents.example",`,
	} {
		name, ambiguous := name, ambiguous
		t.Run(name, func(t *testing.T) {
			payload := []byte(`{` + ambiguous +
				`"iss":"https://agents.example","dwk":"aauth-agent.json",` +
				`"sub":"aauth:reader@agents.example","jti":"agent-token-1",` +
				`"cnf":{"jwk":` + mustCoreTokenJSON(t, agentKey.PublicJWK()) + `},` +
				`"iat":` + fmt.Sprint(now.Unix()) + `,"exp":` + fmt.Sprint(now.Add(time.Hour).Unix()) + `}`)
			compact := signUncheckedCoreToken(t, issuerKey, aauth.AgentTokenType, payload)
			_, err := aauth.VerifyAgentToken(
				context.Background(), compact,
				signaturekey.StaticKeyResolver{
					{Issuer: "https://agents.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: issuerKey.ID()}: issuerKey.PublicJWK(),
				},
				aauth.ClockFunc(func() time.Time { return now }),
			)
			if err == nil || (!strings.Contains(err.Error(), "duplicate") && !strings.Contains(err.Error(), "case variant")) {
				t.Fatalf("VerifyAgentToken error = %v", err)
			}
		})
	}

	t.Run("lone case variant", func(t *testing.T) {
		payload := []byte(
			`{"iss":"https://agents.example","dwk":"aauth-agent.json",` +
				`"SUB":"aauth:reader@agents.example","jti":"agent-token-1",` +
				`"cnf":{"jwk":` + mustCoreTokenJSON(t, agentKey.PublicJWK()) + `},` +
				`"iat":` + fmt.Sprint(now.Unix()) + `,"exp":` + fmt.Sprint(now.Add(time.Hour).Unix()) + `}`,
		)
		compact := signUncheckedCoreToken(t, issuerKey, aauth.AgentTokenType, payload)
		_, err := aauth.VerifyAgentToken(
			context.Background(), compact,
			signaturekey.StaticKeyResolver{
				{Issuer: "https://agents.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: issuerKey.ID()}: issuerKey.PublicJWK(),
			},
			aauth.ClockFunc(func() time.Time { return now }),
		)
		if err == nil || !strings.Contains(err.Error(), "case variant") {
			t.Fatalf("VerifyAgentToken error = %v", err)
		}
	})
}

func TestAgentTokenVerificationRejectsPrivateConfirmationJWK(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	issuerKey := coreTokenKey(t, "private-confirmation-provider-key")
	agentKey := coreTokenKey(t, "private-confirmation-agent-key")
	confirmation := map[string]any{
		"kty": agentKey.PublicJWK().Kty, "crv": agentKey.PublicJWK().Crv,
		"alg": agentKey.PublicJWK().Alg, "x": agentKey.PublicJWK().X,
		"d": "private-material",
	}
	compact := signCoreTokenPayload(t, issuerKey, aauth.AgentTokenType, map[string]any{
		"iss": "https://agents.example", "dwk": aauth.AgentDiscoveryDocument,
		"sub": "aauth:reader@agents.example", "jti": "private-confirmation-agent-token",
		"cnf": map[string]any{"jwk": confirmation},
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	_, err := aauth.VerifyAgentToken(
		context.Background(), compact,
		signaturekey.StaticKeyResolver{
			{Issuer: "https://agents.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: issuerKey.ID()}: issuerKey.PublicJWK(),
		},
		aauth.ClockFunc(func() time.Time { return now }),
	)
	if err == nil || !strings.Contains(err.Error(), "private JWK member") {
		t.Fatalf("VerifyAgentToken error = %v", err)
	}
}

func TestPersonTokenVerificationRejectsAuthorizationClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	personKey := coreTokenKey(t, "person-key")
	agentKey := coreTokenKey(t, "agent-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://person.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
	}
	base := map[string]any{
		"iss": "https://person.example", "dwk": aauth.PersonDiscoveryDocument,
		"aud": "https://resource.example", "sub": "person-123", "jti": "person-token-1",
		"cnf": map[string]any{"jwk": agentKey.PublicJWK()},
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	for _, claim := range []string{"scope", "account"} {
		claim := claim
		t.Run(claim, func(t *testing.T) {
			members := cloneCoreTokenMembers(base)
			members[claim] = "records.read"
			compact := signCoreTokenPayload(t, personKey, aauth.PersonTokenType, members)
			_, err := aauth.VerifyPersonToken(
				context.Background(), compact, resolver,
				aauth.ClockFunc(func() time.Time { return now }),
			)
			if err == nil || !strings.Contains(err.Error(), "unsupported") || !strings.Contains(err.Error(), claim) {
				t.Fatalf("VerifyPersonToken error = %v", err)
			}
		})
	}
}

func TestResourceTokenRejectsEmptyAndNullLoginHint(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	key := coreTokenKey(t, "login-hint-resource")
	agent := coreTokenKey(t, "login-hint-agent")
	thumbprint, err := agent.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
	}
	members := map[string]any{
		"iss": "https://resource.example", "dwk": aauth.ResourceDiscoveryDocument,
		"aud": "https://person.example", "jti": "resource-token-login-hint",
		"ps": "https://person.example", "sub": "person-123", "presented_jti": "person-token-1",
		"agent_jkt": thumbprint, "scope": "records.read",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	if _, err := aauth.VerifyResourceToken(context.Background(), signCoreTokenPayload(t, key, aauth.ResourceTokenType, members), resolver, clock); err != nil {
		t.Fatal(err)
	}
	for _, hint := range []any{"", nil} {
		rejected := cloneCoreTokenMembers(members)
		rejected["login_hint"] = hint
		_, err := aauth.VerifyResourceToken(context.Background(), signCoreTokenPayload(t, key, aauth.ResourceTokenType, rejected), resolver, clock)
		if err == nil || !strings.Contains(err.Error(), "login_hint") {
			t.Fatalf("login_hint %#v error = %v", hint, err)
		}
	}
}

func signCoreTokenPayload(t *testing.T, key jose.SigningKey, tokenType string, members map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.SignCompact(key, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: tokenType, KeyID: key.ID(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func cloneCoreTokenMembers(source map[string]any) map[string]any {
	cloned := make(map[string]any, len(source))
	for name, value := range source {
		cloned[name] = value
	}
	return cloned
}

func mustCoreTokenJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func signUncheckedCoreToken(t *testing.T, key jose.SigningKey, tokenType string, payload []byte) string {
	t.Helper()
	header, err := json.Marshal(jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: tokenType, KeyID: key.ID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	encoding := base64.RawURLEncoding
	signingInput := encoding.EncodeToString(header) + "." + encoding.EncodeToString(payload)
	signature, err := key.Sign(rand.Reader, []byte(signingInput), crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + encoding.EncodeToString(signature)
}

func coreTokenKey(t *testing.T, id string) jose.SigningKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func coreTokenS256(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

type coreTokenResolverFunc func(context.Context, string, string, string) (jose.JWK, error)

func (resolve coreTokenResolverFunc) ResolveKey(ctx context.Context, issuer, document, keyID string) (jose.JWK, error) {
	return resolve(ctx, issuer, document, keyID)
}

type coreRefreshingResolver struct {
	initial   jose.JWK
	refreshed jose.JWK
}

func (resolver coreRefreshingResolver) ResolveKey(context.Context, string, string, string) (jose.JWK, error) {
	return resolver.initial, nil
}

func (resolver coreRefreshingResolver) RefreshKey(context.Context, string, string, string) (jose.JWK, error) {
	return resolver.refreshed, nil
}
