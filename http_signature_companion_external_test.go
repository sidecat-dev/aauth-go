package aauth_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestVerifyRequestRequiresAnExplicitAuthTokenCompanion(t *testing.T) {
	now := time.Date(2026, 8, 29, 7, 0, 0, 0, time.UTC)
	issuer := companionSigningKey(t, "issuer", 0x41)
	agent := companionSigningKey(t, "agent", 0x42)
	reference, err := r3.NewDocumentReference(
		"https://resource.example/r3/direct",
		[]byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := agent.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resourceCompact, err := r3.MintResourceToken(issuer, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-companion", AgentJKT: thumbprint,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Scope: "read",
		PersonServer: "https://person.example", Subject: "person", PresentedJTI: "person-token",
	}, reference)
	if err != nil {
		t.Fatal(err)
	}
	resourceCore, err := aauth.VerifyResourceToken(context.Background(), resourceCompact,
		signaturekey.StaticKeyResolver{"https://resource.example": {issuer.ID(): issuer.PublicJWK()}},
		aauth.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	resourceR3, err := r3.ValidateResourceToken(resourceCore)
	if err != nil {
		t.Fatal(err)
	}
	verifiedReference, err := r3.VerifyDocument(resourceR3, reference.ExactBytes())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := r3.NewDirectGrant(verifiedReference, r3.OperationSet{
		Vocabulary: r3.VocabularyMCP,
		Operations: []json.RawMessage{json.RawMessage(`{"tool":"read"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := r3.MintAuthToken(issuer, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-companion",
		Confirmation: aauth.Confirmation{JWK: agent.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		Subject: "person", Scope: "read", PersonServer: "https://person.example",
	}, grant)
	if err != nil {
		t.Fatal(err)
	}
	makeRequest := func() *http.Request {
		request, requestErr := http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if requestErr := signaturekey.SignJWTRequest(request, agent, compact, aauth.ClockFunc(func() time.Time { return now })); requestErr != nil {
			t.Fatal(requestErr)
		}
		return request
	}
	resolver := signaturekey.StaticKeyResolver{"https://access.example": {issuer.ID(): issuer.PublicJWK()}}
	if _, err := aauth.VerifyRequest(context.Background(), makeRequest(), resolver,
		aauth.ClockFunc(func() time.Time { return now }), aauth.VerifyRequestOptions{}); err == nil {
		t.Fatal("R3 request passed without an explicit companion")
	}
	if _, err := aauth.VerifyRequest(context.Background(), makeRequest(), resolver,
		aauth.ClockFunc(func() time.Time { return now }), aauth.VerifyRequestOptions{
			AuthTokenCompanion: func(aauth.VerifiedToken[aauth.AuthTokenClaims]) (aauth.AuthorizationCompanion, error) {
				return nil, nil
			},
		}); err == nil {
		t.Fatal("R3 request passed a companion callback without evidence")
	}
	var result r3.TokenResult
	verified, err := aauth.VerifyRequest(context.Background(), makeRequest(), resolver,
		aauth.ClockFunc(func() time.Time { return now }), aauth.VerifyRequestOptions{
			AuthTokenCompanion: func(core aauth.VerifiedToken[aauth.AuthTokenClaims]) (aauth.AuthorizationCompanion, error) {
				validated, validationErr := r3.ValidateAuthToken(core)
				result = validated
				return validated, validationErr
			},
		})
	if err != nil || !result.Valid() {
		t.Fatalf("companion request = %#v, %v", result, err)
	}
	if _, err := verified.AuthClaims(); err != nil {
		t.Fatal(err)
	}
}

func companionSigningKey(t *testing.T, id string, seed byte) jose.SigningKey {
	t.Helper()
	key, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}
