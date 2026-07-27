package aauth_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestJWKSURIRequestIdentitySignsAndVerifies(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personServerKey := testSigningKey(t, "ps-key")
	resolver := aauth.StaticKeyResolver{
		"https://ps.example": {"ps-key": personServerKey.PublicJWK()},
	}

	request, err := http.NewRequest(
		http.MethodPost,
		"https://as.example/token",
		bytes.NewReader([]byte(`{"resource_token":"token","agent_token":"token"}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequestWithJWKSURI(
		request,
		personServerKey,
		"https://ps.example",
		aauth.PersonDiscoveryDocument,
		clock,
	); err != nil {
		t.Fatal(err)
	}

	verified, err := aauth.VerifyRequest(context.Background(), request, resolver, clock, aauth.VerifyRequestOptions{
		RequiredComponents:       []string{"content-digest"},
		AllowedSignatureKeyTypes: []string{aauth.SignatureKeyJWKSURI},
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified.SignatureKeyType != aauth.SignatureKeyJWKSURI ||
		verified.Signer != "https://ps.example" ||
		!verified.PublicKey.Equal(personServerKey.PublicJWK()) {
		t.Fatalf("verified PS signing context = %#v", verified)
	}
}

func TestJWKSURIRequestRejectsKeyReferenceSubstitution(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personServerKey := testSigningKey(t, "ps-key")
	otherKey := testSigningKey(t, "other-key")
	resolver := aauth.StaticKeyResolver{
		"https://ps.example":    {"ps-key": personServerKey.PublicJWK()},
		"https://other.example": {"other-key": otherKey.PublicJWK()},
	}

	request, err := http.NewRequest(http.MethodGet, "https://as.example/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithJWKSURI(
		request,
		personServerKey,
		"https://ps.example",
		aauth.PersonDiscoveryDocument,
		clock,
	); err != nil {
		t.Fatal(err)
	}
	request.Header.Set(
		"Signature-Key",
		`sig=jwks_uri;id="https://other.example";dwk="aauth-person.json";kid="other-key"`,
	)

	if _, err := aauth.VerifyRequest(context.Background(), request, resolver, clock, aauth.VerifyRequestOptions{
		AllowedSignatureKeyTypes: []string{aauth.SignatureKeyJWKSURI},
	}); err == nil {
		t.Fatal("substituted jwks_uri key reference was accepted")
	}
}
