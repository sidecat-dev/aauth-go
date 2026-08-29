package signaturekey_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type fixedClock time.Time

func (clock fixedClock) Now() time.Time { return time.Time(clock) }

func TestHWKRequestProofIsPortableAndSealed(t *testing.T) {
	now := time.Date(2026, 8, 28, 22, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	signingKey, err := jose.NewEd25519SigningKey("request-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(signingKey.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(
		http.MethodPost,
		"https://resource.example:443/items/1",
		strings.NewReader(`{"answer":42}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignRequest(
		request,
		signingKey,
		credential,
		fixedClock(now),
		signaturekey.SignOptions{Nonce: "attempt-1"},
	); err != nil {
		t.Fatal(err)
	}

	prepared, err := signaturekey.PrepareRequest(
		request,
		fixedClock(now.Add(10*time.Second)),
		signaturekey.VerifyOptions{
			AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeHWK},
			RequiredComponents:     []string{"content-type"},
			RequireExactComponents: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	parsedCredential := prepared.Credential()
	if parsedCredential.Scheme() != signaturekey.SchemeHWK {
		t.Fatalf("scheme = %q, want %q", parsedCredential.Scheme(), signaturekey.SchemeHWK)
	}
	proofKey, ok := parsedCredential.InlineJWK()
	if !ok || !proofKey.Equal(signingKey.PublicJWK()) {
		t.Fatalf("inline proof key = %#v, %t", proofKey, ok)
	}

	verified, err := prepared.Verify(proofKey)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Scheme() != signaturekey.SchemeHWK ||
		verified.Signer() == "" ||
		verified.ReplayKey() == "" ||
		!verified.PublicKey().Equal(signingKey.PublicJWK()) {
		t.Fatalf("invalid verified proof: scheme=%q signer=%q replay=%q key=%#v",
			verified.Scheme(), verified.Signer(), verified.ReplayKey(), verified.PublicKey())
	}
	if got, want := verified.Method(), http.MethodPost; got != want {
		t.Fatalf("method = %q, want %q", got, want)
	}
	if got, want := verified.Authority(), "resource.example"; got != want {
		t.Fatalf("authority = %q, want %q", got, want)
	}
	if got, want := verified.Path(), "/items/1"; got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	if got, want := verified.Created(), now; !got.Equal(want) {
		t.Fatalf("created = %s, want %s", got, want)
	}
	if got, want := verified.VerifiedAt(), now.Add(10*time.Second); !got.Equal(want) {
		t.Fatalf("verified at = %s, want %s", got, want)
	}
	components := verified.CoveredComponents()
	components[0] = "mutated"
	if verified.CoveredComponents()[0] == "mutated" {
		t.Fatal("covered components alias internal proof state")
	}
	if _, err := (signaturekey.PreparedRequest{}).Verify(proofKey); err == nil {
		t.Fatal("zero prepared request verified")
	}
}

func TestRequestProofCoversAnExactQueryWhenPresent(t *testing.T) {
	now := time.Date(2026, 8, 29, 17, 30, 0, 0, time.UTC)
	key, err := jose.NewEd25519SigningKey(
		"query-key",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x45}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := signaturekey.NewHWKCredential(key.PublicJWK())
	request, _ := http.NewRequest(http.MethodGet, "https://resource.example/records?mode=current&limit=1", nil)
	if err := signaturekey.SignRequest(request, key, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(request.Header.Get("Signature-Input"), `"@query"`) {
		t.Fatalf("query is not covered: %s", request.Header.Get("Signature-Input"))
	}
	prepared, err := signaturekey.PrepareRequest(
		request, fixedClock(now),
		signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK}, RequireExactComponents: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Verify(key.PublicJWK()); err != nil {
		t.Fatal(err)
	}
	request.URL.RawQuery = "mode=other&limit=1"
	changed, err := signaturekey.PrepareRequest(
		request, fixedClock(now),
		signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK}, RequireExactComponents: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changed.Verify(key.PublicJWK()); err == nil {
		t.Fatal("changed query verified under the original proof")
	}
}

func TestJWKSURICredentialResolvesThroughTheGenericKeyContract(t *testing.T) {
	now := time.Date(2026, 8, 28, 22, 45, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	signingKey, err := jose.NewEd25519SigningKey("server-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewJWKSURICredential(
		"https://server.example",
		"service-configuration",
		signingKey.ID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://peer.example/federate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, signingKey, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(
		request,
		fixedClock(now),
		signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWKSURI}},
	)
	if err != nil {
		t.Fatal(err)
	}
	issuer, document, keyID, ok := prepared.Credential().JWKSURI()
	if !ok || issuer != "https://server.example" || document != "service-configuration" || keyID != signingKey.ID() {
		t.Fatalf("JWKS URI reference = %q %q %q %t", issuer, document, keyID, ok)
	}
	resolver := signaturekey.StaticKeyResolver{
		issuer: {keyID: signingKey.PublicJWK()},
	}
	proofKey, err := resolver.ResolveKey(context.Background(), issuer, document, keyID)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := prepared.Verify(proofKey)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Scheme() != signaturekey.SchemeJWKSURI {
		t.Fatalf("scheme = %q", verified.Scheme())
	}
}

func TestJWTCredentialRemainsOpaqueUntilTheCallerSelectsItsProofKey(t *testing.T) {
	now := time.Date(2026, 8, 28, 22, 15, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	signingKey, err := jose.NewEd25519SigningKey("confirmation-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewJWTCredential("opaque.current.token")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, signingKey, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(
		request,
		fixedClock(now),
		signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWT}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := prepared.Credential().JWT(); !ok || got != "opaque.current.token" {
		t.Fatalf("JWT credential = %q, %t", got, ok)
	}
	verified, err := prepared.Verify(signingKey.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	if verified.Scheme() != signaturekey.SchemeJWT || verified.Signer() != "" {
		t.Fatalf("generic proof inferred credential semantics: scheme=%q signer=%q", verified.Scheme(), verified.Signer())
	}
}

func TestUnsupportedSchemeReturnsNegotiableTypedError(t *testing.T) {
	now := time.Date(2026, 8, 28, 22, 30, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	signingKey, err := jose.NewEd25519SigningKey("request-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(signingKey.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, signingKey, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Signature-Key", "sig=future")
	_, err = signaturekey.PrepareRequest(
		request,
		fixedClock(now),
		signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK, signaturekey.SchemeJWT}},
	)
	var failure *signaturekey.Error
	if !errors.As(err, &failure) {
		t.Fatalf("error = %T %v, want *signaturekey.Error", err, err)
	}
	if failure.Code != signaturekey.ErrorUnsupportedScheme {
		t.Fatalf("code = %q, want %q", failure.Code, signaturekey.ErrorUnsupportedScheme)
	}
	if got, want := failure.AcceptedSchemes, []signaturekey.Scheme{signaturekey.SchemeHWK, signaturekey.SchemeJWT}; !equalSchemes(got, want) {
		t.Fatalf("accepted schemes = %#v, want %#v", got, want)
	}
}

func equalSchemes(left, right []signaturekey.Scheme) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
