package aauth_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestHWKRequestCarriesAndProvesItsInlineEd25519Key(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := testSigningKey(t, "durable-key")
	request, err := http.NewRequest(http.MethodPost, "https://ap.example/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := signaturekey.SignHWKRequest(request, key, clock); err != nil {
		t.Fatal(err)
	}
	if got, want := request.Header.Get("Signature-Key"),
		`sig=hwk;kty="OKP";crv="Ed25519";x="`+key.PublicJWK().X+`";alg="Ed25519"`; got != want {
		t.Fatalf("Signature-Key = %q, want %q", got, want)
	}

	verified, err := aauth.VerifyRequest(
		context.Background(),
		request,
		nil,
		clock,
		aauth.VerifyRequestOptions{
			AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeHWK},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := key.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	if verified.SignatureKeyType != signaturekey.SchemeHWK ||
		verified.Signer != identity ||
		!verified.IdentityKey.Equal(key.PublicJWK()) ||
		!verified.PublicKey.Equal(key.PublicJWK()) {
		t.Fatalf("verified hwk context = %#v", verified)
	}
}

func TestJKTJWTRequestProvesDurableIdentityAndDelegatedRequestKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	durable := testSigningKey(t, "durable-key")
	ephemeral := testSigningKey(t, "ephemeral-key")
	delegation, err := signaturekey.MintJKTJWT(
		durable,
		ephemeral.PublicJWK(),
		now,
		time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://ap.example/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignJKTJWTRequest(request, ephemeral, delegation, clock); err != nil {
		t.Fatal(err)
	}

	verified, err := aauth.VerifyRequest(
		context.Background(),
		request,
		nil,
		clock,
		aauth.VerifyRequestOptions{
			AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeJKTJWT},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := durable.PublicJWK().ThumbprintURI()
	if err != nil {
		t.Fatal(err)
	}
	if verified.SignatureKeyType != signaturekey.SchemeJKTJWT ||
		verified.Signer != identity ||
		!verified.IdentityKey.Equal(durable.PublicJWK()) ||
		!verified.PublicKey.Equal(ephemeral.PublicJWK()) ||
		verified.JKTJWT == nil ||
		verified.JKTJWT.Issuer != identity {
		t.Fatalf("verified jkt-jwt context = %#v", verified)
	}
}

func TestJKTJWTRefusesIssuerKeySubstitutionAndInvalidTime(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	durable := testSigningKey(t, "durable-key")
	ephemeral := testSigningKey(t, "ephemeral-key")
	delegation, err := signaturekey.MintJKTJWT(
		durable,
		ephemeral.PublicJWK(),
		now,
		time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(delegation, ".")
	if len(parts) != 3 {
		t.Fatalf("delegation parts = %d", len(parts))
	}
	parts[2] = mutateBase64URL(parts[2])
	if _, err := signaturekey.VerifyJKTJWT(strings.Join(parts, "."), clock); err == nil {
		t.Fatal("delegation with a substituted signature was accepted")
	}

	expiredClock := aauth.ClockFunc(func() time.Time { return now.Add(time.Hour) })
	if _, err := signaturekey.VerifyJKTJWT(delegation, expiredClock); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired delegation error = %v", err)
	}

	futureClock := aauth.ClockFunc(func() time.Time { return now.Add(-time.Second) })
	if _, err := signaturekey.VerifyJKTJWT(delegation, futureClock); err == nil ||
		!strings.Contains(err.Error(), "future") {
		t.Fatalf("future delegation error = %v", err)
	}
}

func TestJKTJWTSignerRefusesAKeyOtherThanTheDelegatedKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	durable := testSigningKey(t, "durable-key")
	ephemeral := testSigningKey(t, "ephemeral-key")
	other := testSigningKey(t, "other-key")
	delegation, err := signaturekey.MintJKTJWT(
		durable,
		ephemeral.PublicJWK(),
		now,
		time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://ap.example/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignJKTJWTRequest(
		request,
		other,
		delegation,
		clock,
	); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("non-delegated signer error = %v", err)
	}
}

func TestHWKDuplicateAlgorithmParameterRemainsCoveredByTheSignature(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := testSigningKey(t, "durable-key")
	request, err := http.NewRequest(http.MethodPost, "https://ap.example/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignHWKRequest(request, key, clock); err != nil {
		t.Fatal(err)
	}
	request.Header.Set(
		"Signature-Key",
		request.Header.Get("Signature-Key")+`;alg="Ed25519"`,
	)
	if _, err := aauth.VerifyRequest(
		context.Background(),
		request,
		nil,
		clock,
		aauth.VerifyRequestOptions{
			AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeHWK},
		},
	); err == nil || !strings.Contains(err.Error(), "HTTP message signature is invalid") {
		t.Fatalf("hwk covered duplicate alg-parameter error = %v", err)
	}
}

func mutateBase64URL(value string) string {
	if strings.HasPrefix(value, "A") {
		return "B" + value[1:]
	}
	return "A" + value[1:]
}
