package aauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestJKTJWTRequestRefusesAnHTTPProofMadeByTheDurableKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	durable := internalTestSigningKey(t, "durable-key")
	ephemeral := internalTestSigningKey(t, "ephemeral-key")
	delegation, err := MintJKTJWT(durable, ephemeral.PublicJWK(), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://ap.example/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signRequestWithSignatureKey(
		request,
		durable,
		`sig=jkt-jwt;jwt="`+delegation+`"`,
		clock,
	); err != nil {
		t.Fatal(err)
	}

	_, err = VerifyRequest(
		context.Background(),
		request,
		nil,
		clock,
		VerifyRequestOptions{
			AllowedSignatureKeyTypes: []string{SignatureKeyJKTJWT},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "HTTP message signature is invalid") {
		t.Fatalf("durable-key HTTP proof error = %v", err)
	}
}

func TestJKTJWTRefusesUnsupportedTypeAlgorithmAndMismatchedIssuer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	durable := internalTestSigningKey(t, "durable-key")
	ephemeral := internalTestSigningKey(t, "ephemeral-key")
	compact, err := MintJKTJWT(durable, ephemeral.PublicJWK(), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("type", func(t *testing.T) {
		mutated := rewriteJKTJWT(t, compact, durable, func(header *jktJWTHeader, _ *JKTJWTClaims) {
			header.Type = "jkt-s512+jwt"
		})
		if _, err := VerifyJKTJWT(mutated, clock); err == nil ||
			!strings.Contains(err.Error(), "typ") {
			t.Fatalf("unsupported typ error = %v", err)
		}
	})
	t.Run("algorithm", func(t *testing.T) {
		mutated := rewriteJKTJWT(t, compact, durable, func(header *jktJWTHeader, _ *JKTJWTClaims) {
			header.Algorithm = "none"
		})
		if _, err := VerifyJKTJWT(mutated, clock); err == nil ||
			!strings.Contains(err.Error(), "forbidden") {
			t.Fatalf("alg none error = %v", err)
		}
	})
	t.Run("issuer", func(t *testing.T) {
		mutated := rewriteJKTJWT(t, compact, durable, func(_ *jktJWTHeader, claims *JKTJWTClaims) {
			claims.Issuer = "urn:jkt:sha-256:substituted"
		})
		if _, err := VerifyJKTJWT(mutated, clock); err == nil ||
			!strings.Contains(err.Error(), "issuer") {
			t.Fatalf("substituted issuer error = %v", err)
		}
	})
}

func rewriteJKTJWT(
	t *testing.T,
	compact string,
	signer SigningKey,
	rewrite func(*jktJWTHeader, *JKTJWTClaims),
) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact parts = %d", len(parts))
	}
	headerBytes, err := rawURL.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	claimsBytes, err := rawURL.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var header jktJWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatal(err)
	}
	var claims JKTJWTClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		t.Fatal(err)
	}
	rewrite(&header, &claims)
	headerBytes, err = json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsBytes, err = json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := rawURL.EncodeToString(headerBytes) + "." + rawURL.EncodeToString(claimsBytes)
	signature, err := signer.sign([]byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + rawURL.EncodeToString(signature)
}

func internalTestSigningKey(t *testing.T, id string) SigningKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
