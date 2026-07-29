package aauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
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
		SignRequestOptions{},
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

func TestJKTJWTRefusesInvalidProtectedMaterial(t *testing.T) {
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
	t.Run("identity key", func(t *testing.T) {
		mutated := rewriteJKTJWT(t, compact, durable, func(header *jktJWTHeader, _ *JKTJWTClaims) {
			header.JWK.X = "not-a-public-key"
		})
		_, err := VerifyJKTJWT(mutated, clock)
		var validationError *TokenValidationError
		if !errors.As(err, &validationError) ||
			validationError.Code != TokenValidationInvalidKey {
			t.Fatalf("invalid identity key error = %v (%#v)", err, validationError)
		}
	})
	t.Run("confirmation key", func(t *testing.T) {
		mutated := rewriteJKTJWT(t, compact, durable, func(_ *jktJWTHeader, claims *JKTJWTClaims) {
			claims.Confirmation.JWK.X = "not-a-public-key"
		})
		_, err := VerifyJKTJWT(mutated, clock)
		var validationError *TokenValidationError
		if !errors.As(err, &validationError) ||
			validationError.Code != TokenValidationInvalidKey {
			t.Fatalf("invalid confirmation key error = %v (%#v)", err, validationError)
		}
	})
}

func TestVerifyRequestClassifiesUnsupportedJWTAlgorithmAsInvalidJWT(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	issuer := internalTestSigningKey(t, "issuer-key")
	requestKey := internalTestSigningKey(t, "request-key")
	claims := AgentTokenClaims{
		Issuer:       "https://ap.example",
		DWK:          AgentDiscoveryDocument,
		Subject:      "aauth:agent@ap.example",
		JTI:          "agent-token",
		Confirmation: Confirmation{JWK: requestKey.PublicJWK()},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
	}
	compact, err := mintTokenWithAlgorithm(issuer, "ES256", AgentTokenType, claims)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequestWithOptions(request, requestKey, compact, clock, SignRequestOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err = VerifyRequest(context.Background(), request, StaticKeyResolver{}, clock, VerifyRequestOptions{
		AllowedCredentialTypes: []string{AgentTokenType},
	})
	var signatureError *SignatureError
	if !errors.As(err, &signatureError) ||
		signatureError.Code != SignatureErrorInvalidJWT ||
		len(signatureError.SupportedAlgorithms) != 0 {
		t.Fatalf("unsupported token algorithm error = %v (%#v)", err, signatureError)
	}
}

func TestVerifyRequestClassifiesMalformedJWTConfirmationAsInvalidKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	issuer := internalTestSigningKey(t, "issuer-key")
	requestKey := internalTestSigningKey(t, "request-key")
	credential, err := mintToken(issuer, AgentTokenType, AgentTokenClaims{
		Issuer:  "https://ap.example",
		DWK:     AgentDiscoveryDocument,
		Subject: "aauth:agent@ap.example",
		JTI:     "agent-token-with-invalid-confirmation",
		Confirmation: Confirmation{JWK: JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   "not-a-public-key",
		}},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(request, requestKey, credential, clock); err != nil {
		t.Fatal(err)
	}
	_, err = VerifyRequest(
		context.Background(),
		request,
		StaticKeyResolver{"https://ap.example": {"issuer-key": issuer.PublicJWK()}},
		clock,
		VerifyRequestOptions{AllowedCredentialTypes: []string{AgentTokenType}},
	)
	var signatureError *SignatureError
	var validationError *TokenValidationError
	if !errors.As(err, &signatureError) ||
		signatureError.Code != SignatureErrorInvalidKey ||
		!errors.As(err, &validationError) ||
		validationError.Code != TokenValidationInvalidKey {
		t.Fatalf(
			"VerifyRequest error = %v signature=%#v validation=%#v, want invalid_key",
			err,
			signatureError,
			validationError,
		)
	}
}

func TestSignatureBaseUsesRFC9421DerivedComponentCanonicalization(t *testing.T) {
	t.Parallel()

	request, err := http.NewRequest("mIxEd", "https://Example.COM:443/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "Example.COM:443"
	base, err := signatureBase(
		request,
		[]string{"@method", "@authority", "@path"},
		`("@method" "@authority" "@path");created=1785326400`,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(base, `"@method": mIxEd`) {
		t.Fatalf("signature base changed method case:\n%s", base)
	}
	if !strings.Contains(base, `"@authority": example.com`) {
		t.Fatalf("signature base did not normalize authority:\n%s", base)
	}
}

func TestVerifyRequestChecksAllMandatoryProofHeadersBeforeKeyMaterial(t *testing.T) {
	t.Parallel()

	request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Signature-Key", "malformed")
	request.Header.Set("Signature-Input", `sig=("@method");created=1785326400`)

	_, err = VerifyRequest(
		context.Background(),
		request,
		nil,
		ClockFunc(func() time.Time { return time.Unix(1785326400, 0) }),
		VerifyRequestOptions{},
	)
	var signatureError *SignatureError
	if !errors.As(err, &signatureError) || signatureError.Code != SignatureErrorInvalidRequest {
		t.Fatalf("missing Signature precedence = %v (%#v)", err, signatureError)
	}
}

func TestVerifyRequestRejectsPreflightFailuresBeforeKeyResolution(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	signingClock := ClockFunc(func() time.Time { return now })
	key := internalTestSigningKey(t, "request-key")

	for _, test := range []struct {
		name        string
		mutate      func(*http.Request)
		verifyClock Clock
		want        SignatureErrorCode
	}{
		{
			name: "missing required coverage",
			mutate: func(request *http.Request) {
				request.Header.Set(
					"Signature-Input",
					strings.Replace(request.Header.Get("Signature-Input"), ` "@path"`, "", 1),
				)
			},
			verifyClock: signingClock,
			want:        SignatureErrorInvalidInput,
		},
		{
			name:        "stale created time",
			mutate:      func(*http.Request) {},
			verifyClock: ClockFunc(func() time.Time { return now.Add(2 * time.Minute) }),
			want:        SignatureErrorInvalidSignature,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := SignRequestWithJWKSURI(
				request,
				key,
				"https://resource.example",
				ResourceDiscoveryDocument,
				signingClock,
			); err != nil {
				t.Fatal(err)
			}
			test.mutate(request)
			resolver := &countingKeyResolver{}
			_, err = VerifyRequest(
				context.Background(),
				request,
				resolver,
				test.verifyClock,
				VerifyRequestOptions{AllowedSignatureKeyTypes: []string{SignatureKeyJWKSURI}},
			)
			var signatureError *SignatureError
			if !errors.As(err, &signatureError) || signatureError.Code != test.want {
				t.Fatalf("VerifyRequest error = %v (%#v), want %q", err, signatureError, test.want)
			}
			if resolver.calls != 0 {
				t.Fatalf("preflight failure made %d key-resolution calls", resolver.calls)
			}
		})
	}
}

type countingKeyResolver struct{ calls int }

func (resolver *countingKeyResolver) ResolveKey(
	context.Context,
	string,
	string,
	string,
) (JWK, error) {
	resolver.calls++
	return JWK{}, errors.New("resolver should not be called")
}

func mintTokenWithAlgorithm(key SigningKey, algorithm, tokenType string, claims any) (string, error) {
	headerBytes, err := json.Marshal(TokenHeader{Algorithm: algorithm, Type: tokenType, KeyID: key.ID()})
	if err != nil {
		return "", err
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := rawURL.EncodeToString(headerBytes) + "." + rawURL.EncodeToString(claimsBytes)
	signature, err := key.sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + rawURL.EncodeToString(signature), nil
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
