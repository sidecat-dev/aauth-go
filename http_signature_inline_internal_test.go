package aauth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type jktJWTHeader struct {
	Algorithm string   `json:"alg"`
	Type      string   `json:"typ"`
	JWK       jose.JWK `json:"jwk"`
}

func TestJKTJWTRequestRefusesAnHTTPProofMadeByTheDurableKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	durable := internalTestSigningKey(t, "durable-key")
	ephemeral := internalTestSigningKey(t, "ephemeral-key")
	delegation, err := signaturekey.MintJKTJWT(durable, ephemeral.PublicJWK(), now, time.Hour)
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
		signaturekey.SignOptions{},
	); err != nil {
		t.Fatal(err)
	}

	_, err = VerifyRequest(
		context.Background(),
		request,
		nil,
		clock,
		VerifyRequestOptions{
			AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeJKTJWT},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "HTTP message signature is invalid") {
		t.Fatalf("durable-key HTTP proof error = %v", err)
	}
}

func TestJWTVerificationClassifierPublishesOnlyUnsupportedClaim(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{
			name: "wrapped unsupported claim",
			err: fmt.Errorf(
				"private outer diagnostic: %w",
				&unsupportedTokenClaimError{tokenType: AuthTokenType, claim: "r3_uri"},
			),
			want: "aauth: aa-auth+jwt contains unsupported r3_uri claim",
		},
		{name: "ordinary invalid JWT", err: errors.New("private parse diagnostic")},
		{
			name: "expired JWT",
			err:  &TokenValidationError{Code: TokenValidationExpired, Cause: errors.New("private clock diagnostic")},
		},
		{
			name: "unknown key",
			err:  &signaturekey.ResolutionError{Code: signaturekey.ResolutionUnknown, Cause: errors.New("private issuer diagnostic")},
		},
		{name: "unsupported algorithm", err: &unsupportedTokenAlgorithmError{algorithm: "private-algorithm"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var signatureError *signaturekey.Error
			if err := classifyJWTVerificationError(test.err); !errors.As(err, &signatureError) {
				t.Fatalf("classified error = %T %v", err, err)
			}
			if got := signatureError.PublicDetail(); got != test.want {
				t.Fatalf("PublicDetail = %q, want %q", got, test.want)
			}
			if strings.Contains(signatureError.PublicDetail(), "private") {
				t.Fatalf("PublicDetail leaked private diagnostic: %q", signatureError.PublicDetail())
			}
		})
	}
}

func TestVerifyRequestExactComponentProfileRejectsAdditionalCoveredHeader(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	issuer := internalTestSigningKey(t, "issuer-key")
	agent := internalTestSigningKey(t, "agent-key")
	credential, err := mintToken(issuer, AgentTokenType, AgentTokenClaims{
		Issuer:       "https://ap.example",
		DWK:          AgentDiscoveryDocument,
		Subject:      "aauth:agent@ap.example",
		JTI:          "agent-token",
		Confirmation: Confirmation{JWK: agent.PublicJWK()},
		IssuedAt:     now.Add(-time.Minute).Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://ps.example/token", strings.NewReader(`{"resource_token":"token"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Retained-Only-In-Live-Request", "covered value")
	request.Header.Set("Signature-Key", `sig=jwt;jwt="`+credential+`"`)
	components := []string{
		"@method", "@authority", "@path", "content-digest", "content-type",
		"x-retained-only-in-live-request", "signature-key",
	}
	body, err := readRequestBody(request)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	request.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
	params := signatureParams(components, now.Unix(), time.Time{}, "")
	base, err := signatureBase(request, components, params)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signTestMessage(agent, []byte(base))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Signature-Input", "sig="+params)
	request.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(signature)+":")

	_, err = VerifyRequest(
		context.Background(),
		request,
		signaturekey.StaticKeyResolver{"https://ap.example": {issuer.ID(): issuer.PublicJWK()}},
		clock,
		VerifyRequestOptions{
			RequiredComponents:     []string{"content-type"},
			AllowedCredentialTypes: []string{AgentTokenType},
			RequireExactComponents: true,
		},
	)
	var signatureError *signaturekey.Error
	if !errors.As(err, &signatureError) || signatureError.Code != signaturekey.ErrorInvalidSignature ||
		!strings.Contains(err.Error(), "exact component profile") {
		t.Fatalf("additional covered component error = %v (%#v)", err, signatureError)
	}
}

func TestVerifyRequestUsesOneTrustedInstantForTheWholeVerification(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	issuer := internalTestSigningKey(t, "issuer-key")
	agent := internalTestSigningKey(t, "agent-key")
	credential, err := mintToken(issuer, AgentTokenType, AgentTokenClaims{
		Issuer: "https://ap.example", DWK: AgentDiscoveryDocument,
		Subject: "aauth:agent@ap.example", JTI: "agent-token",
		Confirmation: Confirmation{JWK: agent.PublicJWK()},
		IssuedAt:     now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignJWTRequest(request, agent, credential, ClockFunc(func() time.Time { return now })); err != nil {
		t.Fatal(err)
	}
	calls := 0
	verificationClock := ClockFunc(func() time.Time {
		calls++
		return now.Add(time.Duration(calls-1) * time.Hour)
	})
	verified, err := VerifyRequest(
		context.Background(),
		request,
		signaturekey.StaticKeyResolver{"https://ap.example": {issuer.ID(): issuer.PublicJWK()}},
		verificationClock,
		VerifyRequestOptions{AllowedCredentialTypes: []string{AgentTokenType}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !verified.VerifiedAt.Equal(now) {
		t.Fatalf("verification clock calls/instant = %d/%s", calls, verified.VerifiedAt)
	}
}

func TestVerifyRequestExactComponentProfileRejectsUndeclaredAndSplitFields(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	issuer := internalTestSigningKey(t, "issuer-key")
	agent := internalTestSigningKey(t, "agent-key")
	credential, err := mintToken(issuer, AgentTokenType, AgentTokenClaims{
		Issuer: "https://ap.example", DWK: AgentDiscoveryDocument,
		Subject: "aauth:agent@ap.example", JTI: "agent-token",
		Confirmation: Confirmation{JWK: agent.PublicJWK()},
		IssuedAt:     now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	verify := func(request *http.Request) error {
		_, err := VerifyRequest(
			context.Background(),
			request,
			signaturekey.StaticKeyResolver{"https://ap.example": {issuer.ID(): issuer.PublicJWK()}},
			clock,
			VerifyRequestOptions{
				RequiredComponents:     []string{"content-type"},
				AllowedCredentialTypes: []string{AgentTokenType},
				RequireExactComponents: true,
			},
		)
		return err
	}

	t.Run("covered authorization was not declared by the endpoint", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodPost, "https://ps.example/token", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer foreign")
		if err := signaturekey.SignJWTRequest(request, agent, credential, clock); err != nil {
			t.Fatal(err)
		}
		if err := verify(request); err == nil || !strings.Contains(err.Error(), "exact component profile") {
			t.Fatalf("undeclared covered authorization error = %v", err)
		}
	})

	t.Run("split retained field", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodPost, "https://ps.example/token", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		if err := signaturekey.SignJWTRequest(request, agent, credential, clock); err != nil {
			t.Fatal(err)
		}
		request.Header["Content-Type"] = append(request.Header["Content-Type"], "application/problem+json")
		if err := verify(request); err == nil || !strings.Contains(err.Error(), "multiple field lines") {
			t.Fatalf("split retained field error = %v", err)
		}
	})
}

func TestJKTJWTRefusesInvalidProtectedMaterial(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	durable := internalTestSigningKey(t, "durable-key")
	ephemeral := internalTestSigningKey(t, "ephemeral-key")
	compact, err := signaturekey.MintJKTJWT(durable, ephemeral.PublicJWK(), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("type", func(t *testing.T) {
		mutated := rewriteJKTJWT(t, compact, durable, func(header *jktJWTHeader, _ *signaturekey.JKTJWTClaims) {
			header.Type = "jkt-s512+jwt"
		})
		if _, err := signaturekey.VerifyJKTJWT(mutated, clock); err == nil ||
			!strings.Contains(err.Error(), "typ") {
			t.Fatalf("unsupported typ error = %v", err)
		}
	})
	t.Run("algorithm", func(t *testing.T) {
		mutated := rewriteJKTJWT(t, compact, durable, func(header *jktJWTHeader, _ *signaturekey.JKTJWTClaims) {
			header.Algorithm = "none"
		})
		if _, err := signaturekey.VerifyJKTJWT(mutated, clock); err == nil ||
			!strings.Contains(err.Error(), "forbidden") {
			t.Fatalf("alg none error = %v", err)
		}
	})
	t.Run("issuer", func(t *testing.T) {
		mutated := rewriteJKTJWT(t, compact, durable, func(_ *jktJWTHeader, claims *signaturekey.JKTJWTClaims) {
			claims.Issuer = "urn:jkt:sha-256:substituted"
		})
		if _, err := signaturekey.VerifyJKTJWT(mutated, clock); err == nil ||
			!strings.Contains(err.Error(), "issuer") {
			t.Fatalf("substituted issuer error = %v", err)
		}
	})
	t.Run("identity key", func(t *testing.T) {
		mutated := rewriteJKTJWT(t, compact, durable, func(header *jktJWTHeader, _ *signaturekey.JKTJWTClaims) {
			header.JWK.X = "not-a-public-key"
		})
		_, err := signaturekey.VerifyJKTJWT(mutated, clock)
		var validationError *signaturekey.Error
		if !errors.As(err, &validationError) ||
			validationError.Code != signaturekey.ErrorInvalidKey {
			t.Fatalf("invalid identity key error = %v (%#v)", err, validationError)
		}
	})
	t.Run("confirmation key", func(t *testing.T) {
		mutated := rewriteJKTJWT(t, compact, durable, func(_ *jktJWTHeader, claims *signaturekey.JKTJWTClaims) {
			claims.Confirmation.JWK.X = "not-a-public-key"
		})
		_, err := signaturekey.VerifyJKTJWT(mutated, clock)
		var validationError *signaturekey.Error
		if !errors.As(err, &validationError) ||
			validationError.Code != signaturekey.ErrorInvalidKey {
			t.Fatalf("invalid confirmation key error = %v (%#v)", err, validationError)
		}
	})
}

func TestVerifyRequestClassifiesUnsupportedJWTAlgorithm(t *testing.T) {
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
	if err := signaturekey.SignJWTRequestWithOptions(request, requestKey, compact, clock, signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err = VerifyRequest(context.Background(), request, signaturekey.StaticKeyResolver{}, clock, VerifyRequestOptions{
		AllowedCredentialTypes: []string{AgentTokenType},
	})
	var signatureError *signaturekey.Error
	if !errors.As(err, &signatureError) ||
		signatureError.Code != signaturekey.ErrorUnsupportedAlgorithm ||
		len(signatureError.AcceptedAlgorithms) != 1 ||
		signatureError.AcceptedAlgorithms[0] != jose.Ed25519Algorithm {
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
		Confirmation: Confirmation{JWK: jose.JWK{
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
	if err := signaturekey.SignJWTRequest(request, requestKey, credential, clock); err != nil {
		t.Fatal(err)
	}
	_, err = VerifyRequest(
		context.Background(),
		request,
		signaturekey.StaticKeyResolver{"https://ap.example": {"issuer-key": issuer.PublicJWK()}},
		clock,
		VerifyRequestOptions{AllowedCredentialTypes: []string{AgentTokenType}},
	)
	var signatureError *signaturekey.Error
	var validationError *TokenValidationError
	if !errors.As(err, &signatureError) ||
		signatureError.Code != signaturekey.ErrorInvalidKey ||
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
	var signatureError *signaturekey.Error
	if !errors.As(err, &signatureError) || signatureError.Code != signaturekey.ErrorInvalidRequest {
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
		want        signaturekey.ErrorCode
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
			want:        signaturekey.ErrorInvalidInput,
		},
		{
			name:        "stale created time",
			mutate:      func(*http.Request) {},
			verifyClock: ClockFunc(func() time.Time { return now.Add(2 * time.Minute) }),
			want:        signaturekey.ErrorInvalidSignature,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := signaturekey.SignJWKSURIRequest(
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
				VerifyRequestOptions{AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeJWKSURI}},
			)
			var signatureError *signaturekey.Error
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
) (jose.JWK, error) {
	resolver.calls++
	return jose.JWK{}, errors.New("resolver should not be called")
}

func mintTokenWithAlgorithm(key jose.SigningKey, algorithm, tokenType string, claims any) (string, error) {
	headerBytes, err := json.Marshal(jose.Header{Algorithm: algorithm, Type: tokenType, KeyID: key.ID()})
	if err != nil {
		return "", err
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	signature, err := signTestMessage(key, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func rewriteJKTJWT(
	t *testing.T,
	compact string,
	signer jose.SigningKey,
	rewrite func(*jktJWTHeader, *signaturekey.JKTJWTClaims),
) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact parts = %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var header jktJWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatal(err)
	}
	var claims signaturekey.JKTJWTClaims
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
	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	signature, err := signTestMessage(signer, []byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func internalTestSigningKey(t *testing.T, id string) jose.SigningKey {
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

func signTestMessage(key jose.SigningKey, message []byte) ([]byte, error) {
	return key.Sign(rand.Reader, message, crypto.Hash(0))
}
