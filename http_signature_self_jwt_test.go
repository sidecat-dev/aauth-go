package aauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestSelfJWTRejectsUnsafeClaimsBeforeDiscovery(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 3, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	key := internalTestSigningKey(t, "resource-key")
	validClaims := map[string]any{
		"iss": "https://resource.example",
		"dwk": ResourceDiscoveryDocument,
		"aud": "aauth:subscriber@ap.example",
		"eid": "event-1",
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	}
	validCompact := mintRawToken(
		t,
		key,
		jose.Header{Algorithm: "Ed25519", Type: EventTokenType, KeyID: key.ID()},
		validClaims,
	)

	for _, test := range []struct {
		name string
		key  string
		want signaturekey.ErrorCode
	}{
		{name: "absent jwt parameter", key: "sig=self-jwt", want: signaturekey.ErrorInvalidKey},
		{name: "non-string jwt parameter", key: "sig=self-jwt;jwt=token", want: signaturekey.ErrorInvalidKey},
		{name: "empty jwt parameter", key: `sig=self-jwt;jwt=""`, want: signaturekey.ErrorInvalidKey},
		{name: "unexpected parameter", key: `sig=self-jwt;jwt="token";kid="extra"`, want: signaturekey.ErrorInvalidKey},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := signaturekey.SignSelfJWTRequest(request, key, validCompact, clock); err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Signature-Key", test.key)
			resolver := &selfJWTCountingResolver{}
			_, err = VerifyRequest(context.Background(), request, resolver, clock, VerifyRequestOptions{
				AllowedCredentialTypes:   []string{EventTokenType},
				AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeSelfJWT},
			})
			requireSignatureErrorCode(t, err, test.want)
			if resolver.calls != 0 {
				t.Fatalf("invalid Signature-Key made %d resolver calls", resolver.calls)
			}
		})
	}

	for _, test := range []struct {
		name   string
		header jose.Header
		claims map[string]any
		rawJWT string
		want   signaturekey.ErrorCode
	}{
		{name: "malformed JWT", rawJWT: "not-a-jwt", want: signaturekey.ErrorInvalidJWT},
		{name: "wrong type", header: jose.Header{Algorithm: "Ed25519", Type: SubscribeTokenType, KeyID: key.ID()}, claims: validClaims, want: signaturekey.ErrorInvalidJWT},
		{name: "expired", header: jose.Header{Algorithm: "Ed25519", Type: EventTokenType, KeyID: key.ID()}, claims: mutateClaim(validClaims, "exp", now.Add(-time.Second).Unix()), want: signaturekey.ErrorExpiredJWT},
		{name: "missing issuer", header: jose.Header{Algorithm: "Ed25519", Type: EventTokenType, KeyID: key.ID()}, claims: mutateClaim(validClaims, "iss", nil), want: signaturekey.ErrorInvalidJWT},
		{name: "unsafe issuer", header: jose.Header{Algorithm: "Ed25519", Type: EventTokenType, KeyID: key.ID()}, claims: mutateClaim(validClaims, "iss", "http://127.0.0.1"), want: signaturekey.ErrorInvalidJWT},
		{name: "missing discovery document", header: jose.Header{Algorithm: "Ed25519", Type: EventTokenType, KeyID: key.ID()}, claims: mutateClaim(validClaims, "dwk", nil), want: signaturekey.ErrorInvalidKey},
		{name: "unsafe discovery document", header: jose.Header{Algorithm: "Ed25519", Type: EventTokenType, KeyID: key.ID()}, claims: mutateClaim(validClaims, "dwk", "../keys.json"), want: signaturekey.ErrorInvalidKey},
		{name: "missing key id", header: jose.Header{Algorithm: "Ed25519", Type: EventTokenType}, claims: validClaims, want: signaturekey.ErrorInvalidKey},
		{name: "algorithm none", header: jose.Header{Algorithm: "none", Type: EventTokenType, KeyID: key.ID()}, claims: validClaims, want: signaturekey.ErrorInvalidJWT},
		{name: "confirmation claim", header: jose.Header{Algorithm: "Ed25519", Type: EventTokenType, KeyID: key.ID()}, claims: mutateClaim(validClaims, "cnf", map[string]any{"jwk": key.PublicJWK()}), want: signaturekey.ErrorInvalidJWT},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			compact := test.rawJWT
			if compact == "" {
				compact = mintRawToken(t, key, test.header, test.claims)
			}
			request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := signRequestWithSignatureKey(request, key, `sig=self-jwt;jwt=`+strconvQuote(compact), clock, signaturekey.SignOptions{}); err != nil {
				t.Fatal(err)
			}
			resolver := &selfJWTCountingResolver{}
			_, err = VerifyRequest(context.Background(), request, resolver, clock, VerifyRequestOptions{
				AllowedCredentialTypes:   []string{EventTokenType},
				AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeSelfJWT},
			})
			var signatureError *signaturekey.Error
			if !errors.As(err, &signatureError) || signatureError.Code != test.want {
				t.Fatalf("VerifyRequest error = %v (%#v), want %q", err, signatureError, test.want)
			}
			if resolver.calls != 0 {
				t.Fatalf("preflight failure made %d resolver calls", resolver.calls)
			}
		})
	}
}

func TestSelfJWTUsesOneDiscoveredKeyForBothProofs(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 3, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	issuerKey := internalTestSigningKey(t, "resource-key")
	otherKey := internalTestSigningKey(t, "other-key")
	claims := EventTokenClaims{
		Issuer:    "https://resource.example",
		DWK:       ResourceDiscoveryDocument,
		Audience:  "aauth:subscriber@ap.example",
		EventID:   "event-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	}
	compact, err := MintEventToken(issuerKey, claims)
	if err != nil {
		t.Fatal(err)
	}

	resolver := &selfJWTCountingResolver{keys: map[string]jose.JWK{
		issuerKey.ID(): issuerKey.PublicJWK(),
		otherKey.ID():  otherKey.PublicJWK(),
	}}
	request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignSelfJWTRequest(request, issuerKey, compact, clock); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRequest(context.Background(), request, resolver, clock, VerifyRequestOptions{
		AllowedCredentialTypes:   []string{EventTokenType},
		AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeSelfJWT},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.calls)
	}
	if verified.SelfJWT == nil || verified.SelfJWT.Issuer != claims.Issuer ||
		verified.SelfJWT.DWK != claims.DWK || !verified.PublicKey.Equal(issuerKey.PublicJWK()) {
		t.Fatalf("verified self-jwt = %#v, public key = %#v", verified.SelfJWT, verified.PublicKey)
	}
	decoded, err := DecodeVerifiedEventToken(*verified.SelfJWT, clock)
	if err != nil || decoded != claims {
		t.Fatalf("DecodeVerifiedEventToken() = %#v, %v, want %#v", decoded, err, claims)
	}
	tampered := *verified.SelfJWT
	tampered.Claims = append(json.RawMessage(nil), tampered.Claims...)
	tampered.Claims[0] ^= 1
	if _, err := DecodeVerifiedEventToken(tampered, clock); err == nil {
		t.Fatal("DecodeVerifiedEventToken accepted mutated verified claims")
	}

	t.Run("HTTP proof uses another valid key", func(t *testing.T) {
		mismatched, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := signRequestWithSignatureKey(mismatched, otherKey, `sig=self-jwt;jwt=`+strconvQuote(compact), clock, signaturekey.SignOptions{}); err != nil {
			t.Fatal(err)
		}
		before := resolver.calls
		_, err = VerifyRequest(context.Background(), mismatched, resolver, clock, VerifyRequestOptions{
			AllowedCredentialTypes:   []string{EventTokenType},
			AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeSelfJWT},
		})
		requireSignatureErrorCode(t, err, signaturekey.ErrorInvalidSignature)
		if resolver.calls != before+1 {
			t.Fatalf("mismatched proof resolver calls = %d, want %d", resolver.calls, before+1)
		}
	})

	t.Run("JWT proof is corrupt", func(t *testing.T) {
		parts := strings.Split(compact, ".")
		parts[2] = mutateSelfJWTBase64URL(parts[2])
		corrupt := strings.Join(parts, ".")
		request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := signRequestWithSignatureKey(request, issuerKey, `sig=self-jwt;jwt=`+strconvQuote(corrupt), clock, signaturekey.SignOptions{}); err != nil {
			t.Fatal(err)
		}
		_, err = VerifyRequest(context.Background(), request, resolver, clock, VerifyRequestOptions{
			AllowedCredentialTypes:   []string{EventTokenType},
			AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeSelfJWT},
		})
		requireSignatureErrorCode(t, err, signaturekey.ErrorInvalidJWT)
		if resolver.refreshCalls != 0 {
			t.Fatalf("corrupt JWT made %d key refresh calls, want 0", resolver.refreshCalls)
		}
	})

	t.Run("unknown key remains typed", func(t *testing.T) {
		unknown := &selfJWTCountingResolver{}
		_, err := VerifyRequest(context.Background(), request, unknown, clock, VerifyRequestOptions{
			AllowedCredentialTypes:   []string{EventTokenType},
			AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeSelfJWT},
		})
		requireSignatureErrorCode(t, err, signaturekey.ErrorUnknownKey)
		if unknown.calls != 1 || unknown.refreshCalls != 0 {
			t.Fatalf("unknown key resolution calls = %d, refreshes = %d, want 1/0", unknown.calls, unknown.refreshCalls)
		}
	})
}

func TestSelfJWTAppliesDeploymentPolicyBeforeHTTPProof(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 3, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	issuerKey := internalTestSigningKey(t, "resource-key")
	otherKey := internalTestSigningKey(t, "other-key")
	resolver := &selfJWTCountingResolver{keys: map[string]jose.JWK{
		issuerKey.ID(): issuerKey.PublicJWK(),
	}}
	claims := EventTokenClaims{
		Issuer:    "https://resource.example",
		DWK:       ResourceDiscoveryDocument,
		Audience:  "aauth:subscriber@ap.example",
		EventID:   "event-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	}
	compact, err := MintEventToken(issuerKey, claims)
	if err != nil {
		t.Fatal(err)
	}

	policyCalls := 0
	policy := func(verified VerifiedSelfJWT) error {
		policyCalls++
		decoded, err := DecodeVerifiedEventToken(verified, clock)
		if err != nil {
			return err
		}
		if decoded.Audience != claims.Audience || decoded.EventID != claims.EventID {
			return errors.New("test policy rejected event routing")
		}
		return nil
	}
	options := VerifyRequestOptions{
		AllowedCredentialTypes:   []string{EventTokenType},
		AllowedSignatureKeyTypes: []signaturekey.Scheme{signaturekey.SchemeSelfJWT},
		SelfJWTMaximumLifetime:   2 * time.Minute,
		SelfJWTClaimPolicy:       policy,
	}
	request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignSelfJWTRequest(request, issuerKey, compact, clock); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRequest(context.Background(), request, resolver, clock, options); err != nil {
		t.Fatal(err)
	}
	if policyCalls != 1 {
		t.Fatalf("valid request policy calls = %d, want 1", policyCalls)
	}

	t.Run("excessive lifetime", func(t *testing.T) {
		excessive := claims
		excessive.ExpiresAt = now.Add(3 * time.Minute).Unix()
		excessiveCompact, err := MintEventToken(issuerKey, excessive)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := signaturekey.SignSelfJWTRequest(request, issuerKey, excessiveCompact, clock); err != nil {
			t.Fatal(err)
		}
		beforePolicy := policyCalls
		_, err = VerifyRequest(context.Background(), request, resolver, clock, options)
		requireSignatureErrorCode(t, err, signaturekey.ErrorInvalidJWT)
		if policyCalls != beforePolicy {
			t.Fatal("claim policy ran after maximum-lifetime refusal")
		}
	})

	t.Run("claim policy follows JWT proof", func(t *testing.T) {
		parts := strings.Split(compact, ".")
		parts[2] = mutateSelfJWTBase64URL(parts[2])
		corrupt := strings.Join(parts, ".")
		request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := signRequestWithSignatureKey(
			request,
			issuerKey,
			`sig=self-jwt;jwt=`+strconvQuote(corrupt),
			clock,
			signaturekey.SignOptions{},
		); err != nil {
			t.Fatal(err)
		}
		beforePolicy := policyCalls
		_, err = VerifyRequest(context.Background(), request, resolver, clock, options)
		requireSignatureErrorCode(t, err, signaturekey.ErrorInvalidJWT)
		if policyCalls != beforePolicy {
			t.Fatal("claim policy ran before JWT proof succeeded")
		}
	})

	t.Run("claim policy precedes HTTP proof", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := signRequestWithSignatureKey(
			request,
			otherKey,
			`sig=self-jwt;jwt=`+strconvQuote(compact),
			clock,
			signaturekey.SignOptions{},
		); err != nil {
			t.Fatal(err)
		}
		policyFailure := errors.New("test deployment policy refusal")
		beforePolicy := policyCalls
		refusing := options
		refusing.SelfJWTClaimPolicy = func(VerifiedSelfJWT) error {
			policyCalls++
			return policyFailure
		}
		_, err = VerifyRequest(context.Background(), request, resolver, clock, refusing)
		var signatureError *signaturekey.Error
		if !errors.As(err, &signatureError) || signatureError.Code != signaturekey.ErrorInvalidJWT ||
			!errors.Is(err, policyFailure) {
			t.Fatalf("claim-policy error = %v (%#v), want invalid_jwt policy refusal", err, signatureError)
		}
		if policyCalls != beforePolicy+1 {
			t.Fatalf("refused request policy calls = %d, want %d", policyCalls, beforePolicy+1)
		}
	})
}

type selfJWTCountingResolver struct {
	calls        int
	refreshCalls int
	keys         map[string]jose.JWK
}

func (resolver *selfJWTCountingResolver) ResolveKey(_ context.Context, _, _, keyID string) (jose.JWK, error) {
	resolver.calls++
	key, ok := resolver.keys[keyID]
	if !ok {
		return jose.JWK{}, &signaturekey.ResolutionError{Code: signaturekey.ResolutionUnknown, Cause: errors.New("test key is absent")}
	}
	return key, nil
}

func (resolver *selfJWTCountingResolver) RefreshKey(_ context.Context, _, _, keyID string) (jose.JWK, error) {
	resolver.refreshCalls++
	key, ok := resolver.keys[keyID]
	if !ok {
		return jose.JWK{}, &signaturekey.ResolutionError{Code: signaturekey.ResolutionUnknown, Cause: errors.New("test key is absent")}
	}
	return key, nil
}

func mintRawToken(t *testing.T, key jose.SigningKey, header jose.Header, claims any) string {
	t.Helper()
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	signature, err := signTestMessage(key, []byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func strconvQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func requireSignatureErrorCode(t *testing.T, err error, code signaturekey.ErrorCode) {
	t.Helper()
	var signatureError *signaturekey.Error
	if !errors.As(err, &signatureError) || signatureError.Code != code {
		t.Fatalf("error = %v (%#v), want %q", err, signatureError, code)
	}
}

func mutateSelfJWTBase64URL(value string) string {
	if value[0] == 'A' {
		return "B" + value[1:]
	}
	return "A" + value[1:]
}
