package aauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Common JWT verification does not treat a future iat as invalid by itself.
// A request-bound caller judges iat against its request window; a consumer
// without a request accepts it, while signature, claim, lifetime, exp and nbf
// checks are unchanged.
func TestCoreVerificationDoesNotRefuseFutureIssuedAtByItself(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	issuerKey := coreTokenKey(t, "issuer-key")
	agentKey := coreTokenKey(t, "agent-key")
	accessKey := coreTokenKey(t, "access-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://agents.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: issuerKey.ID()}:  issuerKey.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}: accessKey.PublicJWK(),
	}
	mintAgent := func(issuedAt time.Time, notBefore time.Time, lifetime time.Duration, jti string) string {
		t.Helper()
		compact, err := aauth.MintAgentToken("https://agents.example", issuerKey, aauth.AgentTokenRequest{
			Agent: "aauth:reader@agents.example", PersonServer: "https://person.example",
			PublicKey: agentKey.PublicJWK(), NotBefore: notBefore, Lifetime: lifetime,
		}, issuedAt, jti)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	verifyAgent := func(compact string) error {
		_, err := aauth.VerifyAgentToken(context.Background(), compact, resolver, clock)
		return err
	}

	t.Run("agent token issued ahead of the verifier clock", func(t *testing.T) {
		for _, ahead := range []time.Duration{90 * time.Second, 10 * time.Minute} {
			claims, err := aauth.VerifyAgentToken(context.Background(), mintAgent(now.Add(ahead), time.Time{}, time.Hour, "future-agent"), resolver, clock)
			if err != nil {
				t.Fatalf("VerifyAgentToken(iat now+%s) = %v, want accepted", ahead, err)
			}
			if claims.IssuedAt != now.Add(ahead).Unix() {
				t.Fatalf("iat = %d, want %d", claims.IssuedAt, now.Add(ahead).Unix())
			}
		}
	})

	t.Run("off-request auth token consumer", func(t *testing.T) {
		compact, err := aauth.MintAuthToken(accessKey, aauth.AuthTokenClaims{
			Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
			Audience: "https://resource.example", JTI: "future-auth-token",
			PersonServer: "https://person.example", Subject: "person-1", Scope: "records.read",
			Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			IssuedAt:     now.Add(90 * time.Second).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := aauth.VerifyAuthToken(context.Background(), compact, resolver, clock); err != nil {
			t.Fatalf("VerifyAuthToken(iat now+90s) = %v, want accepted", err)
		}
	})

	t.Run("future token with a bad signature", func(t *testing.T) {
		compact := mintAgent(now.Add(90*time.Second), time.Time{}, time.Hour, "forged-agent")
		if err := verifyAgent(compact[:len(compact)-4] + "AAAA"); err == nil {
			t.Fatal("forged future agent token was accepted")
		}
	})

	t.Run("future token with malformed claims", func(t *testing.T) {
		compact := signCoreTokenPayload(t, issuerKey, aauth.AgentTokenType, map[string]any{
			"iss": "https://agents.example", "dwk": aauth.AgentDiscoveryDocument,
			"sub": "not-an-agent", "jti": "malformed-agent",
			"cnf": map[string]any{"jwk": agentKey.PublicJWK()},
			"iat": now.Add(90 * time.Second).Unix(), "exp": now.Add(time.Hour).Unix(),
		})
		if err := verifyAgent(compact); err == nil {
			t.Fatal("future agent token with an invalid subject was accepted")
		}
	})

	t.Run("future token without a positive lifetime", func(t *testing.T) {
		compact := signCoreTokenPayload(t, issuerKey, aauth.AgentTokenType, map[string]any{
			"iss": "https://agents.example", "dwk": aauth.AgentDiscoveryDocument,
			"sub": "aauth:reader@agents.example", "jti": "no-lifetime-agent",
			"cnf": map[string]any{"jwk": agentKey.PublicJWK()},
			"iat": now.Add(90 * time.Second).Unix(), "exp": now.Add(90 * time.Second).Unix(),
		})
		if err := verifyAgent(compact); err == nil {
			t.Fatal("future agent token with exp equal to iat was accepted")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		err := verifyAgent(mintAgent(now.Add(-2*time.Hour), time.Time{}, time.Hour, "expired-agent"))
		var failure *aauth.TokenValidationError
		if !errors.As(err, &failure) || failure.Code != aauth.TokenValidationExpired {
			t.Fatalf("expired agent token error = %#v, want %s", err, aauth.TokenValidationExpired)
		}
	})

	t.Run("future token not yet valid", func(t *testing.T) {
		err := verifyAgent(mintAgent(now.Add(90*time.Second), now.Add(2*time.Minute), time.Hour, "nbf-agent"))
		var failure *aauth.TokenValidationError
		if !errors.As(err, &failure) || failure.Code != aauth.TokenValidationNotYetValid {
			t.Fatalf("future-nbf agent token error = %#v, want %s", err, aauth.TokenValidationNotYetValid)
		}
	})
}
