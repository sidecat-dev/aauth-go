package aauth_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Freshness and Replay: a verifier that first sees a signed request after a
// delay verifies that the presented token was valid at the signed created,
// not at the time it happens to look.
func TestDelayedVerifierJudgesThePresentedTokenAtCreated(t *testing.T) {
	t.Parallel()

	providerKey, err := jose.NewEd25519SigningKey("delay-provider", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	agentKey, err := jose.NewEd25519SigningKey("delay-agent", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{32}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	signedAt := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	agentToken, err := aauth.MintAgentToken("https://ap.example", providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:batch@ap.example", PublicKey: agentKey.PublicJWK(), Lifetime: 5 * time.Minute,
	}, signedAt.Add(-time.Minute), "delay-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}
	request := httptest.NewRequest(http.MethodPost, "https://pipeline.example/records", nil)
	if err := signaturekey.SignJWTRequest(request, agentKey, agentToken, aauth.ClockFunc(func() time.Time { return signedAt })); err != nil {
		t.Fatal(err)
	}

	verifiedAt := signedAt.Add(30 * time.Minute)
	prepared, err := signaturekey.PrepareRequest(request, aauth.ClockFunc(func() time.Time { return verifiedAt }), signaturekey.VerifyOptions{
		MaxDelay: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, _ := prepared.Credential().JWT()
	if _, err := aauth.VerifyAgentToken(context.Background(), compact, resolver, aauth.ClockFunc(func() time.Time { return verifiedAt })); err == nil {
		t.Fatal("the agent token is expired at verification time, yet verified")
	}
	claims, err := aauth.VerifyAgentToken(context.Background(), compact, resolver, aauth.ClockFunc(prepared.ValidAt))
	if err != nil {
		t.Fatalf("token valid at created: %v", err)
	}
	if err := prepared.CheckIssuedAt(time.Unix(claims.IssuedAt, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Verify(claims.Confirmation.JWK); err != nil {
		t.Fatal(err)
	}
}
