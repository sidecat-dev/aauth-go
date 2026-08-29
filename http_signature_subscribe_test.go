package aauth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestVerifyRequestAcceptsSubscribeTokenConfirmationProof(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 7, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	apKey := internalTestSigningKey(t, "ap-events-key")
	agentKey := internalTestSigningKey(t, "agent-events-key")
	maxUses := 1
	claims := SubscribeTokenClaims{
		Issuer:       "https://ap.example",
		DWK:          AgentDiscoveryDocument,
		Subject:      "aauth:subscriber@ap.example",
		Audience:     "https://resource.example",
		Confirmation: Confirmation{JWK: agentKey.PublicJWK()},
		EventID:      "event-one",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		MaxUses:      &maxUses,
	}
	compact, err := MintSubscribeToken(apKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://resource.example/events/subscriptions", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignJWTRequest(request, agentKey, compact, clock); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRequest(context.Background(), request, signaturekey.StaticKeyResolver{
		claims.Issuer: {apKey.ID(): apKey.PublicJWK()},
	}, clock, VerifyRequestOptions{AllowedCredentialTypes: []string{SubscribeTokenType}})
	if err != nil {
		t.Fatal(err)
	}
	if verified.CredentialType != SubscribeTokenType || verified.Agent != claims.Subject ||
		verified.Signer != claims.Subject || verified.SubscribeToken == nil ||
		verified.SubscribeToken.Issuer != claims.Issuer ||
		verified.SubscribeToken.EventID != claims.EventID ||
		verified.SubscribeToken.MaxUses == nil || *verified.SubscribeToken.MaxUses != maxUses ||
		!verified.PublicKey.Equal(agentKey.PublicJWK()) {
		t.Fatalf("verified subscribe request = %#v", verified)
	}
	if _, err := VerifyRequest(
		context.Background(),
		request,
		signaturekey.StaticKeyResolver{claims.Issuer: {apKey.ID(): apKey.PublicJWK()}},
		clock,
		VerifyRequestOptions{},
	); err == nil {
		t.Fatal("VerifyRequest accepted a subscribe token without explicit credential opt-in")
	}
}
