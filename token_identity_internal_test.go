package aauth

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAgentTokenRefusesAnIdentifierOutsideTheIssuerDomain(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 13, 0, 0, 0, time.UTC)
	providerKey := internalTestSigningKey(t, "provider-key")
	agentKey := internalTestSigningKey(t, "agent-key")
	request := AgentTokenRequest{
		Agent:     "aauth:install@other.example",
		PublicKey: agentKey.PublicJWK(),
		Lifetime:  time.Hour,
	}
	if _, err := MintAgentToken(
		"https://provider.example",
		providerKey,
		request,
		now,
		"agent-token-1",
	); err == nil || !strings.Contains(err.Error(), "issuer domain") {
		t.Fatalf("mismatched mint error = %v", err)
	}

	compact, err := mintToken(providerKey, AgentTokenType, AgentTokenClaims{
		Issuer:       "https://provider.example",
		DWK:          AgentDiscoveryDocument,
		Subject:      request.Agent,
		JTI:          "agent-token-1",
		Confirmation: Confirmation{JWK: request.PublicKey},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyAgentToken(
		context.Background(),
		compact,
		StaticKeyResolver{
			"https://provider.example": {
				"provider-key": providerKey.PublicJWK(),
			},
		},
		ClockFunc(func() time.Time { return now }),
	)
	if err == nil || !strings.Contains(err.Error(), "issuer domain") {
		t.Fatalf("mismatched verification error = %v", err)
	}
}
