package aauth

import (
	"context"
	"encoding/json"
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

func TestCurrentResourceAndAuthTokensRequirePersonTopology(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
	issuerKey := internalTestSigningKey(t, "issuer-key")
	agentKey := internalTestSigningKey(t, "agent-key")
	thumbprint, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := MintResourceToken(issuerKey, ResourceTokenClaims{
		Issuer:    "https://resource.example",
		DWK:       ResourceDiscoveryDocument,
		Audience:  "https://ps.example",
		JTI:       "resource-token-without-person-topology",
		Agent:     "aauth:planner@ap.example",
		AgentJKT:  thumbprint,
		Scope:     "documents.read",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}); err == nil || !strings.Contains(err.Error(), "resource-token ps") {
		t.Fatalf("resource token without ps/sub/presented_jti error = %v", err)
	}

	if _, err := MintAuthToken(issuerKey, AuthTokenClaims{
		Issuer:       "https://ps.example",
		DWK:          PersonDiscoveryDocument,
		Audience:     "https://resource.example",
		JTI:          "auth-token-without-person-topology",
		Agent:        "aauth:planner@ap.example",
		Confirmation: Confirmation{JWK: agentKey.PublicJWK()},
		Scope:        "documents.read",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
	}); err == nil || !strings.Contains(err.Error(), "auth-token ps") {
		t.Fatalf("person-server auth token without ps/sub error = %v", err)
	}
}

func TestVerifyAgentTokenRejectsCaseVariantClaimAlias(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 2, 19, 0, 0, 0, time.UTC)
	providerKey := internalTestSigningKey(t, "provider-key")
	agentKey := internalTestSigningKey(t, "agent-key")
	claims, err := json.Marshal(AgentTokenClaims{
		Issuer:       "https://provider.example",
		DWK:          AgentDiscoveryDocument,
		Subject:      "aauth:planner@provider.example",
		JTI:          "agent-token",
		Confirmation: Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, claimName := range map[string]string{
		"ASCII case alias":   "SUB",
		"Unicode fold alias": "ſub",
	} {
		t.Run(name, func(t *testing.T) {
			ambiguousClaims := append(
				[]byte(`{"`+claimName+`":"aauth:planner@provider.example",`),
				claims[1:]...,
			)
			compact := signRawTestToken(t, providerKey, AgentTokenType, ambiguousClaims)
			_, err := VerifyAgentToken(
				context.Background(),
				compact,
				StaticKeyResolver{
					"https://provider.example": {"provider-key": providerKey.PublicJWK()},
				},
				ClockFunc(func() time.Time { return now }),
			)
			if err == nil || !strings.Contains(err.Error(), "case-ambiguous object names") {
				t.Fatalf("case-variant agent-token claim error = %v", err)
			}
		})
	}
}
