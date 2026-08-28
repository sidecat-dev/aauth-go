package aauth

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestVerifyPersonTokenRejectsAuthorizationClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 15, 0, 0, 0, time.UTC)
	personServerKey := internalTestSigningKey(t, "ps-key")
	agentKey := internalTestSigningKey(t, "agent-key")
	base, err := json.Marshal(PersonTokenClaims{
		Issuer:       "https://ps.example",
		DWK:          PersonDiscoveryDocument,
		Audience:     "https://resource.example",
		Subject:      "directed-person",
		Confirmation: Confirmation{JWK: agentKey.PublicJWK()},
		JTI:          "person-token",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		`"scope":"records.read"`,
		`"account":"primary"`,
	} {
		claims := append([]byte("{"+forbidden+","), base[1:]...)
		compact := signRawTestToken(t, personServerKey, PersonTokenType, claims)
		_, err := VerifyPersonToken(
			context.Background(),
			compact,
			StaticKeyResolver{
				"https://ps.example": {"ps-key": personServerKey.PublicJWK()},
			},
			ClockFunc(func() time.Time { return now }),
		)
		if err == nil || !strings.Contains(err.Error(), "must not contain scope or account") {
			t.Fatalf("forbidden person-token claim %s error = %v", forbidden, err)
		}
	}
}
