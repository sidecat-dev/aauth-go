package aauth

import (
	"context"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestVerifiedTokenEvidenceRefusesInternalFieldSubstitution(t *testing.T) {
	now := time.Date(2026, 8, 29, 3, 0, 0, 0, time.UTC)
	issuerKey := internalTestSigningKey(t, "issuer-key")
	requestKey := internalTestSigningKey(t, "request-key")
	compact, err := MintAgentToken(
		"https://provider.example",
		issuerKey,
		AgentTokenRequest{
			Agent:        "aauth:worker@provider.example",
			PersonServer: "https://person.example",
			PublicKey:    requestKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		now,
		"sealed-evidence",
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyAgentToken(
		context.Background(),
		compact,
		signaturekey.StaticKeyResolver{
			"https://provider.example": {issuerKey.ID(): issuerKey.PublicJWK()},
		},
		ClockFunc(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}

	changedType := verified
	changedType.tokenType = AuthTokenType
	if changedType.Valid() {
		t.Fatal("token type substitution preserved evidence validity")
	}
	changedInstant := verified
	changedInstant.verifiedAt = changedInstant.verifiedAt.Add(time.Second)
	if changedInstant.Valid() {
		t.Fatal("verification instant substitution preserved evidence validity")
	}
	changedIdentity := verified
	changedIdentity.identity.digest[0] ^= 0xff
	if changedIdentity.Valid() {
		t.Fatal("evidence identity substitution preserved evidence validity")
	}
}
