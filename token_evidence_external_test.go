package aauth_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type tokenEvidenceClock struct {
	now   time.Time
	calls int
}

func (clock *tokenEvidenceClock) Now() time.Time {
	clock.calls++
	return clock.now.Add(time.Duration(clock.calls-1) * time.Second)
}

func TestAgentTokenVerificationReturnsSealedExactEvidence(t *testing.T) {
	now := time.Date(2026, 8, 29, 1, 0, 0, 0, time.UTC)
	issuerKey := tokenEvidenceSigningKey(t, "issuer-key", 0x61)
	agentKey := tokenEvidenceSigningKey(t, "agent-key", 0x62)
	compact, err := aauth.MintAgentToken(
		"https://provider.example",
		issuerKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:worker@provider.example",
			PersonServer: "https://person.example",
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		now,
		"agent-token-evidence",
	)
	if err != nil {
		t.Fatal(err)
	}
	clock := &tokenEvidenceClock{now: now}
	verified, err := aauth.VerifyAgentToken(
		context.Background(),
		compact,
		signaturekey.StaticKeyResolver{
			"https://provider.example": {issuerKey.ID(): issuerKey.PublicJWK()},
		},
		clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	if clock.calls != 1 {
		t.Fatalf("verification clock calls = %d, want exactly 1", clock.calls)
	}
	if !verified.Valid() {
		t.Fatal("verified token evidence is invalid")
	}
	if got, err := verified.Type(); err != nil || got != aauth.AgentTokenType {
		t.Fatalf("type = %q, %v", got, err)
	}
	if got, err := verified.Compact(); err != nil || got != compact {
		t.Fatalf("compact = %q, %v", got, err)
	}
	if got, err := verified.VerificationKey(); err != nil || !got.Equal(issuerKey.PublicJWK()) {
		t.Fatalf("verification key = %#v, %v", got, err)
	}
	if got, err := verified.VerifiedAt(); err != nil || !got.Equal(now) {
		t.Fatalf("verified at = %s, %v", got, err)
	}
	id, err := verified.EvidenceID()
	if err != nil || id.String() == "" {
		t.Fatalf("evidence id = %q, %v", id, err)
	}
	repeated, err := aauth.VerifyAgentToken(
		context.Background(),
		compact,
		signaturekey.StaticKeyResolver{
			"https://provider.example": {issuerKey.ID(): issuerKey.PublicJWK()},
		},
		&tokenEvidenceClock{now: now},
	)
	if err != nil {
		t.Fatal(err)
	}
	repeatedID, err := repeated.EvidenceID()
	if err != nil || repeatedID != id {
		t.Fatalf("same verification identity = %q, want %q, error = %v", repeatedID, id, err)
	}
	later, err := aauth.VerifyAgentToken(
		context.Background(),
		compact,
		signaturekey.StaticKeyResolver{
			"https://provider.example": {issuerKey.ID(): issuerKey.PublicJWK()},
		},
		&tokenEvidenceClock{now: now.Add(time.Second)},
	)
	if err != nil {
		t.Fatal(err)
	}
	laterID, err := later.EvidenceID()
	if err != nil || laterID == id {
		t.Fatalf("different verification instant identity = %q, original %q, error = %v", laterID, id, err)
	}
	claims, err := verified.Claims()
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "aauth:worker@provider.example" || claims.JTI != "agent-token-evidence" {
		t.Fatalf("claims = %#v", claims)
	}

	claims.Subject = "aauth:mutated@provider.example"
	claims.Confirmation.JWK.X = "mutated"
	again, err := verified.Claims()
	if err != nil {
		t.Fatal(err)
	}
	if again.Subject != "aauth:worker@provider.example" || !again.Confirmation.JWK.Equal(agentKey.PublicJWK()) {
		t.Fatalf("claims accessor aliases evidence: %#v", again)
	}
}

func TestVerifiedTokenZeroValueIsInvalid(t *testing.T) {
	var verified aauth.VerifiedToken[aauth.AgentTokenClaims]
	if verified.Valid() {
		t.Fatal("zero verified token is valid")
	}
	if _, err := verified.Claims(); err == nil {
		t.Fatal("zero verified token returned claims")
	}
	if _, err := verified.EvidenceID(); err == nil {
		t.Fatal("zero verified token returned an evidence id")
	}
}

func TestEveryCurrentCoreTokenProfileReturnsExactEvidence(t *testing.T) {
	now := time.Date(2026, 8, 29, 2, 0, 0, 0, time.UTC)
	agentProviderKey := tokenEvidenceSigningKey(t, "agent-provider-key", 0x63)
	personServerKey := tokenEvidenceSigningKey(t, "person-server-key", 0x64)
	resourceKey := tokenEvidenceSigningKey(t, "resource-key", 0x65)
	requestKey := tokenEvidenceSigningKey(t, "request-key", 0x66)
	resolver := signaturekey.StaticKeyResolver{
		"https://provider.example": {agentProviderKey.ID(): agentProviderKey.PublicJWK()},
		"https://person.example":   {personServerKey.ID(): personServerKey.PublicJWK()},
		"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
	}

	agentCompact, err := aauth.MintAgentToken(
		"https://provider.example",
		agentProviderKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:worker@provider.example",
			PersonServer: "https://person.example",
			PublicKey:    requestKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		now,
		"agent-evidence-all-profiles",
	)
	if err != nil {
		t.Fatal(err)
	}
	agentEvidence, err := aauth.VerifyAgentToken(context.Background(), agentCompact, resolver, &tokenEvidenceClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	assertExactTokenEvidence(t, agentEvidence, agentCompact, aauth.AgentTokenType, agentProviderKey.PublicJWK(), now)

	personCompact, err := aauth.MintPersonToken(personServerKey, aauth.PersonTokenClaims{
		Issuer:       "https://person.example",
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     "https://resource.example",
		Subject:      "directed-person",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		JTI:          "person-evidence-all-profiles",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	personEvidence, err := aauth.VerifyPersonToken(context.Background(), personCompact, resolver, &tokenEvidenceClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	assertExactTokenEvidence(t, personEvidence, personCompact, aauth.PersonTokenType, personServerKey.PublicJWK(), now)

	requestThumbprint, err := requestKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resourceCompact, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer:       "https://resource.example",
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     "https://person.example",
		JTI:          "resource-evidence-all-profiles",
		AgentJKT:     requestThumbprint,
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Scope:        "documents.read",
		PersonServer: "https://person.example",
		Subject:      "directed-person",
		PresentedJTI: "person-evidence-all-profiles",
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceEvidence, err := aauth.VerifyResourceToken(context.Background(), resourceCompact, resolver, &tokenEvidenceClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	assertExactTokenEvidence(t, resourceEvidence, resourceCompact, aauth.ResourceTokenType, resourceKey.PublicJWK(), now)

	authCompact, err := aauth.MintAuthToken(personServerKey, aauth.AuthTokenClaims{
		Issuer:       "https://person.example",
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     "https://resource.example",
		JTI:          "auth-evidence-all-profiles",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Subject:      "directed-person",
		Scope:        "documents.read",
		PersonServer: "https://person.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	authEvidence, err := aauth.VerifyAuthToken(context.Background(), authCompact, resolver, &tokenEvidenceClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	assertExactTokenEvidence(t, authEvidence, authCompact, aauth.AuthTokenType, personServerKey.PublicJWK(), now)
}

func assertExactTokenEvidence[T aauth.TokenClaims](
	t *testing.T,
	evidence aauth.VerifiedToken[T],
	compact string,
	tokenType string,
	key jose.JWK,
	verifiedAt time.Time,
) {
	t.Helper()
	if !evidence.Valid() {
		t.Fatal("evidence is invalid")
	}
	if got, err := evidence.Type(); err != nil || got != tokenType {
		t.Fatalf("type = %q, %v", got, err)
	}
	if got, err := evidence.Compact(); err != nil || got != compact {
		t.Fatalf("compact = %q, %v", got, err)
	}
	if got, err := evidence.VerificationKey(); err != nil || !got.Equal(key) {
		t.Fatalf("verification key = %#v, %v", got, err)
	}
	if got, err := evidence.VerifiedAt(); err != nil || !got.Equal(verifiedAt) {
		t.Fatalf("verified at = %s, %v", got, err)
	}
	if identity, err := evidence.EvidenceID(); err != nil || identity.String() == "" {
		t.Fatalf("evidence id = %q, %v", identity, err)
	}
	if _, err := evidence.Claims(); err != nil {
		t.Fatal(err)
	}
}

func tokenEvidenceSigningKey(t *testing.T, keyID string, seed byte) jose.SigningKey {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	key, err := jose.NewEd25519SigningKey(keyID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
