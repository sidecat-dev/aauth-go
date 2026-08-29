package reference

import (
	"context"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestAgentRejectsSubstitutedProtectedResourceChallengeContext(t *testing.T) {
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := referenceTestSigningKey(t, "challenge-resource")
	agentKey := referenceTestSigningKey(t, "challenge-agent")
	otherAgentKey := referenceTestSigningKey(t, "challenge-other-agent")
	thumbprint, _ := agentKey.PublicJWK().Thumbprint()
	otherThumbprint, _ := otherAgentKey.PublicJWK().Thumbprint()
	person := aauth.PersonTokenClaims{
		Issuer: "https://ps.example", DWK: aauth.PersonDiscoveryDocument,
		Audience: "https://resource.example", Subject: "directed-person",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()}, JTI: "person-token",
		MissionS256: r3.S256([]byte("mission")), Tenant: "example-org",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	base := aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://as.example", JTI: "resource-token", AgentJKT: thumbprint,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Scope: "records.write",
		PersonServer: person.Issuer, Subject: person.Subject, PresentedJTI: person.JTI,
		MissionS256: person.MissionS256, Tenant: person.Tenant,
	}
	agent := &Agent{
		signingKey: agentKey,
		keyResolver: signaturekey.StaticKeyResolver{
			"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
		},
		clock: clock,
	}
	compact, err := aauth.MintResourceToken(resourceKey, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.resourceGrantFromChallenge(context.Background(), base.Issuer, person, compact); err != nil {
		t.Fatalf("valid challenge = %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*aauth.ResourceTokenClaims)
	}{
		{"proof key", func(claims *aauth.ResourceTokenClaims) { claims.AgentJKT = otherThumbprint }},
		{"person server", func(claims *aauth.ResourceTokenClaims) { claims.PersonServer = "https://other-ps.example" }},
		{"subject", func(claims *aauth.ResourceTokenClaims) { claims.Subject = "other-person" }},
		{"person token", func(claims *aauth.ResourceTokenClaims) { claims.PresentedJTI = "other-person-token" }},
		{"mission", func(claims *aauth.ResourceTokenClaims) { claims.MissionS256 = r3.S256([]byte("other-mission")) }},
		{"tenant", func(claims *aauth.ResourceTokenClaims) { claims.Tenant = "other-org" }},
		{"account", func(claims *aauth.ResourceTokenClaims) { claims.Account = "unrequested-account" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := base
			test.mutate(&claims)
			changed, mintErr := aauth.MintResourceToken(resourceKey, claims)
			if mintErr != nil {
				t.Fatal(mintErr)
			}
			if _, err := agent.resourceGrantFromChallenge(context.Background(), base.Issuer, person, changed); err == nil {
				t.Fatal("substituted challenge was accepted")
			}
		})
	}
}
