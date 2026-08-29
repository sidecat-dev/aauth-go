package budgets_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestBudgetValuesNarrowWithoutChangingDenomination(t *testing.T) {
	offer, err := budgets.ParseBudget([]byte(`{"amount":5000000,"unit":"USD","decimals":6}`))
	if err != nil || offer.Amount != 5_000_000 || offer.Unit != "USD" || offer.Decimals != 6 {
		t.Fatalf("offer = %#v, %v", offer, err)
	}
	grant, err := budgets.Narrow(offer, 2_000_000)
	if err != nil || grant.Amount != 2_000_000 || grant.Unit != offer.Unit || grant.Decimals != offer.Decimals {
		t.Fatalf("grant = %#v, %v", grant, err)
	}
	if _, err := budgets.Narrow(offer, offer.Amount+1); err == nil {
		t.Fatal("budget widened")
	}
	for _, exact := range [][]byte{
		[]byte(`{"amount":-1,"unit":"USD","decimals":6}`),
		[]byte(`{"amount":1000000000000000,"unit":"USD","decimals":6}`),
		[]byte(`{"amount":1.5,"unit":"USD","decimals":6}`),
		[]byte(`{"amount":1,"unit":"","decimals":6}`),
		[]byte(`{"amount":1,"unit":"USD","decimals":-1}`),
		[]byte(`{"amount":1,"unit":"USD","decimals":6,"other":true}`),
		[]byte(`{"amount":1,"Amount":2,"unit":"USD","decimals":6}`),
	} {
		if _, err := budgets.ParseBudget(exact); err == nil {
			t.Fatalf("invalid budget accepted: %s", exact)
		}
	}
}

func TestBudgetCompanionBindsNarrowedTokenEvidence(t *testing.T) {
	now := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	resourceKey := budgetSigningKey(t, "resource", 0x51)
	accessKey := budgetSigningKey(t, "access", 0x52)
	agentKey := budgetSigningKey(t, "agent", 0x53)
	thumbprint, _ := agentKey.PublicJWK().Thumbprint()
	offer := budgets.Budget{Amount: 5_000_000, Unit: "USD", Decimals: 6}
	resourceDraft, err := aauth.NewResourceTokenDraft(aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://as.example", JTI: "resource-budget", AgentJKT: thumbprint,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Scope: "inference.completions",
		PersonServer: "https://ps.example", Subject: "directed-person", PresentedJTI: "person-token-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceDraft, err = budgets.BindResourceToken(resourceDraft, offer, []budgets.Consumption{
		{JTI: "auth-prior", Consumed: 750_000},
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceCompact, err := resourceDraft.Mint(resourceKey)
	if err != nil {
		t.Fatal(err)
	}
	resourceCore, err := aauth.VerifyResourceToken(context.Background(), resourceCompact,
		signaturekey.StaticKeyResolver{"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()}},
		aauth.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	resourceBudget, err := budgets.ValidateResourceToken(resourceCore)
	if err != nil || !resourceBudget.Valid() {
		t.Fatalf("resource budget = %#v, %v", resourceBudget, err)
	}

	grant, _ := budgets.Narrow(offer, 2_000_000)
	authDraft, err := aauth.NewAuthTokenDraft(aauth.AuthTokenClaims{
		Issuer: "https://as.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-budget",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		Subject: "directed-person", Scope: "inference.completions", PersonServer: "https://ps.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	authDraft, err = budgets.BindAuthToken(authDraft, grant)
	if err != nil {
		t.Fatal(err)
	}
	authCompact, err := authDraft.Mint(accessKey)
	if err != nil {
		t.Fatal(err)
	}
	authCore, err := aauth.VerifyAuthToken(context.Background(), authCompact,
		signaturekey.StaticKeyResolver{"https://as.example": {accessKey.ID(): accessKey.PublicJWK()}},
		aauth.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	authBudget, err := budgets.ValidateAuthToken(authCore)
	if err != nil || budgets.ValidateGrant(resourceBudget, authBudget) != nil {
		t.Fatalf("auth budget = %#v, %v", authBudget, err)
	}
	projected, err := authBudget.Budget()
	if err != nil || projected != grant {
		t.Fatalf("projected grant = %#v, %v", projected, err)
	}
	consumption, err := resourceBudget.Consumption()
	if err != nil || len(consumption) != 1 || consumption[0].Consumed != 750_000 {
		t.Fatalf("consumption = %#v, %v", consumption, err)
	}
	consumption[0].JTI = "changed"
	again, _ := resourceBudget.Consumption()
	if again[0].JTI != "auth-prior" {
		t.Fatal("consumption projection aliases sealed evidence")
	}

	wider := budgets.Budget{Amount: offer.Amount + 1, Unit: offer.Unit, Decimals: offer.Decimals}
	widerDraft, _ := aauth.NewAuthTokenDraft(aauth.AuthTokenClaims{
		Issuer: "https://as.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-wider",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		Subject: "directed-person", Scope: "inference.completions", PersonServer: "https://ps.example",
	})
	widerDraft, _ = budgets.BindAuthToken(widerDraft, wider)
	widerCompact, _ := widerDraft.Mint(accessKey)
	widerCore, _ := aauth.VerifyAuthToken(context.Background(), widerCompact,
		signaturekey.StaticKeyResolver{"https://as.example": {accessKey.ID(): accessKey.PublicJWK()}},
		aauth.ClockFunc(func() time.Time { return now }))
	widerResult, _ := budgets.ValidateAuthToken(widerCore)
	if err := budgets.ValidateGrant(resourceBudget, widerResult); err == nil {
		t.Fatal("auth token widened the resource budget")
	}
}

func TestBudgetHeaderRoundTripsCurrentResponseSemantics(t *testing.T) {
	cost := int64(221_200)
	header := budgets.Header{
		Remaining: 1_568_800, Cost: &cost,
		Unit: "USD", Decimals: budgets.OptionalInteger(6),
	}
	exact, err := budgets.FormatHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := budgets.ParseHeader([]string{exact + `, future=7`})
	if err != nil || parsed.Remaining != header.Remaining || parsed.Cost == nil || *parsed.Cost != cost || parsed.Unit != "USD" || parsed.Decimals == nil || *parsed.Decimals != 6 {
		t.Fatalf("parsed = %#v, %v from %q", parsed, err, exact)
	}
	reserved := int64(400_000)
	if _, err := budgets.FormatHeader(budgets.Header{Remaining: 1, Cost: &cost, Reserved: &reserved}); err == nil {
		t.Fatal("header carried both cost and reserved")
	}
	if _, err := budgets.ParseHeader([]string{`remaining=1, unit="USD"`}); err == nil {
		t.Fatal("header carried unit without decimals")
	}
	if _, err := budgets.ParseHeader([]string{`remaining=-1`}); err == nil {
		t.Fatal("header carried negative remaining")
	}
	if _, err := budgets.ParseHeader([]string{`cost=1`}); err == nil {
		t.Fatal("header omitted remaining")
	}
}

func budgetSigningKey(t *testing.T, id string, fill byte) jose.SigningKey {
	t.Helper()
	key, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}
