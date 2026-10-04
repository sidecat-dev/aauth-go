package budgets

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestConsumptionRecordRoundTripsStrictJSON(t *testing.T) {
	t.Parallel()

	record, err := NewConsumptionRecord("auth-token-1", 431_200)
	if err != nil {
		t.Fatal(err)
	}
	if record.JTI() != "auth-token-1" || record.Consumed() != 431_200 {
		t.Fatalf("record = %q/%d", record.JTI(), record.Consumed())
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"jti":"auth-token-1","consumed":431200}` {
		t.Fatalf("encoded record = %s", encoded)
	}
	var parsed ConsumptionRecord
	if err := json.Unmarshal(encoded, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.JTI() != record.JTI() || parsed.Consumed() != record.Consumed() {
		t.Fatalf("parsed record = %q/%d", parsed.JTI(), parsed.Consumed())
	}

	for _, raw := range []string{
		`null`, `{}`, `{"jti":"x"}`, `{"consumed":1}`, `{"jti":"","consumed":1}`,
		`{"jti":"x","consumed":-1}`, `{"jti":"x","consumed":1.5}`,
		`{"jti":"x","consumed":1,"future":true}`,
		`{"JTI":"x","consumed":1}`, `{"jti":"x","jti":"y","consumed":1}`,
	} {
		var invalid ConsumptionRecord
		if err := json.Unmarshal([]byte(raw), &invalid); err == nil {
			t.Fatalf("accepted consumption record %s", raw)
		}
	}
	if _, err := NewConsumptionRecord("", 1); err == nil {
		t.Fatal("accepted empty consumption-record jti")
	}
	if _, err := NewConsumptionRecord("x", -1); err == nil {
		t.Fatal("accepted negative consumption")
	}
}

func TestBudgetResourceTokenCompanionRoundTripsAndConsumesItsClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	resourceKey := budgetTestKey(t, "resource-key", 1)
	offer := budgetTestValue(t, 5_000_000, "USD", 6)
	record, _ := NewConsumptionRecord("auth-token-1", 2_000_000)
	future := json.RawMessage(`{"retained":true}`)
	claims := budgetResourceClaims(now)
	claims.AdditionalClaims = map[string]json.RawMessage{"future": future}
	if _, err := MintResourceToken(resourceKey, claims, offer, &record); err == nil {
		t.Fatal("minted a consumption record for a token other than the presented one")
	}
	claims.PresentedJTI = "auth-token-1"

	compact, err := MintResourceToken(resourceKey, claims, offer, &record)
	if err != nil {
		t.Fatal(err)
	}
	future[2] = 'X'
	claims.AdditionalClaims["future"] = json.RawMessage(`null`)

	resolver := signaturekey.StaticKeyResolver{
		{Issuer: claims.Issuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	verified, gotOffer, consumed, err := VerifyResourceToken(context.Background(), compact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if verified.JTI != claims.JTI || gotOffer.Amount() != offer.Amount() || !gotOffer.Unit().Equal(offer.Unit()) {
		t.Fatalf("verified Resource token = %#v, %#v", verified, gotOffer)
	}
	if consumed == nil || consumed.JTI() != record.JTI() || consumed.Consumed() != record.Consumed() {
		t.Fatalf("consumed = %#v", consumed)
	}
	if _, present := verified.AdditionalClaims["budget"]; present {
		t.Fatal("verified Resource claims retained consumed budget claim")
	}
	if _, present := verified.AdditionalClaims["budget_consumed"]; present {
		t.Fatal("verified Resource claims retained consumed budget_consumed claim")
	}
	if got := string(verified.AdditionalClaims["future"]); got != `{"retained":true}` {
		t.Fatalf("unrelated additional claim = %s", got)
	}
	if _, err := aauth.VerifyResourceToken(context.Background(), compact, resolver, clock); err == nil {
		t.Fatal("ordinary Core verifier accepted a Budget Resource token")
	}
}

func TestBudgetAuthTokenCompanionRoundTripsAndConsumesItsClaim(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	personKey := budgetTestKey(t, "person-key", 2)
	requestKey := budgetTestKey(t, "request-key", 3)
	grant := budgetTestValue(t, 2_000_000, "USD", 6)
	claims := budgetAuthClaims(now, requestKey.PublicJWK())
	claims.AdditionalClaims = map[string]json.RawMessage{"future": json.RawMessage(`true`)}

	compact, err := MintAuthToken(personKey, claims, grant)
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: claims.Issuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	verified, gotGrant, err := VerifyAuthToken(context.Background(), compact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if verified.JTI != claims.JTI || gotGrant.Amount() != grant.Amount() || !gotGrant.Unit().Equal(grant.Unit()) {
		t.Fatalf("verified Auth token = %#v, %#v", verified, gotGrant)
	}
	if _, present := verified.AdditionalClaims["budget"]; present {
		t.Fatal("verified Auth claims retained consumed budget claim")
	}
	if got := string(verified.AdditionalClaims["future"]); got != `true` {
		t.Fatalf("unrelated additional claim = %s", got)
	}
	if _, err := aauth.VerifyAuthToken(context.Background(), compact, resolver, clock); err == nil {
		t.Fatal("ordinary Core verifier accepted a Budget Auth token")
	}
}

func TestBudgetTokenVerificationRejectsMalformedPartialAndMixedCompanions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	resourceKey := budgetTestKey(t, "resource-key", 4)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	valid := `{"amount":1,"unit":"USD","decimals":6}`

	for _, test := range []struct {
		name       string
		additional map[string]json.RawMessage
	}{
		{name: "missing budget"},
		{name: "null budget", additional: rawClaims("budget", `null`)},
		{name: "partial budget", additional: rawClaims("budget", `{"amount":1,"unit":"USD"}`)},
		{name: "unknown budget member", additional: rawClaims("budget", `{"amount":1,"unit":"USD","decimals":6,"future":true}`)},
		{name: "nested case variant", additional: rawClaims("budget", `{"Amount":1,"unit":"USD","decimals":6}`)},
		{name: "case variant budget claim", additional: rawClaims("Budget", valid)},
		{name: "consumption without budget", additional: rawClaims("budget_consumed", `{"jti":"person-token-1","consumed":1}`)},
		{name: "case variant consumption", additional: mergeRawClaims(rawClaims("budget", valid), rawClaims("Budget_Consumed", `{"jti":"person-token-1","consumed":1}`))},
		{name: "null consumption", additional: mergeRawClaims(rawClaims("budget", valid), rawClaims("budget_consumed", `null`))},
		{name: "malformed consumption", additional: mergeRawClaims(rawClaims("budget", valid), rawClaims("budget_consumed", `{"jti":"person-token-1"}`))},
		{name: "consumption array", additional: mergeRawClaims(rawClaims("budget", valid), rawClaims("budget_consumed", `[{"jti":"person-token-1","consumed":1}]`))},
		{name: "consumption for another token", additional: mergeRawClaims(rawClaims("budget", valid), rawClaims("budget_consumed", `{"jti":"auth-token-0","consumed":1}`))},
		{name: "mixed R3 reference", additional: mergeRawClaims(rawClaims("budget", valid), rawClaims("r3_uri", `"https://resource.example/r3/x"`))},
		{name: "mixed R3 case variant", additional: mergeRawClaims(rawClaims("budget", valid), rawClaims("R3_Granted", `{}`))},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			compact := signBudgetResourcePayload(t, resourceKey, now, test.additional)
			if _, _, _, err := VerifyResourceToken(context.Background(), compact, resolver, clock); err == nil {
				t.Fatal("strict Budget Resource verifier accepted invalid companion claims")
			}
		})
	}
}

func TestBudgetAuthTokenRejectsConsumptionAndMixedR3Claims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	personKey := budgetTestKey(t, "person-key", 5)
	requestKey := budgetTestKey(t, "request-key", 6)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://person.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	valid := `{"amount":1,"unit":"USD","decimals":6}`

	for _, additional := range []map[string]json.RawMessage{
		mergeRawClaims(rawClaims("budget", valid), rawClaims("budget_consumed", `{"jti":"auth-token-0","consumed":1}`)),
		mergeRawClaims(rawClaims("budget", valid), rawClaims("Budget_Consumed", `{"jti":"auth-token-0","consumed":1}`)),
		mergeRawClaims(rawClaims("budget", valid), rawClaims("r3_granted", `{}`)),
		rawClaims("Budget", valid),
	} {
		claims := budgetAuthClaims(now, requestKey.PublicJWK())
		claims.AdditionalClaims = additional
		compact, err := aauth.MintAuthTokenCore(personKey, claims)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifyAuthToken(context.Background(), compact, resolver, clock); err == nil {
			t.Fatal("strict Budget Auth verifier accepted invalid companion claims")
		}
	}
}

func TestBudgetMintRejectsCallerSuppliedTypedAndMixedClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	resourceKey := budgetTestKey(t, "resource-key", 7)
	personKey := budgetTestKey(t, "person-key", 8)
	requestKey := budgetTestKey(t, "request-key", 9)
	value := budgetTestValue(t, 1, "USD", 6)

	for _, name := range []string{"budget", "Budget", "budget_consumed", "R3_URI"} {
		claims := budgetResourceClaims(now)
		claims.AdditionalClaims = rawClaims(name, `null`)
		if compact, err := MintResourceToken(resourceKey, claims, value, nil); err == nil {
			t.Fatalf("Resource mint accepted %q collision: %s", name, compact)
		}
	}
	for _, name := range []string{"budget", "Budget", "budget_consumed", "r3_granted"} {
		claims := budgetAuthClaims(now, requestKey.PublicJWK())
		claims.AdditionalClaims = rawClaims(name, `null`)
		if compact, err := MintAuthToken(personKey, claims, value); err == nil {
			t.Fatalf("Auth mint accepted %q collision: %s", name, compact)
		}
	}
}

func TestBudgetTokensRequireIndependentCoreScope(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	resourceKey := budgetTestKey(t, "scope-resource", 31)
	personKey := budgetTestKey(t, "scope-person", 32)
	requestKey := budgetTestKey(t, "scope-request", 33)
	value := budgetTestValue(t, 1, "USD", 6)
	resourceClaims := budgetResourceClaims(now)
	resourceClaims.Scope = ""
	if compact, err := MintResourceToken(resourceKey, resourceClaims, value, nil); err == nil {
		t.Fatalf("scope-less Budget Resource token minted: %s", compact)
	}
	authClaims := budgetAuthClaims(now, requestKey.PublicJWK())
	authClaims.Scope = ""
	if compact, err := MintAuthToken(personKey, authClaims, value); err == nil {
		t.Fatalf("scope-less Budget Auth token minted: %s", compact)
	}

	resourceClaims.AdditionalClaims = rawClaims("budget", `{"amount":1,"unit":"USD","decimals":6}`)
	resourceCompact, err := aauth.MintResourceTokenCore(resourceKey, resourceClaims)
	if err != nil {
		t.Fatal(err)
	}
	authClaims.AdditionalClaims = rawClaims("budget", `{"amount":1,"unit":"USD","decimals":6}`)
	authCompact, err := aauth.MintAuthTokenCore(personKey, authClaims)
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: resourceClaims.Issuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: authClaims.Issuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:         personKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	if _, _, _, err := VerifyResourceToken(context.Background(), resourceCompact, resolver, clock); err == nil {
		t.Fatal("scope-less Budget Resource token verified")
	}
	if _, _, err := VerifyAuthToken(context.Background(), authCompact, resolver, clock); err == nil {
		t.Fatal("scope-less Budget Auth token verified")
	}
}

func TestTokenCarriesClaimsRoutesEveryBudgetSpellingToTheStrictVerifier(t *testing.T) {
	t.Parallel()

	compact := func(payload string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte("signature"))
	}
	for _, test := range []struct {
		name    string
		compact string
		want    bool
		wantErr bool
	}{
		{name: "Core", compact: compact(`{"iss":"https://issuer.example"}`)},
		{name: "budget", compact: compact(`{"budget":{}}`), want: true},
		{name: "case variant", compact: compact(`{"Budget":null}`), want: true},
		{name: "consumption only", compact: compact(`{"BUDGET_CONSUMED":[]}`), want: true},
		{name: "malformed compact", compact: "not-a-token", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := TokenCarriesClaims(test.compact)
			if got != test.want || (err != nil) != test.wantErr {
				t.Fatalf("TokenCarriesClaims() = %t, %v", got, err)
			}
		})
	}
}

func TestBudgetVerificationPreservesIndependentImmutableResults(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	resourceKey := budgetTestKey(t, "resource-key", 10)
	offer := budgetTestValue(t, 100, "calls", 0)
	record, _ := NewConsumptionRecord("person-token-1", 20)
	compact, err := MintResourceToken(resourceKey, budgetResourceClaims(now), offer, &record)
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	firstClaims, _, firstRecord, err := VerifyResourceToken(context.Background(), compact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	firstClaims.AdditionalClaims = map[string]json.RawMessage{"changed": json.RawMessage(`true`)}
	*firstRecord = ConsumptionRecord{}
	secondClaims, _, secondRecord, err := VerifyResourceToken(context.Background(), compact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed := secondClaims.AdditionalClaims["changed"]; changed || secondRecord == nil || secondRecord.JTI() != "person-token-1" {
		t.Fatalf("second verification inherited mutations: %#v, %#v", secondClaims, secondRecord)
	}
}

func budgetResourceClaims(now time.Time) aauth.ResourceTokenClaims {
	return aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://person.example", JTI: "resource-token-1",
		PersonServer: "https://person.example", Subject: "person-1", PresentedJTI: "person-token-1",
		AgentJKT: budgetS256("agent-key"), Scope: "inference.completions",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
}

func budgetAuthClaims(now time.Time, requestKey jose.JWK) aauth.AuthTokenClaims {
	return aauth.AuthTokenClaims{
		Issuer: "https://person.example", DWK: aauth.PersonDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-token-1",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey}, Scope: "inference.completions",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
}

func budgetTestValue(t *testing.T, amount int64, name string, decimals int64) Value {
	t.Helper()
	unit, err := NewUnit(name, decimals)
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewValue(amount, unit)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func budgetTestKey(t *testing.T, id string, seed byte) jose.SigningKey {
	t.Helper()
	key, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func budgetS256(value string) string {
	digest := sha256Sum([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func sha256Sum(value []byte) [32]byte {
	// Kept local so token fixtures expose no production helper.
	return sha256.Sum256(value)
}

func rawClaims(name, value string) map[string]json.RawMessage {
	return map[string]json.RawMessage{name: json.RawMessage(value)}
}

func mergeRawClaims(left, right map[string]json.RawMessage) map[string]json.RawMessage {
	merged := make(map[string]json.RawMessage, len(left)+len(right))
	for name, value := range left {
		merged[name] = value
	}
	for name, value := range right {
		merged[name] = value
	}
	return merged
}

func signBudgetResourcePayload(t *testing.T, key jose.SigningKey, now time.Time, additional map[string]json.RawMessage) string {
	t.Helper()
	claims := budgetResourceClaims(now)
	members := map[string]any{
		"iss": claims.Issuer, "dwk": claims.DWK, "aud": claims.Audience,
		"jti": claims.JTI, "ps": claims.PersonServer, "sub": claims.Subject,
		"presented_jti": claims.PresentedJTI, "agent_jkt": claims.AgentJKT,
		"scope": claims.Scope, "iat": claims.IssuedAt, "exp": claims.ExpiresAt,
	}
	for name, value := range additional {
		members[name] = value
	}
	payload, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.SignCompact(key, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: aauth.ResourceTokenType, KeyID: key.ID(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}
