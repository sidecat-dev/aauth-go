package aauth

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSubscribeAndEventClaimsRejectRequiredFieldMutations(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 3, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	issuerKey := internalTestSigningKey(t, "issuer-key")
	agentKey := internalTestSigningKey(t, "agent-key")
	resolver := StaticKeyResolver{
		"https://ap.example":       {issuerKey.ID(): issuerKey.PublicJWK()},
		"https://resource.example": {issuerKey.ID(): issuerKey.PublicJWK()},
	}

	maxUses := 2
	subscribe := SubscribeTokenClaims{
		Issuer:       "https://ap.example",
		DWK:          AgentDiscoveryDocument,
		Subject:      "aauth:subscriber@ap.example",
		Audience:     "https://resource.example",
		Confirmation: Confirmation{JWK: agentKey.PublicJWK()},
		EventID:      "event-1",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Minute).Unix(),
		MaxUses:      &maxUses,
	}
	compact, err := MintSubscribeToken(issuerKey, subscribe)
	if err != nil {
		t.Fatal(err)
	}
	verifiedSubscribe, err := VerifySubscribeToken(context.Background(), compact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedSubscribe.MaxUses == nil || *verifiedSubscribe.MaxUses != 2 {
		t.Fatalf("verified max_uses = %v, want 2", verifiedSubscribe.MaxUses)
	}
	withoutMaxUses := subscribe
	withoutMaxUses.MaxUses = nil
	compactWithoutMaxUses, err := MintSubscribeToken(issuerKey, withoutMaxUses)
	if err != nil {
		t.Fatal(err)
	}
	verifiedWithoutMaxUses, err := VerifySubscribeToken(
		context.Background(),
		compactWithoutMaxUses,
		resolver,
		clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedWithoutMaxUses.MaxUses != nil {
		t.Fatalf("verified absent max_uses = %v, want nil", verifiedWithoutMaxUses.MaxUses)
	}

	for _, test := range []struct {
		name   string
		typ    string
		claims map[string]any
	}{
		{name: "wrong type", typ: EventTokenType, claims: subscribeClaimsMap(subscribe)},
		{name: "absent type", typ: "", claims: subscribeClaimsMap(subscribe)},
		{name: "wrong discovery document", typ: SubscribeTokenType, claims: mutateClaim(subscribeClaimsMap(subscribe), "dwk", ResourceDiscoveryDocument)},
		{name: "absent subject", typ: SubscribeTokenType, claims: mutateClaim(subscribeClaimsMap(subscribe), "sub", nil)},
		{name: "invalid subject", typ: SubscribeTokenType, claims: mutateClaim(subscribeClaimsMap(subscribe), "sub", "subscriber")},
		{name: "absent issued time", typ: SubscribeTokenType, claims: mutateClaim(subscribeClaimsMap(subscribe), "iat", nil)},
		{name: "malformed issued time", typ: SubscribeTokenType, claims: mutateClaim(subscribeClaimsMap(subscribe), "iat", "now")},
		{name: "absent expiry", typ: SubscribeTokenType, claims: mutateClaim(subscribeClaimsMap(subscribe), "exp", nil)},
		{name: "malformed expiry", typ: SubscribeTokenType, claims: mutateClaim(subscribeClaimsMap(subscribe), "exp", "later")},
		{name: "absent audience", typ: SubscribeTokenType, claims: mutateClaim(subscribeClaimsMap(subscribe), "aud", nil)},
		{name: "invalid audience", typ: SubscribeTokenType, claims: mutateClaim(subscribeClaimsMap(subscribe), "aud", "resource")},
		{name: "absent event id", typ: SubscribeTokenType, claims: mutateClaim(subscribeClaimsMap(subscribe), "eid", nil)},
		{name: "absent confirmation", typ: SubscribeTokenType, claims: mutateClaim(subscribeClaimsMap(subscribe), "cnf", nil)},
		{name: "invalid confirmation", typ: SubscribeTokenType, claims: mutateClaim(subscribeClaimsMap(subscribe), "cnf", map[string]any{"jwk": map[string]any{"kty": "OKP"}})},
		{name: "zero max uses", typ: SubscribeTokenType, claims: mutateClaim(subscribeClaimsMap(subscribe), "max_uses", 0)},
	} {
		test := test
		t.Run("subscribe "+test.name, func(t *testing.T) {
			t.Parallel()
			mutated := mintRawToken(t, issuerKey, TokenHeader{Algorithm: "Ed25519", Type: test.typ, KeyID: issuerKey.ID()}, test.claims)
			if _, err := VerifySubscribeToken(context.Background(), mutated, resolver, clock); err == nil {
				t.Fatalf("VerifySubscribeToken accepted %s", test.name)
			}
		})
	}

	event := EventTokenClaims{
		Issuer:    "https://resource.example",
		DWK:       ResourceDiscoveryDocument,
		Audience:  "aauth:subscriber@ap.example",
		EventID:   "event-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	}
	eventCompact, err := MintEventToken(issuerKey, event)
	if err != nil {
		t.Fatal(err)
	}
	validEvent := verifiedSelfJWTFromCompact(t, eventCompact)
	if got, err := DecodeVerifiedEventToken(validEvent, clock); err != nil || got != event {
		t.Fatalf("DecodeVerifiedEventToken() = %#v, %v, want %#v", got, err, event)
	}
	forgedEvent := validEvent
	forgedEvent.seal = [32]byte{}
	if _, err := DecodeVerifiedEventToken(forgedEvent, clock); err == nil {
		t.Fatal("DecodeVerifiedEventToken accepted an unverified value")
	}

	for _, test := range []struct {
		name   string
		header TokenHeader
		claims map[string]any
	}{
		{name: "wrong type", header: TokenHeader{Algorithm: "Ed25519", Type: SubscribeTokenType, KeyID: issuerKey.ID()}, claims: eventClaimsMap(event)},
		{name: "absent type", header: TokenHeader{Algorithm: "Ed25519", KeyID: issuerKey.ID()}, claims: eventClaimsMap(event)},
		{name: "wrong discovery document", header: validEvent.Header, claims: mutateClaim(eventClaimsMap(event), "dwk", AgentDiscoveryDocument)},
		{name: "absent issued time", header: validEvent.Header, claims: mutateClaim(eventClaimsMap(event), "iat", nil)},
		{name: "malformed issued time", header: validEvent.Header, claims: mutateClaim(eventClaimsMap(event), "iat", "now")},
		{name: "absent expiry", header: validEvent.Header, claims: mutateClaim(eventClaimsMap(event), "exp", nil)},
		{name: "malformed expiry", header: validEvent.Header, claims: mutateClaim(eventClaimsMap(event), "exp", "later")},
		{name: "absent audience", header: validEvent.Header, claims: mutateClaim(eventClaimsMap(event), "aud", nil)},
		{name: "invalid audience", header: validEvent.Header, claims: mutateClaim(eventClaimsMap(event), "aud", "subscriber")},
		{name: "absent event id", header: validEvent.Header, claims: mutateClaim(eventClaimsMap(event), "eid", nil)},
		{name: "confirmation", header: validEvent.Header, claims: mutateClaim(eventClaimsMap(event), "cnf", map[string]any{"jwk": agentKey.PublicJWK()})},
		{name: "event payload", header: validEvent.Header, claims: mutateClaim(eventClaimsMap(event), "data", map[string]any{"value": true})},
	} {
		test := test
		t.Run("event "+test.name, func(t *testing.T) {
			t.Parallel()
			claims, err := json.Marshal(test.claims)
			if err != nil {
				t.Fatal(err)
			}
			verified := newVerifiedSelfJWT(
				test.header,
				stringClaim(test.claims, "iss"),
				stringClaim(test.claims, "dwk"),
				claims,
			)
			if _, err := DecodeVerifiedEventToken(verified, clock); err == nil {
				t.Fatalf("DecodeVerifiedEventToken accepted %s", test.name)
			}
		})
	}
}

func TestVerifyEventTokenIndependentlyVerifiesCompactJWS(t *testing.T) {
	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return now })
	issuerKey := internalTestSigningKey(t, "resource-events-key")
	claims := EventTokenClaims{
		Issuer: "https://resource.example", DWK: ResourceDiscoveryDocument,
		Audience: "aauth:subscriber@ap.example", EventID: "event-one",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
	compact, err := MintEventToken(issuerKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	resolver := StaticKeyResolver{
		claims.Issuer: {issuerKey.ID(): issuerKey.PublicJWK()},
	}
	verified, err := VerifyEventToken(context.Background(), compact, resolver, clock)
	if err != nil || verified != claims {
		t.Fatalf("VerifyEventToken() = %#v, %v, want %#v", verified, err, claims)
	}
	signature := strings.LastIndexByte(compact, '.') + 1
	replacement := byte('A')
	if compact[signature] == replacement {
		replacement = 'B'
	}
	corrupt := compact[:signature] + string(replacement) + compact[signature+1:]
	if _, err := VerifyEventToken(context.Background(), corrupt, resolver, clock); err == nil {
		t.Fatal("VerifyEventToken accepted a corrupt compact signature")
	}
}

func subscribeClaimsMap(claims SubscribeTokenClaims) map[string]any {
	encoded, _ := json.Marshal(claims)
	var result map[string]any
	_ = json.Unmarshal(encoded, &result)
	return result
}

func eventClaimsMap(claims EventTokenClaims) map[string]any {
	encoded, _ := json.Marshal(claims)
	var result map[string]any
	_ = json.Unmarshal(encoded, &result)
	return result
}

func mutateClaim(claims map[string]any, name string, value any) map[string]any {
	result := make(map[string]any, len(claims))
	for key, item := range claims {
		result[key] = item
	}
	if value == nil {
		delete(result, name)
	} else {
		result[name] = value
	}
	return result
}

func stringClaim(claims map[string]any, name string) string {
	value, _ := claims[name].(string)
	return value
}

func verifiedSelfJWTFromCompact(t *testing.T, compact string) VerifiedSelfJWT {
	t.Helper()
	header, payload, _, _, err := decodeToken(compact)
	if err != nil {
		t.Fatal(err)
	}
	var locator struct {
		Issuer string `json:"iss"`
		DWK    string `json:"dwk"`
	}
	if err := json.Unmarshal(payload, &locator); err != nil {
		t.Fatal(err)
	}
	return newVerifiedSelfJWT(header, locator.Issuer, locator.DWK, payload)
}
