package events_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// draftEventBody is the delivery body of the Events Request example, byte for
// byte; draftEventBodySHA256 is the body_s256 its event-token example shows.
const (
	draftEventBody       = "{\n  \"event_type\": \"slot.available\",\n  \"slot_time\": \"2026-07-15T10:00:00Z\"\n}"
	draftEventBodySHA256 = "30HnqDZZZKuRXvaahsaXMeL7bBJBNUT9TrTpqvOIkH8"
)

func TestBodySHA256MatchesTheDraftExample(t *testing.T) {
	t.Parallel()

	if got := events.BodySHA256([]byte(draftEventBody)); got != draftEventBodySHA256 {
		t.Fatalf("BodySHA256(draft body) = %q, want %q", got, draftEventBodySHA256)
	}
	if got := events.BodySHA256(nil); got != "" {
		t.Fatalf("BodySHA256(no body) = %q, want empty", got)
	}
}

func TestEventTokenCarriesBodySHA256OnlyWithABody(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	key := eventsTestKey(t, "event-body-key", 0x36)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })

	withBody, err := events.MintEventToken("https://resource.example", key, events.EventTokenRequest{
		Agent: "aauth:agent@ap.example", EventID: "evt_8f3k2n9p", Payload: []byte(draftEventBody), Lifetime: 5 * time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	members := compactPayloadMembers(t, withBody)
	if string(members["body_s256"]) != `"`+draftEventBodySHA256+`"` {
		t.Fatalf("body_s256 member = %s, want %q", members["body_s256"], draftEventBodySHA256)
	}
	claims, err := events.VerifyEventToken(context.Background(), withBody, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.BodySHA256 != draftEventBodySHA256 {
		t.Fatalf("verified body_s256 = %q", claims.BodySHA256)
	}

	bodyless, err := events.MintEventToken("https://resource.example", key, events.EventTokenRequest{
		Agent: "aauth:agent@ap.example", EventID: "evt_8f3k2n9p", Lifetime: 5 * time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := compactPayloadMembers(t, bodyless)["body_s256"]; present {
		t.Fatal("a bodyless event token carries body_s256")
	}
}

func TestVerifyEventBodyBindsTheExactDeliveredBody(t *testing.T) {
	t.Parallel()

	declared := events.EventTokenClaims{BodySHA256: draftEventBodySHA256}
	tests := []struct {
		name   string
		claims events.EventTokenClaims
		body   []byte
		ok     bool
	}{
		{name: "matching body", claims: declared, body: []byte(draftEventBody), ok: true},
		{name: "altered body", claims: declared, body: []byte(strings.Replace(draftEventBody, "10:00", "11:00", 1))},
		{name: "reformatted body", claims: declared, body: []byte(`{"event_type":"slot.available","slot_time":"2026-07-15T10:00:00Z"}`)},
		{name: "declared body missing", claims: declared},
		{name: "undeclared body delivered", body: []byte(`{}`)},
		{name: "no body declared or delivered", ok: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := events.VerifyEventBody(test.claims, test.body)
			if test.ok {
				if err != nil {
					t.Fatalf("VerifyEventBody() = %v", err)
				}
				return
			}
			if !errors.Is(err, events.ErrEventBodyMismatch) {
				t.Fatalf("VerifyEventBody() = %v, want ErrEventBodyMismatch", err)
			}
		})
	}
}

func TestEventTokenRejectsMalformedBodySHA256(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 2, 10, 5, 0, 0, time.UTC)
	key := eventsTestKey(t, "event-body-shape-key", 0x37)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
	}
	for name, value := range map[string]any{
		"empty":        "",
		"padded":       draftEventBodySHA256 + "=",
		"standard b64": "30HnqDZZZKuRXvaahsaXMeL7bBJBNUT9TrTpqvOIkH8+",
		"short":        "30HnqDZZZKuRXvaahsaXMeL7bBJBNUT9TrTpqvOI",
		"not a string": 7,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			compact := signEventClaims(t, key, map[string]any{
				"iss": "https://resource.example", "dwk": aauth.ResourceDiscoveryDocument,
				"aud": "aauth:agent@ap.example", "eid": "event-1", "jti": "event-token-1",
				"body_s256": value, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
			})
			if _, err := events.VerifyEventToken(context.Background(), compact, resolver, aauth.ClockFunc(func() time.Time { return now })); err == nil {
				t.Fatalf("VerifyEventToken accepted body_s256 %v", value)
			}
			if err := events.ValidateEventTokenProfile(compact, now); err == nil {
				t.Fatalf("ValidateEventTokenProfile accepted body_s256 %v", value)
			}
		})
	}
}

func TestEventTokenNeverCarriesCnf(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 2, 10, 10, 0, 0, time.UTC)
	key := eventsTestKey(t, "event-cnf-key", 0x38)
	minted, err := events.MintEventToken("https://resource.example", key, events.EventTokenRequest{
		Agent: "aauth:agent@ap.example", EventID: "event-1", Payload: []byte(`{}`), Lifetime: time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := compactPayloadMembers(t, minted)["cnf"]; present {
		t.Fatal("MintEventToken emitted cnf")
	}
	withConfirmation := signEventClaims(t, key, map[string]any{
		"iss": "https://resource.example", "dwk": aauth.ResourceDiscoveryDocument,
		"aud": "aauth:agent@ap.example", "eid": "event-1", "jti": "event-token-1",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"cnf": map[string]any{"jwk": key.PublicJWK()},
	})
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
	}
	if _, err := events.VerifyEventToken(context.Background(), withConfirmation, resolver, aauth.ClockFunc(func() time.Time { return now })); err == nil ||
		!strings.Contains(err.Error(), "cnf") {
		t.Fatalf("VerifyEventToken with cnf = %v", err)
	}
	if err := events.ValidateEventTokenProfile(withConfirmation, now); err == nil {
		t.Fatal("ValidateEventTokenProfile accepted cnf")
	}
}

func TestEventTokenExpiryIsAValidityCheckAndIssuedAtIsNot(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 2, 10, 15, 0, 0, time.UTC)
	key := eventsTestKey(t, "event-time-key", 0x39)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	expired, err := events.MintEventToken("https://resource.example", key, events.EventTokenRequest{
		Agent: "aauth:agent@ap.example", EventID: "event-1", Lifetime: time.Minute,
	}, now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_, err = events.VerifyEventToken(context.Background(), expired, resolver, clock)
	var validation *aauth.TokenValidationError
	if !errors.As(err, &validation) || validation.Code != aauth.TokenValidationExpired {
		t.Fatalf("expired event token = %v, want TokenValidationExpired", err)
	}
	if failure := signaturekey.NormalizeError(err, signaturekey.ErrorInvalidJWT); failure.Code != signaturekey.ErrorExpiredJWT {
		t.Fatalf("expired event token code = %q", failure.Code)
	}

	issuedAhead, err := events.MintEventToken("https://resource.example", key, events.EventTokenRequest{
		Agent: "aauth:agent@ap.example", EventID: "event-1", Lifetime: time.Hour,
	}, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := events.VerifyEventToken(context.Background(), issuedAhead, resolver, clock); err != nil {
		t.Fatalf("an unexpired event token issued ahead of the verifier clock = %v", err)
	}
}

func TestSubscribeTokenCarriesAndRequiresJTI(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 2, 10, 20, 0, 0, time.UTC)
	providerKey := eventsTestKey(t, "subscribe-jti-provider", 0x3a)
	agentKey := eventsTestKey(t, "subscribe-jti-agent", 0x3b)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	generated, err := events.MintSubscribeToken("https://ap.example", providerKey, events.SubscribeTokenRequest{
		Agent: "aauth:agent@ap.example", Resource: "https://resource.example",
		ConfirmationKey: agentKey.PublicJWK(), EventID: "evt_8f3k2n9p", Lifetime: time.Hour,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := events.VerifySubscribeToken(context.Background(), generated, resolver, clock)
	if err != nil || claims.JTI == "" {
		t.Fatalf("generated subscribe-token jti = %q, %v", claims.JTI, err)
	}
	chosen, err := events.MintSubscribeToken("https://ap.example", providerKey, events.SubscribeTokenRequest{
		Agent: "aauth:agent@ap.example", Resource: "https://resource.example",
		ConfirmationKey: agentKey.PublicJWK(), EventID: "evt_8f3k2n9p", JTI: "st-7c1e22", Lifetime: time.Hour,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(compactPayloadMembers(t, chosen)["jti"]) != `"st-7c1e22"` {
		t.Fatalf("subscribe-token jti member = %s", compactPayloadMembers(t, chosen)["jti"])
	}

	payload, err := json.Marshal(map[string]any{
		"iss": "https://ap.example", "dwk": aauth.AgentDiscoveryDocument,
		"sub": "aauth:agent@ap.example", "aud": "https://resource.example",
		"cnf": map[string]any{"jwk": agentKey.PublicJWK()}, "eid": "evt_8f3k2n9p",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	withoutJTI, err := jose.SignCompact(providerKey, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: events.SubscribeTokenType, KeyID: providerKey.ID(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := events.VerifySubscribeToken(context.Background(), withoutJTI, resolver, clock); err == nil ||
		!strings.Contains(err.Error(), "jti") {
		t.Fatalf("subscribe token without jti = %v", err)
	}
}

func signEventClaims(t *testing.T, key jose.SigningKey, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.SignCompact(key, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: events.EventTokenType, KeyID: key.ID(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func compactPayloadMembers(t *testing.T, compact string) map[string]json.RawMessage {
	t.Helper()
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(parsed.Payload(), &members); err != nil {
		t.Fatal(err)
	}
	return members
}
