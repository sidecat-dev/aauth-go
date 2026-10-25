package events_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestSubscribeTokenRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 20, 0, 0, 0, time.UTC)
	providerKey := eventsTestKey(t, "provider-key", 0x31)
	agentKey := eventsTestKey(t, "agent-key", 0x32)
	compact, err := events.MintSubscribeToken(
		"https://ap.example",
		providerKey,
		events.SubscribeTokenRequest{
			Agent:           "aauth:agent@ap.example",
			Resource:        "https://resource.example",
			ConfirmationKey: agentKey.PublicJWK(),
			EventID:         "event-1",
			Lifetime:        time.Hour,
			MaxUses:         3,
		},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := events.VerifySubscribeToken(
		context.Background(),
		compact,
		signaturekey.StaticKeyResolver{
			{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
		},
		aauth.ClockFunc(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "https://ap.example" || claims.DWK != aauth.AgentDiscoveryDocument ||
		claims.Subject != "aauth:agent@ap.example" || claims.Audience != "https://resource.example" ||
		claims.EventID != "event-1" || claims.IssuedAt != now.Unix() ||
		claims.ExpiresAt != now.Add(time.Hour).Unix() || claims.MaxUses != 3 ||
		!claims.Confirmation.JWK.Equal(agentKey.PublicJWK()) {
		t.Fatalf("subscribe claims = %#v", claims)
	}
}

func TestEventTokenRoundTripAndSelfJWTProjection(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 20, 0, 0, 0, time.UTC)
	resourceKey := eventsTestKey(t, "resource-key", 0x33)
	compact, err := events.MintEventToken(
		"https://resource.example",
		resourceKey,
		events.EventTokenRequest{
			Agent:    "aauth:agent@ap.example",
			EventID:  "event-1",
			Lifetime: 5 * time.Minute,
		},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	claims, err := events.VerifyEventToken(
		context.Background(), compact, resolver,
		aauth.ClockFunc(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "https://resource.example" || claims.DWK != aauth.ResourceDiscoveryDocument ||
		claims.Audience != "aauth:agent@ap.example" || claims.EventID != "event-1" || claims.JTI == "" ||
		claims.IssuedAt != now.Unix() || claims.ExpiresAt != now.Add(5*time.Minute).Unix() {
		t.Fatalf("event claims = %#v", claims)
	}

	request, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://ap.example/events",
		bytes.NewReader([]byte(`{"event_type":"slot.available"}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	credential, err := signaturekey.NewSelfJWTCredential(compact)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, resourceKey, credential, aauth.ClockFunc(func() time.Time { return now }), signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
	}); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(request, aauth.ClockFunc(func() time.Time { return now }), signaturekey.VerifyOptions{
		AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeSelfJWT},
		RequiredComponents:     []string{"content-type", "content-digest"},
		RequireExactComponents: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, assertion, err := prepared.VerifySelfJWT(context.Background(), resolver, events.EventTokenType)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := events.EventTokenFromAssertion(assertion, proof.VerifiedAt())
	if err != nil {
		t.Fatal(err)
	}
	if projected != claims {
		t.Fatalf("projected claims = %#v, want %#v", projected, claims)
	}
}

func TestEventTokenRejectsWrongDiscoveryDocumentBeforeResolutionAndCnfCaseVariants(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 20, 0, 0, 0, time.UTC)
	key := eventsTestKey(t, "event-negative-key", 0x34)
	tests := []struct {
		name   string
		claims map[string]any
	}{
		{
			name: "wrong discovery document",
			claims: map[string]any{
				"iss": "https://resource.example", "dwk": aauth.AgentDiscoveryDocument,
				"aud": "aauth:agent@ap.example", "eid": "event-1",
				"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
			},
		},
		{
			name: "case-variant confirmation",
			claims: map[string]any{
				"iss": "https://resource.example", "dwk": aauth.ResourceDiscoveryDocument,
				"aud": "aauth:agent@ap.example", "eid": "event-1",
				"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
				"CNF": map[string]any{"jwk": key.PublicJWK()},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			payload, err := json.Marshal(test.claims)
			if err != nil {
				t.Fatal(err)
			}
			compact, err := jose.SignCompact(key, jose.Header{
				Algorithm: jose.Ed25519Algorithm, Type: events.EventTokenType, KeyID: key.ID(),
			}, payload)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			_, err = events.VerifyEventToken(context.Background(), compact, eventResolverFunc(
				func(context.Context, string, string, string) (jose.JWK, error) {
					calls++
					return key.PublicJWK(), nil
				},
			), aauth.ClockFunc(func() time.Time { return now }))
			if err == nil {
				t.Fatal("VerifyEventToken accepted invalid discovery/profile input")
			}
			if calls != 0 {
				t.Fatalf("invalid token performed %d key resolutions", calls)
			}
		})
	}
}

func TestEventTokenRequiresJTI(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 20, 0, 0, 0, time.UTC)
	key := eventsTestKey(t, "event-jti-key", 0x35)
	payload, err := json.Marshal(map[string]any{
		"iss": "https://resource.example", "dwk": aauth.ResourceDiscoveryDocument,
		"aud": "aauth:agent@ap.example", "eid": "event-1",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.SignCompact(key, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: events.EventTokenType, KeyID: key.ID(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = events.VerifyEventToken(context.Background(), compact, signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
	}, aauth.ClockFunc(func() time.Time { return now }))
	if err == nil || !strings.Contains(err.Error(), "jti") {
		t.Fatalf("missing jti error = %v", err)
	}
	minted, err := events.MintEventToken("https://resource.example", key, events.EventTokenRequest{
		Agent: "aauth:agent@ap.example", EventID: "event-1", JTI: "event-token-1", Lifetime: time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := events.VerifyEventToken(context.Background(), minted, signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: key.ID()}: key.PublicJWK(),
	}, aauth.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if claims.JTI != "event-token-1" {
		t.Fatalf("jti = %q", claims.JTI)
	}
}

func eventsTestKey(t *testing.T, id string, seed byte) jose.SigningKey {
	t.Helper()
	key, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type eventResolverFunc func(context.Context, string, string, string) (jose.JWK, error)

func (resolve eventResolverFunc) ResolveKey(ctx context.Context, issuer, document, keyID string) (jose.JWK, error) {
	return resolve(ctx, issuer, document, keyID)
}
