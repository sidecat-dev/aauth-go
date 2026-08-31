package signaturekey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestSelfJWTRequestUsesOneDiscoveredKeyForTokenAndHTTPProof(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 19, 0, 0, 0, time.UTC)
	issuer := "https://resource.example"
	key := testDiscoverySigningKey(t, "event-key", 0x71)
	compact := signTestSelfJWT(t, key, "aa-event+jwt", map[string]any{
		"iss": issuer,
		"dwk": "aauth-resource.json",
		"aud": "aauth:agent@ap.example",
		"eid": "event-1",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	})
	request, err := http.NewRequest(
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
	if err := signaturekey.SignRequest(request, key, credential, fixedClock(now), signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
	}); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(request, fixedClock(now), signaturekey.VerifyOptions{
		AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeSelfJWT},
		RequiredComponents:     []string{"content-type", "content-digest"},
		RequireExactComponents: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: issuer, DiscoveryDocument: "aauth-resource.json", KeyID: key.ID()}: key.PublicJWK(),
	}
	proof, assertion, err := prepared.VerifySelfJWT(context.Background(), resolver, "aa-event+jwt")
	if err != nil {
		t.Fatal(err)
	}
	if proof.Scheme() != signaturekey.SchemeSelfJWT || proof.Signer() != issuer ||
		!proof.PublicKey().Equal(key.PublicJWK()) || proof.ReplayKey() == "" {
		t.Fatalf("verified proof = scheme:%q signer:%q key:%#v replay:%q",
			proof.Scheme(), proof.Signer(), proof.PublicKey(), proof.ReplayKey())
	}
	if assertion.Issuer() != issuer || assertion.DiscoveryDocument() != "aauth-resource.json" ||
		!assertion.ExpiresAt().Equal(now.Add(5*time.Minute)) || assertion.Compact() != compact {
		t.Fatalf("verified self-jwt = issuer:%q dwk:%q expires:%s compact:%q",
			assertion.Issuer(), assertion.DiscoveryDocument(), assertion.ExpiresAt(), assertion.Compact())
	}
	payload := assertion.Payload()
	payload[0] = 'x'
	if bytes.Equal(payload, assertion.Payload()) {
		t.Fatal("verified self-jwt payload aliases internal state")
	}
	gotCompact, ok := credential.SelfJWT()
	if !ok || gotCompact != compact {
		t.Fatalf("SelfJWT() = %q, %t", gotCompact, ok)
	}
}

func TestSelfJWTRejectsInvalidProfileBeforeHTTPProofAcceptance(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 19, 0, 0, 0, time.UTC)
	issuer := "https://resource.example"
	key := testDiscoverySigningKey(t, "event-profile-key", 0x72)
	tests := []struct {
		name     string
		typeName string
		claims   map[string]any
		want     signaturekey.ErrorCode
	}{
		{
			name:     "confirmation claim",
			typeName: "aa-event+jwt",
			claims: map[string]any{
				"iss": issuer, "dwk": "aauth-resource.json", "exp": now.Add(time.Minute).Unix(),
				"cnf": map[string]any{"jwk": key.PublicJWK()},
			},
			want: signaturekey.ErrorInvalidJWT,
		},
		{
			name:     "expired",
			typeName: "aa-event+jwt",
			claims: map[string]any{
				"iss": issuer, "dwk": "aauth-resource.json", "exp": now.Add(-time.Second).Unix(),
			},
			want: signaturekey.ErrorExpiredJWT,
		},
		{
			name:     "wrong explicit type",
			typeName: "aa-other+jwt",
			claims: map[string]any{
				"iss": issuer, "dwk": "aauth-resource.json", "exp": now.Add(time.Minute).Unix(),
			},
			want: signaturekey.ErrorInvalidJWT,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			compact := signTestSelfJWT(t, key, test.typeName, test.claims)
			prepared := prepareTestSelfJWTRequest(t, key, compact, now)
			resolver := signaturekey.StaticKeyResolver{
				{Issuer: issuer, DiscoveryDocument: "aauth-resource.json", KeyID: key.ID()}: key.PublicJWK(),
			}
			_, _, err := prepared.VerifySelfJWT(context.Background(), resolver, "aa-event+jwt")
			var failure *signaturekey.Error
			if !errors.As(err, &failure) || failure.Code != test.want {
				t.Fatalf("VerifySelfJWT() error = %#v, want %s", err, test.want)
			}
		})
	}
}

func signTestSelfJWT(t *testing.T, key jose.SigningKey, typeName string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.SignCompact(key, jose.Header{
		Algorithm: jose.Ed25519Algorithm,
		Type:      typeName,
		KeyID:     key.ID(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func prepareTestSelfJWTRequest(t *testing.T, key jose.SigningKey, compact string, now time.Time) signaturekey.PreparedRequest {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewSelfJWTCredential(compact)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, key, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(request, fixedClock(now), signaturekey.VerifyOptions{
		AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeSelfJWT},
		RequireExactComponents: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}
