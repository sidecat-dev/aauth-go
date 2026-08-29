package r3_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestR3TokenResultsBindExactCoreEvidence(t *testing.T) {
	now := time.Date(2026, 8, 29, 5, 0, 0, 0, time.UTC)
	issuer := r3SigningKey(t, "issuer", 0x71)
	requestKey := r3SigningKey(t, "request", 0x72)
	digest := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x73}, 32))

	authCompact := r3Compact(t, issuer, aauth.AuthTokenType, aauth.AuthTokenClaims{
		Issuer: "https://person.example", DWK: aauth.PersonDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-r3",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		Subject: "person", Scope: "read", PersonServer: "https://person.example",
	}, map[string]json.RawMessage{
		"r3_uri":      json.RawMessage(`"https://resource.example/r3/current"`),
		"r3_s256":     json.RawMessage(`"` + digest + `"`),
		"r3_granted":  json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`),
		"r3_per_call": json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"write"}]}`),
	})
	authCore, err := aauth.VerifyAuthToken(context.Background(), authCompact,
		signaturekey.StaticKeyResolver{"https://person.example": {issuer.ID(): issuer.PublicJWK()}},
		aauth.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	members, err := authCore.AuthorizationMembers()
	if err != nil || len(members) != 4 {
		t.Fatalf("members = %#v, %v", members, err)
	}
	members["r3_uri"][0] = 'x'
	again, _ := authCore.AuthorizationMembers()
	if string(again["r3_uri"]) != `"https://resource.example/r3/current"` {
		t.Fatal("authorization members alias Core evidence")
	}
	authResult, err := r3.ValidateAuthToken(authCore)
	if err != nil || !authResult.Valid() || authResult.URI() != "https://resource.example/r3/current" || authResult.Digest() != digest {
		t.Fatalf("auth R3 result = %#v, %v", authResult, err)
	}
	coreID, _ := authCore.EvidenceID()
	if authResult.CoreEvidenceID() != coreID {
		t.Fatal("R3 result is not bound to Core evidence")
	}
	granted, ok := authResult.Granted()
	if !ok || !granted.Contains(json.RawMessage(`{"tool":"read"}`)) {
		t.Fatalf("granted = %#v, %t", granted, ok)
	}
	perCall, ok := authResult.PerCall()
	if !ok || !perCall.Contains(json.RawMessage(`{"tool":"write"}`)) {
		t.Fatalf("per-call = %#v, %t", perCall, ok)
	}
	granted.Operations[0][0] = 'x'
	grantedAgain, _ := authResult.Granted()
	if !grantedAgain.Contains(json.RawMessage(`{"tool":"read"}`)) {
		t.Fatal("R3 result aliases a granted projection")
	}

	thumbprint, _ := requestKey.PublicJWK().Thumbprint()
	resourceCompact := r3Compact(t, issuer, aauth.ResourceTokenType, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://person.example", JTI: "resource-r3", AgentJKT: thumbprint,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Scope: "read",
		PersonServer: "https://person.example", Subject: "person", PresentedJTI: "person-token",
	}, map[string]json.RawMessage{
		"r3_uri": json.RawMessage(`"https://resource.example/r3/current"`), "r3_s256": json.RawMessage(`"` + digest + `"`),
	})
	resourceCore, err := aauth.VerifyResourceToken(context.Background(), resourceCompact,
		signaturekey.StaticKeyResolver{"https://resource.example": {issuer.ID(): issuer.PublicJWK()}},
		aauth.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	resourceResult, err := r3.ValidateResourceToken(resourceCore)
	if err != nil || !resourceResult.Valid() {
		t.Fatalf("resource R3 result = %#v, %v", resourceResult, err)
	}
	if _, ok := resourceResult.Granted(); ok {
		t.Fatal("resource result exposes a grant")
	}
}

func TestR3TokenResultZeroValueIsInvalid(t *testing.T) {
	var result r3.TokenResult
	if result.Valid() || result.URI() != "" || result.CoreEvidenceID().String() != "" {
		t.Fatalf("zero result = %#v", result)
	}
	if _, err := r3.ValidateAuthToken(aauth.VerifiedToken[aauth.AuthTokenClaims]{}); err == nil {
		t.Fatal("zero Core evidence passed R3 validation")
	}
}

func TestR3AuthTokenValidationRefusesMalformedMembers(t *testing.T) {
	now := time.Date(2026, 8, 29, 5, 30, 0, 0, time.UTC)
	issuer := r3SigningKey(t, "issuer", 0x74)
	requestKey := r3SigningKey(t, "request", 0x75)
	digest := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x76}, 32))
	base := map[string]json.RawMessage{
		"r3_uri":      json.RawMessage(`"https://resource.example/r3/current"`),
		"r3_s256":     json.RawMessage(`"` + digest + `"`),
		"r3_granted":  json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`),
		"r3_per_call": json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"write"}]}`),
	}
	for _, test := range []struct {
		name   string
		member string
		value  json.RawMessage
	}{
		{name: "non HTTPS URI", member: "r3_uri", value: json.RawMessage(`"http://resource.example/r3"`)},
		{name: "digest is not SHA-256", member: "r3_s256", value: json.RawMessage(`"not-a-digest"`)},
		{name: "granted operation is malformed", member: "r3_granted", value: json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{}]}`)},
		{name: "per-call vocabulary differs", member: "r3_per_call", value: json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:openapi","operations":[{"operationId":"write"}]}`)},
		{name: "per-call overlaps grant", member: "r3_per_call", value: json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}`)},
		{name: "Budget remains unresolved", member: "budget", value: json.RawMessage(`{"amount":100,"unit":"USD","decimals":2}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			members := make(map[string]json.RawMessage, len(base))
			for name, raw := range base {
				members[name] = append(json.RawMessage(nil), raw...)
			}
			members[test.member] = test.value
			compact := r3Compact(t, issuer, aauth.AuthTokenType, aauth.AuthTokenClaims{
				Issuer: "https://person.example", DWK: aauth.PersonDiscoveryDocument,
				Audience: "https://resource.example", JTI: "auth-r3-malformed",
				Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
				IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
				Subject: "person", Scope: "read", PersonServer: "https://person.example",
			}, members)
			core, err := aauth.VerifyAuthToken(context.Background(), compact,
				signaturekey.StaticKeyResolver{"https://person.example": {issuer.ID(): issuer.PublicJWK()}},
				aauth.ClockFunc(func() time.Time { return now }))
			if err != nil {
				t.Fatalf("Core verification = %v", err)
			}
			_, err = r3.ValidateAuthToken(core)
			var validation *r3.ValidationError
			if !errors.As(err, &validation) || validation.Member != test.member {
				t.Fatalf("R3 validation = %#v, want member %q", err, test.member)
			}
		})
	}
}

func r3Compact(t *testing.T, key jose.SigningKey, tokenType string, claims any, members map[string]json.RawMessage) string {
	t.Helper()
	payload, _ := json.Marshal(claims)
	var object map[string]json.RawMessage
	_ = json.Unmarshal(payload, &object)
	for name, raw := range members {
		object[name] = raw
	}
	payload, _ = json.Marshal(object)
	compact, err := jose.SignCompact(key, jose.Header{Algorithm: jose.Ed25519Algorithm, Type: tokenType, KeyID: key.ID()}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func r3SigningKey(t *testing.T, id string, seed byte) jose.SigningKey {
	t.Helper()
	key, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}
