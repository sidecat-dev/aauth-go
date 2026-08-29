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

func TestR3AuthorizationGrantPartitionsTheExactAgentRequest(t *testing.T) {
	now := time.Date(2026, 8, 29, 6, 30, 0, 0, time.UTC)
	resourceKey := r3SigningKey(t, "resource", 0x77)
	accessKey := r3SigningKey(t, "access", 0x78)
	agentKey := r3SigningKey(t, "agent", 0x79)
	exact := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"},{"tool":"write"}],"display":{"summary":"Use records"}}`)
	reference, err := r3.NewDocumentReference("https://resource.example/r3/current", exact)
	if err != nil || !reference.Valid() || reference.Digest() != r3.S256(exact) {
		t.Fatalf("document reference = %#v, %v", reference, err)
	}
	requested := r3.OperationSet{Vocabulary: r3.VocabularyMCP, Operations: []json.RawMessage{json.RawMessage(`{"tool":"read"}`)}}
	if _, err := r3.NewAuthorizationGrant(reference, r3.AuthorizationDecision{Granted: requested}); err == nil {
		t.Fatal("authorization grant used a document that was not bound to Core token evidence")
	}
	resourceToken, err := r3.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-direct", AgentJKT: mustR3Thumbprint(t, agentKey.PublicJWK()),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Scope: "records.read",
		PersonServer: "https://person.example", Subject: "person", PresentedJTI: "person-token",
	}, reference)
	if err != nil {
		t.Fatal(err)
	}
	resourceCore, err := aauth.VerifyResourceToken(context.Background(), resourceToken,
		signaturekey.StaticKeyResolver{"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()}},
		aauth.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	resourceResult, err := r3.ValidateResourceToken(resourceCore)
	if err != nil {
		t.Fatal(err)
	}
	verifiedDocument, err := r3.VerifyDocument(resourceResult, exact)
	if err != nil || verifiedDocument.CoreEvidenceID().String() == "" {
		t.Fatalf("verified document = %#v, %v", verifiedDocument, err)
	}
	copyBytes := verifiedDocument.ExactBytes()
	copyBytes[0] = 'x'
	if verifiedDocument.ExactBytes()[0] != '{' {
		t.Fatal("document reference aliases exact bytes")
	}

	perCall := r3.OperationSet{Vocabulary: r3.VocabularyMCP, Operations: []json.RawMessage{json.RawMessage(`{"tool":"write"}`)}}
	decision := r3.AuthorizationDecision{Granted: requested, PerCall: &perCall}
	grant, err := r3.NewAuthorizationGrant(verifiedDocument, decision)
	if err != nil || !grant.Valid() {
		t.Fatalf("authorization grant = %#v, %v", grant, err)
	}
	authToken, err := r3.MintAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-direct",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		Subject: "person", Scope: "records.read", PersonServer: "https://person.example",
	}, grant)
	if err != nil {
		t.Fatal(err)
	}
	authCore, err := aauth.VerifyAuthToken(context.Background(), authToken,
		signaturekey.StaticKeyResolver{"https://access.example": {accessKey.ID(): accessKey.PublicJWK()}},
		aauth.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	authResult, err := r3.ValidateAuthToken(authCore)
	requestedBoth := r3.OperationSet{Vocabulary: r3.VocabularyMCP, Operations: []json.RawMessage{json.RawMessage(`{"tool":"read"}`), json.RawMessage(`{"tool":"write"}`)}}
	if err != nil || r3.ValidateAuthorizationGrant(resourceResult, authResult, requestedBoth) != nil {
		t.Fatalf("auth R3 result = %#v, %v", authResult, err)
	}
	outOfRequest := r3.OperationSet{Vocabulary: r3.VocabularyMCP, Operations: []json.RawMessage{json.RawMessage(`{"tool":"write"}`)}}
	if err := r3.ValidateAuthorizationGrant(resourceResult, authResult, outOfRequest); err == nil {
		t.Fatal("authorization grant escaped the agent request")
	}
	if _, err := r3.NewAuthorizationGrant(verifiedDocument, r3.AuthorizationDecision{Granted: requested, PerCall: &requested}); err == nil {
		t.Fatal("overlapping direct and per-call grants were accepted")
	}
	if _, err := r3.VerifyDocument(resourceResult, append(exact, ' ')); err == nil {
		t.Fatal("changed exact document passed hash verification")
	}
}

func mustR3Thumbprint(t *testing.T, key jose.JWK) string {
	t.Helper()
	thumbprint, err := key.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	return thumbprint
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
