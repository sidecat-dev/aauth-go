package aauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"aauth-go"
	"aauth-go/jose"
	"aauth-go/r3"
	"aauth-go/signaturekey"
)

func TestR3TokenAPIsPreserveCoreFailClosedBoundary(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	resourceKey := coreTokenKey(t, "resource-key")
	accessKey := coreTokenKey(t, "access-key")
	requestKey := coreTokenKey(t, "request-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })

	operation, err := r3.NewMCPOperation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	operations, err := r3.NewMCPOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	document, err := r3.NewDocument(operations, r3.DocumentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	documentBytes, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	granted, err := r3.NewGrantedOperations(operation)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := r3.NewGrant(granted, document)
	if err != nil {
		t.Fatal(err)
	}

	resourceCompact, reference, err := r3.MintMCPResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-token-1",
		PersonServer: "https://person.example", Subject: "person-1", PresentedJTI: "person-token-1",
		AgentJKT: coreTokenS256("agent-key"), Scope: "records.read",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}, "https://resource.example/r3/document-1", documentBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aauth.VerifyResourceToken(context.Background(), resourceCompact, resolver, clock); err == nil {
		t.Fatal("Core VerifyResourceToken accepted R3 claims")
	} else {
		var unsupported *aauth.UnsupportedTokenClaimError
		if !errors.As(err, &unsupported) || unsupported.TokenType != aauth.ResourceTokenType || unsupported.Claim != "r3_uri" {
			t.Fatalf("Core VerifyResourceToken error = %v, want typed fail-closed R3 refusal", err)
		}
	}
	resourceClaims, resourceReference, err := r3.VerifyMCPResourceToken(context.Background(), resourceCompact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if resourceClaims.JTI != "resource-token-1" || resourceReference != reference {
		t.Fatalf("verified resource token = (%#v, %#v)", resourceClaims, resourceReference)
	}

	authCompact, err := r3.MintMCPDirectAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-token-1",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Scope: "records.read",
		AdditionalClaims: map[string]json.RawMessage{"email": json.RawMessage(`"person@example.com"`)},
	}, reference, documentBytes, grant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aauth.VerifyAuthToken(context.Background(), authCompact, resolver, clock); err == nil {
		t.Fatal("Core VerifyAuthToken accepted R3 claims")
	} else {
		var unsupported *aauth.UnsupportedTokenClaimError
		if !errors.As(err, &unsupported) || unsupported.TokenType != aauth.AuthTokenType || unsupported.Claim != "r3_uri" {
			t.Fatalf("Core VerifyAuthToken error = %v, want typed fail-closed R3 refusal", err)
		}
	}
	authClaims, authReference, grantedOperations, err := r3.VerifyMCPDirectAuthToken(context.Background(), authCompact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.JTI != "auth-token-1" || authReference != reference || !grantedOperations.Equal(grant.GrantedOperations()) {
		t.Fatalf("verified auth token = (%#v, %#v, %#v)", authClaims, authReference, grantedOperations)
	}
	if string(authClaims.AdditionalClaims["email"]) != `"person@example.com"` {
		t.Fatalf("unrelated additional claims = %#v", authClaims.AdditionalClaims)
	}
	for _, name := range []string{"r3_uri", "r3_s256", "r3_granted"} {
		if _, present := authClaims.AdditionalClaims[name]; present {
			t.Fatalf("validated %s claim remained duplicated in AdditionalClaims", name)
		}
	}
}

func TestR3TokenVerificationRejectsPartialOrMixedCompanionClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	resourceKey := coreTokenKey(t, "resource-key")
	accessKey := coreTokenKey(t, "access-key")
	requestKey := coreTokenKey(t, "request-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	digest := r3.Digest([]byte("exact document bytes"))
	grant := map[string]any{
		"vocabulary": r3.MCPVocabulary,
		"operations": []any{map[string]any{"tool": "records.read"}},
	}
	resourceBase := map[string]any{
		"iss": "https://resource.example", "dwk": aauth.ResourceDiscoveryDocument,
		"aud": "https://access.example", "jti": "resource-token-1",
		"ps": "https://person.example", "sub": "person-1", "presented_jti": "person-token-1",
		"agent_jkt": coreTokenS256("agent-key"), "scope": "records.read",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	authBase := map[string]any{
		"iss": "https://access.example", "dwk": aauth.AccessDiscoveryDocument,
		"aud": "https://resource.example", "jti": "auth-token-1",
		"ps": "https://person.example", "sub": "person-1",
		"cnf": map[string]any{"jwk": requestKey.PublicJWK()}, "scope": "records.read",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}

	resourceCases := []struct {
		name   string
		claims map[string]any
	}{
		{name: "missing digest", claims: map[string]any{"r3_uri": "https://resource.example/r3/one"}},
		{name: "missing URI", claims: map[string]any{"r3_s256": digest}},
		{name: "invalid URI", claims: map[string]any{"r3_uri": "http://resource.example/r3/one", "r3_s256": digest}},
		{name: "invalid digest", claims: map[string]any{"r3_uri": "https://resource.example/r3/one", "r3_s256": "short"}},
		{name: "present empty scope", claims: map[string]any{"r3_uri": "https://resource.example/r3/one", "r3_s256": digest, "scope": ""}},
		{name: "grant belongs only in auth token", claims: map[string]any{"r3_uri": "https://resource.example/r3/one", "r3_s256": digest, "r3_granted": grant}},
		{name: "per call deferred", claims: map[string]any{"r3_uri": "https://resource.example/r3/one", "r3_s256": digest, "r3_per_call": grant}},
		{name: "mixed Budget", claims: map[string]any{"r3_uri": "https://resource.example/r3/one", "r3_s256": digest, "budget": map[string]any{"amount": 1}}},
		{name: "Budget case variant", claims: map[string]any{"r3_uri": "https://resource.example/r3/one", "r3_s256": digest, "Budget": map[string]any{"amount": 1}}},
		{name: "case variant", claims: map[string]any{"R3_URI": "https://resource.example/r3/one", "r3_s256": digest}},
	}
	for _, test := range resourceCases {
		t.Run("resource/"+test.name, func(t *testing.T) {
			members := cloneCoreTokenMembers(resourceBase)
			for name, value := range test.claims {
				members[name] = value
			}
			compact := signCoreTokenPayload(t, resourceKey, aauth.ResourceTokenType, members)
			if _, _, err := r3.VerifyMCPResourceToken(context.Background(), compact, resolver, clock); err == nil {
				t.Fatalf("accepted invalid R3 resource claims %#v", test.claims)
			}
		})
	}

	authCases := []struct {
		name   string
		claims map[string]any
	}{
		{name: "missing URI", claims: map[string]any{"r3_s256": digest, "r3_granted": grant}},
		{name: "missing digest", claims: map[string]any{"r3_uri": "https://resource.example/r3/one", "r3_granted": grant}},
		{name: "missing grant", claims: map[string]any{"r3_uri": "https://resource.example/r3/one", "r3_s256": digest}},
		{name: "present empty scope", claims: map[string]any{"r3_uri": "https://resource.example/r3/one", "r3_s256": digest, "r3_granted": grant, "scope": ""}},
		{name: "per call deferred", claims: map[string]any{"r3_uri": "https://resource.example/r3/one", "r3_s256": digest, "r3_granted": grant, "r3_per_call": grant}},
		{name: "mixed Budget", claims: map[string]any{"r3_uri": "https://resource.example/r3/one", "r3_s256": digest, "r3_granted": grant, "budget": map[string]any{"amount": 1}}},
		{name: "Budget case variant", claims: map[string]any{"r3_uri": "https://resource.example/r3/one", "r3_s256": digest, "r3_granted": grant, "Budget": map[string]any{"amount": 1}}},
		{name: "case variant", claims: map[string]any{"R3_GRANTED": grant, "r3_uri": "https://resource.example/r3/one", "r3_s256": digest}},
	}
	for _, test := range authCases {
		t.Run("auth/"+test.name, func(t *testing.T) {
			members := cloneCoreTokenMembers(authBase)
			for name, value := range test.claims {
				members[name] = value
			}
			compact := signCoreTokenPayload(t, accessKey, aauth.AuthTokenType, members)
			if _, _, _, err := r3.VerifyMCPDirectAuthToken(context.Background(), compact, resolver, clock); err == nil {
				t.Fatalf("accepted invalid R3 auth claims %#v", test.claims)
			}
		})
	}
}

func TestR3TokenVerificationAcceptsScopelessEmptyGrantAndUnknownExtensions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	resourceKey := coreTokenKey(t, "resource-key")
	accessKey := coreTokenKey(t, "access-key")
	requestKey := coreTokenKey(t, "request-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	digest := r3.Digest([]byte("exact document bytes"))

	resourceMembers := map[string]any{
		"iss": "https://resource.example", "dwk": aauth.ResourceDiscoveryDocument,
		"aud": "https://access.example", "jti": "resource-token-1",
		"ps": "https://person.example", "sub": "person-1", "presented_jti": "person-token-1",
		"agent_jkt": coreTokenS256("agent-key"), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"r3_uri": "https://resource.example/r3/one", "r3_s256": digest,
		"r3_future": map[string]any{"retained": true},
	}
	resourceCompact := signCoreTokenPayload(t, resourceKey, aauth.ResourceTokenType, resourceMembers)
	resourceClaims, _, err := r3.VerifyMCPResourceToken(context.Background(), resourceCompact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if resourceClaims.Scope != "" || string(resourceClaims.AdditionalClaims["r3_future"]) != `{"retained":true}` {
		t.Fatalf("scopeless Resource claims = %#v", resourceClaims)
	}

	authMembers := map[string]any{
		"iss": "https://access.example", "dwk": aauth.AccessDiscoveryDocument,
		"aud": "https://resource.example", "jti": "auth-token-1",
		"ps": "https://person.example", "sub": "person-1",
		"cnf": map[string]any{"jwk": requestKey.PublicJWK()}, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"r3_uri": "https://resource.example/r3/one", "r3_s256": digest,
		"r3_granted": map[string]any{"vocabulary": r3.MCPVocabulary, "operations": []any{}},
		"r3_future":  map[string]any{"retained": true},
	}
	authCompact := signCoreTokenPayload(t, accessKey, aauth.AuthTokenType, authMembers)
	authClaims, _, granted, err := r3.VerifyMCPDirectAuthToken(context.Background(), authCompact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.Scope != "" || len(granted.Operations()) != 0 || string(authClaims.AdditionalClaims["r3_future"]) != `{"retained":true}` {
		t.Fatalf("scopeless Auth claims = %#v, grant = %#v", authClaims, granted)
	}
}

func TestR3TokenMintersRejectUnprovenOrCollidingClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	key := coreTokenKey(t, "issuer-key")
	requestKey := coreTokenKey(t, "request-key")
	operation, err := r3.NewMCPOperation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	operations, err := r3.NewMCPOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	document, err := r3.NewDocument(operations, r3.DocumentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	documentBytes, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	granted, err := r3.NewGrantedOperations(operation)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := r3.NewGrant(granted, document)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := r3.NewReference("https://resource.example/r3/one", r3.Digest(documentBytes))
	if err != nil {
		t.Fatal(err)
	}
	base := aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-token-1",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()}, Scope: "records.read",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	scopelessAuth := base
	scopelessAuth.Scope = ""
	scopelessAuthCompact, err := r3.MintMCPDirectAuthToken(key, scopelessAuth, reference, documentBytes, grant)
	if err != nil {
		t.Fatalf("MintR3AuthToken rejected a source-valid scopeless token: %v", err)
	}
	assertCompactOmitsClaim(t, scopelessAuthCompact, "scope")

	if _, err := r3.MintMCPDirectAuthToken(key, base, r3.Reference{}, documentBytes, grant); err == nil {
		t.Fatal("MintR3AuthToken accepted an empty reference")
	}
	if _, err := r3.MintMCPDirectAuthToken(key, base, reference, documentBytes, r3.Grant{}); err == nil {
		t.Fatal("MintR3AuthToken accepted an unproven empty grant")
	}
	if _, err := r3.MintMCPDirectAuthToken(key, base, reference, []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"other"}]}`), grant); err == nil {
		t.Fatal("MintR3AuthToken accepted document bytes that do not match the reference")
	}
	otherDocumentBytes := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"other"}]}`)
	otherReference, err := r3.NewReference("https://resource.example/r3/other", r3.Digest(otherDocumentBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r3.MintMCPDirectAuthToken(key, base, otherReference, otherDocumentBytes, grant); err == nil {
		t.Fatal("MintR3AuthToken accepted a grant that was not a subset of the referenced document")
	}
	for _, name := range []string{"r3_uri", "R3_S256", "r3_granted", "r3_per_call", "budget"} {
		claims := base
		claims.AdditionalClaims = map[string]json.RawMessage{name: json.RawMessage(`true`)}
		if _, err := r3.MintMCPDirectAuthToken(key, claims, reference, documentBytes, grant); err == nil {
			t.Fatalf("MintR3AuthToken accepted colliding additional claim %q", name)
		}
	}

	resourceBase := aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-token-1",
		PersonServer: "https://person.example", Subject: "person-1", PresentedJTI: "person-token-1",
		AgentJKT: coreTokenS256("agent-key"), IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
	scopelessResourceCompact, _, err := r3.MintMCPResourceToken(key, resourceBase, "https://resource.example/r3/one", documentBytes)
	if err != nil {
		t.Fatalf("MintR3ResourceToken rejected a source-valid scopeless token: %v", err)
	}
	assertCompactOmitsClaim(t, scopelessResourceCompact, "scope")
	if _, _, err := r3.MintMCPResourceToken(key, resourceBase, "", documentBytes); err == nil {
		t.Fatal("MintR3ResourceToken accepted an empty document URI")
	}
	if _, _, err := r3.MintMCPResourceToken(key, resourceBase, "https://resource.example/r3/one", []byte(`{}`)); err == nil {
		t.Fatal("MintR3ResourceToken accepted invalid document bytes")
	}
	for _, name := range []string{"r3_uri", "R3_S256", "r3_granted", "r3_per_call", "budget"} {
		claims := resourceBase
		claims.AdditionalClaims = map[string]json.RawMessage{name: json.RawMessage(`true`)}
		if _, _, err := r3.MintMCPResourceToken(key, claims, "https://resource.example/r3/one", documentBytes); err == nil {
			t.Fatalf("MintR3ResourceToken accepted colliding additional claim %q", name)
		}
	}
}

func TestMCPR3TokenMintersBindDocumentAccountExactly(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	key := coreTokenKey(t, "issuer-key")
	requestKey := coreTokenKey(t, "request-key")
	operation, err := r3.NewMCPOperation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	operations, err := r3.NewMCPOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	granted, err := r3.NewGrantedOperations(operation)
	if err != nil {
		t.Fatal(err)
	}

	resourceClaims := aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-token-1",
		PersonServer: "https://person.example", Subject: "person-1", PresentedJTI: "person-token-1",
		AgentJKT: coreTokenS256("agent-key"), IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
	authClaims := aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-token-1",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}

	account := "work-account"
	withAccount, err := r3.NewDocument(operations, r3.DocumentOptions{Account: &account})
	if err != nil {
		t.Fatal(err)
	}
	withAccountBytes, err := json.Marshal(withAccount)
	if err != nil {
		t.Fatal(err)
	}
	withAccountGrant, err := r3.NewGrant(granted, withAccount)
	if err != nil {
		t.Fatal(err)
	}
	withAccountReference, err := r3.NewReference("https://resource.example/r3/account", r3.Digest(withAccountBytes))
	if err != nil {
		t.Fatal(err)
	}

	matchingResource := resourceClaims
	matchingResource.Account = &account
	if _, _, err := r3.MintMCPResourceToken(key, matchingResource, withAccountReference.URI(), withAccountBytes); err != nil {
		t.Fatalf("matching Resource account rejected: %v", err)
	}
	matchingAuth := authClaims
	matchingAuth.Account = &account
	if _, err := r3.MintMCPDirectAuthToken(key, matchingAuth, withAccountReference, withAccountBytes, withAccountGrant); err != nil {
		t.Fatalf("matching Auth account rejected: %v", err)
	}

	emptyAccount := ""
	otherAccount := "other-account"
	for _, tokenAccount := range []*string{nil, &emptyAccount, &otherAccount} {
		claims := resourceClaims
		claims.Account = tokenAccount
		if _, _, err := r3.MintMCPResourceToken(key, claims, withAccountReference.URI(), withAccountBytes); err == nil {
			t.Fatalf("Resource token account %#v accepted document account %q", tokenAccount, account)
		}
		auth := authClaims
		auth.Account = tokenAccount
		if _, err := r3.MintMCPDirectAuthToken(key, auth, withAccountReference, withAccountBytes, withAccountGrant); err == nil {
			t.Fatalf("Auth token account %#v accepted document account %q", tokenAccount, account)
		}
	}

	withoutAccount, err := r3.NewDocument(operations, r3.DocumentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	withoutAccountBytes, err := json.Marshal(withoutAccount)
	if err != nil {
		t.Fatal(err)
	}
	withoutAccountGrant, err := r3.NewGrant(granted, withoutAccount)
	if err != nil {
		t.Fatal(err)
	}
	withoutAccountReference, err := r3.NewReference("https://resource.example/r3/no-account", r3.Digest(withoutAccountBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r3.MintMCPResourceToken(key, matchingResource, withoutAccountReference.URI(), withoutAccountBytes); err == nil {
		t.Fatal("Resource token account accepted a document without account")
	}
	if _, err := r3.MintMCPDirectAuthToken(key, matchingAuth, withoutAccountReference, withoutAccountBytes, withoutAccountGrant); err == nil {
		t.Fatal("Auth token account accepted a document without account")
	}

	emptyAccountDocument, err := r3.NewDocument(operations, r3.DocumentOptions{Account: &emptyAccount})
	if err != nil {
		t.Fatal(err)
	}
	emptyAccountDocumentBytes, err := json.Marshal(emptyAccountDocument)
	if err != nil {
		t.Fatal(err)
	}
	emptyAccountGrant, err := r3.NewGrant(granted, emptyAccountDocument)
	if err != nil {
		t.Fatal(err)
	}
	emptyAccountReference, err := r3.NewReference("https://resource.example/r3/empty-account", r3.Digest(emptyAccountDocumentBytes))
	if err != nil {
		t.Fatal(err)
	}
	emptyResource := resourceClaims
	emptyResource.Account = &emptyAccount
	emptyResourceCompact, _, err := r3.MintMCPResourceToken(key, emptyResource, emptyAccountReference.URI(), emptyAccountDocumentBytes)
	if err != nil {
		t.Fatalf("matching present-empty Resource account rejected: %v", err)
	}
	emptyAuth := authClaims
	emptyAuth.Account = &emptyAccount
	emptyAuthCompact, err := r3.MintMCPDirectAuthToken(key, emptyAuth, emptyAccountReference, emptyAccountDocumentBytes, emptyAccountGrant)
	if err != nil {
		t.Fatalf("matching present-empty Auth account rejected: %v", err)
	}
	assertCompactStringClaim(t, emptyResourceCompact, "account", "")
	assertCompactStringClaim(t, emptyAuthCompact, "account", "")
}

func TestMCPR3TokenVerificationPreservesAccountPresence(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	resourceKey := coreTokenKey(t, "resource-key")
	accessKey := coreTokenKey(t, "access-key")
	requestKey := coreTokenKey(t, "request-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	digest := r3.Digest([]byte("exact document bytes"))
	resourceBase := map[string]any{
		"iss": "https://resource.example", "dwk": aauth.ResourceDiscoveryDocument,
		"aud": "https://access.example", "jti": "resource-token-1",
		"ps": "https://person.example", "sub": "person-1", "presented_jti": "person-token-1",
		"agent_jkt": coreTokenS256("agent-key"), "scope": "records.read",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"r3_uri": "https://resource.example/r3/one", "r3_s256": digest,
	}
	authBase := map[string]any{
		"iss": "https://access.example", "dwk": aauth.AccessDiscoveryDocument,
		"aud": "https://resource.example", "jti": "auth-token-1",
		"ps": "https://person.example", "sub": "person-1",
		"cnf": map[string]any{"jwk": requestKey.PublicJWK()}, "scope": "records.read",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"r3_uri": "https://resource.example/r3/one", "r3_s256": digest,
		"r3_granted": map[string]any{"vocabulary": r3.MCPVocabulary, "operations": []any{}},
	}

	empty := ""
	named := "work-account"
	operation, err := r3.NewMCPOperation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	operations, err := r3.NewMCPOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	documents := map[string]r3.Document{}
	for name, account := range map[string]*string{"absent": nil, "empty": &empty, "named": &named} {
		document, err := r3.NewDocument(operations, r3.DocumentOptions{Account: account})
		if err != nil {
			t.Fatal(err)
		}
		documents[name] = document
	}

	cases := []struct {
		name        string
		tokenValue  any
		tokenSet    bool
		document    string
		wantMatch   bool
		wantInvalid bool
	}{
		{name: "absent matches absent", document: "absent", wantMatch: true},
		{name: "empty matches empty", tokenSet: true, tokenValue: "", document: "empty", wantMatch: true},
		{name: "named matches named", tokenSet: true, tokenValue: named, document: "named", wantMatch: true},
		{name: "empty does not match absent", tokenSet: true, tokenValue: "", document: "absent"},
		{name: "absent does not match empty", document: "empty"},
		{name: "null is not a string", tokenSet: true, tokenValue: nil, document: "absent", wantInvalid: true},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			resourceMembers := cloneCoreTokenMembers(resourceBase)
			authMembers := cloneCoreTokenMembers(authBase)
			if test.tokenSet {
				resourceMembers["account"] = test.tokenValue
				authMembers["account"] = test.tokenValue
			}
			resourceCompact := signCoreTokenPayload(t, resourceKey, aauth.ResourceTokenType, resourceMembers)
			resourceClaims, _, resourceErr := r3.VerifyMCPResourceToken(context.Background(), resourceCompact, resolver, clock)
			authCompact := signCoreTokenPayload(t, accessKey, aauth.AuthTokenType, authMembers)
			authClaims, _, _, authErr := r3.VerifyMCPDirectAuthToken(context.Background(), authCompact, resolver, clock)
			if test.wantInvalid {
				if resourceErr == nil || authErr == nil {
					t.Fatalf("null account verification errors = Resource %v, Auth %v", resourceErr, authErr)
				}
				return
			}
			if resourceErr != nil || authErr != nil {
				t.Fatalf("verification errors = Resource %v, Auth %v", resourceErr, authErr)
			}
			resourceMatch := r3.ValidateDocumentAccount(documents[test.document], resourceClaims.Account) == nil
			authMatch := r3.ValidateDocumentAccount(documents[test.document], authClaims.Account) == nil
			if resourceMatch != test.wantMatch || authMatch != test.wantMatch {
				t.Fatalf("account match = Resource %t, Auth %t, want %t", resourceMatch, authMatch, test.wantMatch)
			}
		})
	}
}

func TestMCPR3TokenAdditionalClaimsAreCopied(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	resourceKey := coreTokenKey(t, "resource-key")
	accessKey := coreTokenKey(t, "access-key")
	requestKey := coreTokenKey(t, "request-key")
	operation, err := r3.NewMCPOperation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	operations, err := r3.NewMCPOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	document, err := r3.NewDocument(operations, r3.DocumentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	documentBytes, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	granted, err := r3.NewGrantedOperations(operation)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := r3.NewGrant(granted, document)
	if err != nil {
		t.Fatal(err)
	}

	resourceRaw := json.RawMessage(`{"value":"resource-original"}`)
	resourceAdditional := map[string]json.RawMessage{"r3_future": resourceRaw}
	resourceCompact, reference, err := r3.MintMCPResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-token-1",
		PersonServer: "https://person.example", Subject: "person-1", PresentedJTI: "person-token-1",
		AgentJKT: coreTokenS256("agent-key"), Scope: "records.read",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		AdditionalClaims: resourceAdditional,
	}, "https://resource.example/r3/document", documentBytes)
	if err != nil {
		t.Fatal(err)
	}
	resourceRaw[0] = '['
	resourceAdditional["r3_future"] = json.RawMessage(`null`)

	authRaw := json.RawMessage(`{"value":"auth-original"}`)
	authAdditional := map[string]json.RawMessage{"r3_future": authRaw}
	authCompact, err := r3.MintMCPDirectAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-token-1",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()}, Scope: "records.read",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		AdditionalClaims: authAdditional,
	}, reference, documentBytes, grant)
	if err != nil {
		t.Fatal(err)
	}
	authRaw[0] = '['
	authAdditional["r3_future"] = json.RawMessage(`null`)

	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	firstResource, _, err := r3.VerifyMCPResourceToken(context.Background(), resourceCompact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(firstResource.AdditionalClaims["r3_future"]); got != `{"value":"resource-original"}` {
		t.Fatalf("first Resource additional claim = %s", got)
	}
	firstResource.AdditionalClaims["r3_future"][0] = '['
	firstResource.AdditionalClaims["r3_future"] = json.RawMessage(`null`)
	secondResource, _, err := r3.VerifyMCPResourceToken(context.Background(), resourceCompact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(secondResource.AdditionalClaims["r3_future"]); got != `{"value":"resource-original"}` {
		t.Fatalf("second Resource additional claim = %s", got)
	}

	firstAuth, _, _, err := r3.VerifyMCPDirectAuthToken(context.Background(), authCompact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(firstAuth.AdditionalClaims["r3_future"]); got != `{"value":"auth-original"}` {
		t.Fatalf("first Auth additional claim = %s", got)
	}
	firstAuth.AdditionalClaims["r3_future"][0] = '['
	firstAuth.AdditionalClaims["r3_future"] = json.RawMessage(`null`)
	secondAuth, _, _, err := r3.VerifyMCPDirectAuthToken(context.Background(), authCompact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(secondAuth.AdditionalClaims["r3_future"]); got != `{"value":"auth-original"}` {
		t.Fatalf("second Auth additional claim = %s", got)
	}
}

func TestMCPR3ClassAuthorizationSplitsDirectAndPerCallOperations(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	accessKey := coreTokenKey(t, "access-key")
	requestKey := coreTokenKey(t, "request-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}: accessKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	read, _ := r3.NewMCPOperation("records.read")
	deleteRecord, _ := r3.NewMCPOperation("records.delete")
	operations, _ := r3.NewMCPOperationSet(read, deleteRecord)
	document, _ := r3.NewDocument(operations, r3.DocumentOptions{})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference("https://resource.example/r3/class-one", r3.Digest(exactDocument))
	granted, _ := r3.NewGrantedOperations(read)
	perCall, _ := r3.NewGrantedOperations(deleteRecord)
	authorization, err := r3.NewAuthorization(granted, perCall, document)
	if err != nil {
		t.Fatal(err)
	}

	compact, err := r3.MintMCPAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "class-auth-token",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, reference, exactDocument, authorization)
	if err != nil {
		t.Fatal(err)
	}
	classMembers := compactClaimMap(t, compact)
	if _, ok := classMembers["r3_granted"]; !ok {
		t.Fatal("class Auth token omitted mandatory r3_granted")
	}
	if _, ok := classMembers["r3_per_call"]; !ok {
		t.Fatal("class Auth token omitted nonempty r3_per_call")
	}
	claims, gotReference, operationClaims, err := r3.VerifyMCPAuthTokenClaims(
		context.Background(), compact, resolver, clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	if claims.JTI != "class-auth-token" || gotReference != reference ||
		!operationClaims.GrantedOperations().Equal(granted) || !operationClaims.PerCallOperations().Equal(perCall) {
		t.Fatalf("verified class token = %#v, %#v, %#v", claims, gotReference, operationClaims)
	}
	if _, _, _, err := r3.VerifyMCPDirectAuthToken(context.Background(), compact, resolver, clock); err == nil {
		t.Fatal("direct-only verifier accepted a class token with r3_per_call")
	}
	if _, err := aauth.VerifyAuthToken(context.Background(), compact, resolver, clock); err == nil {
		t.Fatal("Core verifier accepted a class R3 token")
	}

	if _, err := r3.NewAuthorization(granted, granted, document); err == nil {
		t.Fatal("accepted an operation in both r3_granted and r3_per_call")
	}
	outside, _ := r3.NewMCPOperation("records.export")
	outsideSet, _ := r3.NewGrantedOperations(outside)
	if _, err := r3.NewAuthorization(outsideSet, perCall, document); err == nil {
		t.Fatal("accepted a direct operation outside the class document")
	}
	if _, err := r3.NewAuthorization(granted, outsideSet, document); err == nil {
		t.Fatal("accepted a per-call operation outside the class document")
	}
	if _, err := r3.MintMCPAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "zero-authorization",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, reference, exactDocument, r3.Authorization{}); err == nil {
		t.Fatal("class mint accepted an unproven zero Authorization")
	}
	empty, _ := r3.NewGrantedOperations()
	directOnly, _ := r3.NewAuthorization(granted, empty, document)
	directOnlyCompact, err := r3.MintMCPAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "direct-only",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, reference, exactDocument, directOnly)
	if err != nil {
		t.Fatal(err)
	}
	assertCompactOmitsClaim(t, directOnlyCompact, "r3_per_call")
}

func TestMCPR3PerCallTokensBindTheExactProposal(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	resourceKey := coreTokenKey(t, "resource-key")
	accessKey := coreTokenKey(t, "access-key")
	requestKey := coreTokenKey(t, "request-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:       accessKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	operation, _ := r3.NewMCPOperation("records.delete")
	identifier, _ := r3.NewMCPInlineParameter([]byte(`"record-7"`))
	parameters, _ := r3.NewMCPParameters(map[string]r3.MCPParameter{"id": identifier})
	account := "work"
	proposal, _ := r3.NewMCPProposal(operation, parameters, r3.ProposalOptions{Account: &account})
	exactProposal, _ := json.Marshal(proposal)

	resourceCompact, reference, err := r3.MintMCPProposalResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "proposal-resource-token",
		PersonServer: "https://person.example", Subject: "person-1", PresentedJTI: "person-token-1",
		AgentJKT: coreTokenS256("agent-key"), Account: &account,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}, "https://resource.example/r3/proposal-one", exactProposal)
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims, gotReference, err := r3.VerifyMCPResourceToken(context.Background(), resourceCompact, resolver, clock)
	if err != nil || resourceClaims.JTI != "proposal-resource-token" || gotReference != reference {
		t.Fatalf("proposal Resource token = %#v, %#v, %v", resourceClaims, gotReference, err)
	}
	proposalResourceMembers := compactClaimMap(t, resourceCompact)
	for _, forbidden := range []string{"r3_granted", "r3_per_call", "parameters"} {
		if _, ok := proposalResourceMembers[forbidden]; ok {
			t.Fatalf("proposal Resource token contains %q", forbidden)
		}
	}
	parsed, err := r3.ParseReferencedProposal(reference, exactProposal)
	if err != nil || parsed.Operation().Tool() != operation.Tool() {
		t.Fatalf("referenced proposal = %#v, %v", parsed, err)
	}

	authCompact, err := r3.MintMCPPerCallAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "per-call-auth-token",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()}, Account: &account,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, reference, exactProposal)
	if err != nil {
		t.Fatal(err)
	}
	perCallMembers := compactClaimMap(t, authCompact)
	if _, ok := perCallMembers["r3_granted"]; !ok {
		t.Fatal("per-call Auth token omitted r3_granted")
	}
	for _, forbidden := range []string{"r3_per_call", "parameters"} {
		if _, ok := perCallMembers[forbidden]; ok {
			t.Fatalf("per-call Auth token contains %q", forbidden)
		}
	}
	authClaims, authReference, grantedOperation, err := r3.VerifyMCPPerCallAuthToken(
		context.Background(), authCompact, resolver, clock, reference, exactProposal,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.JTI != "per-call-auth-token" || authReference != reference || grantedOperation.Tool() != operation.Tool() {
		t.Fatalf("per-call Auth token = %#v, %#v, %#v", authClaims, authReference, grantedOperation)
	}
	wrongOperation, _ := r3.NewMCPOperation("records.export")
	wrongGranted, _ := r3.NewGrantedOperations(wrongOperation)
	wrongGrantedJSON, _ := json.Marshal(wrongGranted)
	uriJSON, _ := json.Marshal(reference.URI())
	digestJSON, _ := json.Marshal(reference.Digest())
	baseMembers := map[string]any{
		"iss": "https://access.example", "dwk": aauth.AccessDiscoveryDocument,
		"aud": "https://resource.example", "jti": "manually-signed",
		"ps": "https://person.example", "sub": "person-1",
		"cnf": map[string]any{"jwk": requestKey.PublicJWK()}, "account": account,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"r3_uri": json.RawMessage(uriJSON), "r3_s256": json.RawMessage(digestJSON),
		"r3_granted": json.RawMessage(wrongGrantedJSON),
	}
	wrongOperationToken := signCoreTokenPayload(t, accessKey, aauth.AuthTokenType, baseMembers)
	if _, _, _, err := r3.VerifyMCPPerCallAuthToken(context.Background(), wrongOperationToken, resolver, clock, reference, exactProposal); err == nil {
		t.Fatal("per-call verifier accepted a different granted operation")
	}
	wrongAccountMembers := cloneCoreTokenMembers(baseMembers)
	correctGranted, _ := r3.NewGrantedOperations(operation)
	correctGrantedJSON, _ := json.Marshal(correctGranted)
	wrongAccountMembers["r3_granted"] = json.RawMessage(correctGrantedJSON)
	wrongAccountMembers["account"] = "other"
	wrongAccountToken := signCoreTokenPayload(t, accessKey, aauth.AuthTokenType, wrongAccountMembers)
	if _, _, _, err := r3.VerifyMCPPerCallAuthToken(context.Background(), wrongAccountToken, resolver, clock, reference, exactProposal); err == nil {
		t.Fatal("per-call verifier accepted a different account")
	}
	otherReference, _ := r3.NewReference("https://resource.example/r3/proposal-other", reference.Digest())
	otherURIJSON, _ := json.Marshal(otherReference.URI())
	wrongReferenceMembers := cloneCoreTokenMembers(baseMembers)
	wrongReferenceMembers["r3_uri"] = json.RawMessage(otherURIJSON)
	wrongReferenceMembers["r3_granted"] = json.RawMessage(correctGrantedJSON)
	wrongReferenceToken := signCoreTokenPayload(t, accessKey, aauth.AuthTokenType, wrongReferenceMembers)
	if _, _, _, err := r3.VerifyMCPPerCallAuthToken(context.Background(), wrongReferenceToken, resolver, clock, reference, exactProposal); err == nil {
		t.Fatal("per-call verifier accepted a different proposal reference")
	}
	_, _, operationClaims, err := r3.VerifyMCPAuthTokenClaims(context.Background(), authCompact, resolver, clock)
	if err != nil || !operationClaims.GrantedOperations().Contains(operation) || len(operationClaims.PerCallOperations().Operations()) != 0 {
		t.Fatalf("general per-call verification = %#v, %v", operationClaims, err)
	}

	changed := append(append([]byte(nil), exactProposal...), '\n')
	if _, err := r3.ParseMCPProposal(changed); err != nil {
		t.Fatalf("valid reserialization fixture is invalid: %v", err)
	}
	if _, err := r3.ParseReferencedProposal(reference, changed); err == nil {
		t.Fatal("reference accepted a valid proposal reserialization with different exact bytes")
	}
	if _, err := r3.MintMCPPerCallAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "changed",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()}, Account: &account,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, reference, changed); err == nil {
		t.Fatal("per-call mint accepted proposal bytes that changed after hashing")
	}
	otherAccount := "other"
	if _, err := r3.MintMCPPerCallAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "wrong-account",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()}, Account: &otherAccount,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, reference, exactProposal); err == nil {
		t.Fatal("per-call mint accepted a proposal/account mismatch")
	}
}

func TestMCPR3AuthClaimVerificationRejectsMalformedPerCallShapes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 12, 30, 0, 0, time.UTC)
	accessKey := coreTokenKey(t, "access-key")
	requestKey := coreTokenKey(t, "request-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://access.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}: accessKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })
	digest := r3.Digest([]byte("document"))
	base := map[string]any{
		"iss": "https://access.example", "dwk": aauth.AccessDiscoveryDocument,
		"aud": "https://resource.example", "jti": "auth-token",
		"ps": "https://person.example", "sub": "person-1",
		"cnf": map[string]any{"jwk": requestKey.PublicJWK()},
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"r3_uri": "https://resource.example/r3/class", "r3_s256": digest,
		"r3_granted": json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}`),
	}
	for _, test := range []struct {
		name  string
		claim string
		value any
	}{
		{"overlap", "r3_per_call", json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.read"}]}`)},
		{"wrong vocabulary", "r3_per_call", json.RawMessage(`{"vocabulary":"urn:example:other","operations":[{"tool":"records.delete"}]}`)},
		{"missing operations", "r3_per_call", json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:mcp"}`)},
		{"duplicate tool", "r3_per_call", json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.delete"},{"tool":"records.delete"}]}`)},
		{"non-object", "r3_per_call", true},
		{"case variant", "R3_Per_Call", json.RawMessage(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.delete"}]}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			members := cloneCoreTokenMembers(base)
			members[test.claim] = test.value
			compact := signCoreTokenPayload(t, accessKey, aauth.AuthTokenType, members)
			if _, _, _, err := r3.VerifyMCPAuthTokenClaims(context.Background(), compact, resolver, clock); err == nil {
				t.Fatal("accepted malformed r3_per_call claim")
			}
		})
	}
}

func assertCompactOmitsClaim(t *testing.T, compact, claim string) {
	t.Helper()
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(parsed.Payload(), &members); err != nil {
		t.Fatal(err)
	}
	if _, present := members[claim]; present {
		t.Fatalf("compact token unexpectedly contains %q", claim)
	}
}

func compactClaimMap(t *testing.T, compact string) map[string]json.RawMessage {
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

func assertCompactStringClaim(t *testing.T, compact, claim, want string) {
	t.Helper()
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(parsed.Payload(), &members); err != nil {
		t.Fatal(err)
	}
	raw, present := members[claim]
	if !present {
		t.Fatalf("compact token omits %q", claim)
	}
	var got string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("compact token %q is not a string: %v", claim, err)
	}
	if got != want {
		t.Fatalf("compact token %q = %q, want %q", claim, got, want)
	}
}
