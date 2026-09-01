package aauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestR3BudgetTokenAPIsVerifyBothCompanionsTogether(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 1, 5, 0, 0, 0, time.UTC)
	resourceKey := coreTokenKey(t, "r3-budget-resource-key")
	personKey := coreTokenKey(t, "r3-budget-person-key")
	agentKey := coreTokenKey(t, "r3-budget-agent-key")
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
		{Issuer: "https://person.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
	}
	clock := aauth.ClockFunc(func() time.Time { return now })

	operation, err := newMCPR3Operation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	operations, err := r3.NewOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	document, err := r3.NewDocument(operations, r3.DocumentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	exactDocument, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), operation)
	if err != nil {
		t.Fatal(err)
	}
	operationGrant, err := r3.NewGrant(granted, document)
	if err != nil {
		t.Fatal(err)
	}
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := budgets.NewValue(600_000, unit)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := budgets.NewValue(400_000, unit)
	if err != nil {
		t.Fatal(err)
	}

	resourceCompact, reference, err := r3.MintBudgetResourceToken(
		tokenMCPRegistry,
		resourceKey,
		aauth.ResourceTokenClaims{
			Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
			Audience: "https://person.example", JTI: "r3-budget-resource-token",
			PersonServer: "https://person.example", Subject: "person-1", PresentedJTI: "person-token-1",
			AgentJKT: coreTokenS256("agent-key"),
			IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
		},
		"https://resource.example/r3/connector",
		exactDocument,
		offer,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims, gotReference, gotOffer, consumed, err := r3.VerifyBudgetResourceToken(
		context.Background(), tokenMCPRegistry, resourceCompact, resolver, clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	if resourceClaims.JTI != "r3-budget-resource-token" || gotReference != reference ||
		gotOffer.Amount() != offer.Amount() || !gotOffer.Unit().Equal(offer.Unit()) || len(consumed) != 0 {
		t.Fatalf("verified Resource token = %#v, %#v, %#v, %#v", resourceClaims, gotReference, gotOffer, consumed)
	}
	if _, _, err := r3.VerifyResourceToken(context.Background(), resourceCompact, resolver, clock); err == nil {
		t.Fatal("R3-only verifier accepted a combined Resource token")
	}
	if _, _, _, err := budgets.VerifyResourceToken(context.Background(), resourceCompact, resolver, clock); err == nil {
		t.Fatal("Budget-only verifier accepted a combined Resource token")
	}
	resourceMembers := compactClaimMap(t, resourceCompact)
	delete(resourceMembers, "budget")
	partialResource := signCoreTokenPayload(t, resourceKey, aauth.ResourceTokenType, rawMembers(resourceMembers))
	if _, _, _, _, err := r3.VerifyBudgetResourceToken(
		context.Background(), tokenMCPRegistry, partialResource, resolver, clock,
	); err == nil {
		t.Fatal("combined verifier accepted an R3 Resource token without budget")
	}
	resourceMembers = compactClaimMap(t, resourceCompact)
	resourceMembers["Budget"] = resourceMembers["budget"]
	delete(resourceMembers, "budget")
	caseVariantResource := signCoreTokenPayload(t, resourceKey, aauth.ResourceTokenType, rawMembers(resourceMembers))
	if _, _, _, _, err := r3.VerifyBudgetResourceToken(
		context.Background(), tokenMCPRegistry, caseVariantResource, resolver, clock,
	); err == nil {
		t.Fatal("combined verifier accepted a noncanonical Budget claim")
	}

	authCompact, err := r3.MintDirectBudgetAuthToken(
		tokenMCPRegistry,
		personKey,
		aauth.AuthTokenClaims{
			Issuer: "https://person.example", DWK: aauth.PersonDiscoveryDocument,
			Audience: "https://resource.example", JTI: "r3-budget-auth-token",
			PersonServer: "https://person.example", Subject: "person-1",
			Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		},
		reference,
		exactDocument,
		operationGrant,
		grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	authClaims, authReference, authOperations, gotGrant, err := r3.VerifyDirectBudgetAuthToken(
		context.Background(), tokenMCPRegistry, authCompact, resolver, clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.JTI != "r3-budget-auth-token" || authReference != reference ||
		gotGrant.Amount() != grant.Amount() || !gotGrant.Unit().Equal(grant.Unit()) ||
		!tokenGrantedEqual(t, authOperations.GrantedOperations(), operationGrant.GrantedOperations()) {
		t.Fatalf("verified Auth token = %#v, %#v, %#v, %#v", authClaims, authReference, authOperations, gotGrant)
	}
	if _, _, _, err := r3.VerifyDirectAuthToken(context.Background(), tokenMCPRegistry, authCompact, resolver, clock); err == nil {
		t.Fatal("R3-only verifier accepted a combined Auth token")
	}
	if _, _, err := budgets.VerifyAuthToken(context.Background(), authCompact, resolver, clock); err == nil {
		t.Fatal("Budget-only verifier accepted a combined Auth token")
	}
	authMembers := compactClaimMap(t, authCompact)
	authMembers["budget_consumed"] = json.RawMessage(`[]`)
	invalidAuth := signCoreTokenPayload(t, personKey, aauth.AuthTokenType, rawMembers(authMembers))
	if _, _, _, _, err := r3.VerifyDirectBudgetAuthToken(
		context.Background(), tokenMCPRegistry, invalidAuth, resolver, clock,
	); err == nil {
		t.Fatal("combined verifier accepted budget_consumed in an Auth token")
	}
}

func rawMembers(members map[string]json.RawMessage) map[string]any {
	result := make(map[string]any, len(members))
	for name, value := range members {
		result[name] = value
	}
	return result
}

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

	operation, err := newMCPR3Operation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	operations, err := r3.NewOperationSet(operation)
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
	granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), operation)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := r3.NewGrant(granted, document)
	if err != nil {
		t.Fatal(err)
	}

	resourceCompact, reference, err := r3.MintResourceToken(tokenMCPRegistry, resourceKey, aauth.ResourceTokenClaims{
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
	resourceClaims, resourceReference, err := r3.VerifyResourceToken(context.Background(), resourceCompact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if resourceClaims.JTI != "resource-token-1" || resourceReference != reference {
		t.Fatalf("verified resource token = (%#v, %#v)", resourceClaims, resourceReference)
	}

	authCompact, err := r3.MintDirectAuthToken(tokenMCPRegistry, accessKey, aauth.AuthTokenClaims{
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
	authClaims, authReference, grantedOperations, err := r3.VerifyDirectAuthToken(context.Background(), tokenMCPRegistry, authCompact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.JTI != "auth-token-1" || authReference != reference || !tokenGrantedEqual(t, grantedOperations, grant.GrantedOperations()) {
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
		"vocabulary": mcp.URI,
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
			if _, _, err := r3.VerifyResourceToken(context.Background(), compact, resolver, clock); err == nil {
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
			if _, _, _, err := r3.VerifyDirectAuthToken(context.Background(), tokenMCPRegistry, compact, resolver, clock); err == nil {
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
	resourceClaims, _, err := r3.VerifyResourceToken(context.Background(), resourceCompact, resolver, clock)
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
		"r3_granted": map[string]any{"vocabulary": mcp.URI, "operations": []any{}},
		"r3_future":  map[string]any{"retained": true},
	}
	authCompact := signCoreTokenPayload(t, accessKey, aauth.AuthTokenType, authMembers)
	authClaims, _, granted, err := r3.VerifyDirectAuthToken(context.Background(), tokenMCPRegistry, authCompact, resolver, clock)
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
	operation, err := newMCPR3Operation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	operations, err := r3.NewOperationSet(operation)
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
	granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), operation)
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
	scopelessAuthCompact, err := r3.MintDirectAuthToken(tokenMCPRegistry, key, scopelessAuth, reference, documentBytes, grant)
	if err != nil {
		t.Fatalf("MintR3AuthToken rejected a source-valid scopeless token: %v", err)
	}
	assertCompactOmitsClaim(t, scopelessAuthCompact, "scope")

	if _, err := r3.MintDirectAuthToken(tokenMCPRegistry, key, base, r3.Reference{}, documentBytes, grant); err == nil {
		t.Fatal("MintR3AuthToken accepted an empty reference")
	}
	if _, err := r3.MintDirectAuthToken(tokenMCPRegistry, key, base, reference, documentBytes, r3.Grant{}); err == nil {
		t.Fatal("MintR3AuthToken accepted an unproven empty grant")
	}
	if _, err := r3.MintDirectAuthToken(tokenMCPRegistry, key, base, reference, []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"other"}]}`), grant); err == nil {
		t.Fatal("MintR3AuthToken accepted document bytes that do not match the reference")
	}
	otherDocumentBytes := []byte(`{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"other"}]}`)
	otherReference, err := r3.NewReference("https://resource.example/r3/other", r3.Digest(otherDocumentBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r3.MintDirectAuthToken(tokenMCPRegistry, key, base, otherReference, otherDocumentBytes, grant); err == nil {
		t.Fatal("MintR3AuthToken accepted a grant that was not a subset of the referenced document")
	}
	for _, name := range []string{"r3_uri", "R3_S256", "r3_granted", "r3_per_call", "budget"} {
		claims := base
		claims.AdditionalClaims = map[string]json.RawMessage{name: json.RawMessage(`true`)}
		if _, err := r3.MintDirectAuthToken(tokenMCPRegistry, key, claims, reference, documentBytes, grant); err == nil {
			t.Fatalf("MintR3AuthToken accepted colliding additional claim %q", name)
		}
	}

	resourceBase := aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-token-1",
		PersonServer: "https://person.example", Subject: "person-1", PresentedJTI: "person-token-1",
		AgentJKT: coreTokenS256("agent-key"), IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
	scopelessResourceCompact, _, err := r3.MintResourceToken(tokenMCPRegistry, key, resourceBase, "https://resource.example/r3/one", documentBytes)
	if err != nil {
		t.Fatalf("MintR3ResourceToken rejected a source-valid scopeless token: %v", err)
	}
	assertCompactOmitsClaim(t, scopelessResourceCompact, "scope")
	if _, _, err := r3.MintResourceToken(tokenMCPRegistry, key, resourceBase, "", documentBytes); err == nil {
		t.Fatal("MintR3ResourceToken accepted an empty document URI")
	}
	if _, _, err := r3.MintResourceToken(tokenMCPRegistry, key, resourceBase, "https://resource.example/r3/one", []byte(`{}`)); err == nil {
		t.Fatal("MintR3ResourceToken accepted invalid document bytes")
	}
	for _, name := range []string{"r3_uri", "R3_S256", "r3_granted", "r3_per_call", "budget"} {
		claims := resourceBase
		claims.AdditionalClaims = map[string]json.RawMessage{name: json.RawMessage(`true`)}
		if _, _, err := r3.MintResourceToken(tokenMCPRegistry, key, claims, "https://resource.example/r3/one", documentBytes); err == nil {
			t.Fatalf("MintR3ResourceToken accepted colliding additional claim %q", name)
		}
	}
}

func TestMCPR3TokenMintersBindDocumentAccountExactly(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	key := coreTokenKey(t, "issuer-key")
	requestKey := coreTokenKey(t, "request-key")
	operation, err := newMCPR3Operation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	operations, err := r3.NewOperationSet(operation)
	if err != nil {
		t.Fatal(err)
	}
	granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), operation)
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
	if _, _, err := r3.MintResourceToken(tokenMCPRegistry, key, matchingResource, withAccountReference.URI(), withAccountBytes); err != nil {
		t.Fatalf("matching Resource account rejected: %v", err)
	}
	matchingAuth := authClaims
	matchingAuth.Account = &account
	if _, err := r3.MintDirectAuthToken(tokenMCPRegistry, key, matchingAuth, withAccountReference, withAccountBytes, withAccountGrant); err != nil {
		t.Fatalf("matching Auth account rejected: %v", err)
	}

	emptyAccount := ""
	otherAccount := "other-account"
	for _, tokenAccount := range []*string{nil, &emptyAccount, &otherAccount} {
		claims := resourceClaims
		claims.Account = tokenAccount
		if _, _, err := r3.MintResourceToken(tokenMCPRegistry, key, claims, withAccountReference.URI(), withAccountBytes); err == nil {
			t.Fatalf("Resource token account %#v accepted document account %q", tokenAccount, account)
		}
		auth := authClaims
		auth.Account = tokenAccount
		if _, err := r3.MintDirectAuthToken(tokenMCPRegistry, key, auth, withAccountReference, withAccountBytes, withAccountGrant); err == nil {
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
	if _, _, err := r3.MintResourceToken(tokenMCPRegistry, key, matchingResource, withoutAccountReference.URI(), withoutAccountBytes); err == nil {
		t.Fatal("Resource token account accepted a document without account")
	}
	if _, err := r3.MintDirectAuthToken(tokenMCPRegistry, key, matchingAuth, withoutAccountReference, withoutAccountBytes, withoutAccountGrant); err == nil {
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
	emptyResourceCompact, _, err := r3.MintResourceToken(tokenMCPRegistry, key, emptyResource, emptyAccountReference.URI(), emptyAccountDocumentBytes)
	if err != nil {
		t.Fatalf("matching present-empty Resource account rejected: %v", err)
	}
	emptyAuth := authClaims
	emptyAuth.Account = &emptyAccount
	emptyAuthCompact, err := r3.MintDirectAuthToken(tokenMCPRegistry, key, emptyAuth, emptyAccountReference, emptyAccountDocumentBytes, emptyAccountGrant)
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
		"r3_granted": map[string]any{"vocabulary": mcp.URI, "operations": []any{}},
	}

	empty := ""
	named := "work-account"
	operation, err := newMCPR3Operation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	operations, err := r3.NewOperationSet(operation)
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
			resourceClaims, _, resourceErr := r3.VerifyResourceToken(context.Background(), resourceCompact, resolver, clock)
			authCompact := signCoreTokenPayload(t, accessKey, aauth.AuthTokenType, authMembers)
			authClaims, _, _, authErr := r3.VerifyDirectAuthToken(context.Background(), tokenMCPRegistry, authCompact, resolver, clock)
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
	operation, err := newMCPR3Operation("records.read")
	if err != nil {
		t.Fatal(err)
	}
	operations, err := r3.NewOperationSet(operation)
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
	granted, err := r3.NewGrantedOperations(mcp.Vocabulary(), operation)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := r3.NewGrant(granted, document)
	if err != nil {
		t.Fatal(err)
	}

	resourceRaw := json.RawMessage(`{"value":"resource-original"}`)
	resourceAdditional := map[string]json.RawMessage{"r3_future": resourceRaw}
	resourceCompact, reference, err := r3.MintResourceToken(tokenMCPRegistry, resourceKey, aauth.ResourceTokenClaims{
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
	authCompact, err := r3.MintDirectAuthToken(tokenMCPRegistry, accessKey, aauth.AuthTokenClaims{
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
	firstResource, _, err := r3.VerifyResourceToken(context.Background(), resourceCompact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(firstResource.AdditionalClaims["r3_future"]); got != `{"value":"resource-original"}` {
		t.Fatalf("first Resource additional claim = %s", got)
	}
	firstResource.AdditionalClaims["r3_future"][0] = '['
	firstResource.AdditionalClaims["r3_future"] = json.RawMessage(`null`)
	secondResource, _, err := r3.VerifyResourceToken(context.Background(), resourceCompact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(secondResource.AdditionalClaims["r3_future"]); got != `{"value":"resource-original"}` {
		t.Fatalf("second Resource additional claim = %s", got)
	}

	firstAuth, _, _, err := r3.VerifyDirectAuthToken(context.Background(), tokenMCPRegistry, authCompact, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(firstAuth.AdditionalClaims["r3_future"]); got != `{"value":"auth-original"}` {
		t.Fatalf("first Auth additional claim = %s", got)
	}
	firstAuth.AdditionalClaims["r3_future"][0] = '['
	firstAuth.AdditionalClaims["r3_future"] = json.RawMessage(`null`)
	secondAuth, _, _, err := r3.VerifyDirectAuthToken(context.Background(), tokenMCPRegistry, authCompact, resolver, clock)
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
	read, _ := newMCPR3Operation("records.read")
	deleteRecord, _ := newMCPR3Operation("records.delete")
	operations, _ := r3.NewOperationSet(read, deleteRecord)
	document, _ := r3.NewDocument(operations, r3.DocumentOptions{})
	exactDocument, _ := json.Marshal(document)
	reference, _ := r3.NewReference("https://resource.example/r3/class-one", r3.Digest(exactDocument))
	granted, _ := r3.NewGrantedOperations(mcp.Vocabulary(), read)
	perCall, _ := r3.NewGrantedOperations(mcp.Vocabulary(), deleteRecord)
	authorization, err := r3.NewAuthorization(granted, perCall, document)
	if err != nil {
		t.Fatal(err)
	}

	compact, err := r3.MintAuthToken(tokenMCPRegistry, accessKey, aauth.AuthTokenClaims{
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
	claims, gotReference, operationClaims, err := r3.VerifyAuthTokenClaims(
		context.Background(), tokenMCPRegistry, compact, resolver, clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	if claims.JTI != "class-auth-token" || gotReference != reference ||
		!tokenGrantedEqual(t, operationClaims.GrantedOperations(), granted) ||
		!tokenGrantedEqual(t, operationClaims.PerCallOperations(), perCall) {
		t.Fatalf("verified class token = %#v, %#v, %#v", claims, gotReference, operationClaims)
	}
	if _, _, _, err := r3.VerifyDirectAuthToken(context.Background(), tokenMCPRegistry, compact, resolver, clock); err == nil {
		t.Fatal("direct-only verifier accepted a class token with r3_per_call")
	}
	if _, err := aauth.VerifyAuthToken(context.Background(), compact, resolver, clock); err == nil {
		t.Fatal("Core verifier accepted a class R3 token")
	}

	if _, err := r3.NewAuthorization(granted, granted, document); err == nil {
		t.Fatal("accepted an operation in both r3_granted and r3_per_call")
	}
	outside, _ := newMCPR3Operation("records.export")
	outsideSet, _ := r3.NewGrantedOperations(mcp.Vocabulary(), outside)
	if _, err := r3.NewAuthorization(outsideSet, perCall, document); err == nil {
		t.Fatal("accepted a direct operation outside the class document")
	}
	if _, err := r3.NewAuthorization(granted, outsideSet, document); err == nil {
		t.Fatal("accepted a per-call operation outside the class document")
	}
	if _, err := r3.MintAuthToken(tokenMCPRegistry, accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "zero-authorization",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, reference, exactDocument, r3.Authorization{}); err == nil {
		t.Fatal("class mint accepted an unproven zero Authorization")
	}
	empty, _ := r3.NewGrantedOperations(mcp.Vocabulary())
	directOnly, _ := r3.NewAuthorization(granted, empty, document)
	directOnlyCompact, err := r3.MintAuthToken(tokenMCPRegistry, accessKey, aauth.AuthTokenClaims{
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
	operation, _ := newMCPR3Operation("records.delete")
	identifier, _ := r3.NewInlineParameter([]byte(`"record-7"`))
	parameters, _ := r3.NewParameters(map[string]r3.Parameter{"id": identifier})
	account := "work"
	proposal, _ := r3.NewProposal(operation, parameters, r3.ProposalOptions{Account: &account})
	exactProposal, _ := json.Marshal(proposal)

	resourceCompact, reference, err := r3.MintProposalResourceToken(tokenMCPRegistry, resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "proposal-resource-token",
		PersonServer: "https://person.example", Subject: "person-1", PresentedJTI: "person-token-1",
		AgentJKT: coreTokenS256("agent-key"), Account: &account,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}, "https://resource.example/r3/proposal-one", exactProposal)
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims, gotReference, err := r3.VerifyResourceToken(context.Background(), resourceCompact, resolver, clock)
	if err != nil || resourceClaims.JTI != "proposal-resource-token" || gotReference != reference {
		t.Fatalf("proposal Resource token = %#v, %#v, %v", resourceClaims, gotReference, err)
	}
	proposalResourceMembers := compactClaimMap(t, resourceCompact)
	for _, forbidden := range []string{"r3_granted", "r3_per_call", "parameters"} {
		if _, ok := proposalResourceMembers[forbidden]; ok {
			t.Fatalf("proposal Resource token contains %q", forbidden)
		}
	}
	parsed, err := tokenMCPRegistry.ParseReferencedProposal(reference, exactProposal)
	if err != nil || mcpR3Tool(t, parsed.Operation()) != mcpR3Tool(t, operation) {
		t.Fatalf("referenced proposal = %#v, %v", parsed, err)
	}

	authCompact, err := r3.MintPerCallAuthToken(tokenMCPRegistry, accessKey, aauth.AuthTokenClaims{
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
	authClaims, authReference, grantedOperation, err := r3.VerifyPerCallAuthToken(
		context.Background(), tokenMCPRegistry, authCompact, resolver, clock, reference, exactProposal,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.JTI != "per-call-auth-token" || authReference != reference ||
		mcpR3Tool(t, grantedOperation) != mcpR3Tool(t, operation) {
		t.Fatalf("per-call Auth token = %#v, %#v, %#v", authClaims, authReference, grantedOperation)
	}
	wrongOperation, _ := newMCPR3Operation("records.export")
	wrongGranted, _ := r3.NewGrantedOperations(mcp.Vocabulary(), wrongOperation)
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
	if _, _, _, err := r3.VerifyPerCallAuthToken(context.Background(), tokenMCPRegistry, wrongOperationToken, resolver, clock, reference, exactProposal); err == nil {
		t.Fatal("per-call verifier accepted a different granted operation")
	}
	wrongAccountMembers := cloneCoreTokenMembers(baseMembers)
	correctGranted, _ := r3.NewGrantedOperations(mcp.Vocabulary(), operation)
	correctGrantedJSON, _ := json.Marshal(correctGranted)
	wrongAccountMembers["r3_granted"] = json.RawMessage(correctGrantedJSON)
	wrongAccountMembers["account"] = "other"
	wrongAccountToken := signCoreTokenPayload(t, accessKey, aauth.AuthTokenType, wrongAccountMembers)
	if _, _, _, err := r3.VerifyPerCallAuthToken(context.Background(), tokenMCPRegistry, wrongAccountToken, resolver, clock, reference, exactProposal); err == nil {
		t.Fatal("per-call verifier accepted a different account")
	}
	otherReference, _ := r3.NewReference("https://resource.example/r3/proposal-other", reference.Digest())
	otherURIJSON, _ := json.Marshal(otherReference.URI())
	wrongReferenceMembers := cloneCoreTokenMembers(baseMembers)
	wrongReferenceMembers["r3_uri"] = json.RawMessage(otherURIJSON)
	wrongReferenceMembers["r3_granted"] = json.RawMessage(correctGrantedJSON)
	wrongReferenceToken := signCoreTokenPayload(t, accessKey, aauth.AuthTokenType, wrongReferenceMembers)
	if _, _, _, err := r3.VerifyPerCallAuthToken(context.Background(), tokenMCPRegistry, wrongReferenceToken, resolver, clock, reference, exactProposal); err == nil {
		t.Fatal("per-call verifier accepted a different proposal reference")
	}
	_, _, operationClaims, err := r3.VerifyAuthTokenClaims(context.Background(), tokenMCPRegistry, authCompact, resolver, clock)
	if err != nil || !tokenGrantedContains(t, operationClaims.GrantedOperations(), operation) || len(operationClaims.PerCallOperations().Operations()) != 0 {
		t.Fatalf("general per-call verification = %#v, %v", operationClaims, err)
	}

	changed := append(append([]byte(nil), exactProposal...), '\n')
	if _, err := tokenMCPRegistry.ParseProposal(changed); err != nil {
		t.Fatalf("valid reserialization fixture is invalid: %v", err)
	}
	if _, err := tokenMCPRegistry.ParseReferencedProposal(reference, changed); err == nil {
		t.Fatal("reference accepted a valid proposal reserialization with different exact bytes")
	}
	if _, err := r3.MintPerCallAuthToken(tokenMCPRegistry, accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "changed",
		PersonServer: "https://person.example", Subject: "person-1",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()}, Account: &account,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}, reference, changed); err == nil {
		t.Fatal("per-call mint accepted proposal bytes that changed after hashing")
	}
	otherAccount := "other"
	if _, err := r3.MintPerCallAuthToken(tokenMCPRegistry, accessKey, aauth.AuthTokenClaims{
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
			if _, _, _, err := r3.VerifyAuthTokenClaims(context.Background(), tokenMCPRegistry, compact, resolver, clock); err == nil {
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
