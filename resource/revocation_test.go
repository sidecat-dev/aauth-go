package resource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestPSAuthTokenCanBeObservedRevokedAndThenRefused(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "revocation-person", 71)
	resourceKey := testSigningKey(t, "revocation-resource", 72)
	agentKey := testSigningKey(t, "revocation-agent", 73)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
	}
	statuses := newTestAuthTokenStatusStore()
	resolveCalls, protectedCalls := 0, 0
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "unused-resource-token" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson: func(context.Context, PersonIdentity, PersonContext) error {
			resolveCalls++
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			protectedCalls++
			response.WriteHeader(http.StatusNoContent)
		}),
		AuthTokenStatuses: statuses,
	})
	if err != nil {
		t.Fatal(err)
	}

	metadata := httptest.NewRecorder()
	server.Handler().ServeHTTP(metadata, httptest.NewRequest(http.MethodGet, resourceIssuer+"/.well-known/aauth-resource.json", nil))
	var document map[string]json.RawMessage
	if err := json.Unmarshal(metadata.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if got := string(document["revocation_endpoint"]); got != `"`+resourceIssuer+`/revoke"` {
		t.Fatalf("revocation_endpoint = %s", got)
	}

	authToken := mintAuthToken(t, personKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		JTI: "revocable-auth-token", PersonServer: personIssuer, Subject: "person-1",
		Scope: "records.read", Tenant: "tenant-1",
	})
	protected := signedRequest(t, clock, agentKey, authToken, http.MethodGet, resourceIssuer+"/records", "")
	protectedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(protectedResponse, protected)
	if protectedResponse.Code != http.StatusNoContent || resolveCalls != 1 || protectedCalls != 1 {
		t.Fatalf("first use = %d %s; resolve=%d protected=%d", protectedResponse.Code, protectedResponse.Body.String(), resolveCalls, protectedCalls)
	}
	observed, ok := statuses.record(aauth.TokenReference{Issuer: personIssuer, JTI: "revocable-auth-token"})
	if !ok || observed.ExpiresAt != now.Add(time.Hour) || observed.CompactSHA256 != sha256.Sum256([]byte(authToken)) {
		t.Fatalf("observed auth token = %#v, present=%t", observed, ok)
	}
	repeatedUse := signedRequest(t, clock, agentKey, authToken, http.MethodGet, resourceIssuer+"/records/repeated", "")
	repeatedUseResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(repeatedUseResponse, repeatedUse)
	if repeatedUseResponse.Code != http.StatusNoContent || resolveCalls != 2 || protectedCalls != 2 {
		t.Fatalf("active repeat = %d %s; resolve=%d protected=%d", repeatedUseResponse.Code, repeatedUseResponse.Body.String(), resolveCalls, protectedCalls)
	}

	revoke := signedRevocationRequest(t, clock, personKey, personIssuer, "revocable-auth-token")
	revokeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(revokeResponse, revoke)
	if revokeResponse.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", revokeResponse.Code, revokeResponse.Body.String())
	}
	repeated := signedRevocationRequest(t, clock, personKey, personIssuer, "revocable-auth-token")
	repeatedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(repeatedResponse, repeated)
	if repeatedResponse.Code != http.StatusOK {
		t.Fatalf("repeated revoke = %d %s", repeatedResponse.Code, repeatedResponse.Body.String())
	}

	refused := signedRequest(t, clock, agentKey, authToken, http.MethodGet, resourceIssuer+"/records", "")
	refusedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(refusedResponse, refused)
	if resolveCalls != 2 || protectedCalls != 2 {
		t.Fatalf("revoked use reached callbacks; resolve=%d protected=%d", resolveCalls, protectedCalls)
	}
	assertRevokedAuthTokenResponse(t, refusedResponse)

	unknown := signedRevocationRequest(t, clock, personKey, personIssuer, "unknown-auth-token")
	unknownResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(unknownResponse, unknown)
	if unknownResponse.Code != http.StatusOK {
		t.Fatalf("unknown revoke = %d %s", unknownResponse.Code, unknownResponse.Body.String())
	}
	previouslyUnknown := mintAuthToken(t, personKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		JTI: "unknown-auth-token", PersonServer: personIssuer, Subject: "person-1",
		Scope: "records.read", Tenant: "tenant-1",
	})
	firstUse := signedRequest(t, clock, agentKey, previouslyUnknown, http.MethodGet, resourceIssuer+"/records/new", "")
	firstUseResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(firstUseResponse, firstUse)
	assertRevokedAuthTokenResponse(t, firstUseResponse)
	if protectedCalls != 2 {
		t.Fatalf("first use after pre-use revoke reached protected handler; protected=%d", protectedCalls)
	}
}

func TestPSAuthorizationOmitsRevocationWhenNoStatusStoreIsConfigured(t *testing.T) {
	t.Parallel()

	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: resourceIssuer, SigningKey: testSigningKey(t, "no-revocation-resource", 82),
		KeyResolver: signaturekey.StaticKeyResolver{}, Clock: aauth.SystemClock{},
		NewID:             func() string { return "unused" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected:         http.NotFoundHandler(),
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata := httptest.NewRecorder()
	server.Handler().ServeHTTP(metadata, httptest.NewRequest(http.MethodGet, resourceIssuer+"/.well-known/aauth-resource.json", nil))
	var document map[string]json.RawMessage
	if err := json.Unmarshal(metadata.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if _, advertised := document["revocation_endpoint"]; advertised {
		t.Fatalf("unconfigured revocation was advertised: %s", metadata.Body.String())
	}
	request := httptest.NewRequest(http.MethodPost, resourceIssuer+"/revoke", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code == http.StatusOK {
		t.Fatal("unconfigured revocation endpoint accepted a request")
	}
}

func TestRevocationKeysTheSameJTIByIssuer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 10, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const otherPersonIssuer = "https://other-person.example"
	personKey := testSigningKey(t, "namespace-person-a", 83)
	otherPersonKey := testSigningKey(t, "namespace-person-b", 84)
	resourceKey := testSigningKey(t, "namespace-resource", 85)
	agentKey := testSigningKey(t, "namespace-agent", 86)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:           personKey.PublicJWK(),
		{Issuer: otherPersonIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: otherPersonKey.ID()}: otherPersonKey.PublicJWK(),
	}
	statuses := newTestAuthTokenStatusStore()
	protectedCalls := 0
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "unused" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			protectedCalls++
			response.WriteHeader(http.StatusNoContent)
		}),
		AuthTokenStatuses: statuses,
	})
	if err != nil {
		t.Fatal(err)
	}
	mint := func(key jose.SigningKey, issuer string) string {
		return mintAuthToken(t, key, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
			Issuer: issuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
			JTI: "same-jti", PersonServer: issuer, Subject: "person-1", Scope: "records.read",
		})
	}
	first, second := mint(personKey, personIssuer), mint(otherPersonKey, otherPersonIssuer)
	use := func(compact, path string) *httptest.ResponseRecorder {
		request := signedRequest(t, clock, agentKey, compact, http.MethodGet, resourceIssuer+path, "")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	if response := use(first, "/first"); response.Code != http.StatusNoContent {
		t.Fatalf("first issuer use = %d %s", response.Code, response.Body.String())
	}
	if response := use(second, "/second"); response.Code != http.StatusNoContent {
		t.Fatalf("second issuer use = %d %s", response.Code, response.Body.String())
	}
	revoke := signedRevocationRequestWith(
		t, clock, personKey, personIssuer, aauth.PersonDiscoveryDocument,
		aauth.TokenReference{Issuer: personIssuer, JTI: "same-jti"}, nil, nil,
	)
	revoked := httptest.NewRecorder()
	server.Handler().ServeHTTP(revoked, revoke)
	if revoked.Code != http.StatusOK {
		t.Fatalf("first issuer revoke = %d %s", revoked.Code, revoked.Body.String())
	}
	assertRevokedAuthTokenResponse(t, use(first, "/first-again"))
	if response := use(second, "/second-again"); response.Code != http.StatusNoContent {
		t.Fatalf("active second issuer use = %d %s", response.Code, response.Body.String())
	}
	if protectedCalls != 3 {
		t.Fatalf("protected calls = %d, want first, second, and second again", protectedCalls)
	}
}

func TestRevocationEndpointRequiresBoundPersonServerProof(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 15, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "revocation-proof-person", 74)
	resourceKey := testSigningKey(t, "revocation-proof-resource", 75)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
		{Issuer: personIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
	}
	statuses := newTestAuthTokenStatusStore()
	reference := aauth.TokenReference{Issuer: personIssuer, JTI: "proof-bound-auth-token"}
	if err := statuses.Observe(context.Background(), ObservedAuthToken{
		Reference: reference, CompactSHA256: [32]byte{1}, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "unused" },
		ScopeDescriptions:             map[string]string{"records.read": "Read records"},
		AdditionalSignatureComponents: []string{"x-revocation-context"},
		RequiredScopes:                func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:                 func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected:                     http.NotFoundHandler(),
		AuthTokenStatuses:             statuses,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSignatureFailure := func(name string, request *http.Request) {
		t.Helper()
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || response.Header().Get("Signature-Error") == "" {
			t.Fatalf("%s = %d %s headers=%v", name, response.Code, response.Body.String(), response.Header())
		}
	}

	unsignedBody, _ := json.Marshal(map[string]any{"jti": reference.JTI, "exp": clock.Now().Add(time.Hour).Unix()})
	unsigned := httptest.NewRequest(http.MethodPost, resourceIssuer+"/revoke", bytes.NewReader(unsignedBody))
	unsigned.Header.Set("Content-Type", "application/json")
	assertSignatureFailure("unsigned", unsigned)

	missingAdditional := signedRevocationRequest(t, clock, personKey, personIssuer, reference.JTI)
	assertSignatureFailure("missing advertised component", missingAdditional)

	tampered := signedRevocationRequestWith(
		t, clock, personKey, personIssuer, aauth.PersonDiscoveryDocument, reference,
		map[string]string{"X-Revocation-Context": "audit-1"}, []string{"x-revocation-context"},
	)
	changed, _ := json.Marshal(map[string]any{"jti": "another-token", "exp": clock.Now().Add(time.Hour).Unix()})
	tampered.Body = io.NopCloser(bytes.NewReader(changed))
	tampered.ContentLength = int64(len(changed))
	tampered.GetBody = nil
	assertSignatureFailure("tampered body", tampered)

	wrongRole := signedRevocationRequestWith(
		t, clock, personKey, personIssuer, aauth.AccessDiscoveryDocument, reference,
		map[string]string{"X-Revocation-Context": "audit-1"}, []string{"x-revocation-context"},
	)
	assertSignatureFailure("wrong server role", wrongRole)

	for name, body := range map[string]string{
		"missing exp":     `{"jti":"` + reference.JTI + `"}`,
		"string exp":      `{"jti":"` + reference.JTI + `","exp":"soon"}`,
		"zero exp":        `{"jti":"` + reference.JTI + `","exp":0}`,
		"fractional exp":  `{"jti":"` + reference.JTI + `","exp":1.5}`,
		"duplicate jti":   `{"jti":"a","jti":"b","exp":2000000000}`,
		"trailing value":  `{"jti":"a","exp":2000000000} {}`,
		"non-object body": `["a"]`,
		"empty body":      ``,
	} {
		request := signedRevocationBody(t, clock, personKey, personIssuer, aauth.PersonDiscoveryDocument,
			[]byte(body), map[string]string{"X-Revocation-Context": "audit-1"}, []string{"x-revocation-context"})
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"invalid_request"`) {
			t.Fatalf("%s = %d %s", name, response.Code, response.Body.String())
		}
	}

	missingJTI := signedRevocationRequestWith(
		t, clock, personKey, personIssuer, aauth.PersonDiscoveryDocument,
		aauth.TokenReference{Issuer: personIssuer},
		map[string]string{"X-Revocation-Context": "audit-1"}, []string{"x-revocation-context"},
	)
	missingResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(missingResponse, missingJTI)
	if missingResponse.Code != http.StatusBadRequest {
		t.Fatalf("missing jti = %d %s", missingResponse.Code, missingResponse.Body.String())
	}
	if statuses.revokeCount() != 0 {
		t.Fatalf("invalid requests reached store %d times", statuses.revokeCount())
	}

	statuses.revokeError = errors.New("revocation store unavailable")
	storeFailure := signedRevocationRequestWith(
		t, clock, personKey, personIssuer, aauth.PersonDiscoveryDocument, reference,
		map[string]string{"X-Revocation-Context": "audit-1"}, []string{"x-revocation-context"},
	)
	storeFailureResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(storeFailureResponse, storeFailure)
	if storeFailureResponse.Code != http.StatusInternalServerError || statuses.revokeCount() != 1 {
		t.Fatalf("store failure = %d %s; calls=%d", storeFailureResponse.Code, storeFailureResponse.Body.String(), statuses.revokeCount())
	}
	statuses.revokeError = nil
	valid := signedRevocationRequestWith(
		t, clock, personKey, personIssuer, aauth.PersonDiscoveryDocument, reference,
		map[string]string{"X-Revocation-Context": "audit-1"}, []string{"x-revocation-context"},
	)
	validResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusOK || statuses.revokeCount() != 2 {
		t.Fatalf("valid revoke = %d %s; calls=%d", validResponse.Code, validResponse.Body.String(), statuses.revokeCount())
	}
	wantExp := time.Unix(clock.Now().Add(time.Hour).Unix(), 0)
	if got := statuses.lastRevocation; got.Reference != reference || !got.ExpiresAt.Equal(wantExp) {
		t.Fatalf("store received %#v, want %v exp %v", got, reference, wantExp)
	}

	// A body iss is an ignored extension member: the issuer is the verified signer.
	withIss := signedRevocationBody(t, clock, personKey, personIssuer, aauth.PersonDiscoveryDocument,
		[]byte(`{"iss":"https://other-person.example","jti":"`+reference.JTI+`","exp":2000000000}`),
		map[string]string{"X-Revocation-Context": "audit-1"}, []string{"x-revocation-context"})
	withIssResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(withIssResponse, withIss)
	if withIssResponse.Code != http.StatusOK || statuses.lastRevocation.Reference != reference {
		t.Fatalf("body iss = %d %s; stored %#v", withIssResponse.Code, withIssResponse.Body.String(), statuses.lastRevocation)
	}

	// Signature coverage of content-type and content-digest is mandatory.
	for _, omitted := range []string{"content-type", "content-digest"} {
		request := httptest.NewRequest(http.MethodPost, resourceIssuer+"/revoke", strings.NewReader(`{"jti":"`+reference.JTI+`","exp":2000000000}`))
		request.Header.Set("Content-Type", "application/json")
		var components []string
		for _, component := range []string{"content-type", "content-digest", "x-revocation-context"} {
			if component != omitted {
				components = append(components, component)
			}
		}
		request.Header.Set("X-Revocation-Context", "audit-1")
		if err := signaturekey.SignJWKSURIRequestWithOptions(request, personKey, personIssuer, aauth.PersonDiscoveryDocument, clock,
			signaturekey.SignOptions{AdditionalComponents: components}); err != nil {
			t.Fatalf("sign without %s: %v", omitted, err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || response.Header().Get("Signature-Error") == "" {
			t.Fatalf("coverage without %s = %d %s", omitted, response.Code, response.Body.String())
		}
	}
}

func TestAuthTokenStatusFailuresStopEveryHostCallback(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 20, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "revocation-failure-person", 76)
	resourceKey := testSigningKey(t, "revocation-failure-resource", 77)
	agentKey := testSigningKey(t, "revocation-failure-agent", 78)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
	}
	statuses := newTestAuthTokenStatusStore()
	requiredCalls, resolveCalls, protectedCalls := 0, 0, 0
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "unused" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes: func(*http.Request) []string {
			requiredCalls++
			return []string{"records.read"}
		},
		ResolvePerson: func(context.Context, PersonIdentity, PersonContext) error {
			resolveCalls++
			return nil
		},
		Protected:         http.HandlerFunc(func(http.ResponseWriter, *http.Request) { protectedCalls++ }),
		AuthTokenStatuses: statuses,
	})
	if err != nil {
		t.Fatal(err)
	}
	compact := mintAuthToken(t, personKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		JTI: "status-failure-token", PersonServer: personIssuer, Subject: "person-1", Scope: "records.read",
	})
	statuses.observeError = errors.New("status store unavailable")
	request := signedRequest(t, clock, agentKey, compact, http.MethodGet, resourceIssuer+"/records", "")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || requiredCalls != 0 || resolveCalls != 0 || protectedCalls != 0 {
		t.Fatalf("status failure = %d %s; callbacks=%d/%d/%d", response.Code, response.Body.String(), requiredCalls, resolveCalls, protectedCalls)
	}
	problem, err := aauth.DecodeProblemResponse(response.Result())
	if err != nil || problem.Status != http.StatusInternalServerError || problem.Code != "server_error" ||
		problem.Detail != http.StatusText(http.StatusInternalServerError) || strings.Contains(problem.Detail, "status store unavailable") {
		t.Fatalf("status failure problem = %#v, %v", problem, err)
	}

	statuses.observeError = nil
	statuses.seed(ObservedAuthToken{
		Reference:     aauth.TokenReference{Issuer: personIssuer, JTI: "status-failure-token"},
		CompactSHA256: [32]byte{9}, ExpiresAt: now.Add(time.Hour),
	})
	conflictRequest := signedRequest(t, clock, agentKey, compact, http.MethodGet, resourceIssuer+"/records", "")
	conflictResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(conflictResponse, conflictRequest)
	if conflictResponse.Code != http.StatusForbidden || requiredCalls != 0 || resolveCalls != 0 || protectedCalls != 0 {
		t.Fatalf("identity conflict = %d %s; callbacks=%d/%d/%d", conflictResponse.Code, conflictResponse.Body.String(), requiredCalls, resolveCalls, protectedCalls)
	}
}

func TestAuthTokenStatusMutationCanBeRetriedAfterAnUncertainStoreError(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 22, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "revocation-uncertain-person", 82)
	resourceKey := testSigningKey(t, "revocation-uncertain-resource", 83)
	agentKey := testSigningKey(t, "revocation-uncertain-agent", 84)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
	}
	statuses := newTestAuthTokenStatusStore()
	statuses.observeAfterMutationError = errors.New("observation response unavailable after commit")
	requiredCalls, resolveCalls, protectedCalls := 0, 0, 0
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "unused" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes: func(*http.Request) []string {
			requiredCalls++
			return []string{"records.read"}
		},
		ResolvePerson: func(context.Context, PersonIdentity, PersonContext) error {
			resolveCalls++
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			protectedCalls++
			response.WriteHeader(http.StatusNoContent)
		}),
		AuthTokenStatuses: statuses,
	})
	if err != nil {
		t.Fatal(err)
	}
	compact := mintAuthToken(t, personKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		JTI: "uncertain-status-token", PersonServer: personIssuer, Subject: "person-1", Scope: "records.read",
	})
	reference := aauth.TokenReference{Issuer: personIssuer, JTI: "uncertain-status-token"}
	wantObserved := ObservedAuthToken{
		Reference:     reference,
		CompactSHA256: sha256.Sum256([]byte(compact)), ExpiresAt: now.Add(time.Hour),
	}

	firstUse := signedRequest(t, clock, agentKey, compact, http.MethodGet, resourceIssuer+"/records", "")
	firstUseResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(firstUseResponse, firstUse)
	if firstUseResponse.Code != http.StatusInternalServerError || requiredCalls != 0 || resolveCalls != 0 || protectedCalls != 0 {
		t.Fatalf("uncertain observation = %d %s; callbacks=%d/%d/%d", firstUseResponse.Code, firstUseResponse.Body.String(), requiredCalls, resolveCalls, protectedCalls)
	}
	firstUseProblem, err := aauth.DecodeProblemResponse(firstUseResponse.Result())
	if err != nil || firstUseProblem.Status != http.StatusInternalServerError || firstUseProblem.Code != "server_error" ||
		firstUseProblem.Detail != http.StatusText(http.StatusInternalServerError) || strings.Contains(firstUseProblem.Detail, "observation response unavailable") ||
		firstUseResponse.Header().Get("Retry-After") != "" {
		t.Fatalf("uncertain observation problem = %#v, %v; headers=%v", firstUseProblem, err, firstUseResponse.Header())
	}
	if observed, ok := statuses.record(reference); !ok || observed != wantObserved {
		t.Fatalf("observation after uncertain result = %#v, present=%t; want %#v", observed, ok, wantObserved)
	}
	secondUse := signedRequest(t, clock, agentKey, compact, http.MethodGet, resourceIssuer+"/records", "")
	secondUseResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(secondUseResponse, secondUse)
	if secondUseResponse.Code != http.StatusNoContent || requiredCalls != 1 || resolveCalls != 1 || protectedCalls != 1 {
		t.Fatalf("observation retry = %d %s; callbacks=%d/%d/%d", secondUseResponse.Code, secondUseResponse.Body.String(), requiredCalls, resolveCalls, protectedCalls)
	}

	statuses.revokeAfterMutationError = errors.New("revocation response unavailable after commit")
	firstRevoke := signedRevocationRequest(t, clock, personKey, reference.Issuer, reference.JTI)
	firstRevokeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(firstRevokeResponse, firstRevoke)
	if firstRevokeResponse.Code != http.StatusInternalServerError {
		t.Fatalf("uncertain revocation = %d %s", firstRevokeResponse.Code, firstRevokeResponse.Body.String())
	}
	firstRevokeProblem, err := aauth.DecodeProblemResponse(firstRevokeResponse.Result())
	if err != nil || firstRevokeProblem.Status != http.StatusInternalServerError || firstRevokeProblem.Code != "server_error" ||
		firstRevokeProblem.Detail != http.StatusText(http.StatusInternalServerError) || strings.Contains(firstRevokeProblem.Detail, "revocation response unavailable") ||
		firstRevokeResponse.Header().Get("Retry-After") != "" {
		t.Fatalf("uncertain revocation problem = %#v, %v; headers=%v", firstRevokeProblem, err, firstRevokeResponse.Header())
	}
	refusedBeforeRetry := signedRequest(t, clock, agentKey, compact, http.MethodGet, resourceIssuer+"/records", "")
	refusedBeforeRetryResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(refusedBeforeRetryResponse, refusedBeforeRetry)
	assertRevokedAuthTokenResponse(t, refusedBeforeRetryResponse)
	if requiredCalls != 1 || resolveCalls != 1 || protectedCalls != 1 {
		t.Fatalf("use after uncertain revoke reached callbacks=%d/%d/%d", requiredCalls, resolveCalls, protectedCalls)
	}
	secondRevoke := signedRevocationRequest(t, clock, personKey, reference.Issuer, reference.JTI)
	secondRevokeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(secondRevokeResponse, secondRevoke)
	if secondRevokeResponse.Code != http.StatusOK {
		t.Fatalf("revocation retry = %d %s", secondRevokeResponse.Code, secondRevokeResponse.Body.String())
	}
	refusedUse := signedRequest(t, clock, agentKey, compact, http.MethodGet, resourceIssuer+"/records", "")
	refusedUseResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(refusedUseResponse, refusedUse)
	assertRevokedAuthTokenResponse(t, refusedUseResponse)
	if requiredCalls != 1 || resolveCalls != 1 || protectedCalls != 1 {
		t.Fatalf("use after revoke retry reached callbacks=%d/%d/%d", requiredCalls, resolveCalls, protectedCalls)
	}
}

func TestAuthTokenStatusStoreReferenceFixtureLinearizesConcurrentObserveAndRevoke(t *testing.T) {
	t.Parallel()

	store := newTestAuthTokenStatusStore()
	record := ObservedAuthToken{
		Reference:     aauth.TokenReference{Issuer: personIssuer, JTI: "concurrent-status-token"},
		CompactSHA256: [32]byte{1}, ExpiresAt: time.Date(2026, 8, 30, 23, 0, 0, 0, time.UTC),
	}
	reference := record.Reference
	if err := store.Observe(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	observeResult := make(chan error, 1)
	revokeResult := make(chan error, 1)
	go func() {
		<-start
		observeResult <- store.Observe(context.Background(), record)
	}()
	go func() {
		<-start
		revokeResult <- store.Revoke(context.Background(), aauth.RevocationRequest{Reference: reference, ExpiresAt: time.Unix(2000000000, 0)})
	}()
	close(start)

	observeErr := <-observeResult
	revokeErr := <-revokeResult
	if observeErr != nil && !errors.Is(observeErr, ErrAuthTokenRevoked) {
		t.Fatalf("concurrent Observe = %v", observeErr)
	}
	if revokeErr != nil {
		t.Fatalf("concurrent Revoke = %v", revokeErr)
	}
	if err := store.Observe(context.Background(), record); !errors.Is(err, ErrAuthTokenRevoked) {
		t.Fatalf("post-race Observe = %v, want ErrAuthTokenRevoked", err)
	}
}

func TestRouteDeniedAuthTokenIsStillRecognizedForRevocation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 25, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "revocation-route-person", 79)
	resourceKey := testSigningKey(t, "revocation-route-resource", 80)
	agentKey := testSigningKey(t, "revocation-route-agent", 81)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}: personKey.PublicJWK(),
	}
	statuses := newTestAuthTokenStatusStore()
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "unused" },
		ScopeDescriptions: map[string]string{"records.read": "Read records", "records.write": "Write records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.write"} },
		ResolvePerson:     func(context.Context, PersonIdentity, PersonContext) error { return nil },
		Protected:         http.NotFoundHandler(), AuthTokenStatuses: statuses,
	})
	if err != nil {
		t.Fatal(err)
	}
	compact := mintAuthToken(t, personKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: personIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: resourceIssuer,
		JTI: "route-denied-token", PersonServer: personIssuer, Subject: "person-1", Scope: "records.read",
	})
	request := signedRequest(t, clock, agentKey, compact, http.MethodGet, resourceIssuer+"/write", "")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("route denial = %d %s", response.Code, response.Body.String())
	}
	if _, ok := statuses.record(aauth.TokenReference{Issuer: personIssuer, JTI: "route-denied-token"}); !ok {
		t.Fatal("route-denied valid token was not recognized")
	}
	revoke := signedRevocationRequest(t, clock, personKey, personIssuer, "route-denied-token")
	revoked := httptest.NewRecorder()
	server.Handler().ServeHTTP(revoked, revoke)
	if revoked.Code != http.StatusOK {
		t.Fatalf("route-denied revoke = %d %s", revoked.Code, revoked.Body.String())
	}
}

func signedRevocationRequest(
	t *testing.T,
	clock aauth.Clock,
	key jose.SigningKey,
	issuer string,
	jti string,
) *http.Request {
	t.Helper()
	return signedRevocationRequestWith(
		t, clock, key, issuer, aauth.PersonDiscoveryDocument,
		aauth.TokenReference{Issuer: issuer, JTI: jti}, nil, nil,
	)
}

func signedRevocationRequestWith(
	t *testing.T,
	clock aauth.Clock,
	key jose.SigningKey,
	signer string,
	document string,
	reference aauth.TokenReference,
	headers map[string]string,
	additional []string,
) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jti": reference.JTI, "exp": clock.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return signedRevocationBody(t, clock, key, signer, document, body, headers, additional)
}

func signedRevocationBody(
	t *testing.T,
	clock aauth.Clock,
	key jose.SigningKey,
	signer string,
	document string,
	body []byte,
	headers map[string]string,
	additional []string,
) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, resourceIssuer+"/revoke", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		request, key, signer, document, clock,
		signaturekey.SignOptions{AdditionalComponents: append([]string{"content-type", "content-digest"}, additional...)},
	); err != nil {
		t.Fatal(err)
	}
	return request
}

type testAuthTokenStatusStore struct {
	mu                        sync.Mutex
	records                   map[aauth.TokenReference]ObservedAuthToken
	revoked                   map[aauth.TokenReference]bool
	observeError              error
	revokeError               error
	observeAfterMutationError error
	revokeAfterMutationError  error
	revokeCalls               int
	lastRevocation            aauth.RevocationRequest
}

func newTestAuthTokenStatusStore() *testAuthTokenStatusStore {
	return &testAuthTokenStatusStore{
		records: make(map[aauth.TokenReference]ObservedAuthToken),
		revoked: make(map[aauth.TokenReference]bool),
	}
}

func (store *testAuthTokenStatusStore) Observe(_ context.Context, record ObservedAuthToken) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.observeError != nil {
		return store.observeError
	}
	reference := record.Reference
	if _, ok := store.records[reference]; !ok && store.revoked[reference] {
		return ErrAuthTokenRevoked
	}
	if retained, ok := store.records[reference]; ok {
		if retained != record {
			return ErrAuthTokenConflict
		}
		if store.revoked[reference] {
			return ErrAuthTokenRevoked
		}
		return nil
	}
	store.records[reference] = record
	if store.observeAfterMutationError != nil {
		err := store.observeAfterMutationError
		store.observeAfterMutationError = nil
		return err
	}
	return nil
}

func (store *testAuthTokenStatusStore) Revoke(_ context.Context, request aauth.RevocationRequest) error {
	reference := request.Reference
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revokeCalls++
	if store.revokeError != nil {
		return store.revokeError
	}
	store.revoked[reference] = true
	store.lastRevocation = request
	if store.revokeAfterMutationError != nil {
		err := store.revokeAfterMutationError
		store.revokeAfterMutationError = nil
		return err
	}
	return nil
}

func (store *testAuthTokenStatusStore) seed(record ObservedAuthToken) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.records[record.Reference] = record
}

func (store *testAuthTokenStatusStore) revokeCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.revokeCalls
}

func (store *testAuthTokenStatusStore) record(reference aauth.TokenReference) (ObservedAuthToken, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[reference]
	return record, ok
}

var _ AuthTokenStatusStore = (*testAuthTokenStatusStore)(nil)

// assertRevokedAuthTokenResponse pins the Protocol revoked-token response:
// 401, Signature-Error revoked_jwt, and a person-token requirement.
func assertRevokedAuthTokenResponse(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked Auth-token status = %d %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Signature-Error"); !strings.Contains(got, "error=revoked_jwt") && !strings.Contains(got, "revoked_jwt") {
		t.Fatalf("Signature-Error = %q", got)
	}
	if got := response.Header().Get("AAuth-Requirement"); got != "requirement=person-token" {
		t.Fatalf("AAuth-Requirement = %q", got)
	}
}
