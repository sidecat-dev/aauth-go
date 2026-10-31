package resource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestHeldAuthTokenInvocationCompletesOnceAndReplays(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	personKey := testSigningKey(t, "held-person-key", 81)
	resourceKey := testSigningKey(t, "held-resource-key", 82)
	accessKey := testSigningKey(t, "held-access-key", 83)
	alternateAccessKey := testSigningKey(t, "held-access-key-alternate", 85)
	agentKey := testSigningKey(t, "held-agent-key", 84)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:          personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}:    resourceKey.PublicJWK(),
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:          accessKey.PublicJWK(),
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: alternateAccessKey.ID()}: alternateAccessKey.PublicJWK(),
	}
	store := newHeldMemoryStore()
	resolved := 0
	protected := 0
	var expectedAuthToken string
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer:                        resourceIssuer,
		AccessServer:                  accessIssuer,
		SigningKey:                    resourceKey,
		KeyResolver:                   resolver,
		Clock:                         clock,
		NewID:                         func() string { return "held-resource-token-1" },
		ScopeDescriptions:             map[string]string{"records.read": "Read records"},
		AdditionalSignatureComponents: []string{"x-route-proof"},
		RequiredScopes:                func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson: func(_ context.Context, identity PersonIdentity, personContext PersonContext) error {
			resolved++
			if identity != (PersonIdentity{Issuer: personIssuer, Subject: "person-1"}) || personContext.Tenant != "tenant-1" {
				t.Fatalf("resolved person = %#v, context = %#v", identity, personContext)
			}
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			protected++
			compact, ok := AuthTokenFromContext(request.Context())
			if !ok || compact != expectedAuthToken {
				t.Fatalf("held verified auth token = %q, present=%t, want %q", compact, ok, expectedAuthToken)
			}
			principal, ok := AuthPrincipalFromContext(request.Context())
			if !ok || principal.PersonServer != personIssuer || principal.Subject != "person-1" ||
				!reflect.DeepEqual(principal.Scope, []string{"records.read"}) || principal.Tenant != "tenant-1" ||
				!principal.Confirmation.Equal(agentKey.PublicJWK()) {
				t.Fatalf("principal = %#v, present = %t", principal, ok)
			}
			if request.Method != http.MethodGet || request.URL.RawPath != "/records/a%2Fb" ||
				request.URL.RawQuery != "view=full%20detail" || request.Header.Get("X-Route-Proof") != "route-42" {
				t.Fatalf("held request = %s %#v, route = %q", request.Method, request.URL, request.Header.Get("X-Route-Proof"))
			}
			for _, name := range []string{"Signature-Key", "Signature-Input", "Signature"} {
				if value := request.Header.Get(name); value != "" {
					t.Fatalf("held application received stale %s = %q", name, value)
				}
			}
			response.Header().Set("X-Application-Result", "created")
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"record":"a/b","created":true}`))
		}),
		HeldInvocations:              store,
		MaxRetainedRequestBodyBytes:  64 << 10,
		MaxRetainedResponseBodyBytes: 64 << 10,
		MaxRetainedHeaderBytes:       16 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	personToken := mintPersonToken(t, personKey, agentKey.PublicJWK(), now, resourceIssuer, "held-person-token-1")
	initial := httptest.NewRequest(http.MethodGet, resourceIssuer+"/records/a%2Fb?view=full%20detail", nil)
	initial.Header.Set("X-Route-Proof", "route-42")
	if err := signaturekey.SignJWTRequestWithOptions(initial, agentKey, personToken, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"x-route-proof"},
	}); err != nil {
		t.Fatal(err)
	}
	initialResponse := httptest.NewRecorder()
	store.beforeCreate = func() {
		if initialResponse.Header().Get("Location") != "" || initialResponse.Header().Get("AAuth-Requirement") != "" || initialResponse.Body.Len() != 0 {
			t.Fatal("pending response became observable before held invocation creation")
		}
	}
	server.Handler().ServeHTTP(initialResponse, initial)

	if initialResponse.Code != http.StatusAccepted || initialResponse.Header().Get("Retry-After") != "5" ||
		initialResponse.Header().Get("Cache-Control") != "no-store" ||
		initialResponse.Header().Get("Location") != resourceIssuer+"/pending/held-call-0123456789abcdef" {
		t.Fatalf("pending response = %d, headers = %v, body = %s", initialResponse.Code, initialResponse.Header(), initialResponse.Body.String())
	}
	var pendingBody struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(initialResponse.Body.Bytes(), &pendingBody); err != nil || pendingBody.Status != "pending" {
		t.Fatalf("pending body = %s, error = %v", initialResponse.Body.String(), err)
	}
	requirement, err := aauth.ParseAuthTokenRequirement(initialResponse.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims, err := aauth.VerifyResourceToken(context.Background(), requirement.ResourceToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if resourceClaims.Scope != "records.read" || resourceClaims.PersonServer != personIssuer ||
		resourceClaims.Subject != "person-1" || protected != 0 || resolved != 0 {
		t.Fatalf("resource claims = %#v; resolved=%d protected=%d", resourceClaims, resolved, protected)
	}
	held := store.loaded(t)
	if held.ResourceToken != requirement.ResourceToken || !reflect.DeepEqual(held.RequiredScopes, []string{"records.read"}) ||
		!held.ResourceTokenIssuedAt.Equal(now) || !held.ExpiresAt.Equal(now.Add(5*time.Minute)) ||
		!held.CompletionUntil.Equal(now.Add(5*time.Minute+aauth.MaximumAuthTokenLifetime)) ||
		held.Header.Get("X-Route-Proof") != "route-42" || held.Header.Get("Signature-Key") != "" {
		t.Fatalf("held invocation = %#v", held)
	}

	authToken := mintAuthToken(t, accessKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: resourceIssuer,
		JTI: "held-auth-token-1", PersonServer: personIssuer, Subject: "person-1",
		Scope: "records.read", Tenant: "tenant-1", IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
	})
	expectedAuthToken = authToken
	poll := signedRequest(t, clock, agentKey, authToken, http.MethodGet, initialResponse.Header().Get("Location"), "")
	pollResponse := httptest.NewRecorder()
	store.beforeRetain = func() {
		if pollResponse.Body.Len() != 0 || pollResponse.Header().Get("X-Application-Result") != "" {
			t.Fatal("application response became observable before durable retention")
		}
	}
	server.Handler().ServeHTTP(pollResponse, poll)
	assertHeldApplicationResponse(t, pollResponse)
	if protected != 1 || resolved != 1 || store.claims != 1 || store.retains != 1 {
		t.Fatalf("first completion: protected=%d resolved=%d claims=%d retains=%d", protected, resolved, store.claims, store.retains)
	}
	if store.token.SHA256 != sha256.Sum256([]byte(authToken)) || !store.token.PresentedAt.Equal(now) ||
		!store.token.RetainUntil.Equal(time.Unix(resourceClaims.ExpiresAt+25*60, 0)) {
		t.Fatalf("held auth-token identity = %#v", store.token)
	}

	replayPoll := signedRequest(t, clock, agentKey, authToken, http.MethodGet, initialResponse.Header().Get("Location"), "")
	replayResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayResponse, replayPoll)
	assertHeldApplicationResponse(t, replayResponse)
	if protected != 1 || resolved != 1 || store.claims != 2 || store.retains != 1 {
		t.Fatalf("replay: protected=%d resolved=%d claims=%d retains=%d", protected, resolved, store.claims, store.retains)
	}

	sameClaimsAuthToken := mintAuthToken(t, alternateAccessKey, agentKey.PublicJWK(), now, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: resourceIssuer,
		JTI: "held-auth-token-1", PersonServer: personIssuer, Subject: "person-1",
		Scope: "records.read", Tenant: "tenant-1", IssuedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
	})
	originalParsed, err := jose.ParseCompact(authToken)
	if err != nil {
		t.Fatal(err)
	}
	sameClaimsParsed, err := jose.ParseCompact(sameClaimsAuthToken)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalParsed.Payload(), sameClaimsParsed.Payload()) || authToken == sameClaimsAuthToken {
		t.Fatal("alternate compact token does not preserve the exact original claims")
	}
	otherPoll := signedRequest(t, clock, agentKey, sameClaimsAuthToken, http.MethodGet, initialResponse.Header().Get("Location"), "")
	otherResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(otherResponse, otherPoll)
	if otherResponse.Code != http.StatusForbidden {
		t.Fatalf("different auth-token replay status = %d, want %d; body = %s", otherResponse.Code, http.StatusForbidden, otherResponse.Body.String())
	}
	if protected != 1 || resolved != 1 || store.retains != 1 {
		t.Fatalf("different auth token reexecuted: protected=%d resolved=%d retains=%d", protected, resolved, store.retains)
	}
}

func TestExecuteHeldInvocationPreservesMissionContext(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 14, 0, 0, 0, time.UTC)
	mission := strings.Repeat("A", 43)
	account := "work-account"
	agentKey := testSigningKey(t, "held-mission-agent", 86)
	var resolved PersonContext
	var principal AuthPrincipal
	config := validConfigWithKey(testSigningKey(t, "held-mission-resource", 87), http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var ok bool
		principal, ok = AuthPrincipalFromContext(request.Context())
		if !ok {
			t.Fatal("held application received no Auth principal")
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	config.ResolvePerson = func(_ context.Context, identity PersonIdentity, context PersonContext) error {
		if identity != (PersonIdentity{Issuer: personIssuer, Subject: "person-1"}) {
			return errors.New("unexpected person")
		}
		resolved = context
		return nil
	}
	config.HeldInvocations = newHeldMemoryStore()
	config.MaxRetainedRequestBodyBytes = 1024
	config.MaxRetainedResponseBodyBytes = 1024
	config.MaxRetainedHeaderBytes = 1024
	server, err := NewFederatedAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, resourceIssuer+"/records", strings.NewReader(`{"id":7}`))
	snapshot, err := snapshotHeldRequest(request, 1024)
	if err != nil {
		t.Fatal(err)
	}
	result := server.executeHeldInvocation(snapshot, "exact-auth-token", aauth.AuthTokenClaims{
		PersonServer: personIssuer, Subject: "person-1", MissionS256: mission,
		Tenant: "tenant-1", Account: &account, ExpiresAt: now.Add(time.Minute).Unix(),
	}, agentKey.PublicJWK(), now, []string{"records.read"})
	if result.StatusCode != http.StatusNoContent {
		t.Fatalf("held mission execution = %#v", result)
	}
	if resolved.MissionS256 != mission || principal.MissionS256 != mission ||
		principal.Account == nil || *principal.Account != account {
		t.Fatalf("held mission context = resolved %#v principal %#v", resolved, principal)
	}
}

func assertHeldApplicationResponse(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusCreated || response.Header().Get("X-Application-Result") != "created" ||
		response.Body.String() != `{"record":"a/b","created":true}` {
		t.Fatalf("application response = %d, headers = %v, body = %q", response.Code, response.Header(), response.Body.String())
	}
}

func assertHeldServerError(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	var problem struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode held server problem: %v; status=%d body=%s", err, response.Code, response.Body.String())
	}
	if response.Code != http.StatusInternalServerError || problem.Error != "server_error" || response.Header().Get("Retry-After") != "" {
		t.Fatalf("held server problem = %d error=%q Retry-After=%q body=%s",
			response.Code, problem.Error, response.Header().Get("Retry-After"), response.Body.String())
	}
}

func TestHeldAuthTokenCreateFailureWithholdsPendingResponse(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	store.createErr = errors.New("create unavailable")
	fixture := newHeldFailureFixture(t, store)
	response := fixture.begin(t)
	assertHeldServerError(t, response)
	if response.Header().Get("Location") != "" || response.Header().Get("AAuth-Requirement") != "" {
		t.Fatalf("failed create released pending headers: %v", response.Header())
	}
	if fixture.protected != 0 || fixture.resolved != 0 || store.state != "" {
		t.Fatalf("failed create consequences: protected=%d resolved=%d state=%q", fixture.protected, fixture.resolved, store.state)
	}
}

func TestHeldAuthTokenMalformedPollTokenUsesCredentialRefusal(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	fixture := newHeldFailureFixture(t, store)
	pending := fixture.begin(t)
	poll := signedRequest(
		t, fixture.clock, fixture.agentKey, "not-a-compact-token",
		http.MethodGet, pending.Header().Get("Location"), "",
	)
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, poll)
	var problem struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode malformed-token problem: %v; body=%s", err, response.Body.String())
	}
	if response.Code != http.StatusUnauthorized || problem.Error != "invalid_token" {
		t.Fatalf("malformed-token refusal = %d error=%q body=%s", response.Code, problem.Error, response.Body.String())
	}
	if store.claims != 0 || fixture.resolved != 0 || fixture.protected != 0 {
		t.Fatalf(
			"malformed token crossed execution boundary: claims=%d resolved=%d protected=%d",
			store.claims, fixture.resolved, fixture.protected,
		)
	}
}

func TestHeldAuthTokenUnclassifiedStoreFailureUsesCoreServerError(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	fixture := newHeldFailureFixture(t, store)
	pending := fixture.begin(t)
	store.loadErr = errors.New("load unavailable")
	response := fixture.poll(t, pending.Header().Get("Location"), fixture.authToken(t))
	assertHeldServerError(t, response)
	if store.claims != 0 || fixture.resolved != 0 || fixture.protected != 0 {
		t.Fatalf("load failure crossed execution boundary: claims=%d resolved=%d protected=%d",
			store.claims, fixture.resolved, fixture.protected)
	}
}

func TestHeldAuthTokenDeliveryCanBeSelectedPerRequest(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	fixture := newHeldFailureFixtureWithSelector(t, store, func(request *http.Request) bool {
		return request.URL.Path == "/held"
	})
	personToken := mintPersonToken(t, fixture.personKey, fixture.agentKey.PublicJWK(), fixture.now, resourceIssuer, "held-selector-person-token")
	request := signedRequest(t, fixture.clock, fixture.agentKey, personToken, http.MethodGet, resourceIssuer+"/retry", "")
	retry := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(retry, request)
	if retry.Code != http.StatusUnauthorized || retry.Header().Get("Location") != "" || store.state != "" {
		t.Fatalf("baseline-selected response = %d, headers=%v, store=%q", retry.Code, retry.Header(), store.state)
	}
	if _, err := aauth.ParseAuthTokenRequirement(retry.Header().Values("AAuth-Requirement")); err != nil {
		t.Fatalf("baseline requirement: %v", err)
	}

	request = signedRequest(t, fixture.clock, fixture.agentKey, personToken, http.MethodGet, resourceIssuer+"/held", "")
	held := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(held, request)
	if held.Code != http.StatusAccepted || held.Header().Get("Location") == "" || store.state != "pending" {
		t.Fatalf("held-selected response = %d, headers=%v, store=%q", held.Code, held.Header(), store.state)
	}
}

func TestHeldAuthTokenRejectsInvalidStoreIdentifierBeforePendingResponse(t *testing.T) {
	t.Parallel()

	for _, pendingID := range []string{"short", "held/invalid/identifier", "held-identifier-☃-0123456789"} {
		pendingID := pendingID
		t.Run(pendingID, func(t *testing.T) {
			t.Parallel()
			store := newHeldMemoryStore()
			store.pendingID = pendingID
			fixture := newHeldFailureFixture(t, store)
			response := fixture.begin(t)
			if response.Code == http.StatusAccepted || response.Header().Get("Location") != "" || response.Header().Get("AAuth-Requirement") != "" {
				t.Fatalf("invalid store identifier produced pending response: %d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
			}
			if fixture.protected != 0 || fixture.resolved != 0 {
				t.Fatalf("invalid store identifier executed application: protected=%d resolved=%d", fixture.protected, fixture.resolved)
			}
		})
	}
}

func TestHeldAuthTokenRejectsOversizedRequestHeadersBeforeCreate(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	fixture := newHeldFailureFixture(t, store)
	personToken := mintPersonToken(t, fixture.personKey, fixture.agentKey.PublicJWK(), fixture.now, resourceIssuer, "held-large-header-person-token")
	request := httptest.NewRequest(http.MethodGet, resourceIssuer+"/records/42", nil)
	request.Header.Set("X-Application-Metadata", strings.Repeat("x", 2<<10))
	if err := signaturekey.SignJWTRequest(request, fixture.agentKey, personToken, fixture.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, request)

	if response.Code == http.StatusAccepted {
		t.Fatalf("oversized request produced pending response: headers=%v body=%q", response.Header(), response.Body.String())
	}
	if store.state != "" || response.Header().Get("Location") != "" || response.Header().Get("AAuth-Requirement") != "" {
		t.Fatalf("oversized request reached durable create: state=%q headers=%v", store.state, response.Header())
	}
}

func TestHeldAuthTokenRejectsBroaderGrantBeforeClaim(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	fixture := newHeldFailureFixture(t, store)
	pending := fixture.begin(t)
	broader := mintAuthToken(t, fixture.accessKey, fixture.agentKey.PublicJWK(), fixture.now, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: resourceIssuer,
		JTI: "held-broader-auth-token", PersonServer: personIssuer, Subject: "person-1",
		Scope: "records.read records.write", Tenant: "tenant-1", IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(30 * time.Minute).Unix(),
	})
	response := fixture.poll(t, pending.Header().Get("Location"), broader)

	if response.Code != http.StatusForbidden {
		t.Fatalf("broader grant status = %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
	}
	if store.claims != 0 || fixture.resolved != 0 || fixture.protected != 0 {
		t.Fatalf("broader grant crossed claim boundary: claims=%d resolved=%d protected=%d", store.claims, fixture.resolved, fixture.protected)
	}
}

func TestHeldAuthTokenRejectsCorruptLoadedInvocationBeforeClaim(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name   string
		change func(*HeldInvocation)
	}{
		{name: "missing resource token", change: func(invocation *HeldInvocation) { invocation.ResourceToken = "" }},
		{name: "corrupt resource token signature", change: func(invocation *HeldInvocation) {
			replacement := "A"
			if strings.HasSuffix(invocation.ResourceToken, replacement) {
				replacement = "B"
			}
			invocation.ResourceToken = invocation.ResourceToken[:len(invocation.ResourceToken)-1] + replacement
		}},
		{name: "invented R3 marker", change: func(invocation *HeldInvocation) {
			invocation.R3PerCall = &HeldR3PerCall{}
		}},
		{name: "stale proof header", change: func(invocation *HeldInvocation) { invocation.Header.Set("Signature", "stale") }},
		{name: "invalid request target", change: func(invocation *HeldInvocation) { invocation.EscapedPath = "relative" }},
		{name: "missing route scopes", change: func(invocation *HeldInvocation) { invocation.RequiredScopes = nil }},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()
			store := newHeldMemoryStore()
			store.loadResult = func(invocation HeldInvocation) HeldInvocation {
				scenario.change(&invocation)
				return invocation
			}
			fixture := newHeldFailureFixture(t, store)
			pending := fixture.begin(t)
			response := fixture.poll(t, pending.Header().Get("Location"), fixture.authToken(t))
			assertHeldServerError(t, response)
			if store.claims != 0 || fixture.resolved != 0 || fixture.protected != 0 {
				t.Fatalf("corrupt Load crossed claim boundary: claims=%d resolved=%d protected=%d", store.claims, fixture.resolved, fixture.protected)
			}
		})
	}
}

func TestHeldAuthTokenRejectsInvalidExecutionClaimBeforeApplication(t *testing.T) {
	t.Parallel()

	for _, claim := range []HeldClaim{
		{},
		NewHeldExecution(HeldExecution{InvocationID: "other-held-invocation", Fence: "fence"}),
		NewHeldExecution(HeldExecution{InvocationID: "held-call-0123456789abcdef"}),
	} {
		claim := claim
		t.Run(fmt.Sprintf("%#v", claim), func(t *testing.T) {
			t.Parallel()
			store := newHeldMemoryStore()
			store.claimResult = &claim
			fixture := newHeldFailureFixture(t, store)
			pending := fixture.begin(t)
			response := fixture.poll(t, pending.Header().Get("Location"), fixture.authToken(t))
			assertHeldServerError(t, response)
			if fixture.resolved != 0 || fixture.protected != 0 || store.retains != 0 {
				t.Fatalf("invalid Claim executed application: resolved=%d protected=%d retains=%d", fixture.resolved, fixture.protected, store.retains)
			}
		})
	}
}

func TestHeldAuthTokenPendingRouteOnlyAcceptsGET(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodDelete} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			store := newHeldMemoryStore()
			fixture := newHeldFailureFixture(t, store)
			pending := fixture.begin(t)
			authToken := fixture.authToken(t)
			request := signedRequest(t, fixture.clock, fixture.agentKey, authToken, method, pending.Header().Get("Location"), "")
			response := httptest.NewRecorder()
			fixture.server.Handler().ServeHTTP(response, request)

			if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
				t.Fatalf("%s pending response = %d, headers=%v, body=%q", method, response.Code, response.Header(), response.Body.String())
			}
			if store.claims != 0 || fixture.resolved != 0 || fixture.protected != 0 {
				t.Fatalf("%s pending request crossed execution boundary: claims=%d resolved=%d protected=%d", method, store.claims, fixture.resolved, fixture.protected)
			}
		})
	}
}

func TestHeldAuthTokenRejectsMalformedApplicationPendingResponse(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	fixture := newHeldFailureFixture(t, store)
	fixture.server.protected = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		fixture.protected++
		response.WriteHeader(http.StatusAccepted)
		_, _ = response.Write([]byte(`{"status":"pending"}`))
	})
	pending := fixture.begin(t)
	first := fixture.poll(t, pending.Header().Get("Location"), fixture.authToken(t))

	if first.Code != http.StatusInternalServerError {
		t.Fatalf("malformed nested pending status = %d, want %d; headers=%v body=%q", first.Code, http.StatusInternalServerError, first.Header(), first.Body.String())
	}
	second := fixture.poll(t, pending.Header().Get("Location"), fixture.authToken(t))
	if second.Code != http.StatusInternalServerError || fixture.protected != 1 || store.retains != 1 {
		t.Fatalf("malformed nested pending replay = %d; protected=%d retains=%d body=%q", second.Code, fixture.protected, store.retains, second.Body.String())
	}
}

func TestHeldAuthTokenRejectsAmbiguousApplicationPendingResponse(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "wrong content type", contentType: "text/plain", body: `{"status":"pending"}`},
		{name: "duplicate status", contentType: "application/json", body: `{"status":"pending","status":"interacting"}`},
		{name: "case variant status", contentType: "application/json", body: `{"Status":"pending"}`},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()
			store := newHeldMemoryStore()
			fixture := newHeldFailureFixture(t, store)
			fixture.server.protected = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				fixture.protected++
				response.Header().Set("Location", "/downstream/pending/invalid")
				response.Header().Set("Retry-After", "0")
				response.Header().Set("Cache-Control", "no-store")
				response.Header().Set("Content-Type", scenario.contentType)
				response.WriteHeader(http.StatusAccepted)
				_, _ = response.Write([]byte(scenario.body))
			})
			pending := fixture.begin(t)
			response := fixture.poll(t, pending.Header().Get("Location"), fixture.authToken(t))
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("ambiguous nested pending response = %d, headers=%v, body=%q", response.Code, response.Header(), response.Body.String())
			}
			if fixture.protected != 1 || store.retains != 1 {
				t.Fatalf("ambiguous nested pending execution: protected=%d retains=%d", fixture.protected, store.retains)
			}
		})
	}
}

func TestHeldAuthTokenRetainsWellFormedApplicationPendingResponse(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	fixture := newHeldFailureFixture(t, store)
	fixture.server.protected = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		fixture.protected++
		response.Header().Set("Location", "/downstream/pending/123")
		response.Header().Set("Retry-After", "7")
		response.Header().Set("Cache-Control", "private, no-store")
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusAccepted)
		_, _ = response.Write([]byte(`{"status":"pending"}`))
	})
	pending := fixture.begin(t)
	response := fixture.poll(t, pending.Header().Get("Location"), fixture.authToken(t))

	if response.Code != http.StatusAccepted || response.Header().Get("Location") != "/downstream/pending/123" ||
		response.Header().Get("Retry-After") != "7" || response.Header().Get("Cache-Control") != "private, no-store" ||
		response.Body.String() != `{"status":"pending"}` {
		t.Fatalf("well-formed nested pending response = %d, headers=%v, body=%q", response.Code, response.Header(), response.Body.String())
	}
	if fixture.protected != 1 || store.retains != 1 {
		t.Fatalf("well-formed nested pending execution: protected=%d retains=%d", fixture.protected, store.retains)
	}
}

func TestHeldAuthTokenRefusesCorruptApplicationPendingResponseFromStore(t *testing.T) {
	t.Parallel()

	for _, scenario := range []struct {
		name  string
		setup func(*heldMemoryStore)
	}{
		{
			name: "Retain return",
			setup: func(store *heldMemoryStore) {
				store.retainResult = func(response HeldResponse) HeldResponse {
					response.Header.Del("Location")
					return response
				}
			},
		},
		{name: "replay"},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()
			store := newHeldMemoryStore()
			if scenario.setup != nil {
				scenario.setup(store)
			}
			fixture := newHeldFailureFixture(t, store)
			fixture.server.protected = validApplicationPendingHandler(&fixture.protected)
			pending := fixture.begin(t)
			authToken := fixture.authToken(t)
			first := fixture.poll(t, pending.Header().Get("Location"), authToken)

			if scenario.name == "replay" {
				if first.Code != http.StatusAccepted {
					t.Fatalf("first response = %d, want 202; body=%q", first.Code, first.Body.String())
				}
				store.mu.Lock()
				store.response.Header.Del("Location")
				store.mu.Unlock()
				first = fixture.poll(t, pending.Header().Get("Location"), authToken)
			}
			assertHeldServerError(t, first)
			if first.Header().Get("Location") != "" {
				t.Fatalf("corrupt store response = %d, headers=%v, body=%q", first.Code, first.Header(), first.Body.String())
			}
			if fixture.protected != 1 || store.retains != 1 {
				t.Fatalf("corrupt store response reexecuted: protected=%d retains=%d", fixture.protected, store.retains)
			}
		})
	}
}

func validApplicationPendingHandler(calls *int) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		(*calls)++
		response.Header().Set("Location", "/downstream/pending/123")
		response.Header().Set("Retry-After", "7")
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusAccepted)
		_, _ = response.Write([]byte(`{"status":"pending"}`))
	})
}

func TestHeldAuthTokenRetainFailureWithholdsResultAndNeverReexecutes(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	fixture := newHeldFailureFixture(t, store)
	pending := fixture.begin(t)
	if pending.Code != http.StatusAccepted {
		t.Fatalf("pending status = %d; body = %s", pending.Code, pending.Body.String())
	}
	store.retainErr = errors.New("retain unavailable")
	authToken := fixture.authToken(t)
	first := fixture.poll(t, pending.Header().Get("Location"), authToken)
	assertHeldServerError(t, first)
	if first.Header().Get("X-Application-Result") != "" || strings.Contains(first.Body.String(), "application result") {
		t.Fatalf("failed retain response = %d, headers=%v, body=%q", first.Code, first.Header(), first.Body.String())
	}
	if fixture.protected != 1 || fixture.resolved != 1 || store.state != "unresolved" {
		t.Fatalf("failed retain state: protected=%d resolved=%d state=%q", fixture.protected, fixture.resolved, store.state)
	}

	second := fixture.poll(t, pending.Header().Get("Location"), authToken)
	assertHeldServerError(t, second)
	if fixture.protected != 1 || fixture.resolved != 1 || store.retains != 0 {
		t.Fatalf("unresolved call reexecuted: protected=%d resolved=%d retains=%d", fixture.protected, fixture.resolved, store.retains)
	}
}

func TestHeldAuthTokenUncertainRetainRecoversCommittedResult(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	fixture := newHeldFailureFixture(t, store)
	pending := fixture.begin(t)
	store.retainAfterCommitErr = errors.New("retain response lost")
	authToken := fixture.authToken(t)
	first := fixture.poll(t, pending.Header().Get("Location"), authToken)
	assertHeldServerError(t, first)
	if first.Header().Get("X-Application-Result") != "" {
		t.Fatalf("uncertain retain response = %d, headers=%v, body=%q", first.Code, first.Header(), first.Body.String())
	}
	if fixture.protected != 1 || fixture.resolved != 1 || store.state != "complete" {
		t.Fatalf("uncertain retain state: protected=%d resolved=%d state=%q", fixture.protected, fixture.resolved, store.state)
	}

	second := fixture.poll(t, pending.Header().Get("Location"), authToken)
	if second.Code != http.StatusOK || second.Body.String() != "application result" || second.Header().Get("X-Application-Result") != "retained" {
		t.Fatalf("recovered response = %d, headers=%v, body=%q", second.Code, second.Header(), second.Body.String())
	}
	if fixture.protected != 1 || fixture.resolved != 1 || store.retains != 1 {
		t.Fatalf("uncertain retain reexecuted: protected=%d resolved=%d retains=%d", fixture.protected, fixture.resolved, store.retains)
	}
}

func TestHeldAuthTokenReplayOutlivesResourceToken(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	fixture := newHeldFailureFixture(t, store)
	pending := fixture.begin(t)
	authToken := fixture.authToken(t)
	first := fixture.poll(t, pending.Header().Get("Location"), authToken)
	if first.Code != http.StatusOK || first.Body.String() != "application result" {
		t.Fatalf("initial completion = %d, body=%q", first.Code, first.Body.String())
	}

	fixture.now = fixture.now.Add(6 * time.Minute)
	replayed := fixture.poll(t, pending.Header().Get("Location"), authToken)
	if replayed.Code != http.StatusOK || replayed.Body.String() != "application result" {
		t.Fatalf("post-resource-expiry replay = %d, body=%q", replayed.Code, replayed.Body.String())
	}
	if fixture.protected != 1 || fixture.resolved != 1 || store.retains != 1 {
		t.Fatalf("post-resource-expiry replay reexecuted: protected=%d resolved=%d retains=%d", fixture.protected, fixture.resolved, store.retains)
	}
}

func TestHeldAuthTokenIssuedBeforeResourceExpiryCanFirstExecuteLater(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	fixture := newHeldFailureFixture(t, store)
	pending := fixture.begin(t)
	authToken := fixture.authToken(t)
	fixture.now = fixture.now.Add(6 * time.Minute)
	response := fixture.poll(t, pending.Header().Get("Location"), authToken)
	if response.Code != http.StatusOK || response.Body.String() != "application result" {
		t.Fatalf("late first completion = %d, body=%q", response.Code, response.Body.String())
	}
	if fixture.protected != 1 || fixture.resolved != 1 || store.retains != 1 {
		t.Fatalf("late first completion = protected=%d resolved=%d retains=%d", fixture.protected, fixture.resolved, store.retains)
	}
}

func TestHeldAuthTokenIssuedAfterResourceExpiryIsRefusedBeforeClaim(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	fixture := newHeldFailureFixture(t, store)
	pending := fixture.begin(t)
	fixture.now = fixture.now.Add(6 * time.Minute)
	authToken := fixture.authToken(t)
	response := fixture.poll(t, pending.Header().Get("Location"), authToken)
	if response.Code != http.StatusForbidden {
		t.Fatalf("late-issued Auth token = %d, want 403; body=%q", response.Code, response.Body.String())
	}
	if store.claims != 0 || fixture.protected != 0 || fixture.resolved != 0 || store.retains != 0 {
		t.Fatalf(
			"late-issued Auth token crossed Claim: claims=%d protected=%d resolved=%d retains=%d",
			store.claims, fixture.protected, fixture.resolved, store.retains,
		)
	}
}

func TestHeldAuthTokenConcurrentPollsExecuteApplicationOnce(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	fixture := newHeldFailureFixture(t, store)
	started := make(chan struct{})
	release := make(chan struct{})
	var applicationCalls atomic.Int64
	fixture.server.protected = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		if applicationCalls.Add(1) == 1 {
			close(started)
		}
		<-release
		_, _ = response.Write([]byte("concurrent result"))
	})
	pending := fixture.begin(t)
	authToken := fixture.authToken(t)
	firstResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstResult <- fixture.poll(t, pending.Header().Get("Location"), authToken)
	}()
	<-started

	const concurrentPolls = 24
	results := make(chan *httptest.ResponseRecorder, concurrentPolls)
	var wait sync.WaitGroup
	for range concurrentPolls {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- fixture.poll(t, pending.Header().Get("Location"), authToken)
		}()
	}
	wait.Wait()
	close(results)
	for response := range results {
		if response.Code != http.StatusAccepted || response.Header().Get("Retry-After") != "5" {
			t.Fatalf("concurrent poll = %d, headers=%v, body=%q", response.Code, response.Header(), response.Body.String())
		}
	}
	close(release)
	first := <-firstResult
	if first.Code != http.StatusOK || first.Body.String() != "concurrent result" {
		t.Fatalf("first completion = %d, body=%q", first.Code, first.Body.String())
	}
	if applicationCalls.Load() != 1 || store.retains != 1 {
		t.Fatalf("concurrent execution = application calls %d, retains %d", applicationCalls.Load(), store.retains)
	}

	var replayWait sync.WaitGroup
	for range concurrentPolls {
		replayWait.Add(1)
		go func() {
			defer replayWait.Done()
			response := fixture.poll(t, pending.Header().Get("Location"), authToken)
			if response.Code != http.StatusOK || response.Body.String() != "concurrent result" {
				t.Errorf("concurrent replay = %d, body=%q", response.Code, response.Body.String())
			}
		}()
	}
	replayWait.Wait()
	if applicationCalls.Load() != 1 || store.retains != 1 {
		t.Fatalf("concurrent replay reexecuted: application calls %d, retains %d", applicationCalls.Load(), store.retains)
	}
}

func TestHeldAuthTokenExecutionIsDetachedFromPollCancellation(t *testing.T) {
	t.Parallel()

	store := newHeldMemoryStore()
	fixture := newHeldFailureFixture(t, store)
	applicationContext := make(chan context.Context, 1)
	release := make(chan struct{})
	fixture.server.protected = http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		applicationContext <- request.Context()
		<-release
		_, _ = response.Write([]byte("detached result"))
	})
	pending := fixture.begin(t)
	authToken := fixture.authToken(t)
	poll := signedRequest(t, fixture.clock, fixture.agentKey, authToken, http.MethodGet, pending.Header().Get("Location"), "")
	pollContext, cancel := context.WithCancel(context.Background())
	poll = poll.WithContext(pollContext)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		fixture.server.Handler().ServeHTTP(response, poll)
		result <- response
	}()
	appContext := <-applicationContext
	deadline, ok := appContext.Deadline()
	remaining := time.Until(deadline)
	if !ok || remaining > 30*time.Minute || remaining < 29*time.Minute+55*time.Second {
		t.Fatalf("application remaining lifetime = %s, deadline present=%t; want approximately 30m", remaining, ok)
	}
	cancel()
	if err := appContext.Err(); err != nil {
		t.Fatalf("poll cancellation reached application context: %v", err)
	}
	close(release)
	response := <-result
	if response.Code != http.StatusOK || response.Body.String() != "detached result" || store.retains != 1 {
		t.Fatalf("detached completion = %d, body=%q, retains=%d", response.Code, response.Body.String(), store.retains)
	}
}

type heldFailureFixture struct {
	server    *Server
	store     *heldMemoryStore
	clock     aauth.Clock
	now       time.Time
	personKey jose.SigningKey
	accessKey jose.SigningKey
	agentKey  jose.SigningKey
	protected int
	resolved  int
}

func newHeldFailureFixture(t *testing.T, store *heldMemoryStore) *heldFailureFixture {
	return newHeldFailureFixtureWithSelector(t, store, nil)
}

func newHeldFailureFixtureWithSelector(
	t *testing.T,
	store *heldMemoryStore,
	selector func(*http.Request) bool,
) *heldFailureFixture {
	t.Helper()
	fixture := &heldFailureFixture{
		store:     store,
		now:       time.Date(2026, 8, 30, 17, 0, 0, 0, time.UTC),
		personKey: testSigningKey(t, "held-failure-person", 91),
		accessKey: testSigningKey(t, "held-failure-access", 92),
		agentKey:  testSigningKey(t, "held-failure-agent", 93),
	}
	fixture.clock = aauth.ClockFunc(func() time.Time { return fixture.now })
	resourceKey := testSigningKey(t, "held-failure-resource", 94)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: personIssuer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: fixture.personKey.ID()}: fixture.personKey.PublicJWK(),
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}:   resourceKey.PublicJWK(),
		{Issuer: accessIssuer, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: fixture.accessKey.ID()}: fixture.accessKey.PublicJWK(),
	}
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: resourceIssuer, AccessServer: accessIssuer, SigningKey: resourceKey,
		KeyResolver: resolver, Clock: fixture.clock, NewID: func() string { return "held-failure-resource-token" },
		ScopeDescriptions: map[string]string{"records.read": "Read records", "records.write": "Write records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson: func(context.Context, PersonIdentity, PersonContext) error {
			fixture.resolved++
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			fixture.protected++
			response.Header().Set("X-Application-Result", "retained")
			_, _ = response.Write([]byte("application result"))
		}),
		HoldAuthTokenRequest: selector,
		HeldInvocations:      store, MaxRetainedRequestBodyBytes: 1024, MaxRetainedResponseBodyBytes: 1024, MaxRetainedHeaderBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.server = server
	return fixture
}

func (fixture *heldFailureFixture) begin(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	personToken := mintPersonToken(t, fixture.personKey, fixture.agentKey.PublicJWK(), fixture.now, resourceIssuer, "held-failure-person-token")
	request := signedRequest(t, fixture.clock, fixture.agentKey, personToken, http.MethodGet, resourceIssuer+"/records/42", "")
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, request)
	return response
}

func (fixture *heldFailureFixture) authToken(t *testing.T) string {
	t.Helper()
	return mintAuthToken(t, fixture.accessKey, fixture.agentKey.PublicJWK(), fixture.now, aauth.AuthTokenClaims{
		Issuer: accessIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: resourceIssuer,
		JTI: "held-failure-auth-token", PersonServer: personIssuer, Subject: "person-1",
		Scope: "records.read", Tenant: "tenant-1", IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(30 * time.Minute).Unix(),
	})
}

func (fixture *heldFailureFixture) poll(t *testing.T, location, authToken string) *httptest.ResponseRecorder {
	t.Helper()
	request := signedRequest(t, fixture.clock, fixture.agentKey, authToken, http.MethodGet, location, "")
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, request)
	return response
}

type heldMemoryStore struct {
	mu                   sync.Mutex
	invocation           HeldInvocation
	state                string
	token                HeldAuthToken
	response             HeldResponse
	claims               int
	retains              int
	beforeCreate         func()
	beforeClaim          func()
	rejectCanceledClaim  bool
	beforeRetain         func()
	pendingID            string
	rechallenges         int
	createErr            error
	loadErr              error
	retainErr            error
	retainAfterCommitErr error
	retainResult         func(HeldResponse) HeldResponse
	loadResult           func(HeldInvocation) HeldInvocation
	claimResult          *HeldClaim
}

func newHeldMemoryStore() *heldMemoryStore {
	return &heldMemoryStore{pendingID: "held-call-0123456789abcdef"}
}

func (store *heldMemoryStore) Create(_ context.Context, invocation HeldInvocation) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.beforeCreate != nil {
		store.beforeCreate()
	}
	if store.createErr != nil {
		return "", store.createErr
	}
	store.invocation = cloneHeldInvocationForTest(invocation)
	store.state = "pending"
	return store.pendingID, nil
}

func (store *heldMemoryStore) Load(_ context.Context, id string) (HeldInvocation, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil {
		return HeldInvocation{}, store.loadErr
	}
	if id != store.pendingID || store.state == "" {
		return HeldInvocation{}, ErrHeldInvocationNotFound
	}
	result := cloneHeldInvocationForTest(store.invocation)
	if store.loadResult != nil {
		result = store.loadResult(result)
	}
	return result, nil
}

func (store *heldMemoryStore) Claim(ctx context.Context, id string, token HeldAuthToken) (HeldClaim, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.beforeClaim != nil {
		beforeClaim := store.beforeClaim
		store.beforeClaim = nil
		beforeClaim()
	}
	if store.rejectCanceledClaim && ctx.Err() != nil {
		return HeldClaim{}, ctx.Err()
	}
	store.claims++
	if id != store.pendingID || store.state == "" {
		return HeldClaim{}, ErrHeldInvocationNotFound
	}
	if store.claimResult != nil {
		return *store.claimResult, nil
	}
	if store.state == "complete" {
		if store.token.SHA256 != token.SHA256 {
			return HeldClaim{}, ErrHeldAuthTokenMismatch
		}
		return NewHeldReplay(store.response), nil
	}
	if store.state == "expired" {
		return HeldClaim{}, ErrHeldInvocationExpired
	}
	if store.state == "executing" {
		return HeldClaim{}, ErrHeldInvocationConflict
	}
	if store.state != "pending" {
		return HeldClaim{}, ErrHeldExecutionUnresolved
	}
	if !token.PresentedAt.Before(store.invocation.CompletionUntil) {
		store.state = "expired"
		return HeldClaim{}, ErrHeldInvocationExpired
	}
	store.state = "executing"
	store.token = token
	return NewHeldExecution(HeldExecution{InvocationID: store.pendingID, Fence: "held-fence-1"}), nil
}

func (store *heldMemoryStore) Retain(_ context.Context, execution HeldExecution, response HeldResponse) (HeldResponse, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.beforeRetain != nil {
		store.beforeRetain()
	}
	if store.retainErr != nil {
		store.state = "unresolved"
		return HeldResponse{}, store.retainErr
	}
	if store.state != "executing" || execution != (HeldExecution{InvocationID: store.pendingID, Fence: "held-fence-1"}) {
		return HeldResponse{}, ErrHeldCompletionStale
	}
	store.retains++
	store.response = cloneHeldResponseForTest(response)
	store.state = "complete"
	if store.retainAfterCommitErr != nil {
		return HeldResponse{}, store.retainAfterCommitErr
	}
	result := cloneHeldResponseForTest(store.response)
	if store.retainResult != nil {
		result = store.retainResult(result)
	}
	return result, nil
}

func (store *heldMemoryStore) Rechallenge(_ context.Context, id string, challenge HeldRechallenge) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if id != store.pendingID || store.state == "" {
		return ErrHeldInvocationNotFound
	}
	switch store.state {
	case "pending":
	case "complete":
		return ErrHeldAuthTokenMismatch
	case "expired":
		return ErrHeldInvocationExpired
	default:
		return ErrHeldInvocationConflict
	}
	if store.invocation.ResourceToken != challenge.Previous {
		return ErrHeldInvocationConflict
	}
	store.rechallenges++
	store.invocation.ResourceToken = challenge.ResourceToken
	store.invocation.ResourceTokenIssuedAt = challenge.ResourceTokenIssuedAt
	store.invocation.ExpiresAt = challenge.ExpiresAt
	store.invocation.CompletionUntil = challenge.CompletionUntil
	return nil
}

func (store *heldMemoryStore) loaded(t *testing.T) HeldInvocation {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneHeldInvocationForTest(store.invocation)
}

func cloneHeldInvocationForTest(invocation HeldInvocation) HeldInvocation {
	invocation.Header = invocation.Header.Clone()
	invocation.Body = append([]byte(nil), invocation.Body...)
	invocation.RequiredScopes = append([]string(nil), invocation.RequiredScopes...)
	if invocation.Budget != nil {
		budget := *invocation.Budget
		invocation.Budget = &budget
	}
	if invocation.R3PerCall != nil {
		cloned := *invocation.R3PerCall
		cloned.ExactProposal = append([]byte(nil), invocation.R3PerCall.ExactProposal...)
		if cloned.Release != nil {
			release := cloneHeldResponseForTest(*cloned.Release)
			cloned.Release = &release
		}
		invocation.R3PerCall = &cloned
	}
	return invocation
}

func cloneHeldResponseForTest(response HeldResponse) HeldResponse {
	response.Header = response.Header.Clone()
	response.Body = append([]byte(nil), response.Body...)
	response.Trailer = response.Trailer.Clone()
	return response
}

var _ HeldInvocationStore = (*heldMemoryStore)(nil)
