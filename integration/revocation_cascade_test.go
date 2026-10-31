package integration_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

const (
	cascadeAgentProvider = "https://ap-cascade.example"
	cascadeAgent         = "aauth:reader@ap-cascade.example"
	cascadePersonServer  = "https://ps-cascade.example"
	cascadeAccessServer  = "https://as-cascade.example"
	cascadeResource      = "https://resource-cascade.example"
)

// revocationFixture is one Agent, Person Server, Resource and, for four-party
// access, Access Server, each with revocation enabled, on one logical network.
type revocationFixture struct {
	t           *testing.T
	ctx         context.Context
	clock       aauth.Clock
	nowMu       sync.Mutex
	now         time.Time
	network     *logicalTransport
	observer    *pendingObserver
	httpClient  *http.Client
	keyResolver signaturekey.KeyResolver
	admit       signaturekey.EgressAdmitter

	personServerKey jose.SigningKey
	resourceKey     jose.SigningKey
	agentConfig     clientagent.Config
	agent           *clientagent.Client

	personTokens   *memoryPersonTokenStore
	people         *personserver.Server
	peopleConfig   personserver.FederatedAuthorizationConfig
	threeParty     personserver.PSAuthorizationConfig
	access         *accessserver.Server
	protected      *resource.Server
	protectedCalls int

	mu          sync.Mutex
	requests    []string
	interceptor func(http.ResponseWriter, *http.Request) bool
}

func newRevocationFixture(t *testing.T, fourParty bool, resourceLimits aauth.RevocationLimits, accessHold time.Duration) *revocationFixture {
	t.Helper()
	fixture := &revocationFixture{
		t: t, ctx: context.Background(), now: time.Date(2026, 10, 30, 18, 0, 0, 0, time.UTC),
		network: newLogicalTransport(), personTokens: newMemoryPersonTokenStore(),
		personServerKey: newSigningKey(t, "cascade-ps"), resourceKey: newSigningKey(t, "cascade-resource"),
	}
	fixture.clock = aauth.ClockFunc(func() time.Time {
		fixture.nowMu.Lock()
		defer fixture.nowMu.Unlock()
		return fixture.now
	})
	fixture.observer = &pendingObserver{base: contextTransport{base: fixture.network}}
	fixture.httpClient = &http.Client{Transport: fixture.observer}
	fixture.admit = func(_ context.Context, endpoint string) error {
		if strings.HasPrefix(endpoint, "https://") && strings.Contains(endpoint, "-cascade.example/") {
			return nil
		}
		return errors.New("unexpected egress endpoint: " + endpoint)
	}
	keyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: fixture.httpClient, TransportEnforcesEgress: true, Clock: fixture.clock, Admit: fixture.admit,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.keyResolver = keyResolver

	agentKey := newSigningKey(t, "cascade-agent")
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: cascadeAgentProvider, SigningKey: newSigningKey(t, "cascade-ap"), Clock: fixture.clock,
		NewID: func() string { return "cascade-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: cascadeAgent, PersonServer: cascadePersonServer, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.network.Handle(cascadeAgentProvider, provider.Handler())

	ids := newSequence()
	scopes := []string{"records.read"}
	tokenRevocation := &personserver.TokenRevocationConfig{
		Revocations: testutil.NewTokenRevocationStore(), HTTPClient: fixture.httpClient, Admit: fixture.admit,
		Hold: 2 * time.Second,
	}
	bindPerson := func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
		return personserver.Person{Subject: "person-123", Lifetime: 30 * time.Minute}, nil
	}
	resourceRevocation := &resource.RevocationConfig{
		PersonTokens: testutil.NewTokenRevocationStore(), HTTPClient: fixture.httpClient, Admit: fixture.admit,
		Limits: resourceLimits,
	}
	protected := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		fixture.protectedCalls++
		_, _ = io.WriteString(response, "records")
	})
	resolvePerson := func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil }
	if fourParty {
		fixture.peopleConfig = personserver.FederatedAuthorizationConfig{
			Issuer: cascadePersonServer, SigningKey: fixture.personServerKey, KeyResolver: keyResolver,
			Clock: fixture.clock, NewID: ids.source("person-token"), HTTPClient: fixture.httpClient,
			Tokens: fixture.personTokens, BindPerson: bindPerson,
			AccessServerEndpoint: func(context.Context, string) (string, error) { return cascadeAccessServer + "/token", nil },
			Consent:              func(context.Context, personserver.AuthorizationRequest) error { return nil },
			TokenRevocation:      tokenRevocation,
		}
		fixture.people, err = personserver.NewFederatedAuthorization(fixture.peopleConfig)
		if err != nil {
			t.Fatal(err)
		}
		fixture.access, err = accessserver.New(accessserver.Config{
			Issuer: cascadeAccessServer, SigningKey: newSigningKey(t, "cascade-as"), KeyResolver: keyResolver,
			Clock: fixture.clock, NewID: ids.source("auth-token"),
			TrustPersonServer: func(_ context.Context, issuer string) error {
				if issuer != cascadePersonServer {
					return accessserver.ErrAccessDenied
				}
				return nil
			},
			Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
				return accessserver.Decision{Scopes: request.Scopes, Lifetime: 20 * time.Minute}, nil
			},
			Revocation: &accessserver.RevocationConfig{
				Revocations: testutil.NewTokenRevocationStore(), IssuedTokens: testutil.NewAccessIssuedAuthTokenStore(),
				HTTPClient: fixture.httpClient, Admit: fixture.admit, Hold: accessHold,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		fixture.protected, err = resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
			Issuer: cascadeResource, AccessServer: cascadeAccessServer, SigningKey: fixture.resourceKey,
			KeyResolver: keyResolver, Clock: fixture.clock, NewID: ids.source("resource-token"),
			ScopeDescriptions: map[string]string{"records.read": "Read records"},
			RequiredScopes:    func(*http.Request) []string { return scopes },
			ResolvePerson:     resolvePerson, Protected: protected,
			AuthTokenStatuses: newMemoryAuthTokenStatusStore(), Revocation: resourceRevocation,
		})
		if err != nil {
			t.Fatal(err)
		}
		fixture.route(cascadeAccessServer, fixture.access.Handler())
	} else {
		fixture.threeParty = personserver.PSAuthorizationConfig{
			Issuer: cascadePersonServer, SigningKey: fixture.personServerKey, KeyResolver: keyResolver,
			Clock: fixture.clock, NewID: ids.source("ps-token"), Tokens: fixture.personTokens, BindPerson: bindPerson,
			Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				return personserver.AuthorizationDecision{Scopes: request.Scopes, Lifetime: 20 * time.Minute}, nil
			},
			TokenRevocation: tokenRevocation,
		}
		fixture.people, err = personserver.NewPSAuthorization(fixture.threeParty)
		if err != nil {
			t.Fatal(err)
		}
		fixture.protected, err = resource.NewPSAuthorization(resource.PSAuthorizationConfig{
			Issuer: cascadeResource, SigningKey: fixture.resourceKey, KeyResolver: keyResolver,
			Clock: fixture.clock, NewID: ids.source("resource-token"),
			ScopeDescriptions: map[string]string{"records.read": "Read records"},
			RequiredScopes:    func(*http.Request) []string { return scopes },
			ResolvePerson:     resolvePerson, Protected: protected,
			AuthTokenStatuses: newMemoryAuthTokenStatusStore(), Revocation: resourceRevocation,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	fixture.route(cascadePersonServer, fixture.people.Handler())
	fixture.route(cascadeResource, fixture.protected.Handler())

	fixture.agentConfig = clientagent.Config{
		Identifier: cascadeAgent, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: keyResolver, HTTPClient: fixture.httpClient, Clock: fixture.clock,
	}
	fixture.agent = fixture.newAgent()
	return fixture
}

// route serves origin with handler, recording each request and letting the
// test intercept one before it reaches the role.
func (fixture *revocationFixture) route(origin string, handler http.Handler) {
	fixture.network.Handle(origin, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		fixture.mu.Lock()
		fixture.requests = append(fixture.requests, request.Method+" "+origin+request.URL.Path)
		interceptor := fixture.interceptor
		fixture.mu.Unlock()
		if interceptor != nil && interceptor(response, request) {
			return
		}
		handler.ServeHTTP(response, request)
	}))
}

func (fixture *revocationFixture) advance(delay time.Duration) {
	fixture.nowMu.Lock()
	defer fixture.nowMu.Unlock()
	fixture.now = fixture.now.Add(delay)
}

func (fixture *revocationFixture) count(request string) int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	count := 0
	for _, seen := range fixture.requests {
		if seen == request {
			count++
		}
	}
	return count
}

func (fixture *revocationFixture) newAgent() *clientagent.Client {
	fixture.t.Helper()
	agent, err := clientagent.New(fixture.ctx, fixture.agentConfig)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return agent
}

func (fixture *revocationFixture) personToken() string {
	fixture.t.Helper()
	result, err := fixture.agent.PersonToken(fixture.ctx, clientagent.PersonTokenRequest{
		PersonServer: cascadePersonServer, Resource: cascadeResource,
	})
	if err != nil {
		fixture.t.Fatal(err)
	}
	token, ok := result.Token()
	if !ok {
		fixture.t.Fatalf("person-token result = %#v", result)
	}
	return token
}

func (fixture *revocationFixture) recordsRequest() *http.Request {
	fixture.t.Helper()
	request, err := http.NewRequestWithContext(fixture.ctx, http.MethodGet, cascadeResource+"/records/42", nil)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return request
}

func (fixture *revocationFixture) resourceToken(agent *clientagent.Client, personToken string) (string, error) {
	fixture.t.Helper()
	result, err := agent.Begin(fixture.ctx, clientagent.InitialCall{Request: fixture.recordsRequest(), PersonToken: personToken})
	if err != nil {
		return "", err
	}
	requirement, ok := result.AuthorizationRequired()
	if !ok {
		fixture.t.Fatal("the Resource did not ask for an auth token")
	}
	return requirement.ResourceToken, nil
}

func (fixture *revocationFixture) call(authToken string) error {
	fixture.t.Helper()
	response, err := fixture.agent.Do(fixture.ctx, clientagent.Call{Request: fixture.recordsRequest(), AuthToken: authToken})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("protected response %d", response.StatusCode)
	}
	return nil
}

func requireRevokedJWT(t *testing.T, err error, label string) {
	t.Helper()
	var failure *signaturekey.Error
	if !errors.As(err, &failure) || failure.Code != signaturekey.ErrorRevokedJWT {
		t.Fatalf("%s error = %v, want Signature-Error revoked_jwt", label, err)
	}
}

func requireProblem(t *testing.T, err error, status int, code aauth.ErrorCode, label string) {
	t.Helper()
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Status != status || problem.Code != code {
		t.Fatalf("%s error = %v, want %d %s", label, err, status, code)
	}
}

func requireAttempts(t *testing.T, label string, attempts []aauth.RevocationAttempt, want ...string) {
	t.Helper()
	got := make([]string, 0, len(attempts))
	for _, attempt := range attempts {
		state := "recorded"
		switch {
		case attempt.Pending:
			state = "pending"
		case attempt.Error != "":
			state = string(attempt.Error)
		}
		got = append(got, attempt.Recipient+" "+state)
	}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Fatalf("%s attempts = %v, want %v", label, got, want)
	}
}

// Protocol 70d6737, Revocation Cascade and Token Endpoint Error Codes: a
// Person Server that revokes a person token revokes it at the Resource in its
// aud and at the Access Server it was presented to, and the Access Server
// revokes at the Resource the auth token it issued against it. A Resource
// withdrawing a resource token revokes it at the Access Server and the Person
// Server, and each refuses it with revoked_resource_token.
func TestFourPartyRevocationCascadesFromPersonServerThroughAccessServer(t *testing.T) {
	t.Parallel()
	fixture := newRevocationFixture(t, true, aauth.RevocationLimits{}, 0)
	ctx := fixture.ctx

	personToken := fixture.personToken()
	resourceToken, err := fixture.resourceToken(fixture.agent, personToken)
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := fixture.agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: cascadePersonServer, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.call(authToken); err != nil {
		t.Fatal(err)
	}

	// The Resource withdraws a second resource token before it is redeemed.
	withdrawn, err := fixture.resourceToken(fixture.agent, personToken)
	if err != nil {
		t.Fatal(err)
	}
	withdrawnClaims := tokenClaims(t, withdrawn)
	result, err := fixture.protected.RevokeResourceToken(ctx, resource.ResourceTokenRevocation{
		JTI: claimString(t, withdrawnClaims, "jti"), ExpiresAt: time.Unix(int64(withdrawnClaims["exp"].(float64)), 0),
		Audience: cascadeAccessServer, PersonServer: cascadePersonServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireAttempts(t, "resource-token revocation", result.Attempts, cascadeAccessServer+" recorded", cascadePersonServer+" recorded")
	_, err = fixture.agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: cascadePersonServer, ResourceToken: withdrawn, PresentedToken: personToken,
	})
	requireProblem(t, err, http.StatusBadRequest, "revoked_resource_token", "Person Server exchange of a withdrawn resource token")
	if !errors.Is(err, clientagent.ErrResourceTokenRevoked) {
		t.Fatalf("withdrawn resource token error = %v, want ErrResourceTokenRevoked", err)
	}

	// A Person Server that kept no record still cannot get an auth token for
	// it: the Access Server refuses the resource token itself.
	ledgerless := fixture.peopleConfig
	ledgerless.TokenRevocation = nil
	forgetful, err := personserver.NewFederatedAuthorization(ledgerless)
	if err != nil {
		t.Fatal(err)
	}
	fixture.route(cascadePersonServer, forgetful.Handler())
	_, err = fixture.newAgent().Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: cascadePersonServer, ResourceToken: withdrawn, PresentedToken: personToken,
	})
	requireProblem(t, err, http.StatusBadRequest, "revoked_resource_token", "Access Server exchange of a withdrawn resource token")
	fixture.route(cascadePersonServer, fixture.people.Handler())

	personJTI := claimString(t, tokenClaims(t, personToken), "jti")
	revoked, err := fixture.people.RevokePersonToken(ctx, personJTI)
	if err != nil {
		t.Fatal(err)
	}
	requireAttempts(t, "person-token revocation", revoked.Attempts, cascadeResource+" recorded", cascadeAccessServer+" recorded")
	if revoked.Pending() {
		t.Fatal("a recorded cascade is reported pending")
	}
	if report := revoked.Attempts[1].Downstream; len(report) != 1 || report[0] != (aauth.DownstreamRevocation{Recipient: cascadeResource}) {
		t.Fatalf("Access Server downstream report = %#v", report)
	}

	// The Resource refuses the person token and the auth token issued against it.
	_, err = fixture.resourceToken(fixture.agent, personToken)
	requireRevokedJWT(t, err, "person token at the Resource")
	requireRevokedJWT(t, fixture.call(authToken), "auth token issued against it")
	calls := fixture.protectedCalls

	// The Person Server refuses the person token as presented_token, and does
	// not present it to the Access Server.
	asTokenRequests := fixture.count("POST " + cascadeAccessServer + "/token")
	_, err = fixture.agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: cascadePersonServer, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	requireProblem(t, err, http.StatusBadRequest, "revoked_presented_token", "Person Server exchange of a revoked person token")
	if fixture.count("POST "+cascadeAccessServer+"/token") != asTokenRequests {
		t.Fatal("the Person Server presented a revoked person token to the Access Server")
	}

	// The Access Server issues no further auth token against it either.
	fixture.route(cascadePersonServer, forgetful.Handler())
	_, err = fixture.newAgent().Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: cascadePersonServer, ResourceToken: resourceToken, PresentedToken: personToken,
	})
	requireProblem(t, err, http.StatusBadRequest, "revoked_presented_token", "Access Server exchange of a revoked person token")
	fixture.route(cascadePersonServer, fixture.people.Handler())

	// Revoking again records nothing new and calls no recipient that recorded it.
	asRevocations := fixture.count("POST " + cascadeAccessServer + "/revoke")
	again, err := fixture.people.RevokePersonToken(ctx, personJTI)
	if err != nil {
		t.Fatal(err)
	}
	requireAttempts(t, "repeated person-token revocation", again.Attempts, cascadeResource+" recorded", cascadeAccessServer+" recorded")
	if fixture.count("POST "+cascadeAccessServer+"/revoke") != asRevocations {
		t.Fatal("a repeated revocation called an Access Server that had recorded it")
	}
	if fixture.protectedCalls != calls {
		t.Fatal("a revoked credential reached the protected handler")
	}
}

// Protocol 70d6737, Revocation Response: a cascade that outlasts the
// recipient's hold is answered 202, the caller polls the pending URL with a
// signed GET under the identity that revoked, any other identity is answered
// 404, and once the terminal response is returned the URL is 410.
func TestRevocationCascadeIsDeferredAndPolledByItsCaller(t *testing.T) {
	t.Parallel()
	fixture := newRevocationFixture(t, true, aauth.RevocationLimits{}, time.Second)
	ctx := fixture.ctx

	personToken := fixture.personToken()
	resourceToken, err := fixture.resourceToken(fixture.agent, personToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: cascadePersonServer, ResourceToken: resourceToken, PresentedToken: personToken,
	}); err != nil {
		t.Fatal(err)
	}

	// The Resource does not answer the Access Server until released.
	release := make(chan struct{})
	fixture.mu.Lock()
	fixture.interceptor = func(response http.ResponseWriter, request *http.Request) bool {
		if request.URL.Host == strings.TrimPrefix(cascadeResource, "https://") && request.URL.Path == "/revoke" &&
			strings.Contains(request.Header.Get("Signature-Key"), cascadeAccessServer) {
			select {
			case <-release:
			case <-request.Context().Done():
				return true
			}
		}
		return false
	}
	fixture.mu.Unlock()

	personJTI := claimString(t, tokenClaims(t, personToken), "jti")
	revoked, err := fixture.people.RevokePersonToken(ctx, personJTI)
	if err != nil {
		t.Fatal(err)
	}
	requireAttempts(t, "held person-token revocation", revoked.Attempts, cascadeResource+" recorded", cascadeAccessServer+" pending")
	if !revoked.Pending() || revoked.RetryAfter() <= 0 {
		t.Fatalf("pending revocation = %#v", revoked)
	}
	location := fixture.observer.pending()
	if !strings.HasPrefix(location, cascadeAccessServer+"/revoke/pending/") {
		t.Fatalf("Access Server pending URL = %q", location)
	}

	poll := func(key jose.SigningKey, issuer, document string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, location, nil)
		if err := signaturekey.SignJWKSURIRequest(request, key, issuer, document, fixture.clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		fixture.access.Handler().ServeHTTP(response, request)
		return response
	}
	if response := poll(fixture.resourceKey, cascadeResource, aauth.ResourceDiscoveryDocument); response.Code != http.StatusNotFound {
		t.Fatalf("poll by another identity = %d %s", response.Code, response.Body.String())
	}
	unsigned := httptest.NewRecorder()
	fixture.access.Handler().ServeHTTP(unsigned, httptest.NewRequest(http.MethodGet, location, nil))
	if unsigned.Code != http.StatusUnauthorized || unsigned.Header().Get("Signature-Error") == "" {
		t.Fatalf("unsigned poll = %d %v", unsigned.Code, unsigned.Header())
	}

	close(release)
	// The Person Server polls once the Access Server's Retry-After has passed.
	early, err := fixture.people.RevokePersonToken(ctx, personJTI)
	if err != nil {
		t.Fatal(err)
	}
	requireAttempts(t, "revocation before Retry-After", early.Attempts, cascadeResource+" recorded", cascadeAccessServer+" pending")
	if fixture.count("GET "+location) != 0 {
		t.Fatal("the Person Server polled before Retry-After")
	}
	fixture.advance(revoked.RetryAfter())
	completed, err := fixture.people.RevokePersonToken(ctx, personJTI)
	if err != nil {
		t.Fatal(err)
	}
	requireAttempts(t, "completed person-token revocation", completed.Attempts, cascadeResource+" recorded", cascadeAccessServer+" recorded")
	if report := completed.Attempts[1].Downstream; len(report) != 1 || report[0] != (aauth.DownstreamRevocation{Recipient: cascadeResource}) {
		t.Fatalf("Access Server downstream report = %#v", report)
	}
	if fixture.count("GET "+location) != 1 {
		t.Fatal("the Person Server did not poll the pending URL once")
	}
	if response := poll(fixture.personServerKey, cascadePersonServer, aauth.PersonDiscoveryDocument); response.Code != http.StatusGone {
		t.Fatalf("poll after the terminal response = %d %s", response.Code, response.Body.String())
	}
}

// Protocol 70d6737, Revocation Response: a recipient bounds the revocations
// one caller sends and answers rate_limited with Retry-After; Token Endpoint
// Error Codes: revoked_resource_token is terminal for that token, so the
// Agent never submits it again and calls the Resource for a fresh one.
func TestThreePartyWithdrawnResourceTokenAndRateLimitedRevocation(t *testing.T) {
	t.Parallel()
	fixture := newRevocationFixture(t, false, aauth.RevocationLimits{Requests: 1}, 0)
	ctx := fixture.ctx

	personToken := fixture.personToken()
	withdrawn, err := fixture.resourceToken(fixture.agent, personToken)
	if err != nil {
		t.Fatal(err)
	}
	claims := tokenClaims(t, withdrawn)
	result, err := fixture.protected.RevokeResourceToken(ctx, resource.ResourceTokenRevocation{
		JTI: claimString(t, claims, "jti"), ExpiresAt: time.Unix(int64(claims["exp"].(float64)), 0),
		Audience: cascadePersonServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireAttempts(t, "resource-token revocation", result.Attempts, cascadePersonServer+" recorded")

	exchange := clientagent.ExchangeRequest{PersonServer: cascadePersonServer, ResourceToken: withdrawn, PresentedToken: personToken}
	_, err = fixture.agent.Exchange(ctx, exchange)
	requireProblem(t, err, http.StatusBadRequest, "revoked_resource_token", "exchange of a withdrawn resource token")
	tokenRequests := fixture.count("POST " + cascadePersonServer + "/token")
	_, err = fixture.agent.Exchange(ctx, exchange)
	var refusal *clientagent.RevokedResourceTokenError
	if !errors.As(err, &refusal) || refusal.Problem != nil || !errors.Is(err, clientagent.ErrResourceTokenRevoked) {
		t.Fatalf("resubmission error = %v, want a local refusal", err)
	}
	if fixture.count("POST "+cascadePersonServer+"/token") != tokenRequests {
		t.Fatal("the Agent submitted a withdrawn resource token again")
	}
	fresh, err := fixture.resourceToken(fixture.agent, personToken)
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := fixture.agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: cascadePersonServer, ResourceToken: fresh, PresentedToken: personToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.call(authToken); err != nil {
		t.Fatal(err)
	}

	// The Resource accepts one revocation per window from this Person Server.
	first, err := fixture.people.RevokePersonToken(ctx, claimString(t, tokenClaims(t, personToken), "jti"))
	if err != nil {
		t.Fatal(err)
	}
	requireAttempts(t, "first person-token revocation", first.Attempts, cascadeResource+" recorded")
	secondJTI := claimString(t, tokenClaims(t, fixture.personToken()), "jti")
	second, err := fixture.people.RevokePersonToken(ctx, secondJTI)
	if err != nil {
		t.Fatal(err)
	}
	// rate_limited is not terminal: the revocation stays pending until the
	// Resource's Retry-After has passed, and is then made again.
	requireAttempts(t, "rate-limited person-token revocation", second.Attempts, cascadeResource+" pending")
	var limited *aauth.RateLimitedError
	if !errors.As(second.Attempts[0].Cause, &limited) || limited.Problem.Status != http.StatusTooManyRequests ||
		limited.Problem.Code != "rate_limited" || limited.RetryAfter <= 0 || second.Attempts[0].RetryAfter != limited.RetryAfter {
		t.Fatalf("rate-limited attempt = %#v", second.Attempts[0])
	}
	fixture.advance(limited.RetryAfter)
	retried, err := fixture.people.RevokePersonToken(ctx, secondJTI)
	if err != nil {
		t.Fatal(err)
	}
	requireAttempts(t, "person-token revocation after Retry-After", retried.Attempts, cascadeResource+" recorded")
}

// contextTransport ends a round trip when its request context ends, as a
// network transport does, while the handler behind it keeps running.
type contextTransport struct{ base http.RoundTripper }

func (transport contextTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	type answer struct {
		response *http.Response
		err      error
	}
	answers := make(chan answer, 1)
	go func() {
		response, err := transport.base.RoundTrip(request)
		answers <- answer{response: response, err: err}
	}()
	select {
	case received := <-answers:
		return received.response, received.err
	case <-request.Context().Done():
		return nil, request.Context().Err()
	}
}

// pendingObserver records the Location of the last 202 revocation answer.
type pendingObserver struct {
	base     http.RoundTripper
	mu       sync.Mutex
	location string
}

func (observer *pendingObserver) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := observer.base.RoundTrip(request)
	if err == nil && response.StatusCode == http.StatusAccepted && request.URL.Path == "/revoke" {
		observer.mu.Lock()
		observer.location = response.Header.Get("Location")
		observer.mu.Unlock()
	}
	return response, err
}

func (observer *pendingObserver) pending() string {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	return observer.location
}

// sequence issues distinct identifiers for each prefix.
type sequence struct {
	mu   sync.Mutex
	next map[string]int
}

func newSequence() *sequence { return &sequence{next: make(map[string]int)} }

func (ids *sequence) source(prefix string) func() string {
	return func() string {
		ids.mu.Lock()
		defer ids.mu.Unlock()
		ids.next[prefix]++
		return fmt.Sprintf("%s-%d", prefix, ids.next[prefix])
	}
}
