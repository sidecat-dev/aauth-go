package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// TestPSAuthorizationAuthTokenStaysInsidePersonAndResourceTokens covers the
// Person Server's own authorization path with a Person token shorter than the
// Auth lifetime and with a policy that returns after its inputs expire.
func TestPSAuthorizationAuthTokenStaysInsidePersonAndResourceTokens(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 10, 2, 18, 0, 0, 0, time.UTC)
	tests := []struct {
		name           string
		personExpires  time.Duration
		resourceExpiry time.Duration
		arrive         time.Duration
		policyReturns  time.Duration
		wantProblem    string
		wantPolicy     bool
		wantIssuedAt   time.Duration
		wantExpiresAt  time.Duration
	}{
		{
			name: "longer Person token keeps policy lifetime", personExpires: 20 * time.Minute,
			resourceExpiry: 5 * time.Minute, wantPolicy: true, wantExpiresAt: 5 * time.Minute,
		},
		{
			name: "shorter Person token caps Auth token", personExpires: time.Minute,
			resourceExpiry: 5 * time.Minute, wantPolicy: true, wantExpiresAt: time.Minute,
		},
		{
			name: "near-expiry Person token buys only its remainder", personExpires: time.Minute,
			resourceExpiry: 5 * time.Minute, arrive: 59 * time.Second, wantPolicy: true,
			wantIssuedAt: 59 * time.Second, wantExpiresAt: time.Minute,
		},
		{
			name: "expired Person token closes authorization before policy", personExpires: time.Minute,
			resourceExpiry: 5 * time.Minute, arrive: time.Minute, wantProblem: "expired_presented_token",
		},
		{
			name: "slow policy issues at its return instant", personExpires: time.Minute,
			resourceExpiry: 5 * time.Minute, policyReturns: 59 * time.Second, wantPolicy: true,
			wantIssuedAt: 59 * time.Second, wantExpiresAt: time.Minute,
		},
		{
			name: "slow policy outlasting Person token issues nothing", personExpires: time.Minute,
			resourceExpiry: 5 * time.Minute, policyReturns: time.Minute, wantPolicy: true,
			wantProblem: "expired_presented_token",
		},
		{
			name: "slow policy outlasting Resource token issues nothing", personExpires: 20 * time.Minute,
			resourceExpiry: 2 * time.Minute, policyReturns: 2 * time.Minute, wantPolicy: true,
			wantProblem: "expired_resource_token",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var mu sync.Mutex
			current := start
			setClock := func(value time.Time) {
				mu.Lock()
				defer mu.Unlock()
				current = value
			}
			clock := aauth.ClockFunc(func() time.Time {
				mu.Lock()
				defer mu.Unlock()
				return current
			})
			providerKey := personServerTestKey(t, "predecessor-provider")
			personKey := personServerTestKey(t, "predecessor-person")
			resourceKey := personServerTestKey(t, "predecessor-resource")
			agentKey := personServerTestKey(t, "predecessor-agent")
			const (
				providerID = "https://provider.example"
				personID   = "https://person.example"
				resourceID = "https://resource.example"
				agentID    = "aauth:planner@provider.example"
			)
			resolver := signaturekey.StaticKeyResolver{
				{Issuer: providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
				{Issuer: personID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personKey.ID()}:       personKey.PublicJWK(),
				{Issuer: resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
			}
			agentToken, err := aauth.MintAgentToken(providerID, providerKey, aauth.AgentTokenRequest{
				Agent: agentID, PersonServer: personID, PublicKey: agentKey.PublicJWK(), Lifetime: 30 * time.Minute,
			}, start, "predecessor-agent-token")
			if err != nil {
				t.Fatal(err)
			}
			agentJKT, err := agentKey.PublicJWK().Thumbprint()
			if err != nil {
				t.Fatal(err)
			}
			resourceToken, err := aauth.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
				Issuer: resourceID, DWK: aauth.ResourceDiscoveryDocument, Audience: personID,
				JTI: "predecessor-resource-token", AgentJKT: agentJKT,
				IssuedAt: start.Unix(), ExpiresAt: start.Add(test.resourceExpiry).Unix(),
				Scope: "records.read", PersonServer: personID, Subject: "person-123",
				PresentedJTI: "predecessor-person-token", Tenant: "tenant-1",
			})
			if err != nil {
				t.Fatal(err)
			}
			store := newMemoryTokenStore()
			if err := store.Commit(context.Background(), directPersonTokenRecord(
				"predecessor-person-token", personID, resourceID, "person-123", "tenant-1",
				providerID, agentID, agentKey.PublicJWK(),
				start.Add(test.personExpires), start.Add(test.personExpires+time.Hour),
			)); err != nil {
				t.Fatal(err)
			}
			policyCalls := 0
			server, err := NewPSAuthorization(PSAuthorizationConfig{
				Issuer: personID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
				NewID: func() string { return "predecessor-auth-token" }, Tokens: store,
				BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
				Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
					policyCalls++
					if test.policyReturns != 0 {
						setClock(start.Add(test.policyReturns))
					}
					return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: 5 * time.Minute}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			setClock(start.Add(test.arrive))
			presentedToken := testPresentedPersonToken(
				t, personKey, resourceToken, agentKey.PublicJWK(), start, start.Add(test.personExpires),
			)
			body := testTokenRequestBody(t, resourceToken, presentedToken)
			request := httptest.NewRequest(http.MethodPost, personID+"/token", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			if err := signPersonServerTestRequest(request, agentKey, agentToken, clock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)

			wantCalls := 0
			if test.wantPolicy {
				wantCalls = 1
			}
			if policyCalls != wantCalls {
				t.Fatalf("policy calls = %d, want %d", policyCalls, wantCalls)
			}
			if test.wantProblem != "" {
				assertPersonServerProblem(t, response, test.wantProblem)
				return
			}
			if response.Code != http.StatusOK {
				t.Fatalf("exchange = %d %s", response.Code, response.Body.String())
			}
			var output struct {
				AuthToken string `json:"auth_token"`
				ExpiresIn int64  `json:"expires_in"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
				t.Fatal(err)
			}
			claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, resolver, clock)
			if err != nil {
				t.Fatal(err)
			}
			if claims.IssuedAt != start.Add(test.wantIssuedAt).Unix() ||
				claims.ExpiresAt != start.Add(test.wantExpiresAt).Unix() ||
				output.ExpiresIn != int64((test.wantExpiresAt-test.wantIssuedAt)/time.Second) {
				t.Fatalf("auth token iat=%d exp=%d expires_in=%d, want iat=%d exp=%d",
					claims.IssuedAt, claims.ExpiresAt, output.ExpiresIn,
					start.Add(test.wantIssuedAt).Unix(), start.Add(test.wantExpiresAt).Unix())
			}
		})
	}
}

// TestDeferredAuthorizationAuthTokenStaysInsideRetainedPersonToken approves a
// pending authorization one second before the retained Person token expires
// with a longer Auth lifetime. Minting, retained-result recovery and poll
// delivery all keep the Auth token inside the Person token.
func TestDeferredAuthorizationAuthTokenStaysInsideRetainedPersonToken(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	start := protocol.now
	personExpiresAt := start.Add(60 * time.Second)
	// The presented Person token expires with the retained record it names.
	protocol.presentedExpiresAt = personExpiresAt
	store := newMemoryDeferredAuthorizationStore()
	newServer := func() *Server {
		t.Helper()
		config := protocol.config(store)
		tokens := newMemoryTokenStore()
		if err := tokens.Commit(context.Background(), directPersonTokenRecord(
			"authorization-person-token", protocol.personServerID, protocol.resourceID, protocol.subject, protocol.tenant,
			protocol.providerID, protocol.agentID, protocol.agentKey.PublicJWK(), personExpiresAt, personExpiresAt.Add(time.Hour),
		)); err != nil {
			t.Fatal(err)
		}
		config.Tokens = tokens
		server, err := NewPSAuthorization(config)
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	server := newServer()
	response := protocol.exchange(t, server, []string{"interaction"})
	if response.Code != http.StatusAccepted {
		t.Fatalf("initial response = %d %s", response.Code, response.Body.String())
	}
	if pending := store.onlyPending(t); !pending.PersonTokenExpiresAt.Equal(personExpiresAt) || !pending.ExpiresAt.Equal(personExpiresAt) {
		t.Fatalf("pending Person token expiry = %s, deadline = %s; want both %s",
			pending.PersonTokenExpiresAt, pending.ExpiresAt, personExpiresAt)
	}
	requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	value, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}

	protocol.now = start.Add(59 * time.Second)
	decision := AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: 300 * time.Second}
	store.approveReturnChange = func(canonical *AuthorizationApproval) { canonical.Token = "" }
	if err := server.ApproveAuthorizationInteraction(context.Background(), value, decision); err == nil {
		t.Fatal("server accepted a malformed canonical approval")
	}
	store.approveReturnChange = nil
	if retained := store.approvedPoll(t); retained.ExpiresIn != 1 || !retained.DecidedAt.Equal(protocol.now) {
		t.Fatalf("retained approval expires_in = %d, decided_at = %s", retained.ExpiresIn, retained.DecidedAt)
	}
	if err := server.ApproveAuthorizationInteraction(context.Background(), value, decision); err != nil {
		t.Fatalf("retained approval recovery = %v", err)
	}
	if calls := protocol.tokenIDCalls(); calls != 1 {
		t.Fatalf("token ID allocations = %d", calls)
	}

	poll := protocol.poll(t, newServer(), response.Header().Get("Location"), protocol.agentKey, protocol.agentToken)
	if poll.Code != http.StatusOK {
		t.Fatalf("approved poll = %d %s", poll.Code, poll.Body.String())
	}
	var output struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(poll.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), output.AuthToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.IssuedAt != protocol.now.Unix() || claims.ExpiresAt != personExpiresAt.Unix() || output.ExpiresIn != 1 {
		t.Fatalf("auth token iat=%d exp=%d expires_in=%d, want iat=%d exp=%d expires_in=1",
			claims.IssuedAt, claims.ExpiresAt, output.ExpiresIn, protocol.now.Unix(), personExpiresAt.Unix())
	}
}
