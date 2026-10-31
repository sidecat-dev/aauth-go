package accessserver_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

const (
	chainPersonServer = "https://ps.example"
	chainRelay        = "https://relay.example"
	chainRelayAgent   = "aauth:relay@relay.example"
	chainResource     = "https://inventory.example"
	chainAccess       = "https://as.example"
	chainUpstreamAS   = "https://orders-as.example"
)

func chainKey(t *testing.T, id string) jose.SigningKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.NewEd25519SigningKey(id, private)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type chainFixture struct {
	t          *testing.T
	now        time.Time
	clock      aauth.Clock
	keys       map[string]jose.SigningKey
	relayToken string
	resource   string
	presented  string
	server     *accessserver.Server
	evaluated  []accessserver.AuthorizationRequest
	pending    bool
	nextID     int
	// revokedAt records each revocation the Access Server sends a Resource.
	revokedMu sync.Mutex
	revokedAt []string
}

func newChainFixture(t *testing.T) *chainFixture {
	t.Helper()
	fixture := &chainFixture{t: t, now: time.Date(2026, 10, 30, 15, 0, 0, 0, time.UTC), keys: map[string]jose.SigningKey{}}
	fixture.clock = aauth.ClockFunc(func() time.Time { return fixture.now })
	for _, name := range []string{"ps", "other-ps", "relay-provider", "relay-agent", "caller", "resource", "as", "orders-as"} {
		fixture.keys[name] = chainKey(t, name)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: chainPersonServer, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: "ps"}:                fixture.keys["ps"].PublicJWK(),
		{Issuer: "https://other-ps.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: "other-ps"}: fixture.keys["other-ps"].PublicJWK(),
		{Issuer: chainRelay, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: "relay-provider"}:            fixture.keys["relay-provider"].PublicJWK(),
		{Issuer: chainResource, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: "resource"}:            fixture.keys["resource"].PublicJWK(),
		{Issuer: chainAccess, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: "as"}:                      fixture.keys["as"].PublicJWK(),
		{Issuer: chainUpstreamAS, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: "orders-as"}:           fixture.keys["orders-as"].PublicJWK(),
	}
	var err error
	// The intermediary is its own Agent Provider. Its Agent token names its
	// own Person Server, which is not the person's.
	fixture.relayToken, err = aauth.MintAgentToken(chainRelay, fixture.keys["relay-provider"], aauth.AgentTokenRequest{
		Agent: chainRelayAgent, PersonServer: "https://relay-person.example",
		PublicKey: fixture.keys["relay-agent"].PublicJWK(), Lifetime: time.Hour,
	}, fixture.now, "relay-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	relayJKT, err := fixture.keys["relay-agent"].PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	fixture.resource, err = aauth.MintResourceToken(fixture.keys["resource"], aauth.ResourceTokenClaims{
		Issuer: chainResource, DWK: aauth.ResourceDiscoveryDocument, Audience: chainAccess,
		JTI: "inventory-resource-token", AgentJKT: relayJKT, IssuedAt: fixture.now.Unix(),
		ExpiresAt: fixture.now.Add(5 * time.Minute).Unix(), Scope: "inventory.reserve",
		PersonServer: chainPersonServer, Subject: "person-at-inventory", PresentedJTI: "inventory-person-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.presented, err = aauth.MintPersonToken(fixture.keys["ps"], aauth.PersonTokenClaims{
		Issuer: chainPersonServer, DWK: aauth.PersonDiscoveryDocument, Audience: chainResource,
		Subject: "person-at-inventory", Confirmation: aauth.Confirmation{JWK: fixture.keys["relay-agent"].PublicJWK()},
		JTI: "inventory-person-token", IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(50 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.server, err = accessserver.New(accessserver.Config{
		Issuer: chainAccess, SigningKey: fixture.keys["as"], KeyResolver: resolver, Clock: fixture.clock,
		NewID: func() string {
			fixture.nextID++
			return fmt.Sprintf("inventory-auth-token-%d", fixture.nextID)
		},
		TrustPersonServer: func(context.Context, string) error { return nil },
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			fixture.evaluated = append(fixture.evaluated, request)
			if fixture.pending {
				return accessserver.Decision{Pending: &accessserver.PendingDecision{}}, nil
			}
			return accessserver.Decision{Scopes: []string{"inventory.reserve"}, Lifetime: 30 * time.Minute}, nil
		},
		Deferred: &accessserver.DeferredConfig{Store: testutil.NewAccessAuthorizationStore(), Lifetime: time.Hour},
		Revocation: &accessserver.RevocationConfig{
			Revocations: testutil.NewTokenRevocationStore(), IssuedTokens: testutil.NewAccessIssuedAuthTokenStore(),
			HTTPClient: &http.Client{Transport: chainRecipient{fixture}},
			Admit:      func(context.Context, string) error { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

// chainRecipient answers a Resource's metadata and revocation endpoint and
// records the jti each revocation names.
type chainRecipient struct{ fixture *chainFixture }

func (recipient chainRecipient) RoundTrip(request *http.Request) (*http.Response, error) {
	origin := request.URL.Scheme + "://" + request.URL.Host
	response := httptest.NewRecorder()
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/.well-known/aauth-resource.json":
		_ = json.NewEncoder(response).Encode(map[string]string{"issuer": origin, "revocation_endpoint": origin + "/revoke"})
	case request.Method == http.MethodPost && request.URL.Path == "/revoke":
		var revocation struct {
			JTI string `json:"jti"`
		}
		_ = json.NewDecoder(request.Body).Decode(&revocation)
		recipient.fixture.revokedMu.Lock()
		recipient.fixture.revokedAt = append(recipient.fixture.revokedAt, origin+" "+revocation.JTI)
		recipient.fixture.revokedMu.Unlock()
	default:
		response.WriteHeader(http.StatusNotFound)
	}
	result := response.Result()
	result.Request = request
	return result, nil
}

// revoke posts a signed revocation of jti to the Access Server as the server
// that issued the token: the Person Server, or the Resource.
func (fixture *chainFixture) revoke(issuer, document, key, jti string) *httptest.ResponseRecorder {
	fixture.t.Helper()
	body, err := aauth.EncodeRevocationRequest(aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: issuer, JTI: jti}, ExpiresAt: fixture.now.Add(time.Hour),
	})
	if err != nil {
		fixture.t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, chainAccess+"/revoke", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		request, fixture.keys[key], issuer, document, fixture.clock,
		signaturekey.SignOptions{AdditionalComponents: []string{"content-type", "content-digest"}, MaxBodyBytes: int64(len(body))},
	); err != nil {
		fixture.t.Fatal(err)
	}
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, request)
	return response
}

func (fixture *chainFixture) upstreamPerson(change func(*aauth.PersonTokenClaims), signer string) string {
	claims := aauth.PersonTokenClaims{
		Issuer: chainPersonServer, DWK: aauth.PersonDiscoveryDocument, Audience: chainRelay,
		Subject: "person-at-relay", Confirmation: aauth.Confirmation{JWK: fixture.keys["caller"].PublicJWK()},
		JTI: "relay-person-token", IssuedAt: fixture.now.Add(-time.Minute).Unix(), ExpiresAt: fixture.now.Add(10 * time.Minute).Unix(),
	}
	if change != nil {
		change(&claims)
	}
	compact, err := aauth.MintPersonToken(fixture.keys[signer], claims)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return compact
}

func (fixture *chainFixture) upstreamAuth() string {
	compact, err := aauth.MintAuthToken(fixture.keys["orders-as"], aauth.AuthTokenClaims{
		Issuer: chainUpstreamAS, DWK: aauth.AccessDiscoveryDocument, Audience: chainRelay, JTI: "orders-auth-token",
		PersonServer: chainPersonServer, Subject: "person-at-relay",
		Confirmation: aauth.Confirmation{JWK: fixture.keys["caller"].PublicJWK()},
		IssuedAt:     fixture.now.Add(-time.Minute).Unix(), ExpiresAt: fixture.now.Add(8 * time.Minute).Unix(),
		Scope: "orders.fulfill",
	})
	if err != nil {
		fixture.t.Fatal(err)
	}
	return compact
}

func (fixture *chainFixture) signed(method, target string, body []byte) *http.Request {
	fixture.t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	options := signaturekey.SignOptions{}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
		options = signaturekey.SignOptions{AdditionalComponents: []string{"content-type", "content-digest"}, MaxBodyBytes: int64(len(body))}
	}
	if err := signaturekey.SignJWKSURIRequestWithOptions(
		request, fixture.keys["ps"], chainPersonServer, aauth.PersonDiscoveryDocument, fixture.clock, options,
	); err != nil {
		fixture.t.Fatal(err)
	}
	return request
}

func (fixture *chainFixture) token(input map[string]any) *httptest.ResponseRecorder {
	fixture.t.Helper()
	body := map[string]any{
		"resource_token": fixture.resource, "agent_token": fixture.relayToken, "presented_token": fixture.presented,
	}
	for name, value := range input {
		if value == nil {
			delete(body, name)
			continue
		}
		body[name] = value
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		fixture.t.Fatal(err)
	}
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, fixture.signed(http.MethodPost, chainAccess+"/token", encoded))
	return response
}

func chainProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var problem struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &problem)
	if response.Code != status || problem.Error != code {
		t.Fatalf("response = %d %s, want %d %s", response.Code, response.Body.String(), status, code)
	}
}

// PS-to-AS Token Request: an Access Server verifies the upstream_token a
// Person Server passes through, per Upstream Token Verification, and the
// downstream auth token never outlives it or copies its sub.
func TestAccessServerVerifiesTheUpstreamTokenOfAChainedRequest(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		upstream  func(*chainFixture) string
		expiresAt time.Duration
		person    bool
	}{
		{name: "person token", upstream: func(f *chainFixture) string { return f.upstreamPerson(nil, "ps") }, expiresAt: 10 * time.Minute, person: true},
		{name: "auth token from another Access Server", upstream: (*chainFixture).upstreamAuth, expiresAt: 8 * time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newChainFixture(t)
			response := fixture.token(map[string]any{"upstream_token": test.upstream(fixture)})
			if response.Code != http.StatusOK {
				t.Fatalf("token response = %d %s", response.Code, response.Body.String())
			}
			var output struct {
				AuthToken string `json:"auth_token"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
				t.Fatal(err)
			}
			parsed, err := jose.ParseCompact(output.AuthToken)
			if err != nil {
				t.Fatal(err)
			}
			var claims aauth.AuthTokenClaims
			if err := json.Unmarshal(parsed.Payload(), &claims); err != nil {
				t.Fatal(err)
			}
			if claims.Subject != "person-at-inventory" || claims.ExpiresAt != fixture.now.Add(test.expiresAt).Unix() ||
				!claims.Confirmation.JWK.Equal(fixture.keys["relay-agent"].PublicJWK()) || claims.PersonServer != chainPersonServer {
				t.Fatalf("downstream auth token = %#v", claims)
			}
			if len(fixture.evaluated) != 1 {
				t.Fatalf("policy calls = %d", len(fixture.evaluated))
			}
			evaluated := fixture.evaluated[0]
			if evaluated.Agent.Identifier != chainRelayAgent || evaluated.Subject != "person-at-inventory" {
				t.Fatalf("policy request = %#v", evaluated)
			}
			if test.person {
				if evaluated.Upstream != nil || evaluated.UpstreamPerson == nil || evaluated.UpstreamPerson.Subject != "person-at-relay" {
					t.Fatalf("policy upstream = %#v, %#v", evaluated.Upstream, evaluated.UpstreamPerson)
				}
			} else if evaluated.UpstreamPerson != nil || evaluated.Upstream == nil || evaluated.Upstream.Issuer != chainUpstreamAS {
				t.Fatalf("policy upstream = %#v, %#v", evaluated.Upstream, evaluated.UpstreamPerson)
			}
		})
	}

	fixture := newChainFixture(t)
	for _, test := range []struct {
		name   string
		input  map[string]any
		status int
		code   string
	}{
		{name: "an Agent token", input: map[string]any{"upstream_token": fixture.relayToken}, status: 400, code: "invalid_upstream_token"},
		{name: "another audience", input: map[string]any{"upstream_token": fixture.upstreamPerson(func(claims *aauth.PersonTokenClaims) {
			claims.Audience = "https://elsewhere.example"
		}, "ps")}, status: 400, code: "invalid_upstream_token"},
		{name: "another Person Server", input: map[string]any{"upstream_token": fixture.upstreamPerson(func(claims *aauth.PersonTokenClaims) {
			claims.Issuer = "https://other-ps.example"
		}, "other-ps")}, status: 400, code: "invalid_upstream_token"},
		{name: "a forged signature", input: map[string]any{"upstream_token": fixture.upstreamPerson(nil, "other-ps")}, status: 400, code: "invalid_upstream_token"},
		{name: "an expired token", input: map[string]any{"upstream_token": fixture.upstreamPerson(func(claims *aauth.PersonTokenClaims) {
			claims.IssuedAt, claims.ExpiresAt = fixture.now.Add(-time.Hour).Unix(), fixture.now.Add(-time.Minute).Unix()
		}, "ps")}, status: 400, code: "expired_upstream_token"},
		{name: "a token issued after the request", input: map[string]any{"upstream_token": fixture.upstreamPerson(func(claims *aauth.PersonTokenClaims) {
			claims.IssuedAt = fixture.now.Add(5 * time.Minute).Unix()
		}, "ps")}, status: 400, code: "clock_skew"},
		{name: "a malformed value", input: map[string]any{"upstream_token": 7}, status: 400, code: "invalid_upstream_token"},
		{name: "a sub-agent token beside it", input: map[string]any{"upstream_token": fixture.upstreamPerson(nil, "ps"), "subagent_token": fixture.relayToken}, status: 400, code: "invalid_request"},
		{name: "no upstream token for the intermediary", input: map[string]any{}, status: 400, code: "invalid_agent_token"},
	} {
		t.Run("refuses "+test.name, func(t *testing.T) {
			before := len(fixture.evaluated)
			chainProblem(t, fixture.token(test.input), test.status, test.code)
			if len(fixture.evaluated) != before {
				t.Fatal("a refused chained request reached authorization policy")
			}
		})
	}
}

// A pending downstream request whose upstream token expires before it
// completes ends with expired.
func TestAccessServerEndsAChainedWaitWhenItsUpstreamTokenExpires(t *testing.T) {
	t.Parallel()

	fixture := newChainFixture(t)
	fixture.pending = true
	// The upstream token ends before the Resource token, the presented token
	// and the Access Server's own wait limit.
	upstream := fixture.upstreamPerson(func(claims *aauth.PersonTokenClaims) {
		claims.ExpiresAt = fixture.now.Add(3 * time.Minute).Unix()
	}, "ps")
	response := fixture.token(map[string]any{"upstream_token": upstream})
	if response.Code != http.StatusAccepted {
		t.Fatalf("token response = %d %s", response.Code, response.Body.String())
	}
	location := response.Header().Get("Location")
	fixture.now = fixture.now.Add(2 * time.Minute)
	poll := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(poll, fixture.signed(http.MethodGet, location, nil))
	if poll.Code != http.StatusAccepted {
		t.Fatalf("poll before the upstream token expires = %d %s", poll.Code, poll.Body.String())
	}
	fixture.now = fixture.now.Add(time.Minute + time.Second)
	poll = httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(poll, fixture.signed(http.MethodGet, location, nil))
	chainProblem(t, poll, http.StatusRequestTimeout, "expired")
}

// Presenting a Revoked Token: a request waiting at the Access Server whose
// upstream token, or whose resource token, is revoked while it waits ends with
// the polling error revoked, and detail says which.
func TestAccessServerEndsAChainedWaitWhenItsUpstreamOrResourceTokenIsRevoked(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name                     string
		issuer, document, signer string
		jti, detail              string
	}{
		{
			name: "upstream token", issuer: chainPersonServer, document: aauth.PersonDiscoveryDocument, signer: "ps",
			jti: "relay-person-token", detail: "The upstream token of this chained request was revoked.",
		},
		{
			name: "resource token", issuer: chainResource, document: aauth.ResourceDiscoveryDocument, signer: "resource",
			jti: "inventory-resource-token", detail: "The resource token this request was started for was revoked.",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newChainFixture(t)
			fixture.pending = true
			response := fixture.token(map[string]any{"upstream_token": fixture.upstreamPerson(nil, "ps")})
			if response.Code != http.StatusAccepted {
				t.Fatalf("token response = %d %s", response.Code, response.Body.String())
			}
			location := response.Header().Get("Location")
			if revoked := fixture.revoke(test.issuer, test.document, test.signer, test.jti); revoked.Code != http.StatusOK {
				t.Fatalf("revocation = %d %s", revoked.Code, revoked.Body.String())
			}
			fixture.now = fixture.now.Add(time.Second)
			poll := httptest.NewRecorder()
			fixture.server.Handler().ServeHTTP(poll, fixture.signed(http.MethodGet, location, nil))
			chainProblem(t, poll, http.StatusForbidden, "revoked")
			var problem struct {
				Detail string `json:"detail"`
			}
			if err := json.Unmarshal(poll.Body.Bytes(), &problem); err != nil || problem.Detail != test.detail {
				t.Fatalf("revoked detail = %q, %v", problem.Detail, err)
			}
			poll = httptest.NewRecorder()
			fixture.server.Handler().ServeHTTP(poll, fixture.signed(http.MethodGet, location, nil))
			chainProblem(t, poll, http.StatusGone, "request_consumed")
		})
	}
}

// Revocation Cascade: an Access Server that receives a person token's
// revocation revokes every auth token it issued against it at its Resource,
// step-ups included, and issues no further auth token against any of them.
func TestAccessServerRevokesStepUpsWithTheirPersonToken(t *testing.T) {
	t.Parallel()

	fixture := newChainFixture(t)
	// An Agent with no call chain: its own Agent token names the Person Server.
	agentToken, err := aauth.MintAgentToken(chainRelay, fixture.keys["relay-provider"], aauth.AgentTokenRequest{
		Agent: chainRelayAgent, PersonServer: chainPersonServer,
		PublicKey: fixture.keys["relay-agent"].PublicJWK(), Lifetime: time.Hour,
	}, fixture.now, "direct-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	response := fixture.token(map[string]any{"agent_token": agentToken})
	if response.Code != http.StatusOK {
		t.Fatalf("first grant = %d %s", response.Code, response.Body.String())
	}
	var first struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	stepUp := func(presented string, jti string) *httptest.ResponseRecorder {
		t.Helper()
		claims, err := aauth.VerifyAuthToken(context.Background(), presented, signaturekey.StaticKeyResolver{
			{Issuer: chainAccess, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: "as"}: fixture.keys["as"].PublicJWK(),
		}, fixture.clock)
		if err != nil {
			t.Fatal(err)
		}
		relayJKT, err := fixture.keys["relay-agent"].PublicJWK().Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		resourceToken, err := aauth.MintResourceToken(fixture.keys["resource"], aauth.ResourceTokenClaims{
			Issuer: chainResource, DWK: aauth.ResourceDiscoveryDocument, Audience: chainAccess,
			JTI: jti, AgentJKT: relayJKT, IssuedAt: fixture.now.Unix(),
			ExpiresAt: fixture.now.Add(5 * time.Minute).Unix(), Scope: "inventory.reserve",
			PersonServer: chainPersonServer, Subject: "person-at-inventory", PresentedJTI: claims.JTI,
		})
		if err != nil {
			t.Fatal(err)
		}
		return fixture.token(map[string]any{"agent_token": agentToken, "resource_token": resourceToken, "presented_token": presented})
	}
	response = stepUp(first.AuthToken, "step-up-resource-token")
	if response.Code != http.StatusOK {
		t.Fatalf("step-up = %d %s", response.Code, response.Body.String())
	}
	var second struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}

	revoked := fixture.revoke(chainPersonServer, aauth.PersonDiscoveryDocument, "ps", "inventory-person-token")
	if revoked.Code != http.StatusOK || !bytes.Contains(revoked.Body.Bytes(), []byte(chainResource)) {
		t.Fatalf("person-token revocation = %d %s", revoked.Code, revoked.Body.String())
	}
	fixture.revokedMu.Lock()
	sent := slices.Sorted(slices.Values(fixture.revokedAt))
	fixture.revokedMu.Unlock()
	if got := strings.Join(sent, ", "); got != chainResource+" inventory-auth-token-1, "+chainResource+" inventory-auth-token-2" {
		t.Fatalf("revocations sent to the Resource = %s", got)
	}
	chainProblem(t, stepUp(second.AuthToken, "late-step-up-resource-token"), http.StatusBadRequest, "revoked_presented_token")
}
