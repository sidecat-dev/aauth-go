package integration_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// rateLimitingRecipient serves a real server's metadata and keys over a socket
// but answers every revocation POST with a rate_limited problem and one
// Retry-After. It records what the client sent. It does not verify the HTTP
// message signature: the client's signature headers are only inspected for
// presence, so this test proves received-response handling, not acceptance.
type rateLimitingRecipient struct {
	mu         sync.Mutex
	next       http.Handler
	retryAfter string
	posts      []receivedRevocation
}

type receivedRevocation struct {
	contentType  string
	hasSignature bool
	body         map[string]any
}

func (recipient *rateLimitingRecipient) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != "/revoke" {
		recipient.next.ServeHTTP(response, request)
		return
	}
	raw, _ := io.ReadAll(request.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	recipient.mu.Lock()
	recipient.posts = append(recipient.posts, receivedRevocation{
		contentType: request.Header.Get("Content-Type"),
		hasSignature: request.Header.Get("Signature") != "" &&
			request.Header.Get("Signature-Input") != "" && request.Header.Get("Content-Digest") != "",
		body: body,
	})
	recipient.mu.Unlock()
	response.Header().Set("Content-Type", "application/problem+json")
	response.Header().Set("Retry-After", recipient.retryAfter)
	response.WriteHeader(http.StatusTooManyRequests)
	_, _ = io.WriteString(response, `{"status":429,"error":"rate_limited"}`)
}

func (recipient *rateLimitingRecipient) onlyPost(t *testing.T, jti string) {
	t.Helper()
	recipient.mu.Lock()
	defer recipient.mu.Unlock()
	if len(recipient.posts) != 1 {
		t.Fatalf("recipient received %d revocation POSTs, want 1", len(recipient.posts))
	}
	post := recipient.posts[0]
	if post.contentType != "application/json" || !post.hasSignature || post.body["jti"] != jti {
		t.Fatalf("recipient received %+v, want a signed application/json body with jti %q", post, jti)
	}
}

// startRecipient starts a TLS server whose handler is installed after the
// issuer URL, which is the server URL, is known.
func startRecipient(t *testing.T) (*httptest.Server, func(*rateLimitingRecipient)) {
	t.Helper()
	var mu sync.Mutex
	var handler http.Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		current := handler
		mu.Unlock()
		current.ServeHTTP(response, request)
	}))
	t.Cleanup(server.Close)
	return server, func(recipient *rateLimitingRecipient) {
		mu.Lock()
		handler = recipient
		mu.Unlock()
	}
}

func TestRevocationClientsReturnRateLimitedFeedbackOverHTTP(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const agentProviderID = "https://ap-rate-limit.example"
	const (
		personServerID = "https://ps-rate-limit.example"
		resourceID     = "https://resource-rate-limit.example"
	)
	personServerSocket, installPersonServer := startRecipient(t)
	resourceSocket, installResource := startRecipient(t)
	providerKey := newSigningKey(t, "rate-limit-ap")
	personKey := newSigningKey(t, "rate-limit-ps")
	resourceKey := newSigningKey(t, "rate-limit-resource")
	// AAuth server identifiers are https hosts without a port, so the client
	// dials each identifier's host to its loopback TLS test server. The test
	// certificate is not valid for these names, so verification is skipped; the
	// exchange is still real HTTP over a socket.
	dial := map[string]string{
		"ps-rate-limit.example:443":       personServerSocket.Listener.Addr().String(),
		"resource-rate-limit.example:443": resourceSocket.Listener.Addr().String(),
	}
	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			target, ok := dial[address]
			if !ok {
				return nil, errors.New("unexpected dial " + address)
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	}}
	t.Cleanup(httpClient.CloseIdleConnections)
	admit := func(context.Context, string) error { return nil }
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true, Clock: clock, Admit: admit,
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "rate-limited-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}

	// Agent-token revocation at a Person Server.
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string { return "rate-limit-person-token" }, Tokens: newMemoryPersonTokenStore(),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{}, errors.New("not used")
		},
		Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{}, errors.New("not used")
		},
		AgentTokenRevocations: newIntegrationAgentTokenRevocationStore(),
		Revocation: &personserver.AuthTokenRevocationConfig{
			IssuedTokens: newMemoryIssuedAuthTokenStore(), HTTPClient: httpClient, Admit: admit,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	psRecipient := &rateLimitingRecipient{next: people.Handler(), retryAfter: "45"}
	installPersonServer(psRecipient)
	revoker, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider: provider, HTTPClient: httpClient, Admit: admit,
	})
	if err != nil {
		t.Fatal(err)
	}
	reference := aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: agentProviderID, JTI: "rate-limited-agent-token"},
		ExpiresAt: now.Add(time.Hour),
	}
	err = revoker.RevokeAgentToken(ctx, personServerID, reference)
	var limited *aauth.RateLimitedError
	var problem *aauth.ProblemError
	if !errors.As(err, &limited) || !errors.As(err, &problem) || limited.RetryAfter != 45*time.Second ||
		limited.Problem != problem || problem.Status != http.StatusTooManyRequests || problem.Code != "rate_limited" {
		t.Fatalf("Agent Provider revoke = %v typed=%+v", err, limited)
	}
	psRecipient.onlyPost(t, "rate-limited-agent-token")

	// Auth-token revocation at a Resource.
	issued := newMemoryIssuedAuthTokenStore()
	issuer, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
		NewID: func() string { return "rate-limit-id" }, Tokens: newMemoryPersonTokenStore(),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{}, errors.New("not used")
		},
		Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{}, errors.New("not used")
		},
		Revocation: &personserver.AuthTokenRevocationConfig{IssuedTokens: issued, HTTPClient: httpClient, Admit: admit},
	})
	if err != nil {
		t.Fatal(err)
	}
	protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		NewID:             func() string { return "rate-limit-resource-token" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson: func(context.Context, resource.PersonIdentity, resource.PersonContext) error {
			return nil
		},
		Protected:         http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		AuthTokenStatuses: newMemoryAuthTokenStatusStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceRecipient := &rateLimitingRecipient{next: protectedResource.Handler(), retryAfter: "Thu, 01 Oct 2026 12:03:00 GMT"}
	installResource(resourceRecipient)
	authReference := aauth.TokenReference{Issuer: personServerID, JTI: "rate-limited-auth-token"}
	if err := issued.CommitIssuedAuthToken(ctx, personserver.IssuedAuthTokenRecord{
		Reference: authReference, Resource: resourceID, CompactSHA256: [32]byte{7},
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	err = issuer.RevokeIssuedAuthToken(ctx, authReference)
	limited, problem = nil, nil
	if !errors.As(err, &limited) || !errors.As(err, &problem) || limited.RetryAfter != 3*time.Minute ||
		limited.Problem != problem || problem.Status != http.StatusTooManyRequests || problem.Code != "rate_limited" {
		t.Fatalf("Person Server revoke = %v typed=%+v", err, limited)
	}
	resourceRecipient.onlyPost(t, "rate-limited-auth-token")
}
