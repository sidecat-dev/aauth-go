package integration_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// rateLimitingRecipient serves a real server's metadata and keys but answers
// every revocation POST with a rate_limited problem and one Retry-After.
type rateLimitingRecipient struct {
	next       http.Handler
	posts      int
	retryAfter string
}

func (recipient *rateLimitingRecipient) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != "/revoke" {
		recipient.next.ServeHTTP(response, request)
		return
	}
	recipient.posts++
	_, _ = io.Copy(io.Discard, request.Body)
	response.Header().Set("Content-Type", "application/problem+json")
	response.Header().Set("Retry-After", recipient.retryAfter)
	response.WriteHeader(http.StatusTooManyRequests)
	_, _ = io.WriteString(response, `{"status":429,"error":"rate_limited"}`)
}

func TestRevocationClientsReturnRateLimitedFeedbackOverSignedExchange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap-rate-limit.example"
		personServerID  = "https://ps-rate-limit.example"
		resourceID      = "https://resource-rate-limit.example"
	)
	providerKey := newSigningKey(t, "rate-limit-ap")
	personKey := newSigningKey(t, "rate-limit-ps")
	resourceKey := newSigningKey(t, "rate-limit-resource")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	admit := func(context.Context, string) error { return nil }
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: admit,
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
	network.Handle(agentProviderID, provider.Handler())

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
	network.Handle(personServerID, psRecipient)
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
		limited.Problem != problem || problem.Code != "rate_limited" || psRecipient.posts != 1 {
		t.Fatalf("Agent Provider revoke = %v typed=%+v posts=%d", err, limited, psRecipient.posts)
	}

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
	network.Handle(resourceID, resourceRecipient)
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
		limited.Problem != problem || problem.Code != "rate_limited" || resourceRecipient.posts != 1 {
		t.Fatalf("Person Server revoke = %v typed=%+v posts=%d", err, limited, resourceRecipient.posts)
	}
}
