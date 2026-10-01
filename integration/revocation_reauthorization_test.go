package integration_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestThreePartyRevocationAndExplicitReauthorizationAcrossResourceRecomposition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 30, 22, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap-revocation.example"
		agentID         = "aauth:reader@ap-revocation.example"
		personServerID  = "https://ps-revocation.example"
		resourceID      = "https://resource-revocation.example"
	)
	scope := []string{"records.read"}
	agentProviderKey := newSigningKey(t, "revocation-ap")
	agentKey := newSigningKey(t, "revocation-agent")
	personServerKey := newSigningKey(t, "revocation-ps")
	resourceKey := newSigningKey(t, "revocation-resource")

	network := newLogicalTransport()
	lostResponse := errors.New("revocation response lost after delivery")
	transport := &loseOneRevocationResponseTransport{base: network, failure: lostResponse}
	httpClient := &http.Client{Transport: transport}
	admitEgress := func(_ context.Context, endpoint string) error {
		if stringsHasAnySuffix(endpoint,
			"/.well-known/aauth-agent.json", "/.well-known/aauth-person.json",
			"/.well-known/aauth-resource.json", "/.well-known/jwks.json", "/revoke",
		) {
			return nil
		}
		return errors.New("unexpected egress endpoint: " + endpoint)
	}
	keyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: admitEgress,
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: agentProviderKey, Clock: clock,
		NewID: func() string { return "revocation-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	personTokens := newMemoryPersonTokenStore()
	issuedTokens := newMemoryIssuedAuthTokenStore()
	personIDs := []string{"revocation-person-token", "revocation-auth-token-1", "revocation-auth-token-2"}
	personConfig := func() personserver.PSAuthorizationConfig {
		return personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: personServerKey, KeyResolver: keyResolver,
			Clock: clock, Tokens: personTokens,
			NewID: func() string {
				id := personIDs[0]
				personIDs = personIDs[1:]
				return id
			},
			BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
				if request.Agent != agentID || request.Resource != resourceID {
					return personserver.Person{}, errors.New("unexpected person binding context")
				}
				return personserver.Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: 20 * time.Minute}, nil
			},
			Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				if request.Agent != agentID || request.Resource != resourceID || request.Subject != "person-123" ||
					request.Tenant != "tenant-1" || !slices.Equal(request.Scopes, scope) {
					return personserver.AuthorizationDecision{}, errors.New("unexpected authorization context")
				}
				return personserver.AuthorizationDecision{Scopes: append([]string(nil), scope...), Lifetime: 30 * time.Minute}, nil
			},
			Revocation: &personserver.AuthTokenRevocationConfig{
				IssuedTokens: issuedTokens, HTTPClient: httpClient, Admit: admitEgress,
			},
		}
	}
	people, err := personserver.NewPSAuthorization(personConfig())
	if err != nil {
		t.Fatal(err)
	}

	authStatuses := newMemoryAuthTokenStatusStore()
	resourceIDs := []string{"revocation-resource-token-1", "revocation-resource-token-2"}
	requiredScopeCalls, resolveCalls, protectedCalls := 0, 0, 0
	resourceConfig := func() resource.PSAuthorizationConfig {
		return resource.PSAuthorizationConfig{
			Issuer: resourceID, SigningKey: resourceKey, KeyResolver: keyResolver, Clock: clock,
			NewID: func() string {
				id := resourceIDs[0]
				resourceIDs = resourceIDs[1:]
				return id
			},
			ScopeDescriptions: map[string]string{"records.read": "Read records"},
			RequiredScopes: func(*http.Request) []string {
				requiredScopeCalls++
				return append([]string(nil), scope...)
			},
			ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
				resolveCalls++
				if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) || personContext.Tenant != "tenant-1" {
					return errors.New("unexpected Resource person")
				}
				return nil
			},
			Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				protectedCalls++
				_, _ = io.WriteString(response, "accepted")
			}),
			AuthTokenStatuses: authStatuses,
		}
	}
	protectedResource, err := resource.NewPSAuthorization(resourceConfig())
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, protectedResource.Handler())

	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: keyResolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	personResult, err := reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatalf("person-token result = %#v", personResult)
	}
	authorizeAndExchange := func() (string, aauth.ResourceTokenClaims, string, aauth.AuthTokenClaims) {
		t.Helper()
		resourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
			Resource: resourceID, PersonToken: personToken, Scopes: scope,
		})
		if err != nil {
			t.Fatal(err)
		}
		resourceClaims, err := aauth.VerifyResourceToken(ctx, resourceToken, keyResolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		authToken, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
			PersonServer: personServerID, ResourceToken: resourceToken,
		})
		if err != nil {
			t.Fatal(err)
		}
		authClaims, err := aauth.VerifyAuthToken(ctx, authToken, keyResolver, clock)
		if err != nil {
			t.Fatal(err)
		}
		return resourceToken, resourceClaims, authToken, authClaims
	}
	_, firstResourceClaims, firstAuthToken, firstAuthClaims := authorizeAndExchange()
	firstRequest, _ := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	firstResponse, err := reader.Do(ctx, clientagent.Call{Request: firstRequest, AuthToken: firstAuthToken})
	if err != nil {
		t.Fatal(err)
	}
	firstResponse.Body.Close()
	if firstResponse.StatusCode != http.StatusOK || requiredScopeCalls != 1 || resolveCalls != 1 || protectedCalls != 1 {
		t.Fatalf("first use = %d; required=%d resolve=%d protected=%d", firstResponse.StatusCode, requiredScopeCalls, resolveCalls, protectedCalls)
	}

	people, err = personserver.NewPSAuthorization(personConfig())
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(personServerID, people.Handler())
	reference := aauth.TokenReference{Issuer: firstAuthClaims.Issuer, JTI: firstAuthClaims.JTI}
	transport.Arm()
	if err := people.RevokeIssuedAuthToken(ctx, reference); !errors.Is(err, lostResponse) {
		t.Fatalf("lost revocation response = %v", err)
	}
	protectedResource, err = resource.NewPSAuthorization(resourceConfig())
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(resourceID, protectedResource.Handler())
	assertOldTokenRefused := func(path string) {
		t.Helper()
		oldRequest, _ := http.NewRequest(http.MethodGet, resourceID+path, nil)
		oldResponse, oldErr := reader.Do(ctx, clientagent.Call{Request: oldRequest, AuthToken: firstAuthToken})
		var clientFailure *clientagent.Error
		var problem *aauth.ProblemError
		if oldResponse != nil || !errors.As(oldErr, &clientFailure) || !errors.As(oldErr, &problem) ||
			problem.Status != http.StatusForbidden || problem.Code != "access_denied" {
			t.Fatalf("revoked use response=%#v error=%v client=%#v problem=%#v", oldResponse, oldErr, clientFailure, problem)
		}
		if requiredScopeCalls != 1 || resolveCalls != 1 || protectedCalls != 1 {
			t.Fatalf("revoked use reached host callbacks: required=%d resolve=%d protected=%d", requiredScopeCalls, resolveCalls, protectedCalls)
		}
	}
	assertOldTokenRefused("/records/after-lost-response")
	now = now.Add(time.Second)
	if err := people.RevokeIssuedAuthToken(ctx, reference); err != nil {
		t.Fatalf("explicit revocation retry: %v", err)
	}
	assertOldTokenRefused("/records/after-explicit-retry")

	_, secondResourceClaims, secondAuthToken, secondAuthClaims := authorizeAndExchange()
	if secondResourceClaims.JTI == firstResourceClaims.JTI || secondAuthClaims.JTI == firstAuthClaims.JTI {
		t.Fatalf("re-authorization reused token identity: resource=%q auth=%q", secondResourceClaims.JTI, secondAuthClaims.JTI)
	}
	secondRequest, _ := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	secondResponse, err := reader.Do(ctx, clientagent.Call{Request: secondRequest, AuthToken: secondAuthToken})
	if err != nil {
		t.Fatal(err)
	}
	secondResponse.Body.Close()
	if secondResponse.StatusCode != http.StatusOK || requiredScopeCalls != 2 || resolveCalls != 2 || protectedCalls != 2 {
		t.Fatalf("fresh use = %d; required=%d resolve=%d protected=%d", secondResponse.StatusCode, requiredScopeCalls, resolveCalls, protectedCalls)
	}
}

type memoryAuthTokenStatusStore struct {
	mu      sync.Mutex
	records map[aauth.TokenReference]resource.ObservedAuthToken
	revoked map[aauth.TokenReference]bool
}

func newMemoryAuthTokenStatusStore() *memoryAuthTokenStatusStore {
	return &memoryAuthTokenStatusStore{
		records: make(map[aauth.TokenReference]resource.ObservedAuthToken),
		revoked: make(map[aauth.TokenReference]bool),
	}
}

func (store *memoryAuthTokenStatusStore) Observe(_ context.Context, record resource.ObservedAuthToken) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	reference := record.Reference
	if _, ok := store.records[reference]; !ok && store.revoked[reference] {
		return resource.ErrAuthTokenRevoked
	}
	if retained, ok := store.records[reference]; ok {
		if retained != record {
			return resource.ErrAuthTokenConflict
		}
		if store.revoked[reference] {
			return resource.ErrAuthTokenRevoked
		}
		return nil
	}
	store.records[reference] = record
	return nil
}

func (store *memoryAuthTokenStatusStore) Revoke(_ context.Context, request aauth.RevocationRequest) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revoked[request.Reference] = true
	return nil
}

type memoryIssuedAuthTokenStore struct {
	mu      sync.Mutex
	records map[aauth.TokenReference]personserver.IssuedAuthTokenRecord
}

func newMemoryIssuedAuthTokenStore() *memoryIssuedAuthTokenStore {
	return &memoryIssuedAuthTokenStore{records: make(map[aauth.TokenReference]personserver.IssuedAuthTokenRecord)}
}

func (store *memoryIssuedAuthTokenStore) CommitIssuedAuthToken(_ context.Context, record personserver.IssuedAuthTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if retained, ok := store.records[record.Reference]; ok && retained != record {
		return personserver.ErrIssuedAuthTokenConflict
	}
	store.records[record.Reference] = record
	return nil
}

func (store *memoryIssuedAuthTokenStore) LoadIssuedAuthToken(_ context.Context, reference aauth.TokenReference) (personserver.IssuedAuthTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[reference]
	if !ok {
		return personserver.IssuedAuthTokenRecord{}, personserver.ErrIssuedAuthTokenNotFound
	}
	return record, nil
}

type loseOneRevocationResponseTransport struct {
	mu      sync.Mutex
	base    http.RoundTripper
	failure error
	armed   bool
}

func (transport *loseOneRevocationResponseTransport) Arm() {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.armed = true
}

func (transport *loseOneRevocationResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	transport.mu.Lock()
	lose := transport.armed && request.Method == http.MethodPost && request.URL.Path == "/revoke"
	if lose {
		transport.armed = false
	}
	transport.mu.Unlock()
	if !lose {
		return response, nil
	}
	response.Body.Close()
	return nil, transport.failure
}

func stringsHasAnySuffix(value string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if len(value) >= len(suffix) && value[len(value)-len(suffix):] == suffix {
			return true
		}
	}
	return false
}

var _ resource.AuthTokenStatusStore = (*memoryAuthTokenStatusStore)(nil)
var _ personserver.IssuedAuthTokenStore = (*memoryIssuedAuthTokenStore)(nil)
