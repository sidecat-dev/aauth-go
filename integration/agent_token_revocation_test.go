package integration_test

import (
	"context"
	"errors"
	"net/http"
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

func TestAgentProviderRevokesAgentTokenAtPersonServerAcrossRecomposition(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 7, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:revocable@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
	)
	providerKey := newSigningKey(t, "agent-revocation-provider")
	agentKey := newSigningKey(t, "agent-revocation-agent")
	personKey := newSigningKey(t, "agent-revocation-person")
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "revocable-agent-token" },
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
	claims, err := aauth.VerifyAgentToken(ctx, agentToken, signaturekey.StaticKeyResolver{
		{Issuer: agentProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}, clock)
	if err != nil {
		t.Fatal(err)
	}
	reference := aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI}

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	admit := func(context.Context, string) error { return nil }
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: admit,
	})
	if err != nil {
		t.Fatal(err)
	}
	revocations := newIntegrationAgentTokenRevocationStore()
	personTokens := newMemoryPersonTokenStore()
	policyCalls := 0
	newPersonServer := func(store personserver.AgentTokenRevocationStore) *personserver.Server {
		server, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver, Clock: clock,
			NewID: func() string { return "revocation-person-token" }, Tokens: personTokens,
			BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
				policyCalls++
				if request.Agent != agentID {
					return personserver.Person{}, errors.New("unexpected Agent")
				}
				return personserver.Person{Subject: "person-123", Lifetime: time.Minute}, nil
			},
			Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				return personserver.AuthorizationDecision{Scopes: []string{"unused"}, Lifetime: time.Minute}, nil
			},
			AgentTokenRevocations: store,
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, newPersonServer(revocations).Handler())
	agent, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := agent.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	}); err != nil {
		t.Fatal(err)
	} else if _, ok := result.Token(); !ok {
		t.Fatal("initial Person-token request did not complete")
	}

	revoker, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider: provider, HTTPClient: httpClient, Admit: admit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := revoker.RevokeAgentToken(ctx, personServerID, reference); err != nil {
		t.Fatal(err)
	}
	if err := revoker.RevokeAgentToken(ctx, personServerID, reference); err != nil {
		t.Fatalf("exact revocation replay = %v", err)
	}

	// Recompose the Person Server around the same retained revocation store.
	network.Handle(personServerID, newPersonServer(revocations).Handler())
	_, err = agent.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Code != "invalid_agent_token" {
		t.Fatalf("revoked Agent-token request = %v", err)
	}
	if policyCalls != 1 {
		t.Fatalf("revoked Agent token reached person policy; calls=%d", policyCalls)
	}
}

func TestAgentProviderRevokesAgentTokenAtDirectResourceAcrossRecomposition(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:local@ap.example"
		resourceID      = "https://resource.example"
	)
	providerKey := newSigningKey(t, "resource-revocation-provider")
	agentKey := newSigningKey(t, "resource-revocation-agent")
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "resource-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAgentToken(ctx, agentToken, signaturekey.StaticKeyResolver{
		{Issuer: agentProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}, clock)
	if err != nil {
		t.Fatal(err)
	}
	reference := aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI}

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	admit := func(context.Context, string) error { return nil }
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock, Admit: admit,
	})
	if err != nil {
		t.Fatal(err)
	}
	revocations := newIntegrationAgentTokenRevocationStore()
	applicationCalls := 0
	newResource := func(store resource.AgentTokenRevocationStore) *resource.Server {
		server, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
			Issuer: resourceID, KeyResolver: resolver, Clock: clock,
			AgentTokenRevocations: store,
			Protected: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				applicationCalls++
				response.WriteHeader(http.StatusNoContent)
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(resourceID, newResource(revocations).Handler())
	agent, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	response, err := agent.CallAsAgent(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || applicationCalls != 1 {
		t.Fatalf("initial call = %d; application_calls=%d", response.StatusCode, applicationCalls)
	}

	revoker, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider: provider, HTTPClient: httpClient, Admit: admit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := revoker.RevokeAgentTokenAtResource(ctx, resourceID, reference); err != nil {
		t.Fatal(err)
	}
	if err := revoker.RevokeAgentTokenAtResource(ctx, resourceID, reference); err != nil {
		t.Fatalf("exact Resource revocation replay = %v", err)
	}
	network.Handle(resourceID, newResource(revocations).Handler())
	request, _ = http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	response, err = agent.CallAsAgent(ctx, request)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || applicationCalls != 1 {
		t.Fatalf("revoked direct call = response %#v, error %v; application_calls=%d", response, err, applicationCalls)
	}
}

type integrationAgentTokenRevocationStore struct {
	mu      sync.Mutex
	revoked map[aauth.TokenReference]struct{}
}

func newIntegrationAgentTokenRevocationStore() *integrationAgentTokenRevocationStore {
	return &integrationAgentTokenRevocationStore{revoked: make(map[aauth.TokenReference]struct{})}
}

func (store *integrationAgentTokenRevocationStore) Revoke(
	_ context.Context,
	reference aauth.TokenReference,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revoked[reference] = struct{}{}
	return nil
}

func (store *integrationAgentTokenRevocationStore) IsRevoked(
	_ context.Context,
	reference aauth.TokenReference,
) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, revoked := store.revoked[reference]
	return revoked, nil
}

var _ personserver.AgentTokenRevocationStore = (*integrationAgentTokenRevocationStore)(nil)
var _ resource.AgentTokenRevocationStore = (*integrationAgentTokenRevocationStore)(nil)
