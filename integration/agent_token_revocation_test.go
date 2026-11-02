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
	"gitlab.com/sidecat-dev/aauth-go/testutil"
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
	agentToken, err := provider.Issue(ctx, aauth.AgentTokenRequest{
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
	reference := aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI},
		ExpiresAt: time.Unix(claims.ExpiresAt, 0),
	}

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	admit := func(context.Context, string) error { return nil }
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true, Clock: clock, Admit: admit,
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
	var signatureFailure *signaturekey.Error
	if !errors.As(err, &signatureFailure) || signatureFailure.Code != signaturekey.ErrorRevokedJWT {
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
	agentToken, err := provider.Issue(ctx, aauth.AgentTokenRequest{
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
	reference := aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI},
		ExpiresAt: time.Unix(claims.ExpiresAt, 0),
	}

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	admit := func(context.Context, string) error { return nil }
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true, Clock: clock, Admit: admit,
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
	request aauth.RevocationRequest,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revoked[request.Reference] = struct{}{}
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

// TestAgentProviderRevokesAnAgentAtEveryPersonServerItsTokensName: the
// Agent Provider records each Agent token it issues, so revoking the Agent
// reaches the Person Server each token names without the host naming any.
// A token with no ps has no revocation path and is reported as such.
func TestAgentProviderRevokesAnAgentAtEveryPersonServerItsTokensName(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:roaming@ap.example"
		homeID          = "https://home-ps.example"
		workID          = "https://work-ps.example"
		resourceID      = "https://resource.example"
	)
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	admit := func(context.Context, string) error { return nil }
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true, Clock: clock, Admit: admit,
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := 0
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: newSigningKey(t, "fan-out-provider"), Clock: clock,
		NewID: func() string {
			ids++
			return "roaming-token-" + string(rune('a'+ids))
		},
		IssuedTokens: testutil.NewIssuedAgentTokenStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(agentProviderID, provider.Handler())
	agents := map[string]*clientagent.Client{}
	for _, personServerID := range []string{homeID, workID} {
		server, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: newSigningKey(t, "fan-out-"+personServerID), KeyResolver: resolver, Clock: clock,
			NewID: func() string { return "person-token" }, Tokens: newMemoryPersonTokenStore(),
			BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "person-123", Lifetime: time.Minute}, nil
			},
			Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				return personserver.AuthorizationDecision{Scopes: []string{"unused"}, Lifetime: time.Minute}, nil
			},
			AgentTokenRevocations: newIntegrationAgentTokenRevocationStore(),
		})
		if err != nil {
			t.Fatal(err)
		}
		network.Handle(personServerID, server.Handler())
		key := newSigningKey(t, "fan-out-agent-"+personServerID)
		token, err := provider.Issue(ctx, aauth.AgentTokenRequest{
			Agent: agentID, PersonServer: personServerID, PublicKey: key.PublicJWK(), Lifetime: time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		agents[personServerID], err = clientagent.New(ctx, clientagent.Config{
			Identifier: agentID, SigningKey: key, AgentToken: token, KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := agents[personServerID].PersonToken(ctx, clientagent.PersonTokenRequest{
			PersonServer: personServerID, Resource: resourceID,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := provider.Issue(ctx, aauth.AgentTokenRequest{
		Agent: agentID, PublicKey: newSigningKey(t, "fan-out-direct").PublicJWK(), Lifetime: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}

	revoker, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider: provider, HTTPClient: httpClient, Admit: admit,
	})
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 2; round++ {
		outcomes, err := revoker.RevokeAgent(ctx, agentID)
		if err != nil {
			t.Fatal(err)
		}
		revoked, unreachable := map[string]bool{}, 0
		for _, outcome := range outcomes {
			switch {
			case outcome.Err == nil:
				revoked[outcome.Token.PersonServer] = true
			case errors.Is(outcome.Err, agentprovider.ErrAgentTokenNamesNoPersonServer) && outcome.Token.PersonServer == "":
				unreachable++
			default:
				t.Fatalf("round %d: %s at %q = %v", round, outcome.Token.JTI, outcome.Token.PersonServer, outcome.Err)
			}
		}
		if len(outcomes) != 3 || !revoked[homeID] || !revoked[workID] || unreachable != 1 {
			t.Fatalf("round %d outcomes = %+v", round, outcomes)
		}
	}
	for personServerID, agent := range agents {
		_, err := agent.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: personServerID, Resource: resourceID})
		var signatureFailure *signaturekey.Error
		if !errors.As(err, &signatureFailure) || signatureFailure.Code != signaturekey.ErrorRevokedJWT {
			t.Fatalf("request at %s after RevokeAgent = %v", personServerID, err)
		}
	}
}
