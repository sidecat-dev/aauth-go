package aauth_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

type refusingTokenExchangeTransport struct {
	calls int
}

func (transport *refusingTokenExchangeTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls++
	return nil, errors.New("token exchange must not reach the network")
}

type refusingResourceGrantKeyResolver struct {
	delegate aauth.KeyResolver
	calls    int
	refuse   bool
}

func (resolver *refusingResourceGrantKeyResolver) ResolveKey(
	ctx context.Context,
	issuer string,
	discoveryDocument string,
	keyID string,
) (aauth.JWK, error) {
	resolver.calls++
	if resolver.refuse {
		return aauth.JWK{}, errors.New("resource-token PS preflight must not resolve a key")
	}
	return resolver.delegate.ResolveKey(ctx, issuer, discoveryDocument, keyID)
}

func TestAgentRefusesResourceTokenWhosePSDiffersFromSelectedEndpointBeforeAnyNetwork(t *testing.T) {
	type tokenEntryPoint struct {
		name   string
		invoke func(*reference.Agent, reference.ResourceGrant) error
	}
	entryPoints := []tokenEntryPoint{
		{
			name: "direct",
			invoke: func(agent *reference.Agent, grant reference.ResourceGrant) error {
				_, err := agent.RequestTokenAuthorization(context.Background(), "https://ps.example/token", grant)
				return err
			},
		},
		{
			name: "direct subagent",
			invoke: func(agent *reference.Agent, grant reference.ResourceGrant) error {
				_, err := agent.RequestSubagentTokenAuthorization(
					context.Background(),
					"https://ps.example/token",
					grant,
					"must-not-verify-subagent-token",
				)
				return err
			},
		},
		{
			name: "chained",
			invoke: func(agent *reference.Agent, grant reference.ResourceGrant) error {
				_, err := agent.RequestChainedTokenAuthorization(
					context.Background(),
					"https://ps.example/token",
					grant,
					"must-not-verify-upstream-token",
				)
				return err
			},
		},
		{
			name: "chained subagent",
			invoke: func(agent *reference.Agent, grant reference.ResourceGrant) error {
				_, err := agent.RequestChainedSubagentTokenAuthorization(
					context.Background(),
					"https://ps.example/token",
					grant,
					"must-not-verify-subagent-token",
					"must-not-verify-upstream-token",
				)
				return err
			},
		},
	}
	for _, audience := range []string{"https://ps.example", "https://as.example"} {
		for _, entryPoint := range entryPoints {
			t.Run(entryPoint.name+"/"+audience, func(t *testing.T) {
				testAgentResourceTokenPSPreflight(t, audience, entryPoint.invoke)
			})
		}
	}
}

func testAgentResourceTokenPSPreflight(
	t *testing.T,
	audience string,
	invoke func(*reference.Agent, reference.ResourceGrant) error,
) {
	t.Helper()

	now := time.Date(2026, 8, 28, 20, 15, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := testSigningKey(t, "provider-key")
	resourceKey := testSigningKey(t, "resource-key")
	agentKey := testSigningKey(t, "agent-key")
	agentToken, err := aauth.MintAgentToken(
		"https://provider.example",
		providerKey,
		aauth.AgentTokenRequest{
			Agent:        "aauth:agent@provider.example",
			PersonServer: "https://ps.example",
			PublicKey:    agentKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		now,
		"agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims := aauth.ResourceTokenClaims{
		Issuer:       "https://resource.example",
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     audience,
		JTI:          "resource-token",
		AgentJKT:     thumbprint,
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Scope:        "records.read",
		PersonServer: "https://other-ps.example",
		Subject:      "directed-person",
		PresentedJTI: "person-token",
	}
	resourceToken, err := aauth.MintResourceToken(resourceKey, resourceClaims)
	if err != nil {
		t.Fatal(err)
	}
	transport := &refusingTokenExchangeTransport{}
	resolver := &refusingResourceGrantKeyResolver{delegate: aauth.StaticKeyResolver{
		"https://provider.example": {providerKey.ID(): providerKey.PublicJWK()},
		"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
	}}
	agent, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:agent@provider.example",
		SigningKey:         agentKey,
		AgentToken:         agentToken,
		KeyResolver:        resolver,
		HTTPClient:         &http.Client{Transport: transport},
		Clock:              clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver.calls = 0
	resolver.refuse = true
	err = invoke(agent, reference.ResourceGrant{
		Resource:      "https://resource.example",
		ResourceToken: resourceToken,
		Claims:        resourceClaims,
	})
	if err == nil || !strings.Contains(err.Error(), "resource token ps does not match selected person server") {
		t.Fatalf("resource-token PS preflight error = %v", err)
	}
	if resolver.calls != 0 {
		t.Fatalf("resource-token PS mismatch made %d key-resolution calls", resolver.calls)
	}
	if transport.calls != 0 {
		t.Fatalf("resource-token PS mismatch made %d HTTP calls", transport.calls)
	}
}

func TestAgentRefusesDirectSubagentWithoutPersonServerBeforeHTTP(t *testing.T) {
	now := time.Date(2026, 8, 28, 20, 45, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey := testSigningKey(t, "provider-key")
	resourceKey := testSigningKey(t, "resource-key")
	parentKey := testSigningKey(t, "parent-key")
	subagentKey := testSigningKey(t, "subagent-key")
	parentID := "aauth:parent@provider.example"
	parentToken, err := aauth.MintAgentToken(
		"https://provider.example",
		providerKey,
		aauth.AgentTokenRequest{
			Agent:        parentID,
			PersonServer: "https://ps.example",
			PublicKey:    parentKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		now,
		"parent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	subagentToken, err := aauth.MintAgentToken(
		"https://provider.example",
		providerKey,
		aauth.AgentTokenRequest{
			Agent:       "aauth:parent+worker@provider.example",
			ParentAgent: parentID,
			PublicKey:   subagentKey.PublicJWK(),
			Lifetime:    time.Hour,
		},
		now,
		"empty-ps-subagent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := subagentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims := aauth.ResourceTokenClaims{
		Issuer:       "https://resource.example",
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     "https://ps.example",
		JTI:          "subagent-resource-token",
		AgentJKT:     thumbprint,
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Scope:        "records.read",
		PersonServer: "https://ps.example",
		Subject:      "directed-person",
		PresentedJTI: "person-token",
	}
	resourceToken, err := aauth.MintResourceToken(resourceKey, resourceClaims)
	if err != nil {
		t.Fatal(err)
	}
	transport := &refusingTokenExchangeTransport{}
	agent, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         parentID,
		SigningKey:         parentKey,
		AgentToken:         parentToken,
		KeyResolver: aauth.StaticKeyResolver{
			"https://provider.example": {providerKey.ID(): providerKey.PublicJWK()},
			"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
		},
		HTTPClient: &http.Client{Transport: transport},
		Clock:      clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("person token", func(t *testing.T) {
		_, err := agent.RequestPersonTokenForSubagent(
			context.Background(),
			"https://ps.example/person",
			"https://resource.example",
			subagentToken,
		)
		if err == nil || !strings.Contains(err.Error(), "parent and person server") {
			t.Fatalf("empty-ps subagent person-token error = %v", err)
		}
		if transport.calls != 0 {
			t.Fatalf("empty-ps subagent person-token request made %d HTTP calls", transport.calls)
		}
	})

	t.Run("resource-token exchange", func(t *testing.T) {
		_, err := agent.RequestSubagentTokenAuthorization(
			context.Background(),
			"https://ps.example/token",
			reference.ResourceGrant{
				Resource:      "https://resource.example",
				ResourceToken: resourceToken,
				Claims:        resourceClaims,
			},
			subagentToken,
		)
		if err == nil || !strings.Contains(err.Error(), "different person server") {
			t.Fatalf("empty-ps subagent resource-token error = %v", err)
		}
		if transport.calls != 0 {
			t.Fatalf("empty-ps subagent resource-token request made %d HTTP calls", transport.calls)
		}
	})
}
