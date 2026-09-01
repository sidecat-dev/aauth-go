package integration_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestSelfHostedAgentSelfIssuesAndCallsResource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentOrigin  = "https://agent.example"
		agentID      = "aauth:local@agent.example"
		personServer = "https://ps.example"
		resourceID   = "https://resource.example"
	)
	key := newSigningKey(t, "self-hosted-agent-key")
	ids := 0
	selfHosted, err := agentprovider.NewSelfHostedAgent(agentprovider.SelfHostedAgentConfig{
		Issuer: agentOrigin, Agent: agentID, SigningKey: key, Clock: clock,
		NewID: func() string {
			ids++
			return fmt.Sprintf("self-hosted-token-%d", ids)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	network := newLogicalTransport()
	network.Handle(agentOrigin, selfHosted.Handler())
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			if endpoint != agentOrigin+"/.well-known/aauth-agent.json" &&
				endpoint != agentOrigin+"/.well-known/jwks.json" {
				return fmt.Errorf("unexpected discovery endpoint %s", endpoint)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := selfHosted.Issue(agentprovider.SelfHostedAgentTokenRequest{
		PersonServer: personServer, Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	protected, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: resourceID, KeyResolver: resolver, Clock: clock,
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AgentPrincipalFromContext(request.Context())
			if !ok || principal.AgentProvider != agentOrigin || principal.Agent != agentID ||
				!principal.Confirmation.Equal(key.PublicJWK()) {
				t.Fatalf("self-hosted principal = %#v, present=%v", principal, ok)
			}
			_, _ = io.WriteString(response, "self-hosted identity accepted")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(resourceID, protected.Handler())
	client, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: key, AgentToken: compact,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, resourceID+"/records", nil)
	response, err := client.CallAsAgent(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "self-hosted identity accepted" {
		t.Fatalf("protected response = %d %q", response.StatusCode, body)
	}

	now = now.Add(30 * time.Minute)
	reissued, err := selfHosted.Issue(agentprovider.SelfHostedAgentTokenRequest{
		PersonServer: personServer, Lifetime: time.Hour,
	})
	if err != nil || reissued == compact || ids != 2 {
		t.Fatalf("reissue equal=%v ids=%d error=%v", reissued == compact, ids, err)
	}
}
