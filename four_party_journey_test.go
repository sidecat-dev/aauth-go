package aauth_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestFourPartyPersonServerAccessServerJourney(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 8, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs("agent-token", "resource-token", "auth-token")
	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	accessKey := testSigningKey(t, "access-key")
	resourceKey := testSigningKey(t, "resource-key")
	agentKey := testSigningKey(t, "agent-key")

	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: apKey,
		Clock:      clock,
		NewID:      ids,
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:planner@ap.example",
		PersonServer: "https://ps.example",
		PublicKey:    agentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	protocolClient := &http.Client{}
	keyResolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: protocolClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			for _, allowed := range []string{
				"https://ap.example/",
				"https://ps.example/",
				"https://as.example/",
				"https://resource.example/",
			} {
				if strings.HasPrefix(endpoint, allowed) {
					return nil
				}
			}
			return fmt.Errorf("endpoint outside trust boundary: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var accessPolicyRequest aauth.AuthorizationRequest
	accessServer, err := reference.NewAccessServer(reference.AccessServerConfig{
		Identifier:  "https://as.example",
		SigningKey:  accessKey,
		KeyResolver: keyResolver,
		Clock:       clock,
		NewID:       ids,
		TrustedPersonServer: func(_ context.Context, identifier string) error {
			if identifier != "https://ps.example" {
				return fmt.Errorf("untrusted person server %s", identifier)
			}
			return nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			accessPolicyRequest = request
			return aauth.AuthorizationDecision{
				Subject: "federated-pairwise-user",
				Scope:   request.Scope,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var personPolicyRequest aauth.AuthorizationRequest
	personServer, err := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier:       "https://ps.example",
		SigningKey:       psKey,
		KeyResolver:      keyResolver,
		Clock:            clock,
		NewID:            ids,
		FederationClient: protocolClient,
		AccessServerEndpoint: func(_ context.Context, identifier string) (string, error) {
			if identifier != "https://as.example" {
				return "", fmt.Errorf("unknown access server %s", identifier)
			}
			return identifier + "/token", nil
		},
		MissionPolicy: func(_ context.Context, proposal aauth.MissionProposal) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: proposal.Description}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			personPolicyRequest = request
			return aauth.AuthorizationDecision{
				Subject: "person-server-user",
				Scope:   request.Scope,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var operationRequest aauth.AuthorizedRequest
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier:   "https://resource.example",
		AccessServer: "https://as.example",
		SigningKey:   resourceKey,
		KeyResolver:  keyResolver,
		Clock:        clock,
		NewID:        ids,
		Scopes:       []string{"records.read"},
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			operationRequest = request
			return map[string]any{"records": []string{"one"}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example":       ap.Handler(),
		"ps.example":       personServer.Handler(),
		"as.example":       accessServer.Handler(),
		"resource.example": resource.Handler(),
	})
	defer gateway.Close()
	protocolClient.Transport = gateway.Client().Transport

	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:planner@ap.example",
		SigningKey:  agentKey,
		AgentToken:  agentToken,
		KeyResolver: keyResolver,
		HTTPClient:  protocolClient,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	mission, err := agent.CreateMission(context.Background(), "https://ps.example/mission", aauth.MissionProposal{
		Description: "Read the federated records needed for the report.",
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := agent.Authorize(
		context.Background(),
		"https://resource.example/authorize",
		"https://ps.example/token",
		[]string{"records.read"},
		mission,
	)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Claims.Issuer != "https://as.example" ||
		grant.Claims.DWK != aauth.AccessDiscoveryDocument ||
		grant.Claims.Audience != "https://resource.example" {
		t.Fatalf("federated auth claims = %#v", grant.Claims)
	}
	if personPolicyRequest.Agent != "aauth:planner@ap.example" ||
		accessPolicyRequest.Agent != "aauth:planner@ap.example" {
		t.Fatalf("policy inputs: PS=%#v AS=%#v", personPolicyRequest, accessPolicyRequest)
	}

	response, err := agent.DoAuthorized(
		context.Background(),
		http.MethodGet,
		"https://resource.example/records",
		grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("federated protected operation status = %d, body = %s", response.StatusCode, body)
	}
	if operationRequest.Agent != "aauth:planner@ap.example" ||
		operationRequest.Subject != "federated-pairwise-user" {
		t.Fatalf("protected operation context = %#v", operationRequest)
	}
}
