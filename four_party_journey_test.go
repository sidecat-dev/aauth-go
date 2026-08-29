package aauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestCurrentFourPartyPersonServerAccessServerJourney(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 8, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs("agent-token", "person-token", "resource-token", "auth-token")
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
	keyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
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
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "https://as.example",
		SigningKey:         accessKey,
		KeyResolver:        keyResolver,
		Clock:              clock,
		NewID:              ids,
		TrustedPersonServer: func(_ context.Context, identifier string) error {
			if identifier != "https://ps.example" {
				return fmt.Errorf("untrusted person server %s", identifier)
			}
			return nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			accessPolicyRequest = request
			return aauth.AuthorizationDecision{
				Subject: request.Subject,
				Scope:   request.Scope,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var personPolicyRequest aauth.AuthorizationRequest
	personTokenStore, missionIssuanceStore := testCurrentPersonServerCustody(t)
	personServer, err := reference.NewPersonServer(reference.PersonServerConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "https://ps.example",
		SigningKey:         psKey,
		KeyResolver:        keyResolver,
		Clock:              clock,
		NewID:              ids,
		FederationClient:   protocolClient,
		AccessServerEndpoint: func(_ context.Context, identifier string) (string, error) {
			if identifier != "https://as.example" {
				return "", fmt.Errorf("unknown access server %s", identifier)
			}
			return identifier + "/token", nil
		},
		PersonTokenStore:     personTokenStore,
		MissionIssuanceStore: missionIssuanceStore,
		PersonTokenPolicy: func(_ context.Context, request aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			return aauth.PersonTokenDecision{Subject: "federated-pairwise-user", Lifetime: time.Hour}, nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: evaluation.Proposal.Description}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			personPolicyRequest = request
			return aauth.AuthorizationDecision{
				Subject: request.Subject,
				Scope:   request.Scope,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var operationRequest aauth.AuthorizedRequest
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier:                   "https://resource.example",
		AccessMode:                   aauth.AccessModeAuthToken,
		AccessServer:                 "https://as.example",
		SigningKey:                   resourceKey,
		KeyResolver:                  keyResolver,
		Clock:                        clock,
		NewID:                        ids,
		Scopes:                       []string{"records.read"},
		ScopeDescriptions:            map[string]string{"records.read": "Read records"},
		RequiredScopesForRequest:     testRequiredResourceScopes("records.read"),
		ReplayStore:                  testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error { return nil },
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

	metadataResponse, err := protocolClient.Get("https://resource.example/.well-known/aauth-resource.json")
	if err != nil {
		t.Fatal(err)
	}
	defer metadataResponse.Body.Close()
	var metadata map[string]any
	if err := json.NewDecoder(metadataResponse.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	if value := metadata["access_mode"]; value != string(aauth.AccessModeAuthToken) {
		t.Fatalf("resource access_mode = %#v", value)
	}

	agent, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:planner@ap.example",
		SigningKey:         agentKey,
		AgentToken:         agentToken,
		KeyResolver:        keyResolver,
		HTTPClient:         protocolClient,
		Clock:              clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	person, err := agent.RequestPersonToken(context.Background(), "https://ps.example/person", "https://resource.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := agent.AuthorizeWithPersonToken(
		context.Background(),
		"https://resource.example/authorize",
		"https://ps.example/token",
		[]string{"records.read"},
		person.PersonToken,
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
	if operationRequest.Agent != "" ||
		operationRequest.PersonServer != "https://ps.example" ||
		operationRequest.Subject != "federated-pairwise-user" {
		t.Fatalf("protected operation context = %#v", operationRequest)
	}
}
