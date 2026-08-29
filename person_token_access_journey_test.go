package aauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentPersonTokenAccessUsesDirectedIdentityWithoutAuthToken(t *testing.T) {
	now := time.Date(2026, 8, 29, 19, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey, psKey := testSigningKey(t, "identity-ap"), testSigningKey(t, "identity-ps")
	agentKey := testSigningKey(t, "identity-agent")
	ap, _ := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example", SigningKey: apKey, Clock: clock, NewID: sequentialIDs("agent-token"),
	})
	agentToken, _ := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent: "aauth:identity-agent@ap.example", PersonServer: "https://ps.example",
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	client := &http.Client{}
	resolver, _ := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasPrefix(endpoint, "https://ap.example/") || strings.HasPrefix(endpoint, "https://ps.example/") {
				return nil
			}
			return fmt.Errorf("untrusted endpoint: %s", endpoint)
		},
	})
	personTokens, issuance := testCurrentPersonServerCustody(t)
	ps, _ := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier: "https://ps.example", SigningKey: psKey, KeyResolver: resolver, Clock: clock,
		NewID: sequentialIDs("person-token"), AuthorizationStore: testAuthorizationStateStore(t),
		PersonTokenStore: personTokens, MissionIssuanceStore: issuance,
		PersonTokenPolicy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			return aauth.PersonTokenDecision{Subject: "directed-person", Tenant: "example-org", Lifetime: time.Hour}, nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: evaluation.Proposal.Description}, nil
		},
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{}, nil
		},
	})
	policyCalls, operationCalls := 0, 0
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aauth.AccessModePersonToken,
		KeyResolver: resolver, Clock: clock, NewID: sequentialIDs("unused"),
		Scopes: []string{"profile.read"}, RequiredScopesForRequest: testRequiredResourceScopes("profile.read"),
		ReplayStore: testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: func(_ context.Context, request aauth.AuthorizedRequest) error {
			policyCalls++
			if request.PersonServer != "https://ps.example" || request.Subject != "directed-person" || request.Tenant != "example-org" {
				return fmt.Errorf("wrong person context")
			}
			return nil
		},
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			operationCalls++
			return map[string]string{"target": request.Target, "body": string(request.Body)}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(), "ps.example": ps.Handler(), "resource.example": resource.Handler(),
	})
	defer gateway.Close()
	client.Transport = gateway.Client().Transport
	agent, _ := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:identity-agent@ap.example", SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: client, Clock: clock, AuthorizationStore: testAuthorizationStateStore(t),
	})
	person, err := agent.RequestPersonToken(context.Background(), "https://ps.example/person", "https://resource.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := agent.DoWithPersonToken(context.Background(), reference.AuthorizedCall{
		Method: http.MethodPost, Endpoint: "https://resource.example/profile?view=current",
		Body: []byte(`{"include":"summary"}`), ContentType: "application/json",
	}, person.PersonToken)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]string
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || result["target"] != "/profile?view=current" ||
		result["body"] != `{"include":"summary"}` || policyCalls != 1 || operationCalls != 1 {
		t.Fatalf("person-token result = %d %#v policy/operation=%d/%d", response.StatusCode, result, policyCalls, operationCalls)
	}
}

func TestAgentFollowsPersonTokenRequirementThroughDiscoveredPersonServer(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey, psKey := testSigningKey(t, "automatic-ap"), testSigningKey(t, "automatic-ps")
	agentKey := testSigningKey(t, "automatic-agent")
	pslessKey := testSigningKey(t, "automatic-psless-agent")
	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example", SigningKey: apKey, Clock: clock,
		NewID: sequentialIDs("agent-token", "psless-agent-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent: "aauth:automatic-agent@ap.example", PersonServer: "https://ps.example",
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	pslessToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent: "aauth:psless-agent@ap.example", PublicKey: pslessKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			for _, allowed := range []string{"https://ap.example/", "https://ps.example/"} {
				if strings.HasPrefix(endpoint, allowed) {
					return nil
				}
			}
			return fmt.Errorf("untrusted endpoint: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	personTokens, issuance := testCurrentPersonServerCustody(t)
	ps, err := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier: "https://ps.example", SigningKey: psKey, KeyResolver: resolver, Clock: clock,
		NewID: sequentialIDs("person-token"), AuthorizationStore: testAuthorizationStateStore(t),
		PersonTokenStore: personTokens, MissionIssuanceStore: issuance,
		PersonTokenPolicy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			return aauth.PersonTokenDecision{Subject: "directed-person", Tenant: "example-org", Lifetime: time.Hour}, nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: evaluation.Proposal.Description}, nil
		},
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	policyCalls, operationCalls := 0, 0
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aauth.AccessModePersonToken,
		KeyResolver: resolver, Clock: clock, NewID: sequentialIDs("unused"),
		Scopes: []string{"profile.read"}, RequiredScopesForRequest: testRequiredResourceScopes("profile.read"),
		ReplayStore: testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: func(_ context.Context, request aauth.AuthorizedRequest) error {
			policyCalls++
			if request.PersonServer != "https://ps.example" || request.Subject != "directed-person" || request.Tenant != "example-org" {
				return fmt.Errorf("wrong person context")
			}
			return nil
		},
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			operationCalls++
			return map[string]string{"target": request.Target, "body": string(request.Body)}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	psRequests := 0
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			psRequests++
			ps.Handler().ServeHTTP(response, request)
		}),
		"resource.example": resource.Handler(),
	})
	defer gateway.Close()
	client.Transport = gateway.Client().Transport
	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:automatic-agent@ap.example", SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: client, Clock: clock, AuthorizationStore: testAuthorizationStateStore(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	call := reference.AuthorizedCall{
		Method: http.MethodPost, Endpoint: "https://resource.example/profile?view=current",
		Body: []byte(`{"include":"summary"}`), ContentType: "application/json",
	}
	response, err := agent.Do(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]string
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || result["target"] != "/profile?view=current" ||
		result["body"] != `{"include":"summary"}` || policyCalls != 1 || operationCalls != 1 {
		t.Fatalf("automatic person-token result = %d %#v policy/operation=%d/%d", response.StatusCode, result, policyCalls, operationCalls)
	}

	requestsBeforePSLessCall := psRequests
	pslessAgent, err := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:psless-agent@ap.example", SigningKey: pslessKey, AgentToken: pslessToken,
		KeyResolver: resolver, HTTPClient: client, Clock: clock, AuthorizationStore: testAuthorizationStateStore(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pslessAgent.Do(context.Background(), call); err == nil || !strings.Contains(err.Error(), "has no person server") {
		t.Fatalf("PS-less automatic person-token error = %v", err)
	}
	if psRequests != requestsBeforePSLessCall {
		t.Fatalf("PS-less requirement made %d person-server calls", psRequests-requestsBeforePSLessCall)
	}
}
