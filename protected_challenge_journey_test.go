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

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentProtectedResourceChallengeCompletesOneExactFourPartyCall(t *testing.T) {
	now := time.Date(2026, 8, 29, 15, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs(
		"agent-token", "person-token", "resource-token", "auth-token",
		"renewed-resource-token", "renewed-auth-token",
	)
	apKey := testSigningKey(t, "challenge-ap")
	psKey := testSigningKey(t, "challenge-ps")
	asKey := testSigningKey(t, "challenge-as")
	resourceKey := testSigningKey(t, "challenge-resource")
	agentKey := testSigningKey(t, "challenge-agent")

	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example", SigningKey: apKey, Clock: clock, NewID: ids,
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent: "aauth:challenge-agent@ap.example", PersonServer: "https://ps.example",
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			for _, prefix := range []string{"https://ap.example/", "https://ps.example/", "https://as.example/", "https://resource.example/"} {
				if strings.HasPrefix(endpoint, prefix) {
					return nil
				}
			}
			return fmt.Errorf("endpoint outside test trust: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	accessPolicyCalls := 0
	accessServer, err := reference.NewAccessServer(reference.AccessServerConfig{
		Identifier: "https://as.example", SigningKey: asKey, KeyResolver: resolver,
		Clock: clock, NewID: ids, AuthorizationStore: testAuthorizationStateStore(t),
		TrustedPersonServer: func(_ context.Context, identifier string) error {
			if identifier != "https://ps.example" {
				return fmt.Errorf("untrusted person server: %s", identifier)
			}
			return nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			accessPolicyCalls++
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	personTokens, missionIssuance := testCurrentPersonServerCustody(t)
	personPolicyCalls := 0
	personServer, err := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier: "https://ps.example", SigningKey: psKey, KeyResolver: resolver,
		Clock: clock, NewID: ids, AuthorizationStore: testAuthorizationStateStore(t),
		PersonTokenStore: personTokens, MissionIssuanceStore: missionIssuance,
		PersonTokenPolicy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			return aauth.PersonTokenDecision{Subject: "challenge-person", Tenant: "example-org", Lifetime: time.Hour}, nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: evaluation.Proposal.Description}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			personPolicyCalls++
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		},
		FederationClient: client,
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://as.example/token", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	operationCalls := 0
	var operationRequest aauth.AuthorizedRequest
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aauth.AccessModeAuthToken,
		AccessServer: "https://as.example", SigningKey: resourceKey, KeyResolver: resolver,
		Clock: clock, NewID: ids, Scopes: []string{"records.write"},
		ScopeDescriptions:            map[string]string{"records.write": "Write records"},
		RequiredScopesForRequest:     testRequiredResourceScopes("records.write"),
		ReplayStore:                  testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error { return nil },
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			operationCalls++
			operationRequest = request
			return map[string]string{"status": "stored"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(), "ps.example": personServer.Handler(),
		"as.example": accessServer.Handler(), "resource.example": resource.Handler(),
	})
	defer gateway.Close()
	observed := &protectedChallengeObservingTransport{base: gateway.Client().Transport}
	client.Transport = observed

	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:challenge-agent@ap.example", SigningKey: agentKey,
		AgentToken: agentToken, KeyResolver: resolver, HTTPClient: client, Clock: clock,
		AuthorizationStore: testAuthorizationStateStore(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	call := reference.AuthorizedCall{
		Method: http.MethodPost, Endpoint: "https://resource.example/records",
		Body: []byte(`{"name":"current"}`), ContentType: "application/json",
	}
	response, err := agent.Do(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		t.Fatalf("protected result status = %d: %s", response.StatusCode, body)
	}
	var result map[string]string
	if decodeErr := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&result); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if result["status"] != "stored" {
		t.Fatalf("protected result = %d %#v", response.StatusCode, result)
	}
	if operationCalls != 1 || personPolicyCalls != 1 || accessPolicyCalls != 1 {
		t.Fatalf("operation/PS/AS calls = %d/%d/%d", operationCalls, personPolicyCalls, accessPolicyCalls)
	}
	if len(observed.requirements) != 2 || observed.requirements[0].Type != aauth.RequirementPersonToken ||
		observed.requirements[1].Type != aauth.RequirementAuthToken ||
		observed.requirements[1].ResourceToken == "" || observed.cacheControl != "no-store" {
		t.Fatalf("observed requirements = %#v, cache-control %q", observed.requirements, observed.cacheControl)
	}
	if operationRequest.Method != call.Method || operationRequest.Path != "/records" ||
		operationRequest.Target != "/records" || string(operationRequest.Body) != string(call.Body) || operationRequest.ContentType != call.ContentType {
		t.Fatalf("retried operation = %#v", operationRequest)
	}
	if operationRequest.PersonServer != "https://ps.example" || operationRequest.Subject != "challenge-person" ||
		operationRequest.Tenant != "example-org" {
		t.Fatalf("challenge operation context = %#v", operationRequest)
	}
	response, err = agent.Do(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(observed.requirements) != 2 || operationCalls != 2 || personPolicyCalls != 1 || accessPolicyCalls != 1 {
		t.Fatalf("cached auth-token requirements/operation/PS/AS = %d/%d/%d/%d, want 2/2/1/1", len(observed.requirements), operationCalls, personPolicyCalls, accessPolicyCalls)
	}
	now = now.Add(6 * time.Minute)
	response, err = agent.Do(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(observed.requirements) != 3 || observed.requirements[2].Type != aauth.RequirementAuthToken ||
		operationCalls != 3 || personPolicyCalls != 2 || accessPolicyCalls != 2 {
		t.Fatalf("renewed auth-token requirements/operation/PS/AS = %#v/%d/%d/%d", observed.requirements, operationCalls, personPolicyCalls, accessPolicyCalls)
	}
}

type protectedChallengeObservingTransport struct {
	base         http.RoundTripper
	requirements []aauth.Requirement
	cacheControl string
}

func (transport *protectedChallengeObservingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil || request.URL.Host != "resource.example" || request.URL.Path != "/records" || response.StatusCode != http.StatusUnauthorized {
		return response, err
	}
	transport.cacheControl = response.Header.Get("Cache-Control")
	requirement, _ := aauth.ParseRequirementHeader(response.Header.Get("AAuth-Requirement"))
	transport.requirements = append(transport.requirements, requirement)
	return response, nil
}
