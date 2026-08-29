package aauth_test

import (
	"context"
	"errors"
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

func TestCurrentDeferredProtectedCallRecoversAfterLostResultAndResourceRestart(t *testing.T) {
	now := time.Date(2026, 8, 29, 17, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs("agent-token", "person-token", "resource-token", "pending-call", "auth-token")
	apKey, psKey := testSigningKey(t, "deferred-ap"), testSigningKey(t, "deferred-ps")
	asKey, resourceKey := testSigningKey(t, "deferred-as"), testSigningKey(t, "deferred-resource")
	agentKey := testSigningKey(t, "deferred-agent")
	ap, _ := reference.NewAgentProvider(reference.AgentProviderConfig{Identifier: "https://ap.example", SigningKey: apKey, Clock: clock, NewID: ids})
	agentToken, _ := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent: "aauth:deferred-agent@ap.example", PersonServer: "https://ps.example",
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})

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
	accessServer, _ := reference.NewAccessServer(reference.AccessServerConfig{
		Identifier: "https://as.example", SigningKey: asKey, KeyResolver: resolver, Clock: clock, NewID: ids,
		AuthorizationStore:  testAuthorizationStateStore(t),
		TrustedPersonServer: func(context.Context, string) error { return nil },
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		},
	})
	personTokens, issuance := testCurrentPersonServerCustody(t)
	personServer, _ := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier: "https://ps.example", SigningKey: psKey, KeyResolver: resolver, Clock: clock, NewID: ids,
		AuthorizationStore: testAuthorizationStateStore(t), PersonTokenStore: personTokens, MissionIssuanceStore: issuance,
		PersonTokenPolicy: func(context.Context, aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			return aauth.PersonTokenDecision{Subject: "deferred-person", Lifetime: time.Hour}, nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: evaluation.Proposal.Description}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		},
		FederationClient:     client,
		AccessServerEndpoint: func(context.Context, string) (string, error) { return "https://as.example/token", nil },
	})

	storePath := t.TempDir() + "/deferred-protected.json"
	operationCalls, protectedPolicyCalls := 0, 0
	var resourceHandler http.Handler
	newResource := func() *reference.Resource {
		store, openErr := reference.NewFileDeferredProtectedCallStore(storePath)
		if openErr != nil {
			t.Fatal(openErr)
		}
		resource, resourceErr := reference.NewResource(reference.ResourceConfig{
			Identifier: "https://resource.example", AccessMode: aauth.AccessModeAuthToken,
			AccessServer: "https://as.example", SigningKey: resourceKey, KeyResolver: resolver,
			Clock: clock, NewID: ids, Scopes: []string{"records.write"},
			ScopeDescriptions:        map[string]string{"records.write": "Write records"},
			RequiredScopesForRequest: testRequiredResourceScopes("records.write"),
			ReplayStore:              testResourceReplayStore(t, clock),
			ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error {
				protectedPolicyCalls++
				return nil
			},
			Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) {
				return nil, errors.New("ordinary operation must not execute a held invocation")
			},
			DeferredProtected: &reference.ResourceDeferredProtectedConfig{
				Store:  store,
				Select: func(context.Context, *http.Request) (bool, error) { return true, nil },
				Operation: func(_ context.Context, request aauth.AuthorizedRequest, consequenceKey string) (any, error) {
					operationCalls++
					if consequenceKey == "" {
						return nil, errors.New("deferred consequence key is empty")
					}
					return map[string]any{"stored": true, "body": string(request.Body), "target": request.Target}, nil
				},
			},
		})
		if resourceErr != nil {
			t.Fatal(resourceErr)
		}
		return resource
	}
	resourceHandler = newResource().Handler()
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(), "ps.example": personServer.Handler(), "as.example": accessServer.Handler(),
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			resourceHandler.ServeHTTP(response, request)
		}),
	})
	defer gateway.Close()
	drop := true
	client.Transport = &deferredProtectedLostResultTransport{
		base: gateway.Client().Transport, drop: &drop,
		reconstruct: func() { resourceHandler = newResource().Handler() },
	}
	agent, _ := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:deferred-agent@ap.example", SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: client, Clock: clock, AuthorizationStore: testAuthorizationStateStore(t),
	})
	person, err := agent.RequestPersonToken(context.Background(), "https://ps.example/person", "https://resource.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, _, err := agent.DoWithPersonTokenAuthorization(context.Background(), reference.AuthorizedCall{
		Method: http.MethodPost, Endpoint: "https://resource.example/records?mode=current",
		Body: []byte(`{"name":"deferred"}`), ContentType: "application/json",
	}, "https://ps.example/token", person.PersonToken)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"stored":true`) ||
		!strings.Contains(string(body), `"target":"/records?mode=current"`) ||
		operationCalls != 1 || protectedPolicyCalls != 1 || drop {
		t.Fatalf("terminal response = %d %s, operation/policy=%d/%d drop=%t", response.StatusCode, body, operationCalls, protectedPolicyCalls, drop)
	}
}

type deferredProtectedLostResultTransport struct {
	base        http.RoundTripper
	drop        *bool
	reconstruct func()
}

func (transport *deferredProtectedLostResultTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil || transport.drop == nil || !*transport.drop || request.URL.Host != "resource.example" ||
		!strings.HasPrefix(request.URL.Path, "/deferred/") || response.StatusCode != http.StatusOK {
		return response, err
	}
	*transport.drop = false
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	transport.reconstruct()
	return nil, errors.New("lost deferred terminal response")
}
