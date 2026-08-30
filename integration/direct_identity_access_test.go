package integration_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	aauth "aauth-go"
	clientagent "aauth-go/agent"
	"aauth-go/agentprovider"
	"aauth-go/personserver"
	"aauth-go/resource"
	"aauth-go/signaturekey"
)

func TestCurrentCoreDirectIdentityAccessModes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID  = "https://ap.example"
		agentID          = "aauth:reader@ap.example"
		personServerID   = "https://ps.example"
		agentResourceID  = "https://agent-resource.example"
		personResourceID = "https://person-resource.example"
	)

	agentProviderKey := newSigningKey(t, "direct-ap-key")
	agentKey := newSigningKey(t, "direct-agent-key")
	personServerKey := newSigningKey(t, "direct-ps-key")
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: agentProviderKey, Clock: clock,
		NewID: func() string { return "direct-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
		AdditionalClaims: map[string]json.RawMessage{
			"platform_attestation": json.RawMessage(`{"level":"example"}`),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resolver := signaturekey.StaticKeyResolver{
		{Issuer: agentProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: agentProviderKey.ID()}: agentProviderKey.PublicJWK(),
		{Issuer: personServerID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personServerKey.ID()}:  personServerKey.PublicJWK(),
	}
	network := newLogicalTransport()
	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: &http.Client{Transport: network}, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	agentResource, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer:      agentResourceID,
		KeyResolver: resolver, Clock: clock,
		AdditionalSignatureComponents: []string{"x-request-id"},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AgentPrincipalFromContext(request.Context())
			if !ok || principal.AgentProvider != agentProviderID || principal.Agent != agentID ||
				principal.PersonServer != personServerID || !principal.Confirmation.Equal(agentKey.PublicJWK()) ||
				string(principal.AdditionalClaims["platform_attestation"]) != `{"level":"example"}` {
				t.Errorf("agent principal = %#v, present = %v", principal, ok)
			}
			_, _ = io.WriteString(response, "agent identity accepted")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(agentResourceID, agentResource.Handler())
	agentRequest, err := http.NewRequest(http.MethodGet, agentResourceID+"/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	agentRequest.Header.Set("X-Request-ID", "agent-direct-1")
	agentResponse, err := reader.CallAsAgent(ctx, agentRequest)
	if err != nil {
		t.Fatal(err)
	}
	agentBody, _ := io.ReadAll(agentResponse.Body)
	agentResponse.Body.Close()
	if agentResponse.StatusCode != http.StatusOK || string(agentBody) != "agent identity accepted" {
		t.Fatalf("agent response = %d %q", agentResponse.StatusCode, agentBody)
	}

	people, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: personServerID, SigningKey: personServerKey, KeyResolver: resolver,
		Clock: clock, NewID: func() string { return "direct-person-token" },
		HTTPClient: &http.Client{Transport: network},
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://unused-access.example/token", nil
		},
		Tokens: newMemoryPersonTokenStore(),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: 20 * time.Minute}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(personServerID, people.Handler())
	personResource, err := resource.NewPersonIdentity(resource.PersonIdentityConfig{
		Issuer:      personResourceID,
		KeyResolver: resolver, Clock: clock,
		AdditionalSignatureComponents: []string{"x-request-id"},
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, context resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) || context.Tenant != "tenant-1" {
				t.Errorf("person identity = %#v, context = %#v", identity, context)
			}
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.PersonPrincipalFromContext(request.Context())
			if !ok || principal.PersonServer != personServerID || principal.Subject != "person-123" ||
				principal.Tenant != "tenant-1" || !principal.Confirmation.Equal(agentKey.PublicJWK()) {
				t.Errorf("person principal = %#v, present = %v", principal, ok)
			}
			_, _ = io.WriteString(response, "person identity accepted")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(personResourceID, personResource.Handler())
	personResult, err := reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: personResourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatalf("person-token result = %#v", personResult)
	}
	personRequest, err := http.NewRequest(http.MethodGet, personResourceID+"/profile", nil)
	if err != nil {
		t.Fatal(err)
	}
	personRequest.Header.Set("X-Request-ID", "person-direct-1")
	callResult, err := reader.Begin(ctx, clientagent.InitialCall{Request: personRequest, PersonToken: personToken})
	if err != nil {
		t.Fatal(err)
	}
	personResponse, ok := callResult.Response()
	if !ok {
		t.Fatalf("person call result = %#v", callResult)
	}
	personBody, _ := io.ReadAll(personResponse.Body)
	personResponse.Body.Close()
	if personResponse.StatusCode != http.StatusOK || string(personBody) != "person identity accepted" {
		t.Fatalf("person response = %d %q", personResponse.StatusCode, personBody)
	}
}
