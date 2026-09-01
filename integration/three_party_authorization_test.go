package integration_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentCoreImmediatePSAuthorization(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:reader@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
		accessServerID  = "https://as.example"
	)
	scope := []string{"records.read"}
	account := "primary"
	agentProviderKey := newSigningKey(t, "three-party-ap")
	agentKey := newSigningKey(t, "three-party-agent")
	personServerKey := newSigningKey(t, "three-party-ps")
	resourceKey := newSigningKey(t, "three-party-resource")

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	keyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasSuffix(endpoint, ".example/.well-known/aauth-agent.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-person.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-resource.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/jwks.json") {
				return nil
			}
			return errors.New("unexpected discovery endpoint: " + endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: agentProviderKey, Clock: clock,
		NewID: func() string { return "three-party-agent-token" },
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
	personTokens := newMemoryPersonTokenStore()
	ids := []string{"three-party-person-token", "three-party-auth-token"}
	people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personServerKey, KeyResolver: keyResolver,
		Clock: clock, Tokens: personTokens,
		NewID: func() string {
			id := ids[0]
			ids = ids[1:]
			return id
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != agentID || request.Resource != resourceID {
				return personserver.Person{}, errors.New("unexpected person binding context")
			}
			return personserver.Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: 20 * time.Minute}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			if request.Agent != agentID || request.Resource != resourceID || request.Subject != "person-123" ||
				request.Tenant != "tenant-1" || request.Account == nil || *request.Account != account ||
				!slices.Equal(request.Scopes, scope) {
				return personserver.AuthorizationDecision{}, errors.New("unexpected authorization context")
			}
			*request.Account = "mutated-by-person-policy"
			return personserver.AuthorizationDecision{Scopes: append([]string(nil), request.Scopes...), Lifetime: 30 * time.Minute}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	protectedCalls := 0
	protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: keyResolver, Clock: clock,
		NewID:             func() string { return "three-party-resource-token" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return append([]string(nil), scope...) },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) || personContext.Tenant != "tenant-1" {
				return errors.New("unexpected Resource person")
			}
			return nil
		},
		ValidateAccount: func(_ context.Context, identity resource.PersonIdentity, got string) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) || got != account {
				return errors.Join(resource.ErrInvalidAccount, errors.New("unexpected Resource account"))
			}
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			protectedCalls++
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok || principal.PersonServer != personServerID || principal.Subject != "person-123" ||
				principal.Tenant != "tenant-1" || principal.Account == nil || *principal.Account != account ||
				!slices.Equal(principal.Scope, scope) ||
				!principal.Confirmation.Equal(agentKey.PublicJWK()) {
				t.Errorf("three-party principal = %#v, present=%t", principal, ok)
			}
			_, _ = io.WriteString(response, "three-party accepted")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	accessCalls := 0
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, protectedResource.Handler())
	network.Handle(accessServerID, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { accessCalls++ }))

	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: keyResolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	personResult, err := reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatalf("person-token result = %#v", personResult)
	}
	resourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: scope, Account: &account,
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims, err := aauth.VerifyResourceToken(ctx, resourceToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if resourceClaims.Audience != personServerID || resourceClaims.PersonServer != personServerID ||
		resourceClaims.Account == nil || *resourceClaims.Account != account {
		t.Fatalf("three-party resource token = %#v", resourceClaims)
	}
	authToken, err := reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	authClaims, err := aauth.VerifyAuthToken(ctx, authToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.Issuer != personServerID || authClaims.DWK != aauth.PersonDiscoveryDocument ||
		authClaims.Audience != resourceID || authClaims.PersonServer != personServerID ||
		authClaims.Subject != "person-123" || authClaims.Account == nil || *authClaims.Account != account ||
		!slices.Equal(strings.Fields(authClaims.Scope), scope) {
		t.Fatalf("three-party auth token = %#v", authClaims)
	}
	request, _ := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	response, err := reader.Do(ctx, clientagent.Call{Request: request, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "three-party accepted" || protectedCalls != 1 || accessCalls != 0 {
		t.Fatalf("response=%d %q protected=%d access=%d", response.StatusCode, body, protectedCalls, accessCalls)
	}
}
