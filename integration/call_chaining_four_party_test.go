package integration_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

// TestFourPartyCallChainPassesTheUpstreamTokenToTheAccessServer chains a call
// through an Access Server. The calling Agent holds a person token for the
// intermediary Resource. The intermediary, its own Agent Provider, gets a
// downstream person token and resource token, and its Person Server passes
// the exact upstream_token to the downstream Resource's Access Server, which
// verifies it before policy and bounds the auth token by it.
func TestFourPartyCallChainPassesTheUpstreamTokenToTheAccessServer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 10, 30, 16, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		callerProviderID = "https://agents.example"
		callerID         = "aauth:shopper@agents.example"
		personServerID   = "https://person.example"
		relayID          = "https://orders.example"
		relayAgentID     = "aauth:relay@orders.example"
		relayOwnPS       = "https://relay-person.example"
		inventoryID      = "https://inventory.example"
		accessServerID   = "https://inventory-as.example"
	)
	callerProviderKey := newSigningKey(t, "chain4-caller-provider")
	callerKey := newSigningKey(t, "chain4-caller")
	personServerKey := newSigningKey(t, "chain4-ps")
	relayProviderKey := newSigningKey(t, "chain4-relay-provider")
	relayKey := newSigningKey(t, "chain4-relay")
	inventoryKey := newSigningKey(t, "chain4-inventory")
	accessKey := newSigningKey(t, "chain4-as")
	keys := signaturekey.StaticKeyResolver{
		{Issuer: callerProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: callerProviderKey.ID()}: callerProviderKey.PublicJWK(),
		{Issuer: personServerID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personServerKey.ID()}:    personServerKey.PublicJWK(),
		{Issuer: relayID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: relayProviderKey.ID()}:           relayProviderKey.PublicJWK(),
		{Issuer: inventoryID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: inventoryKey.ID()}:        inventoryKey.PublicJWK(),
		{Issuer: accessServerID, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:          accessKey.PublicJWK(),
	}
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}

	issue := func(provider *agentprovider.Server, request aauth.AgentTokenRequest) string {
		t.Helper()
		token, err := provider.Issue(request)
		if err != nil {
			t.Fatalf("%s agent token: %v", request.Agent, err)
		}
		return token
	}
	callerProvider, err := agentprovider.New(agentprovider.Config{
		Issuer: callerProviderID, SigningKey: callerProviderKey, Clock: clock,
		NewID: func() string { return "chain4-caller-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	relayProvider, err := agentprovider.New(agentprovider.Config{
		Issuer: relayID, SigningKey: relayProviderKey, Clock: clock,
		NewID: func() string { return "chain4-relay-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	callerToken := issue(callerProvider, aauth.AgentTokenRequest{
		Agent: callerID, PersonServer: personServerID, PublicKey: callerKey.PublicJWK(), Lifetime: time.Hour,
	})
	// The intermediary's own Agent token names its own Person Server, which
	// neither its Person Server nor the Access Server may route by.
	relayToken := issue(relayProvider, aauth.AgentTokenRequest{
		Agent: relayAgentID, PersonServer: relayOwnPS, PublicKey: relayKey.PublicJWK(), Lifetime: time.Hour,
	})

	var accessRequests []accessserver.AuthorizationRequest
	access, err := accessserver.New(accessserver.Config{
		Issuer: accessServerID, SigningKey: accessKey, KeyResolver: keys, Clock: clock,
		NewID: func() string { return "chain4-auth-token" },
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != personServerID {
				return errors.New("untrusted Person Server")
			}
			return nil
		},
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			accessRequests = append(accessRequests, request)
			return accessserver.Decision{Scopes: request.Scopes, Lifetime: 30 * time.Minute}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: inventoryID, AccessServer: accessServerID, SigningKey: inventoryKey, KeyResolver: keys,
		Clock: clock, NewID: func() string { return "chain4-resource-token" },
		ScopeDescriptions: map[string]string{"inventory.reserve": "Reserve stock"},
		RequiredScopes:    func(*http.Request) []string { return []string{"inventory.reserve"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, _ := resource.AuthPrincipalFromContext(request.Context())
			_, _ = io.WriteString(response, "reserved for "+principal.Subject)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	var chainedConsent []personserver.AuthorizationRequest
	people, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: personServerID, SigningKey: personServerKey, KeyResolver: keys, Clock: clock,
		NewID:      sequenceIDs("chain4-person-token"),
		HTTPClient: httpClient, Tokens: newMemoryPersonTokenStore(),
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			if issuer != accessServerID {
				return "", errors.New("unknown Access Server")
			}
			return accessServerID + "/token", nil
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != callerID || request.Resource != relayID {
				return personserver.Person{}, errors.New("unexpected direct person-token request")
			}
			return personserver.Person{Subject: "person-at-orders", Lifetime: 10 * time.Minute}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error {
			return errors.New("ordinary consent received a chained request")
		},
		IssuedTokens: testutil.NewIssuedAuthTokenStore(),
		CallChaining: &personserver.FederatedCallChainingConfig{
			BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
				if request.Agent != relayAgentID || request.Resource != inventoryID ||
					request.UpstreamPerson == nil || request.UpstreamPerson.Subject != "person-at-orders" {
					return personserver.Person{}, errors.New("unexpected chained person-token request")
				}
				return personserver.Person{Subject: "person-at-inventory", Lifetime: time.Hour}, nil
			},
			Consent: func(_ context.Context, request personserver.AuthorizationRequest) error {
				chainedConsent = append(chainedConsent, request)
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(personServerID, people.Handler())
	network.Handle(inventoryID, inventory.Handler())
	network.Handle(accessServerID, access.Handler())

	caller, err := clientagent.New(ctx, clientagent.Config{
		Identifier: callerID, SigningKey: callerKey, AgentToken: callerToken,
		KeyResolver: keys, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	relay, err := clientagent.New(ctx, clientagent.Config{
		Identifier: relayAgentID, SigningKey: relayKey, AgentToken: relayToken,
		KeyResolver: keys, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The calling Agent's person token for the intermediary is the upstream
	// token: the intermediary served the call on the person's identity.
	upstreamResult, err := caller.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: personServerID, Resource: relayID})
	if err != nil {
		t.Fatal(err)
	}
	upstream, _ := upstreamResult.Token()
	upstreamClaims := tokenClaims(t, upstream)

	now = now.Add(time.Minute)
	downstreamResult, err := relay.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: inventoryID, UpstreamToken: upstream})
	if err != nil {
		t.Fatal(err)
	}
	downstream, _ := downstreamResult.Token()
	resourceToken, err := relay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: inventoryID, PersonToken: downstream, UpstreamToken: upstream, Scopes: []string{"inventory.reserve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	authToken, err := relay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken: resourceToken, PresentedToken: downstream, UpstreamToken: upstream,
	})
	if err != nil {
		t.Fatal(err)
	}
	authClaims := tokenClaims(t, authToken)
	if authClaims["iss"] != accessServerID || authClaims["sub"] != "person-at-inventory" ||
		authClaims["exp"].(float64) > upstreamClaims["exp"].(float64) {
		t.Fatalf("downstream auth token = %v, upstream exp %v", authClaims, upstreamClaims["exp"])
	}
	if len(chainedConsent) != 1 || chainedConsent[0].UpstreamPerson == nil ||
		chainedConsent[0].UpstreamPerson.JTI != upstreamClaims["jti"] {
		t.Fatalf("chained consent = %#v", chainedConsent)
	}
	if len(accessRequests) != 1 {
		t.Fatalf("Access Server policy calls = %d", len(accessRequests))
	}
	evaluated := accessRequests[0]
	if evaluated.Agent.Identifier != relayAgentID || evaluated.Subject != "person-at-inventory" ||
		evaluated.Upstream != nil || evaluated.UpstreamPerson == nil ||
		evaluated.UpstreamPerson.JTI != upstreamClaims["jti"] || evaluated.UpstreamPerson.Audience != relayID {
		t.Fatalf("Access Server policy request = %#v", evaluated)
	}

	call, err := http.NewRequest(http.MethodPost, inventoryID+"/reservations", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := relay.Do(ctx, clientagent.Call{Request: call, AuthToken: authToken, UpstreamToken: upstream})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "reserved for person-at-inventory" {
		t.Fatalf("downstream call = %d %s", response.StatusCode, body)
	}

	// Downstream access does not outlive the upstream token: once it has
	// expired the chain cannot be carried on, and nothing reaches the Access
	// Server.
	now = time.Unix(int64(upstreamClaims["exp"].(float64)), 0).UTC()
	_, err = relay.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: inventoryID, UpstreamToken: upstream})
	if err == nil {
		t.Fatal("an expired upstream token still produced a downstream person token")
	}
	if len(accessRequests) != 1 {
		t.Fatalf("Access Server policy calls after expiry = %d", len(accessRequests))
	}
}

// sequenceIDs returns a counter-based ID source for one sequential test.
func sequenceIDs(prefix string) func() string {
	next := 0
	return func() string {
		next++
		return fmt.Sprintf("%s-%d", prefix, next)
	}
}
