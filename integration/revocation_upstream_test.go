package integration_test

import (
	"context"
	"errors"
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

// Protocol 70d6737, Upstream Token Verification step 1 and Revocation
// Cascade: a person token the Person Server passed to an Access Server as
// upstream_token is revoked there too, so the Access Server answers a chained
// request carrying it with revoked_upstream_token, as the Person Server does.
func TestRevokedUpstreamPersonTokenIsRefusedAtTheAccessServer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 10, 30, 16, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		callerProviderID = "https://agents-revoke.example"
		callerID         = "aauth:shopper@agents-revoke.example"
		personServerID   = "https://person-revoke.example"
		relayID          = "https://orders-revoke.example"
		relayAgentID     = "aauth:relay@orders-revoke.example"
		inventoryID      = "https://inventory-revoke.example"
		accessServerID   = "https://inventory-as-revoke.example"
	)
	callerProviderKey := newSigningKey(t, "revoke-caller-provider")
	callerKey := newSigningKey(t, "revoke-caller")
	personServerKey := newSigningKey(t, "revoke-ps")
	relayProviderKey := newSigningKey(t, "revoke-relay-provider")
	relayKey := newSigningKey(t, "revoke-relay")
	inventoryKey := newSigningKey(t, "revoke-inventory")
	accessKey := newSigningKey(t, "revoke-as")
	keys := signaturekey.StaticKeyResolver{
		{Issuer: callerProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: callerProviderKey.ID()}: callerProviderKey.PublicJWK(),
		{Issuer: personServerID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: personServerKey.ID()}:    personServerKey.PublicJWK(),
		{Issuer: relayID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: relayProviderKey.ID()}:           relayProviderKey.PublicJWK(),
		{Issuer: inventoryID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: inventoryKey.ID()}:        inventoryKey.PublicJWK(),
		{Issuer: accessServerID, DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: accessKey.ID()}:          accessKey.PublicJWK(),
	}
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	admit := func(context.Context, string) error { return nil }

	callerProvider, err := agentprovider.New(agentprovider.Config{
		Issuer: callerProviderID, SigningKey: callerProviderKey, Clock: clock,
		NewID: func() string { return "revoke-caller-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	relayProvider, err := agentprovider.New(agentprovider.Config{
		Issuer: relayID, SigningKey: relayProviderKey, Clock: clock,
		NewID: func() string { return "revoke-relay-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	callerToken, err := callerProvider.Issue(ctx, aauth.AgentTokenRequest{
		Agent: callerID, PersonServer: personServerID, PublicKey: callerKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	relayToken, err := relayProvider.Issue(ctx, aauth.AgentTokenRequest{
		Agent: relayAgentID, PersonServer: personServerID, PublicKey: relayKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	access, err := accessserver.New(accessserver.Config{
		Issuer: accessServerID, SigningKey: accessKey, KeyResolver: keys, Clock: clock,
		NewID: sequenceIDs("revoke-auth-token"),
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != personServerID {
				return accessserver.ErrAccessDenied
			}
			return nil
		},
		Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Decision{Scopes: request.Scopes, Lifetime: 30 * time.Minute}, nil
		},
		Revocation: &accessserver.RevocationConfig{
			Revocations: testutil.NewTokenRevocationStore(), IssuedTokens: testutil.NewAccessIssuedAuthTokenStore(),
			HTTPClient: httpClient, Admit: admit,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: inventoryID, AccessServer: accessServerID, SigningKey: inventoryKey, KeyResolver: keys,
		Clock: clock, NewID: sequenceIDs("revoke-resource-token"),
		ScopeDescriptions: map[string]string{"inventory.reserve": "Reserve stock"},
		RequiredScopes:    func(*http.Request) []string { return []string{"inventory.reserve"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected:         http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(response, "reserved") }),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The intermediary serves the calling Agent on the person's identity, and
	// accepts the Person Server's revocations of the person tokens it was shown.
	orders, err := resource.NewPersonIdentity(resource.PersonIdentityConfig{
		Issuer: relayID, KeyResolver: keys, Clock: clock,
		ResolvePerson: func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected:     http.NotFoundHandler(),
		Revocation:    &resource.RevocationConfig{PersonTokens: testutil.NewTokenRevocationStore()},
	})
	if err != nil {
		t.Fatal(err)
	}
	peopleConfig := personserver.FederatedAuthorizationConfig{
		Issuer: personServerID, SigningKey: personServerKey, KeyResolver: keys, Clock: clock,
		NewID:      sequenceIDs("revoke-person-token"),
		HTTPClient: httpClient, Tokens: newMemoryPersonTokenStore(),
		AccessServerEndpoint: func(context.Context, string) (string, error) { return accessServerID + "/token", nil },
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-at-orders", Lifetime: 10 * time.Minute}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error {
			return errors.New("ordinary consent received a chained request")
		},
		IssuedTokens: testutil.NewIssuedAuthTokenStore(),
		CallChaining: &personserver.FederatedCallChainingConfig{
			BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "person-at-inventory", Lifetime: time.Hour}, nil
			},
			Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		},
		TokenRevocation: &personserver.TokenRevocationConfig{
			Revocations: testutil.NewTokenRevocationStore(), HTTPClient: httpClient, Admit: admit,
		},
	}
	people, err := personserver.NewFederatedAuthorization(peopleConfig)
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(personServerID, people.Handler())
	network.Handle(relayID, orders.Handler())
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
	upstreamResult, err := caller.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: personServerID, Resource: relayID})
	if err != nil {
		t.Fatal(err)
	}
	upstream, _ := upstreamResult.Token()
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
	exchange := clientagent.ExchangeRequest{ResourceToken: resourceToken, PresentedToken: downstream, UpstreamToken: upstream}
	if _, err := relay.Exchange(ctx, exchange); err != nil {
		t.Fatal(err)
	}

	// The upstream token reached the Access Server only as upstream_token, and
	// its revocation reaches it there.
	revoked, err := people.RevokePersonToken(ctx, claimString(t, tokenClaims(t, upstream), "jti"))
	if err != nil {
		t.Fatal(err)
	}
	requireAttempts(t, "upstream person-token revocation", revoked.Attempts, relayID+" recorded", accessServerID+" recorded")

	_, err = relay.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: inventoryID, UpstreamToken: upstream})
	requireProblem(t, err, http.StatusBadRequest, "revoked_upstream_token", "Person Server person token on a revoked upstream token")

	// A Person Server that kept no record still cannot carry the chain on: the
	// Access Server refuses the upstream token itself.
	ledgerless := peopleConfig
	ledgerless.TokenRevocation = nil
	forgetful, err := personserver.NewFederatedAuthorization(ledgerless)
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(personServerID, forgetful.Handler())
	_, err = relay.Exchange(ctx, exchange)
	requireProblem(t, err, http.StatusBadRequest, "revoked_upstream_token", "Access Server exchange on a revoked upstream token")
}
