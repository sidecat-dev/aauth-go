package integration_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "aauth-go"
	clientagent "aauth-go/agent"
	"aauth-go/agentprovider"
	"aauth-go/personserver"
	"aauth-go/signaturekey"
)

func TestCurrentCorePersonTokenInteractionAcrossPersonServerRecomposition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:reader@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
	)
	providerKey := newSigningKey(t, "interaction-ap-key")
	agentKey := newSigningKey(t, "interaction-agent-key")
	personServerKey := newSigningKey(t, "interaction-ps-key")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}

	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "interaction-agent-token" },
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
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasSuffix(endpoint, ".example/.well-known/aauth-agent.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-person.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/jwks.json") {
				return nil
			}
			return errors.New("unexpected discovery endpoint: " + endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryPersonTokenStore()
	newPeople := func() *personserver.Server {
		server, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
			Issuer: personServerID, SigningKey: personServerKey,
			KeyResolver: resolver, Clock: clock, NewID: func() string { return "interaction-person-token" },
			HTTPClient: httpClient, Tokens: store,
			AccessServerEndpoint: func(context.Context, string) (string, error) {
				return "https://as.example/token", nil
			},
			BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{}, errors.New("interaction path called immediate person binding")
			},
			RequirePersonTokenInteraction: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.PersonTokenInteractionPolicy, bool, error) {
				if request.Agent != agentID || request.Resource != resourceID {
					return personserver.PersonTokenInteractionPolicy{}, false, errors.New("unexpected person-token request")
				}
				return personserver.PersonTokenInteractionPolicy{
					URL: personServerID + "/interaction", Lifetime: 5 * time.Minute, RetryAfter: 2 * time.Second,
				}, true, nil
			},
			Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	people := newPeople()
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok || !strings.HasPrefix(pending.InteractionURL(), personServerID+"/interaction/") || pending.RetryAfter() != 2*time.Second {
		t.Fatalf("initial result = %#v, pending = %#v", result, pending)
	}
	if _, commits, _ := store.observation(); commits != 0 {
		t.Fatalf("person-token records before approval = %d", commits)
	}

	// A new Person Server value continues the retained pending request.
	people = newPeople()
	network.Handle(personServerID, people.Handler())
	interactionReference := strings.TrimPrefix(pending.InteractionURL(), personServerID+"/interaction/")
	if interactionReference == pending.InteractionURL() || interactionReference == "" {
		t.Fatalf("interaction URL = %q", pending.InteractionURL())
	}
	interaction, err := people.ConsumePersonTokenInteractionCode(ctx, interactionReference, pending.InteractionCode())
	if err != nil {
		t.Fatal(err)
	}
	reference := interaction.Reference()
	interacting, err := reader.PollPersonToken(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	updated, ok := interacting.Pending()
	if !ok || updated.Location() != pending.Location() {
		t.Fatalf("interacting result = %#v", interacting)
	}
	people = newPeople()
	network.Handle(personServerID, people.Handler())
	interaction, err = people.ResumePersonTokenInteraction(ctx, reference)
	if err != nil {
		t.Fatal(err)
	}
	if err := people.ApprovePersonTokenInteraction(ctx, interaction, personserver.Person{
		Subject: "person-123", Lifetime: 20 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}

	people = newPeople()
	network.Handle(personServerID, people.Handler())
	approved, err := reader.PollPersonToken(ctx, updated)
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := approved.Token()
	if !ok {
		t.Fatalf("approved result = %#v", approved)
	}
	claims, err := aauth.VerifyPersonToken(ctx, personToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != personServerID || claims.Audience != resourceID || claims.Subject != "person-123" ||
		!claims.Confirmation.JWK.Equal(agentKey.PublicJWK()) {
		t.Fatalf("approved person token = %#v", claims)
	}
	if record, err := store.Load(ctx, claims.Issuer, claims.JTI); err != nil || record.Subject != claims.Subject {
		t.Fatalf("retained person token = %#v, %v", record, err)
	}

	_, err = reader.PollPersonToken(ctx, updated)
	var gone *aauth.ProblemError
	if !errors.As(err, &gone) || gone.Status != http.StatusGone || gone.Code != "invalid_code" {
		t.Fatalf("terminal replay error = %v, problem = %#v", err, gone)
	}
}
