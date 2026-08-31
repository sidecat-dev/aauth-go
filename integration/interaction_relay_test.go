package integration_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/internal/exampleutil"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentCoreMissionlessInteractionRelay(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 9, 1, 3, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:operator@ap.example"
		personServerID  = "https://ps.example"
	)
	providerKey := newSigningKey(t, "relay-journey-ap")
	agentKey := newSigningKey(t, "relay-journey-agent")
	personKey := newSigningKey(t, "relay-journey-ps")
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.Contains(endpoint, ".example/.well-known/") {
				return nil
			}
			return errors.New("unexpected discovery endpoint: " + endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "relay-agent-token" },
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

	store := exampleutil.NewInteractionRelayStore()
	policyCalls := 0
	newPeople := func(unavailable bool) *personserver.Server {
		people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: personKey, KeyResolver: resolver,
			Clock: clock, Tokens: exampleutil.NewMissionStore(), NewID: func() string { return "unused-token" },
			BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "person", Lifetime: time.Minute}, nil
			},
			Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				return personserver.AuthorizationDecision{Scopes: []string{"unused"}, Lifetime: time.Minute}, nil
			},
			InteractionRelay: &personserver.InteractionRelayConfig{
				Store: store,
				Policy: func(_ context.Context, request personserver.InteractionRelayPolicyRequest) (personserver.InteractionRelayPendingPolicy, error) {
					policyCalls++
					if request.Agent != agentID || request.Document.Relay.URL != "https://resource.example/confirm" ||
						!request.ReceivedAt.Equal(now) {
						return personserver.InteractionRelayPendingPolicy{}, errors.New("unexpected relay policy input")
					}
					if unavailable {
						return personserver.InteractionRelayPendingPolicy{}, personserver.ErrInteractionRelayUnavailable
					}
					return personserver.InteractionRelayPendingPolicy{Lifetime: time.Minute, RetryAfter: 0}, nil
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return people
	}
	people := newPeople(false)
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	operator, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	input := clientagent.InteractionRelayRequest{
		PersonServer: personServerID,
		Relay: aauth.InteractionRelay{
			Type:        aauth.InteractionRelayInteraction,
			Description: "The Resource needs confirmation.",
			URL:         "https://resource.example/confirm",
			Code:        "ABCD-EFGH",
			MaxWait:     10 * time.Second,
		},
	}
	result, err := operator.RequestInteractionRelay(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatalf("relay result = %#v, want pending", result)
	}
	people = newPeople(false)
	network.Handle(personServerID, people.Handler())
	reference := strings.TrimPrefix(pending.Location(), personServerID+"/interaction/relay/")
	handle, err := people.ResumeInteractionRelay(ctx, reference)
	if err != nil {
		t.Fatal(err)
	}
	if err := people.MarkInteractionRelayEngaged(ctx, handle); err != nil {
		t.Fatal(err)
	}
	result, err = operator.PollInteractionRelay(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	completion, ok := result.Completion()
	if !ok || completion.Completion.Status != aauth.InteractionRelayInteracting {
		t.Fatalf("completion = %#v, present=%t", completion, ok)
	}

	people = newPeople(true)
	network.Handle(personServerID, people.Handler())
	result, err = operator.RequestInteractionRelay(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	fallback, ok := result.Fallback()
	if !ok || fallback.Relay != input.Relay {
		t.Fatalf("fallback = %#v, present=%t", fallback, ok)
	}
	if policyCalls != 2 {
		t.Fatalf("policy calls = %d", policyCalls)
	}
}
