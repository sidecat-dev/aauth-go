// The events example runs the public AAuth Events path: the Agent Provider
// issues a subscribe token, the Agent registers it with a Resource, and the
// Resource delivers one event back through the Agent Provider.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	agentProviderID = "https://agents.example"
	agentID         = "aauth:calendar@agents.example"
	resourceID      = "https://calendar.example"
)

func main() {
	if err := run(os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(output io.Writer) error {
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerKey, err := newSigningKey("events-provider-key")
	if err != nil {
		return err
	}
	resourceKey, err := newSigningKey("events-resource-key")
	if err != nil {
		return err
	}
	agentKey, err := newSigningKey("events-agent-key")
	if err != nil {
		return err
	}
	keys := signaturekey.StaticKeyResolver{
		{Issuer: agentProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
		{Issuer: resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}:   resourceKey.PublicJWK(),
	}
	providerStore := newProviderEventStore()
	eventIDs := []string{"event-1", "event-protected"}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "agent-token-1" },
		Events: &agentprovider.EventsConfig{
			EventEndpoint: agentProviderID + "/events",
			NewEventID: func() string {
				id := eventIDs[0]
				eventIDs = eventIDs[1:]
				return id
			},
			KeyResolver: keys,
			Store:       providerStore,
		},
	})
	if err != nil {
		return err
	}
	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	endpointResolver, err := resource.NewHTTPEventEndpointResolver(resource.HTTPEventEndpointResolverConfig{
		Client: httpClient,
		Admit:  network.Admit,
	})
	if err != nil {
		return err
	}
	resourceStore := newResourceEventStore()
	eventService, err := resource.NewEventService(resource.EventServiceConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: keys, Clock: clock,
		SubscriptionEndpoint: resourceID + "/events/subscribe",
		Store:                resourceStore,
		RegisterPublic: func(_ context.Context, request resource.PublicSubscriptionRequest) (resource.PublicSubscriptionDecision, error) {
			if request.Token.EventID == "" {
				return resource.PublicSubscriptionDecision{}, resource.ErrEventSubscriptionDenied
			}
			return resource.PublicSubscriptionDecision{ExpiresAt: now.Add(24 * time.Hour)}, nil
		},
		Protected: &resource.ProtectedSubscriptionConfig{
			EndpointPrefix: resourceID + "/events/protected/", NewTicketID: func() string { return "ticket-1" },
			MaximumTicketLifetime: 5 * time.Minute,
			Register: func(_ context.Context, request resource.ProtectedSubscriptionRequest) (resource.PublicSubscriptionDecision, error) {
				if request.Ticket.Agent != agentID || string(request.Ticket.Context) != "created appointment" {
					return resource.PublicSubscriptionDecision{}, resource.ErrEventSubscriptionDenied
				}
				return resource.PublicSubscriptionDecision{ExpiresAt: now.Add(24 * time.Hour)}, nil
			},
		},
		ResolveEventEndpoint: endpointResolver,
		AdmitEventEndpoint:   network.Admit,
		HTTPClient:           httpClient,
		AsyncAPIDocument:     []byte(asyncAPIDocument),
	})
	if err != nil {
		return err
	}
	network.Handle(agentProviderID, provider.Handler())
	network.Handle(resourceID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/events/protected/") {
			eventService.ProtectedSubscriptionHandler().ServeHTTP(response, request)
			return
		}
		if request.URL.Path == "/asyncapi.json" {
			eventService.AsyncAPIHandler().ServeHTTP(response, request)
			return
		}
		eventService.PublicSubscriptionHandler().ServeHTTP(response, request)
	}))

	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		return err
	}
	agentStore := newAgentEventStore()
	agentClient, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: keys, HTTPClient: httpClient, Clock: clock,
		Events: &clientagent.EventsConfig{Store: agentStore},
	})
	if err != nil {
		return err
	}
	issued, err := provider.IssueSubscribeToken(ctx, agentprovider.SubscribeRequest{
		Agent: agentID, Resource: resourceID, ConfirmationKey: agentKey.PublicJWK(),
		Lifetime: 10 * time.Minute, MaxUses: 1,
	})
	if err != nil {
		return err
	}
	if _, err := agentClient.RegisterPublicSubscription(ctx, clientagent.PublicSubscriptionInput{
		Endpoint: resourceID + "/events/subscribe", SubscribeToken: issued.Compact,
		Parameters: []byte(`{"event_types":["slot.available"]}`), ContentType: "application/json",
		Context: []byte("appointment waitlist"),
	}); err != nil {
		return err
	}
	ticket, err := eventService.IssueProtectedSubscriptionTicket(ctx, resource.ProtectedSubscriptionTicketRequest{
		Agent: agentID, Context: []byte("created appointment"), Lifetime: 2 * time.Minute,
	})
	if err != nil {
		return err
	}
	protectedToken, err := provider.IssueSubscribeToken(ctx, agentprovider.SubscribeRequest{
		Agent: agentID, Resource: resourceID, ConfirmationKey: agentKey.PublicJWK(),
		Lifetime: 10 * time.Minute, MaxUses: 1,
	})
	if err != nil {
		return err
	}
	if _, err := agentClient.RegisterProtectedSubscription(ctx, clientagent.ProtectedSubscriptionInput{
		TicketURL: ticket.URL, SubscribeToken: protectedToken.Compact,
		Parameters: []byte(`{"event_types":["appointment.changed"]}`), ContentType: "application/json",
		Context: []byte("protected appointment"),
	}); err != nil {
		return err
	}
	prepared, err := eventService.PrepareEvent(ctx, resource.EventInput{
		AgentProvider: agentProviderID, EventID: issued.EventID, ContentType: "application/json",
		Payload: []byte(`{"event_type":"slot.available","slot":"10:00"}`), Lifetime: 5 * time.Minute,
	})
	if err != nil {
		return err
	}
	result, err := eventService.DeliverEvent(ctx, prepared)
	if err != nil {
		return err
	}
	delivery, err := providerStore.Delivery(issued.EventID)
	if err != nil {
		return err
	}
	received, err := agentClient.AcceptEvent(ctx, clientagent.EventDeliveryInput{
		EventToken: delivery.Token, Payload: delivery.Payload, ContentType: delivery.ContentType,
	})
	if err != nil {
		return err
	}
	if received.Duplicate || string(received.Context) != "appointment waitlist" {
		return errors.New("events example: Agent received an uncorrelated event")
	}
	_, err = fmt.Fprintf(output, "AAuth public event complete: %s; remaining uses %d\n", received.Payload, result.RemainingUses)
	if err != nil {
		return err
	}
	protectedPrepared, err := eventService.PrepareEvent(ctx, resource.EventInput{
		AgentProvider: agentProviderID, EventID: protectedToken.EventID, ContentType: "application/json",
		Payload: []byte(`{"event_type":"appointment.changed"}`), Lifetime: 5 * time.Minute,
	})
	if err != nil {
		return err
	}
	if _, err := eventService.DeliverEvent(ctx, protectedPrepared); err != nil {
		return err
	}
	protectedDelivery, err := providerStore.Delivery(protectedToken.EventID)
	if err != nil {
		return err
	}
	protectedReceived, err := agentClient.AcceptEvent(ctx, clientagent.EventDeliveryInput{
		EventToken: protectedDelivery.Token, Payload: protectedDelivery.Payload,
		ContentType: protectedDelivery.ContentType,
	})
	if err != nil {
		return err
	}
	if protectedReceived.Duplicate || string(protectedReceived.Context) != "protected appointment" {
		return errors.New("events example: Agent received an uncorrelated protected event")
	}
	_, err = fmt.Fprintf(output, "AAuth protected event complete: %s\n", protectedReceived.Payload)
	return err
}

// asyncAPIDocument describes the Resource's event channels. Events requires it
// to declare the aauth_subscribe security scheme.
const asyncAPIDocument = `{
  "asyncapi": "3.0.0",
  "info": {"title": "Calendar Events", "version": "1.0.0"},
  "channels": {
    "waitlist": {
      "address": "/events/subscribe",
      "messages": {"slotAvailable": {"$ref": "#/components/messages/SlotAvailable"}}
    }
  },
  "operations": {
    "subscribeWaitlist": {
      "action": "receive",
      "channel": {"$ref": "#/channels/waitlist"},
      "security": [{"$ref": "#/components/securitySchemes/aauth_subscribe"}]
    }
  },
  "components": {
    "messages": {
      "SlotAvailable": {
        "contentType": "application/json",
        "payload": {
          "type": "object",
          "properties": {"event_type": {"type": "string", "const": "slot.available"}, "slot": {"type": "string"}},
          "required": ["event_type"]
        }
      }
    },
    "securitySchemes": {
      "aauth_subscribe": {
        "type": "http",
        "scheme": "aauth-subscribe",
        "description": "AAuth Subscribe Token as Signature-Key JWT"
      }
    }
  }
}`

func newSigningKey(id string) (jose.SigningKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return jose.NewEd25519SigningKey(id, privateKey)
}
