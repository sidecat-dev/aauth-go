package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentProtectedEventsSubscriptionJourney(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		providerID = "https://ap.example"
		resourceID = "https://resource.example"
		agentID    = "aauth:events@ap.example"
	)
	providerKey := newSigningKey(t, "protected-events-provider")
	resourceKey := newSigningKey(t, "protected-events-resource")
	agentKey := newSigningKey(t, "protected-events-agent")
	otherAgentKey := newSigningKey(t, "protected-events-other-agent")
	agentThumbprint, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
		{Issuer: resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	providerStore := newMemoryEventInboxStore()
	eventIDs := []string{"protected-event-other", "protected-event-1"}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: providerID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "protected-agent-token" },
		Events: &agentprovider.EventsConfig{
			EventEndpoint: providerID + "/events",
			NewEventID: func() string {
				eventID := eventIDs[0]
				eventIDs = eventIDs[1:]
				return eventID
			},
			KeyResolver: resolver, Store: providerStore,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := newLogicalTransport()
	httpClient := &http.Client{Transport: transport}
	endpointResolver, err := resource.NewHTTPEventEndpointResolver(resource.HTTPEventEndpointResolverConfig{
		Client: httpClient, Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceStore := newProtectedIntegrationEventStore()
	resourceEvents, err := resource.NewEventService(resource.EventServiceConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		SubscriptionEndpoint: resourceID + "/events/public", Store: resourceStore,
		RegisterPublic: func(context.Context, resource.PublicSubscriptionRequest) (resource.PublicSubscriptionDecision, error) {
			return resource.PublicSubscriptionDecision{}, nil
		},
		Protected: &resource.ProtectedSubscriptionConfig{
			EndpointPrefix: resourceID + "/events/protected/", NewTicketID: func() string { return "ticket-1" },
			MaximumTicketLifetime: 5 * time.Minute,
			Register: func(_ context.Context, request resource.ProtectedSubscriptionRequest) (resource.PublicSubscriptionDecision, error) {
				if request.Ticket.KeyThumbprint != agentThumbprint || string(request.Ticket.Context) != `{"operation":"appointments.create"}` {
					return resource.PublicSubscriptionDecision{}, resource.ErrEventSubscriptionDenied
				}
				return resource.PublicSubscriptionDecision{ExpiresAt: now.Add(time.Hour)}, nil
			},
		},
		ResolveEventEndpoint: endpointResolver, AdmitEventEndpoint: func(context.Context, string) error { return nil },
		HTTPClient: httpClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceIdentity, err := resource.NewAgentIdentity(resource.AgentIdentityConfig{
		Issuer: resourceID, KeyResolver: resolver, Clock: clock,
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			principal, ok := resource.AgentPrincipalFromContext(request.Context())
			if !ok {
				http.Error(response, "missing Agent", http.StatusInternalServerError)
				return
			}
			ticket, err := resourceEvents.IssueProtectedSubscriptionTicket(request.Context(), resource.ProtectedSubscriptionTicketRequest{
				ConfirmationKey: principal.Confirmation, Context: []byte(`{"operation":"appointments.create"}`), Lifetime: 2 * time.Minute,
			})
			if err != nil {
				http.Error(response, err.Error(), http.StatusInternalServerError)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(ticket)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	transport.Handle(providerID, provider.Handler())
	transport.Handle(resourceID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/events/protected/") {
			resourceEvents.ProtectedSubscriptionHandler().ServeHTTP(response, request)
			return
		}
		resourceIdentity.Handler().ServeHTTP(response, request)
	}))
	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	agentStore := newMemoryAgentEventStore()
	agentClient, err := clientagent.New(ctx, clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
		Events: &clientagent.EventsConfig{Store: agentStore},
	})
	if err != nil {
		t.Fatal(err)
	}
	priorRequest, _ := http.NewRequestWithContext(ctx, http.MethodPost, resourceID+"/operations/create", nil)
	priorResponse, err := agentClient.CallAsAgent(ctx, priorRequest)
	if err != nil {
		t.Fatal(err)
	}
	var ticket resource.IssuedProtectedSubscriptionTicket
	if err := json.NewDecoder(priorResponse.Body).Decode(&ticket); err != nil {
		t.Fatal(err)
	}
	priorResponse.Body.Close()

	// Another Agent, with its own key, cannot use the ticket even though the
	// AP issues it a valid subscribe token for this Resource.
	otherAgentID := "aauth:other-events@ap.example"
	otherAgentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: otherAgentID, PublicKey: otherAgentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherAgentClient, err := clientagent.New(ctx, clientagent.Config{
		Identifier: otherAgentID, SigningKey: otherAgentKey, AgentToken: otherAgentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
		Events: &clientagent.EventsConfig{Store: newMemoryAgentEventStore()},
	})
	if err != nil {
		t.Fatal(err)
	}
	otherIssued, err := provider.IssueSubscribeToken(ctx, agentprovider.SubscribeRequest{
		Agent: otherAgentID, Resource: resourceID, ConfirmationKey: otherAgentKey.PublicJWK(),
		Lifetime: 10 * time.Minute, MaxUses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = otherAgentClient.RegisterProtectedSubscription(ctx, clientagent.ProtectedSubscriptionInput{
		TicketURL: ticket.URL, SubscribeToken: otherIssued.Compact,
		Parameters: []byte(`{"event_types":["appointment.changed"]}`), ContentType: "application/json",
		Context: []byte(`{"purpose":"not mine"}`),
	})
	var refused *aauth.ProblemError
	if !errors.As(err, &refused) || refused.Status != http.StatusNotFound || resourceStore.subscriptionCount() != 0 {
		t.Fatalf("ticket use by another key = %v, subscriptions=%d", err, resourceStore.subscriptionCount())
	}

	issued, err := provider.IssueSubscribeToken(ctx, agentprovider.SubscribeRequest{
		Agent: agentID, Resource: resourceID, ConfirmationKey: agentKey.PublicJWK(),
		Lifetime: 10 * time.Minute, MaxUses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = agentClient.RegisterProtectedSubscription(ctx, clientagent.ProtectedSubscriptionInput{
		TicketURL: ticket.URL, SubscribeToken: issued.Compact,
		Parameters: []byte(`{"event_types":["appointment.changed"]}`), ContentType: "application/json",
		Context: []byte(`{"purpose":"created appointment"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := resourceEvents.PrepareEvent(ctx, resource.EventInput{
		AgentProvider: providerID, EventID: issued.EventID, ContentType: "application/json",
		Payload: []byte(`{"event_type":"appointment.changed"}`), Lifetime: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resourceEvents.DeliverEvent(ctx, prepared); err != nil {
		t.Fatal(err)
	}
	delivery := providerStore.deliveryAt(t, 0)
	received, err := agentClient.AcceptEvent(ctx, clientagent.EventDeliveryInput{
		EventToken: delivery.Token, Payload: delivery.Payload, ContentType: delivery.ContentType,
	})
	if err != nil {
		t.Fatal(err)
	}
	if received.Duplicate || string(received.Context) != `{"purpose":"created appointment"}` || resourceStore.subscriptionCount() != 1 {
		t.Fatalf("received = %#v, subscriptions=%d", received, resourceStore.subscriptionCount())
	}
}

type protectedIntegrationEventStore struct {
	mu      sync.Mutex
	tickets map[string]resource.ProtectedSubscriptionTicket
	records map[string]resource.EventSubscription
}

func newProtectedIntegrationEventStore() *protectedIntegrationEventStore {
	return &protectedIntegrationEventStore{
		tickets: make(map[string]resource.ProtectedSubscriptionTicket),
		records: make(map[string]resource.EventSubscription),
	}
}

func (store *protectedIntegrationEventStore) CreateProtectedSubscriptionTicket(_ context.Context, ticket resource.ProtectedSubscriptionTicket) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.tickets[ticket.ID]; exists {
		return resource.ErrProtectedSubscriptionConflict
	}
	store.tickets[ticket.ID] = cloneProtectedIntegrationTicket(ticket)
	return nil
}

func (store *protectedIntegrationEventStore) LoadProtectedSubscriptionTicket(_ context.Context, id, keyThumbprint string, at time.Time) (resource.ProtectedSubscriptionTicket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ticket, exists := store.tickets[id]
	if !exists || ticket.KeyThumbprint != keyThumbprint {
		return resource.ProtectedSubscriptionTicket{}, resource.ErrProtectedSubscriptionNotFound
	}
	if !at.Before(ticket.ExpiresAt) && ticket.UsedAt.IsZero() {
		return resource.ProtectedSubscriptionTicket{}, resource.ErrProtectedSubscriptionExpired
	}
	return cloneProtectedIntegrationTicket(ticket), nil
}

func (store *protectedIntegrationEventStore) CommitProtectedSubscription(_ context.Context, expected resource.ProtectedSubscriptionTicket, candidate resource.EventSubscription) (resource.EventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ticket, exists := store.tickets[expected.ID]
	if !exists || !reflect.DeepEqual(ticket, expected) {
		return resource.EventSubscription{}, resource.ErrProtectedSubscriptionConflict
	}
	key := candidate.AgentProvider + "\x00" + candidate.EventID
	if retained, exists := store.records[key]; exists {
		if retained.RegistrationSHA256 == candidate.RegistrationSHA256 && ticket.RegistrationSHA256 == candidate.RegistrationSHA256 {
			return cloneResourceSubscription(retained), nil
		}
		return resource.EventSubscription{}, resource.ErrProtectedSubscriptionConflict
	}
	if !ticket.UsedAt.IsZero() || !candidate.RegisteredAt.Before(ticket.ExpiresAt) {
		return resource.EventSubscription{}, resource.ErrProtectedSubscriptionConflict
	}
	store.records[key] = cloneResourceSubscription(candidate)
	ticket.UsedAt = candidate.RegisteredAt
	ticket.RegistrationSHA256 = candidate.RegistrationSHA256
	store.tickets[ticket.ID] = cloneProtectedIntegrationTicket(ticket)
	return cloneResourceSubscription(candidate), nil
}

func (store *protectedIntegrationEventStore) Commit(context.Context, resource.EventSubscription) (resource.EventSubscription, error) {
	return resource.EventSubscription{}, errors.New("public registration not configured")
}

func (store *protectedIntegrationEventStore) Load(_ context.Context, ref resource.EventSubscriptionRef) (resource.EventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[ref.AgentProvider+"\x00"+ref.EventID]
	if !exists {
		return resource.EventSubscription{}, resource.ErrEventSubscriptionNotFound
	}
	return cloneResourceSubscription(record), nil
}

func (store *protectedIntegrationEventStore) subscriptionCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.records)
}

func cloneProtectedIntegrationTicket(ticket resource.ProtectedSubscriptionTicket) resource.ProtectedSubscriptionTicket {
	ticket.Context = append([]byte(nil), ticket.Context...)
	return ticket
}

var _ resource.ProtectedSubscriptionStore = (*protectedIntegrationEventStore)(nil)
