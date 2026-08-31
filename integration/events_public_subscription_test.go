package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentPublicEventsJourney(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 23, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	providerID := "https://ap.example"
	resourceID := "https://resource.example"
	agentID := "aauth:events@ap.example"
	providerKey := newSigningKey(t, "events-provider-key")
	resourceKey := newSigningKey(t, "events-resource-key")
	agentKey := newSigningKey(t, "events-agent-key")
	eventIDs := []string{"event-1", "event-2"}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
		{Issuer: resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	providerStore := newMemoryEventInboxStore()
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: providerID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "agent-token-1" },
		Events: &agentprovider.EventsConfig{
			EventEndpoint: "https://ap.example/events-v1",
			NewEventID: func() string {
				eventID := eventIDs[0]
				eventIDs = eventIDs[1:]
				return eventID
			},
			KeyResolver: resolver,
			Store:       providerStore,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := newLogicalTransport()
	httpClient := &http.Client{Transport: transport}
	metadataAdmissions := 0
	deliveryAdmissions := 0
	endpointResolver, err := resource.NewHTTPEventEndpointResolver(resource.HTTPEventEndpointResolverConfig{
		Client: httpClient,
		Admit: func(_ context.Context, endpoint string) error {
			metadataAdmissions++
			if endpoint != providerID+"/.well-known/aauth-agent.json" {
				t.Fatalf("metadata endpoint = %q", endpoint)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceStore := &memoryEventSubscriptionStore{}
	resourceEvents, err := resource.NewEventService(resource.EventServiceConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: resolver, Clock: clock,
		SubscriptionEndpoint: resourceID + "/events/subscribe",
		Store:                resourceStore,
		RegisterPublic: func(_ context.Context, request resource.PublicSubscriptionRequest) (resource.PublicSubscriptionDecision, error) {
			switch request.Token.EventID {
			case "event-1":
				if request.Token.MaxUses != 3 || request.ContentType != "application/json" || len(request.Parameters) == 0 {
					t.Fatalf("bounded registration policy input = %#v", request)
				}
			case "event-2":
				if request.Token.MaxUses != 0 || request.ContentType != "" || len(request.Parameters) != 0 {
					t.Fatalf("bodyless registration policy input = %#v", request)
				}
			default:
				t.Fatalf("unexpected registration policy input = %#v", request)
			}
			return resource.PublicSubscriptionDecision{ExpiresAt: now.Add(24 * time.Hour)}, nil
		},
		ResolveEventEndpoint: endpointResolver,
		AdmitEventEndpoint: func(_ context.Context, endpoint string) error {
			deliveryAdmissions++
			if endpoint != "https://ap.example/events-v2" {
				t.Fatalf("delivery endpoint = %q", endpoint)
			}
			return nil
		},
		HTTPClient: httpClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	transport.Handle(providerID, provider.Handler())
	transport.Handle(resourceID, resourceEvents.PublicSubscriptionHandler())

	agentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: agentID, PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	agentStore := newMemoryAgentEventStore()
	agentClient, err := clientagent.New(context.Background(), clientagent.Config{
		Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
		Events: &clientagent.EventsConfig{Store: agentStore},
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := provider.IssueSubscribeToken(context.Background(), agentprovider.SubscribeRequest{
		Agent: agentID, Resource: resourceID, ConfirmationKey: agentKey.PublicJWK(),
		Lifetime: 10 * time.Minute, MaxUses: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if providerStore.subscriptionCount() != 1 {
		t.Fatal("subscribe token was exposed without one retained AP subscription")
	}
	_, err = agentClient.RegisterPublicSubscription(context.Background(), clientagent.PublicSubscriptionInput{
		Endpoint: resourceID + "/events/subscribe", SubscribeToken: issued.Compact,
		Parameters: []byte(`{"event_types":["slot.available"]}`), ContentType: "application/json",
		Context: []byte(`{"purpose":"appointment waitlist"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resourceStore.commitCount() != 1 || agentStore.contextCount() != 1 {
		t.Fatalf("registration custody: Resource=%d Agent=%d", resourceStore.commitCount(), agentStore.contextCount())
	}
	now = now.Add(time.Second)
	_, err = agentClient.RegisterPublicSubscription(context.Background(), clientagent.PublicSubscriptionInput{
		Endpoint: resourceID + "/events/subscribe", SubscribeToken: issued.Compact,
		Parameters: []byte(`{"event_types":["slot.available"]}`), ContentType: "application/json",
		Context: []byte(`{"purpose":"appointment waitlist"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resourceStore.commitCount() != 1 || agentStore.contextCount() != 1 {
		t.Fatalf("exact registration retry created state: Resource=%d Agent=%d", resourceStore.commitCount(), agentStore.contextCount())
	}
	unlimitedIssued, err := provider.IssueSubscribeToken(context.Background(), agentprovider.SubscribeRequest{
		Agent: agentID, Resource: resourceID, ConfirmationKey: agentKey.PublicJWK(),
		Lifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = agentClient.RegisterPublicSubscription(context.Background(), clientagent.PublicSubscriptionInput{
		Endpoint: resourceID + "/events/subscribe", SubscribeToken: unlimitedIssued.Compact,
		Context: []byte(`{"purpose":"bodyless status signal"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resourceStore.commitCount() != 2 || agentStore.contextCount() != 2 {
		t.Fatalf("bodyless registration custody: Resource=%d Agent=%d", resourceStore.commitCount(), agentStore.contextCount())
	}

	// Replace the AP surface after registration. Delivery must discover and use
	// the new endpoint rather than a retained registration-time URL.
	providerV2, err := agentprovider.New(agentprovider.Config{
		Issuer: providerID, SigningKey: providerKey, Clock: clock,
		NewID: func() string { return "unused-agent-token" },
		Events: &agentprovider.EventsConfig{
			EventEndpoint: "https://ap.example/events-v2",
			NewEventID:    func() string { return "unused-event" },
			KeyResolver:   resolver,
			Store:         providerStore,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport.Handle(providerID, providerV2.Handler())
	firstPrepared, err := resourceEvents.PrepareEvent(context.Background(), resource.EventInput{
		AgentProvider: providerID, EventID: issued.EventID, ContentType: "application/json",
		Payload: []byte(`{"event_type":"slot.available","slot":"10:00"}`), Lifetime: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstResult, err := resourceEvents.DeliverEvent(context.Background(), firstPrepared)
	if err != nil {
		t.Fatal(err)
	}
	if !firstResult.Limited || firstResult.RemainingUses != 2 {
		t.Fatalf("first delivery result = %#v", firstResult)
	}
	if metadataAdmissions != 1 || deliveryAdmissions != 1 {
		t.Fatalf("admissions after first delivery: metadata=%d delivery=%d", metadataAdmissions, deliveryAdmissions)
	}
	firstDelivery := providerStore.deliveryAt(t, 0)
	firstReceived, err := agentClient.AcceptEvent(context.Background(), clientagent.EventDeliveryInput{
		EventToken: firstDelivery.Token, Payload: firstDelivery.Payload, ContentType: firstDelivery.ContentType,
	})
	if err != nil {
		t.Fatal(err)
	}
	if firstReceived.Duplicate || string(firstReceived.Context) != `{"purpose":"appointment waitlist"}` {
		t.Fatalf("first Agent event = %#v", firstReceived)
	}
	alteredRequest, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, "https://ap.example/events-v2",
		bytes.NewReader([]byte(`{"event_type":"slot.available","slot":"altered"}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	alteredRequest.Header.Set("Content-Type", "application/json")
	alteredCredential, err := signaturekey.NewSelfJWTCredential(firstDelivery.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(alteredRequest, resourceKey, alteredCredential, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
	}); err != nil {
		t.Fatal(err)
	}
	alteredResponse, err := httpClient.Do(alteredRequest)
	if err != nil {
		t.Fatal(err)
	}
	var alteredFeedback struct {
		RemainingUses int64 `json:"remaining_uses"`
	}
	if err := json.NewDecoder(alteredResponse.Body).Decode(&alteredFeedback); err != nil {
		_ = alteredResponse.Body.Close()
		t.Fatal(err)
	}
	_ = alteredResponse.Body.Close()
	if alteredResponse.StatusCode != http.StatusAccepted || providerStore.deliveryCount() != 2 {
		t.Fatalf("altered-payload response = %d, retained deliveries = %d", alteredResponse.StatusCode, providerStore.deliveryCount())
	}
	if alteredFeedback.RemainingUses != 1 {
		t.Fatalf("altered-payload feedback = %#v", alteredFeedback)
	}
	secondDelivery := providerStore.deliveryAt(t, 1)
	secondReceived, err := agentClient.AcceptEvent(context.Background(), clientagent.EventDeliveryInput{
		EventToken: secondDelivery.Token, Payload: secondDelivery.Payload, ContentType: secondDelivery.ContentType,
	})
	if err != nil {
		t.Fatal(err)
	}
	if secondReceived.Duplicate || agentStore.acceptedCount() != 2 {
		t.Fatalf("same-tick second Agent event = %#v, accepted = %d", secondReceived, agentStore.acceptedCount())
	}
	now = now.Add(time.Second)
	bodylessPrepared, err := resourceEvents.PrepareEvent(context.Background(), resource.EventInput{
		AgentProvider: providerID, EventID: issued.EventID, Lifetime: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	bodylessResult, err := resourceEvents.DeliverEvent(context.Background(), bodylessPrepared)
	if err != nil {
		t.Fatal(err)
	}
	if !bodylessResult.Limited || bodylessResult.RemainingUses != 0 || providerStore.deliveryCount() != 3 {
		t.Fatalf("bodyless delivery = %#v, retained deliveries = %d", bodylessResult, providerStore.deliveryCount())
	}
	bodylessDelivery := providerStore.deliveryAt(t, 2)
	bodylessReceived, err := agentClient.AcceptEvent(context.Background(), clientagent.EventDeliveryInput{
		EventToken: bodylessDelivery.Token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bodylessReceived.Duplicate || len(bodylessReceived.Payload) != 0 || bodylessReceived.ContentType != "" || agentStore.acceptedCount() != 3 {
		t.Fatalf("bodyless Agent event = %#v, accepted = %d", bodylessReceived, agentStore.acceptedCount())
	}

	firstReplay, err := resourceEvents.DeliverEvent(context.Background(), firstPrepared)
	if err != nil {
		t.Fatal(err)
	}
	if firstReplay.RemainingUses != 2 || providerStore.deliveryCount() != 3 {
		t.Fatalf("first replay = %#v, retained deliveries = %d", firstReplay, providerStore.deliveryCount())
	}
	replayedAtAgent, err := agentClient.AcceptEvent(context.Background(), clientagent.EventDeliveryInput{
		EventToken: firstDelivery.Token, Payload: firstDelivery.Payload, ContentType: firstDelivery.ContentType,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !replayedAtAgent.Duplicate {
		t.Fatal("exact AP-forwarded replay was returned as new")
	}

	now = now.Add(time.Second)
	fourthPrepared, err := resourceEvents.PrepareEvent(context.Background(), resource.EventInput{
		AgentProvider: providerID, EventID: issued.EventID, ContentType: "application/json",
		Payload: []byte(`{"event_type":"slot.available","slot":"12:00"}`), Lifetime: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = resourceEvents.DeliverEvent(context.Background(), fourthPrepared)
	var deliveryFailure *resource.EventDeliveryError
	if !errors.As(err, &deliveryFailure) || deliveryFailure.StatusCode != http.StatusTooManyRequests ||
		providerStore.deliveryCount() != 3 {
		t.Fatalf("fourth delivery error = %#v, retained deliveries = %d", err, providerStore.deliveryCount())
	}

	now = now.Add(time.Second)
	unlimitedPrepared, err := resourceEvents.PrepareEvent(context.Background(), resource.EventInput{
		AgentProvider: providerID, EventID: unlimitedIssued.EventID, Lifetime: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlimitedResult, err := resourceEvents.DeliverEvent(context.Background(), unlimitedPrepared)
	if err != nil {
		t.Fatal(err)
	}
	if unlimitedResult.Limited || unlimitedResult.RemainingUses != 0 || providerStore.deliveryCount() != 4 {
		t.Fatalf("unlimited delivery = %#v, retained deliveries = %d", unlimitedResult, providerStore.deliveryCount())
	}
	unlimitedDelivery := providerStore.deliveryAt(t, 3)
	unlimitedReceived, err := agentClient.AcceptEvent(context.Background(), clientagent.EventDeliveryInput{
		EventToken: unlimitedDelivery.Token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if unlimitedReceived.Duplicate || string(unlimitedReceived.Context) != `{"purpose":"bodyless status signal"}` {
		t.Fatalf("unlimited Agent event = %#v", unlimitedReceived)
	}
}

type memoryEventInboxStore struct {
	mu            sync.Mutex
	subscriptions map[string]agentprovider.EventSubscription
	deliveries    map[events.DeliveryFingerprint]agentprovider.EventDelivery
	acceptances   map[events.DeliveryFingerprint]agentprovider.EventAcceptance
	order         []events.DeliveryFingerprint
	uses          map[string]int64
}

func newMemoryEventInboxStore() *memoryEventInboxStore {
	return &memoryEventInboxStore{
		subscriptions: make(map[string]agentprovider.EventSubscription),
		deliveries:    make(map[events.DeliveryFingerprint]agentprovider.EventDelivery),
		acceptances:   make(map[events.DeliveryFingerprint]agentprovider.EventAcceptance),
		uses:          make(map[string]int64),
	}
}

func (store *memoryEventInboxStore) CommitSubscription(_ context.Context, record agentprovider.EventSubscription) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.subscriptions[record.EventID]; ok {
		if existing.EventID == record.EventID && existing.Agent == record.Agent && existing.Resource == record.Resource &&
			existing.MaxUses == record.MaxUses && existing.TokenSHA256 == record.TokenSHA256 {
			return nil
		}
		return agentprovider.ErrEventDeliveryConflict
	}
	record.CompactToken = string([]byte(record.CompactToken))
	store.subscriptions[record.EventID] = record
	return nil
}

func (store *memoryEventInboxStore) AcceptEvent(_ context.Context, delivery agentprovider.EventDelivery) (agentprovider.EventAcceptance, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	subscription, ok := store.subscriptions[delivery.EventID]
	if !ok {
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventSubscriptionNotFound
	}
	if subscription.Resource != delivery.Resource {
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventResourceMismatch
	}
	if subscription.Agent != delivery.Agent {
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventAgentMismatch
	}
	fingerprint := delivery.Fingerprint
	if fingerprint != events.Fingerprint(delivery.Token, delivery.ContentType, delivery.Payload) {
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventDeliveryConflict
	}
	if existing, ok := store.deliveries[fingerprint]; ok {
		if existing.TokenSHA256 != delivery.TokenSHA256 || existing.PayloadSHA256 != delivery.PayloadSHA256 ||
			existing.ContentType != delivery.ContentType {
			return agentprovider.EventAcceptance{}, agentprovider.ErrEventDeliveryConflict
		}
		accepted := store.acceptances[fingerprint]
		accepted.Duplicate = true
		return accepted, nil
	}
	if subscription.MaxUses > 0 && store.uses[delivery.EventID] >= subscription.MaxUses {
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventUsesExceeded
	}
	delivery.Token = string([]byte(delivery.Token))
	delivery.Payload = append([]byte(nil), delivery.Payload...)
	store.deliveries[fingerprint] = delivery
	store.order = append(store.order, fingerprint)
	store.uses[delivery.EventID]++
	remaining := int64(0)
	if subscription.MaxUses > 0 {
		remaining = subscription.MaxUses - store.uses[delivery.EventID]
	}
	accepted := agentprovider.EventAcceptance{MaximumUses: subscription.MaxUses, RemainingUses: remaining}
	store.acceptances[fingerprint] = accepted
	return accepted, nil
}

func (store *memoryEventInboxStore) subscriptionCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.subscriptions)
}

func (store *memoryEventInboxStore) deliveryCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.deliveries)
}

func (store *memoryEventInboxStore) deliveryAt(t *testing.T, index int) agentprovider.EventDelivery {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if index < 0 || index >= len(store.order) {
		t.Fatalf("delivery index %d outside %d records", index, len(store.order))
	}
	record := store.deliveries[store.order[index]]
	record.Payload = append([]byte(nil), record.Payload...)
	return record
}

type memoryEventSubscriptionStore struct {
	mu      sync.Mutex
	records map[string]resource.EventSubscription
	commits int
}

func (store *memoryEventSubscriptionStore) Commit(_ context.Context, record resource.EventSubscription) (resource.EventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.records == nil {
		store.records = make(map[string]resource.EventSubscription)
	}
	key := record.AgentProvider + "\x00" + record.EventID
	if retained, ok := store.records[key]; ok {
		if sameResourceSubscription(retained, record) {
			return cloneResourceSubscription(retained), nil
		}
		return resource.EventSubscription{}, resource.ErrEventSubscriptionConflict
	}
	store.records[key] = cloneResourceSubscription(record)
	store.commits++
	return cloneResourceSubscription(record), nil
}

func (store *memoryEventSubscriptionStore) Load(_ context.Context, ref resource.EventSubscriptionRef) (resource.EventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[ref.AgentProvider+"\x00"+ref.EventID]
	if !ok {
		return resource.EventSubscription{}, resource.ErrEventSubscriptionNotFound
	}
	return cloneResourceSubscription(record), nil
}

func (store *memoryEventSubscriptionStore) commitCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.commits
}

func sameResourceSubscription(left, right resource.EventSubscription) bool {
	return left.EventID == right.EventID && left.RegistrationSHA256 == right.RegistrationSHA256
}

func cloneResourceSubscription(record resource.EventSubscription) resource.EventSubscription {
	record.Parameters = append([]byte(nil), record.Parameters...)
	return record
}

type memoryAgentEventStore struct {
	mu       sync.Mutex
	contexts map[string]clientagent.EventContext
	events   map[events.DeliveryFingerprint]clientagent.AcceptedEvent
}

func newMemoryAgentEventStore() *memoryAgentEventStore {
	return &memoryAgentEventStore{
		contexts: make(map[string]clientagent.EventContext),
		events:   make(map[events.DeliveryFingerprint]clientagent.AcceptedEvent),
	}
}

func (store *memoryAgentEventStore) BindContext(_ context.Context, record clientagent.EventContext) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.Resource + "\x00" + record.EventID
	if existing, ok := store.contexts[key]; ok {
		if existing.SubscribeTokenSHA256 == record.SubscribeTokenSHA256 && bytes.Equal(existing.Context, record.Context) {
			return nil
		}
		return clientagent.ErrEventContextConflict
	}
	record.Context = append([]byte(nil), record.Context...)
	store.contexts[key] = record
	return nil
}

func (store *memoryAgentEventStore) AcceptEvent(_ context.Context, candidate clientagent.AcceptedEvent) (clientagent.EventAcceptance, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := candidate.Resource + "\x00" + candidate.EventID
	contextRecord, ok := store.contexts[key]
	if !ok {
		return clientagent.EventAcceptance{}, clientagent.ErrEventContextNotFound
	}
	if _, ok := store.events[candidate.Fingerprint]; ok {
		contextRecord.Context = append([]byte(nil), contextRecord.Context...)
		return clientagent.EventAcceptance{Context: contextRecord, Duplicate: true}, nil
	}
	candidate.Payload = append([]byte(nil), candidate.Payload...)
	store.events[candidate.Fingerprint] = candidate
	contextRecord.Context = append([]byte(nil), contextRecord.Context...)
	return clientagent.EventAcceptance{Context: contextRecord}, nil
}

func (store *memoryAgentEventStore) contextCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.contexts)
}

func (store *memoryAgentEventStore) acceptedCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.events)
}
