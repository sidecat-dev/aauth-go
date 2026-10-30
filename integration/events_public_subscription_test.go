package integration_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	agentstoretest "gitlab.com/sidecat-dev/aauth-go/agentprovider/storetest"
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
	otherResourceKey := newSigningKey(t, "events-other-resource-key")
	agentKey := newSigningKey(t, "events-agent-key")
	eventIDs := []string{"event-1", "event-2"}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:                               providerKey.PublicJWK(),
		{Issuer: resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}:                            resourceKey.PublicJWK(),
		{Issuer: "https://other-resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: otherResourceKey.ID()}: otherResourceKey.PublicJWK(),
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
	firstPayload := []byte(`{"event_type":"slot.available","slot":"10:00"}`)
	firstPrepared, err := resourceEvents.PrepareEvent(context.Background(), resource.EventInput{
		AgentProvider: providerID, EventID: issued.EventID, ContentType: "application/json",
		Payload: firstPayload, Lifetime: 5 * time.Minute,
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
	// The AP reads the exact bytes the Resource sent from its inbox; the host
	// transport hands them to the Agent unchanged, and the Agent checks
	// body_s256.
	pending, err := providerV2.PendingEvents(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending deliveries = %d, want 1", len(pending))
	}
	firstDelivery := pending[0]
	if !bytes.Equal(firstDelivery.Payload, firstPayload) || firstDelivery.ContentType != "application/json" {
		t.Fatalf("AP-retained delivery = %#v", firstDelivery)
	}
	firstReceived, err := agentClient.AcceptEvent(context.Background(), clientagent.EventDeliveryInput{
		EventToken: firstDelivery.Token, Payload: firstDelivery.Payload, ContentType: firstDelivery.ContentType,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := providerV2.AcknowledgeEvent(context.Background(), agentID, firstDelivery.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if pending, err := providerV2.PendingEvents(context.Background(), agentID); err != nil || len(pending) != 0 {
		t.Fatalf("pending deliveries after acknowledgment = %d, %v", len(pending), err)
	}
	if firstReceived.Duplicate || string(firstReceived.Context) != `{"purpose":"appointment waitlist"}` ||
		!bytes.Equal(firstReceived.Payload, firstPayload) {
		t.Fatalf("first Agent event = %#v", firstReceived)
	}
	alteredPayload := []byte(`{"event_type":"slot.available","slot":"altered"}`)
	if _, err := agentClient.AcceptEvent(context.Background(), clientagent.EventDeliveryInput{
		EventToken: firstDelivery.Token, Payload: alteredPayload, ContentType: firstDelivery.ContentType,
	}); !errors.Is(err, events.ErrEventBodyMismatch) {
		t.Fatalf("Agent accepted a body altered on the way through the AP: %v", err)
	}

	// A resigned delivery that pairs the first token with another body fails
	// body_s256 at the AP and consumes no use.
	alteredRequest, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, "https://ap.example/events-v2",
		bytes.NewReader(alteredPayload),
	)
	if err != nil {
		t.Fatal(err)
	}
	alteredRequest.Header.Set("Content-Type", "application/json")
	alteredCredential, err := signaturekey.NewSelfJWTCredential(firstDelivery.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(alteredRequest, resourceKey, alteredCredential, clock, signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	alteredResponse, err := httpClient.Do(alteredRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = alteredResponse.Body.Close()
	alteredFailure, err := signaturekey.ParseError(alteredResponse.Header.Get("Signature-Error"))
	if alteredResponse.StatusCode != http.StatusUnauthorized || err != nil || alteredFailure.Code != signaturekey.ErrorInvalidJWT ||
		providerStore.deliveryCount() != 1 {
		t.Fatalf("altered-payload response = %d %q, retained deliveries = %d",
			alteredResponse.StatusCode, alteredResponse.Header.Get("Signature-Error"), providerStore.deliveryCount())
	}

	// Another Resource cannot deliver on this eid, even with a valid
	// signature of its own.
	foreignToken, err := events.MintEventToken("https://other-resource.example", otherResourceKey, events.EventTokenRequest{
		Agent: agentID, EventID: issued.EventID, Payload: firstPayload, Lifetime: time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	foreignRequest, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, "https://ap.example/events-v2", bytes.NewReader(firstPayload),
	)
	if err != nil {
		t.Fatal(err)
	}
	foreignRequest.Header.Set("Content-Type", "application/json")
	foreignCredential, err := signaturekey.NewSelfJWTCredential(foreignToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(foreignRequest, otherResourceKey, foreignCredential, clock, signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	foreignResponse, err := httpClient.Do(foreignRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = foreignResponse.Body.Close()
	if foreignResponse.StatusCode != http.StatusForbidden || foreignResponse.Header.Get("Signature-Error") != "" ||
		providerStore.deliveryCount() != 1 {
		t.Fatalf("delivery by another Resource = %d, retained deliveries = %d", foreignResponse.StatusCode, providerStore.deliveryCount())
	}

	secondPayload := []byte(`{"event_type":"slot.available","slot":"11:00"}`)
	secondPrepared, err := resourceEvents.PrepareEvent(context.Background(), resource.EventInput{
		AgentProvider: providerID, EventID: issued.EventID, ContentType: "application/json",
		Payload: secondPayload, Lifetime: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondResult, err := resourceEvents.DeliverEvent(context.Background(), secondPrepared)
	if err != nil {
		t.Fatal(err)
	}
	if secondResult.RemainingUses != 1 || providerStore.deliveryCount() != 2 {
		t.Fatalf("second delivery = %#v, retained deliveries = %d", secondResult, providerStore.deliveryCount())
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
	if !errors.As(err, &deliveryFailure) || deliveryFailure.StatusCode != http.StatusNotFound ||
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

func TestMemoryEventInboxStoreContract(t *testing.T) {
	t.Parallel()
	agentstoretest.RunEventInbox(t, agentstoretest.EventInboxContract{
		New: func(testing.TB) agentprovider.EventInboxStore { return newMemoryEventInboxStore() },
		Delivery: func(
			_ testing.TB,
			store agentprovider.EventInboxStore,
			fingerprint events.DeliveryFingerprint,
		) (agentprovider.EventDelivery, error) {
			return store.(*memoryEventInboxStore).delivery(fingerprint)
		},
	})
	agentstoretest.RunEventInboxReader(t, agentstoretest.EventInboxReaderContract{
		New: func(testing.TB) agentstoretest.EventInboxReaderStore { return newMemoryEventInboxStore() },
	})
}

type memoryEventInboxStore struct {
	mu            sync.Mutex
	subscriptions map[string]agentprovider.EventSubscription
	deliveries    map[events.DeliveryFingerprint]agentprovider.EventDelivery
	acceptances   map[events.DeliveryFingerprint]agentprovider.EventAcceptance
	order         []events.DeliveryFingerprint
	pending       map[string][]events.DeliveryFingerprint
	uses          map[string]int64
}

func newMemoryEventInboxStore() *memoryEventInboxStore {
	return &memoryEventInboxStore{
		subscriptions: make(map[string]agentprovider.EventSubscription),
		deliveries:    make(map[events.DeliveryFingerprint]agentprovider.EventDelivery),
		acceptances:   make(map[events.DeliveryFingerprint]agentprovider.EventAcceptance),
		pending:       make(map[string][]events.DeliveryFingerprint),
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
	store.pending[delivery.Agent] = append(store.pending[delivery.Agent], fingerprint)
	store.uses[delivery.EventID]++
	remaining := int64(0)
	if subscription.MaxUses > 0 {
		remaining = subscription.MaxUses - store.uses[delivery.EventID]
	}
	accepted := agentprovider.EventAcceptance{MaximumUses: subscription.MaxUses, RemainingUses: remaining}
	store.acceptances[fingerprint] = accepted
	return accepted, nil
}

func (store *memoryEventInboxStore) PendingEvents(_ context.Context, agent string) ([]agentprovider.EventDelivery, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending := make([]agentprovider.EventDelivery, 0, len(store.pending[agent]))
	for _, fingerprint := range store.pending[agent] {
		record := store.deliveries[fingerprint]
		record.Payload = append([]byte(nil), record.Payload...)
		pending = append(pending, record)
	}
	return pending, nil
}

func (store *memoryEventInboxStore) AcknowledgeEvent(_ context.Context, agent string, fingerprint events.DeliveryFingerprint) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.pending[agent] = slices.DeleteFunc(store.pending[agent], func(candidate events.DeliveryFingerprint) bool {
		return candidate == fingerprint
	})
	return nil
}

func (store *memoryEventInboxStore) delivery(fingerprint events.DeliveryFingerprint) (agentprovider.EventDelivery, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.deliveries[fingerprint]
	if !ok {
		return agentprovider.EventDelivery{}, errors.New("no accepted delivery")
	}
	record.Payload = append([]byte(nil), record.Payload...)
	return record, nil
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
