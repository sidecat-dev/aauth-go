package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

type providerEventStore struct {
	mu            sync.Mutex
	subscriptions map[string]agentprovider.EventSubscription
	deliveries    map[events.DeliveryFingerprint]agentprovider.EventDelivery
	acceptances   map[events.DeliveryFingerprint]agentprovider.EventAcceptance
	order         map[string][]events.DeliveryFingerprint
	uses          map[string]int64
}

func newProviderEventStore() *providerEventStore {
	return &providerEventStore{
		subscriptions: make(map[string]agentprovider.EventSubscription),
		deliveries:    make(map[events.DeliveryFingerprint]agentprovider.EventDelivery),
		acceptances:   make(map[events.DeliveryFingerprint]agentprovider.EventAcceptance),
		order:         make(map[string][]events.DeliveryFingerprint),
		uses:          make(map[string]int64),
	}
}

func (store *providerEventStore) CommitSubscription(_ context.Context, record agentprovider.EventSubscription) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if retained, ok := store.subscriptions[record.EventID]; ok {
		if retained.Agent == record.Agent && retained.Resource == record.Resource &&
			retained.MaxUses == record.MaxUses && retained.TokenSHA256 == record.TokenSHA256 {
			return nil
		}
		return agentprovider.ErrEventDeliveryConflict
	}
	store.subscriptions[record.EventID] = record
	return nil
}

func (store *providerEventStore) AcceptEvent(_ context.Context, delivery agentprovider.EventDelivery) (agentprovider.EventAcceptance, error) {
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
	if delivery.Fingerprint != events.Fingerprint(delivery.Token, delivery.ContentType, delivery.Payload) {
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventDeliveryConflict
	}
	if retained, ok := store.deliveries[delivery.Fingerprint]; ok {
		if retained.TokenSHA256 != delivery.TokenSHA256 || retained.PayloadSHA256 != delivery.PayloadSHA256 ||
			retained.ContentType != delivery.ContentType {
			return agentprovider.EventAcceptance{}, agentprovider.ErrEventDeliveryConflict
		}
		accepted := store.acceptances[delivery.Fingerprint]
		accepted.Duplicate = true
		return accepted, nil
	}
	if subscription.MaxUses > 0 && store.uses[delivery.EventID] >= subscription.MaxUses {
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventUsesExceeded
	}
	delivery.Payload = append([]byte(nil), delivery.Payload...)
	store.deliveries[delivery.Fingerprint] = delivery
	store.order[delivery.EventID] = append(store.order[delivery.EventID], delivery.Fingerprint)
	store.uses[delivery.EventID]++
	remaining := int64(0)
	if subscription.MaxUses > 0 {
		remaining = subscription.MaxUses - store.uses[delivery.EventID]
	}
	accepted := agentprovider.EventAcceptance{MaximumUses: subscription.MaxUses, RemainingUses: remaining}
	store.acceptances[delivery.Fingerprint] = accepted
	return accepted, nil
}

// deliveryFor reads one accepted delivery by fingerprint, as the host's
// AP-to-Agent transport would, returning an independent copy of its exact
// token and payload.
func (store *providerEventStore) deliveryFor(fingerprint events.DeliveryFingerprint) (agentprovider.EventDelivery, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	delivery, ok := store.deliveries[fingerprint]
	if !ok {
		return agentprovider.EventDelivery{}, errors.New("events example: Agent Provider has no such delivery")
	}
	delivery.Payload = append([]byte(nil), delivery.Payload...)
	return delivery, nil
}

func (store *providerEventStore) Delivery(eventID string) (agentprovider.EventDelivery, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	order := store.order[eventID]
	if len(order) == 0 {
		return agentprovider.EventDelivery{}, errors.New("events example: Agent Provider has no accepted delivery")
	}
	delivery := store.deliveries[order[len(order)-1]]
	delivery.Payload = append([]byte(nil), delivery.Payload...)
	return delivery, nil
}

type resourceEventStore struct {
	mu      sync.Mutex
	records map[string]resource.EventSubscription
	tickets map[string]resource.ProtectedSubscriptionTicket
}

func newResourceEventStore() *resourceEventStore {
	return &resourceEventStore{
		records: make(map[string]resource.EventSubscription),
		tickets: make(map[string]resource.ProtectedSubscriptionTicket),
	}
}

func (store *resourceEventStore) CreateProtectedSubscriptionTicket(
	_ context.Context,
	ticket resource.ProtectedSubscriptionTicket,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.tickets[ticket.ID]; exists {
		return resource.ErrProtectedSubscriptionConflict
	}
	store.tickets[ticket.ID] = cloneProtectedTicket(ticket)
	return nil
}

func (store *resourceEventStore) LoadProtectedSubscriptionTicket(
	_ context.Context,
	id string,
	keyThumbprint string,
	at time.Time,
) (resource.ProtectedSubscriptionTicket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ticket, exists := store.tickets[id]
	if !exists || ticket.KeyThumbprint != keyThumbprint {
		return resource.ProtectedSubscriptionTicket{}, resource.ErrProtectedSubscriptionNotFound
	}
	if !at.Before(ticket.ExpiresAt) && ticket.UsedAt.IsZero() {
		return resource.ProtectedSubscriptionTicket{}, resource.ErrProtectedSubscriptionExpired
	}
	return cloneProtectedTicket(ticket), nil
}

func (store *resourceEventStore) CommitProtectedSubscription(
	_ context.Context,
	expected resource.ProtectedSubscriptionTicket,
	candidate resource.EventSubscription,
) (resource.EventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ticket, exists := store.tickets[expected.ID]
	if !exists || !reflect.DeepEqual(ticket, expected) {
		return resource.EventSubscription{}, resource.ErrProtectedSubscriptionConflict
	}
	key := candidate.AgentProvider + "\x00" + candidate.EventID
	if retained, exists := store.records[key]; exists {
		if retained.RegistrationSHA256 == candidate.RegistrationSHA256 &&
			ticket.RegistrationSHA256 == candidate.RegistrationSHA256 {
			return cloneResourceEventSubscription(retained), nil
		}
		return resource.EventSubscription{}, resource.ErrProtectedSubscriptionConflict
	}
	if !ticket.UsedAt.IsZero() || ticket.RegistrationSHA256 != [32]byte{} ||
		!candidate.RegisteredAt.Before(ticket.ExpiresAt) {
		return resource.EventSubscription{}, resource.ErrProtectedSubscriptionConflict
	}
	store.records[key] = cloneResourceEventSubscription(candidate)
	ticket.UsedAt = candidate.RegisteredAt
	ticket.RegistrationSHA256 = candidate.RegistrationSHA256
	store.tickets[ticket.ID] = cloneProtectedTicket(ticket)
	return cloneResourceEventSubscription(candidate), nil
}

func (store *resourceEventStore) Commit(_ context.Context, record resource.EventSubscription) (resource.EventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.AgentProvider + "\x00" + record.EventID
	if retained, ok := store.records[key]; ok {
		if retained.RegistrationSHA256 == record.RegistrationSHA256 {
			return cloneResourceEventSubscription(retained), nil
		}
		return resource.EventSubscription{}, resource.ErrEventSubscriptionConflict
	}
	store.records[key] = cloneResourceEventSubscription(record)
	return cloneResourceEventSubscription(record), nil
}

func (store *resourceEventStore) Load(_ context.Context, ref resource.EventSubscriptionRef) (resource.EventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[ref.AgentProvider+"\x00"+ref.EventID]
	if !ok {
		return resource.EventSubscription{}, resource.ErrEventSubscriptionNotFound
	}
	return cloneResourceEventSubscription(record), nil
}

func cloneResourceEventSubscription(record resource.EventSubscription) resource.EventSubscription {
	record.Parameters = append([]byte(nil), record.Parameters...)
	return record
}

func cloneProtectedTicket(ticket resource.ProtectedSubscriptionTicket) resource.ProtectedSubscriptionTicket {
	ticket.Context = append([]byte(nil), ticket.Context...)
	return ticket
}

var _ resource.ProtectedSubscriptionStore = (*resourceEventStore)(nil)

type agentEventStore struct {
	mu       sync.Mutex
	contexts map[string]clientagent.EventContext
	events   map[events.DeliveryFingerprint]clientagent.AcceptedEvent
}

func newAgentEventStore() *agentEventStore {
	return &agentEventStore{
		contexts: make(map[string]clientagent.EventContext),
		events:   make(map[events.DeliveryFingerprint]clientagent.AcceptedEvent),
	}
}

func (store *agentEventStore) BindContext(_ context.Context, record clientagent.EventContext) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.Resource + "\x00" + record.EventID
	if retained, ok := store.contexts[key]; ok {
		if retained.SubscribeTokenSHA256 == record.SubscribeTokenSHA256 && bytes.Equal(retained.Context, record.Context) {
			return nil
		}
		return clientagent.ErrEventContextConflict
	}
	record.Context = append([]byte(nil), record.Context...)
	store.contexts[key] = record
	return nil
}

func (store *agentEventStore) AcceptEvent(_ context.Context, candidate clientagent.AcceptedEvent) (clientagent.EventAcceptance, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	contextRecord, ok := store.contexts[candidate.Resource+"\x00"+candidate.EventID]
	if !ok {
		return clientagent.EventAcceptance{}, clientagent.ErrEventContextNotFound
	}
	if retained, ok := store.events[candidate.Fingerprint]; ok {
		if retained.EventToken != candidate.EventToken || !bytes.Equal(retained.Payload, candidate.Payload) ||
			retained.ContentType != candidate.ContentType {
			return clientagent.EventAcceptance{}, clientagent.ErrEventReplayConflict
		}
		contextRecord.Context = append([]byte(nil), contextRecord.Context...)
		return clientagent.EventAcceptance{Context: contextRecord, Duplicate: true}, nil
	}
	candidate.Payload = append([]byte(nil), candidate.Payload...)
	store.events[candidate.Fingerprint] = candidate
	contextRecord.Context = append([]byte(nil), contextRecord.Context...)
	return clientagent.EventAcceptance{Context: contextRecord}, nil
}
