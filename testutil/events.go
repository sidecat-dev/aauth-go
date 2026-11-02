package testutil

import (
	"context"
	"reflect"
	"slices"
	"sync"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

// EventInboxStore is an Agent Provider's subscription and accepted-delivery
// state with the read path to its Agents. AcceptEvent compares the delivery
// with the subscription's Resource and Agent, enforces max_uses atomically,
// and retains the exact token, content type and payload that PendingEvents
// later hands over.
type EventInboxStore interface {
	agentprovider.EventInboxStore
	agentprovider.EventInboxReader
	// LoadDelivery is a read-only observation for storetest fixtures. It
	// returns an independent copy of one accepted delivery.
	LoadDelivery(events.DeliveryFingerprint) (agentprovider.EventDelivery, bool)
}

// NewEventInboxStore returns an empty, concurrency-safe in-memory Agent
// Provider Events store.
func NewEventInboxStore() EventInboxStore {
	return &eventInboxStore{
		subscriptions: make(map[string]agentprovider.EventSubscription),
		deliveries:    make(map[events.DeliveryFingerprint]agentprovider.EventDelivery),
		acceptances:   make(map[events.DeliveryFingerprint]agentprovider.EventAcceptance),
		pending:       make(map[string][]events.DeliveryFingerprint),
		uses:          make(map[string]int64),
	}
}

type eventInboxStore struct {
	mu            sync.Mutex
	subscriptions map[string]agentprovider.EventSubscription
	deliveries    map[events.DeliveryFingerprint]agentprovider.EventDelivery
	acceptances   map[events.DeliveryFingerprint]agentprovider.EventAcceptance
	pending       map[string][]events.DeliveryFingerprint
	uses          map[string]int64
}

func (store *eventInboxStore) CommitSubscription(_ context.Context, record agentprovider.EventSubscription) error {
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

func (store *eventInboxStore) AcceptEvent(_ context.Context, delivery agentprovider.EventDelivery) (agentprovider.EventAcceptance, error) {
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
	store.pending[delivery.Agent] = append(store.pending[delivery.Agent], delivery.Fingerprint)
	store.uses[delivery.EventID]++
	remaining := int64(0)
	if subscription.MaxUses > 0 {
		remaining = subscription.MaxUses - store.uses[delivery.EventID]
	}
	accepted := agentprovider.EventAcceptance{MaximumUses: subscription.MaxUses, RemainingUses: remaining}
	store.acceptances[delivery.Fingerprint] = accepted
	return accepted, nil
}

func (store *eventInboxStore) LoadDelivery(fingerprint events.DeliveryFingerprint) (agentprovider.EventDelivery, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	delivery, ok := store.deliveries[fingerprint]
	delivery.Payload = append([]byte(nil), delivery.Payload...)
	return delivery, ok
}

// PendingEvents returns the deliveries accepted for agent and not yet
// acknowledged, oldest first.
func (store *eventInboxStore) PendingEvents(_ context.Context, agent string) ([]agentprovider.EventDelivery, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	pending := make([]agentprovider.EventDelivery, 0, len(store.pending[agent]))
	for _, fingerprint := range store.pending[agent] {
		delivery := store.deliveries[fingerprint]
		delivery.Payload = append([]byte(nil), delivery.Payload...)
		pending = append(pending, delivery)
	}
	return pending, nil
}

// AcknowledgeEvent drops one handed-over delivery from agent's pending list.
// The delivery stays known, so an exact replay is still a duplicate.
func (store *eventInboxStore) AcknowledgeEvent(_ context.Context, agent string, fingerprint events.DeliveryFingerprint) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.pending[agent] = slices.DeleteFunc(store.pending[agent], func(candidate events.DeliveryFingerprint) bool {
		return candidate == fingerprint
	})
	return nil
}

// NewProtectedEventStore returns an empty, concurrency-safe in-memory Resource
// Events store for public and protected subscriptions. A ticket is loaded
// only for the key it is bound to, and CommitProtectedSubscription consumes
// it: a later registration with other input is
// resource.ErrProtectedSubscriptionConflict, while an exact repeat returns the
// retained subscription.
func NewProtectedEventStore() resource.ProtectedSubscriptionStore {
	return &protectedEventStore{
		records: make(map[resource.EventSubscriptionRef]resource.EventSubscription),
		tickets: make(map[string]resource.ProtectedSubscriptionTicket),
	}
}

type protectedEventStore struct {
	mu      sync.Mutex
	records map[resource.EventSubscriptionRef]resource.EventSubscription
	tickets map[string]resource.ProtectedSubscriptionTicket
}

func (store *protectedEventStore) CreateProtectedSubscriptionTicket(_ context.Context, ticket resource.ProtectedSubscriptionTicket) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.tickets[ticket.ID]; exists {
		return resource.ErrProtectedSubscriptionConflict
	}
	store.tickets[ticket.ID] = cloneProtectedTicket(ticket)
	return nil
}

func (store *protectedEventStore) LoadProtectedSubscriptionTicket(
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

func (store *protectedEventStore) CommitProtectedSubscription(
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
	ref := resource.EventSubscriptionRef{AgentProvider: candidate.AgentProvider, EventID: candidate.EventID}
	if retained, exists := store.records[ref]; exists {
		if retained.RegistrationSHA256 == candidate.RegistrationSHA256 &&
			ticket.RegistrationSHA256 == candidate.RegistrationSHA256 {
			return cloneEventSubscription(retained), nil
		}
		return resource.EventSubscription{}, resource.ErrProtectedSubscriptionConflict
	}
	if !ticket.UsedAt.IsZero() || ticket.RegistrationSHA256 != [32]byte{} ||
		!candidate.RegisteredAt.Before(ticket.ExpiresAt) {
		return resource.EventSubscription{}, resource.ErrProtectedSubscriptionConflict
	}
	store.records[ref] = cloneEventSubscription(candidate)
	ticket.UsedAt = candidate.RegisteredAt
	ticket.RegistrationSHA256 = candidate.RegistrationSHA256
	store.tickets[ticket.ID] = cloneProtectedTicket(ticket)
	return cloneEventSubscription(candidate), nil
}

func (store *protectedEventStore) Commit(_ context.Context, record resource.EventSubscription) (resource.EventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ref := resource.EventSubscriptionRef{AgentProvider: record.AgentProvider, EventID: record.EventID}
	if retained, ok := store.records[ref]; ok {
		if retained.RegistrationSHA256 == record.RegistrationSHA256 {
			return cloneEventSubscription(retained), nil
		}
		return resource.EventSubscription{}, resource.ErrEventSubscriptionConflict
	}
	store.records[ref] = cloneEventSubscription(record)
	return cloneEventSubscription(record), nil
}

func (store *protectedEventStore) Load(_ context.Context, ref resource.EventSubscriptionRef) (resource.EventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[ref]
	if !ok {
		return resource.EventSubscription{}, resource.ErrEventSubscriptionNotFound
	}
	return cloneEventSubscription(record), nil
}

func cloneEventSubscription(record resource.EventSubscription) resource.EventSubscription {
	record.Parameters = append([]byte(nil), record.Parameters...)
	return record
}

func cloneProtectedTicket(ticket resource.ProtectedSubscriptionTicket) resource.ProtectedSubscriptionTicket {
	ticket.Context = append([]byte(nil), ticket.Context...)
	return ticket
}
