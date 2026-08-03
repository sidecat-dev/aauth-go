package reference

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

var (
	// ErrEventRecordInvalid means a store input does not satisfy the durable
	// Events record contract.
	ErrEventRecordInvalid = errors.New("reference: event record is invalid")
	// ErrEventSubscriptionNotFound includes subscriptions that are unknown or
	// no longer active at the supplied acceptance time.
	ErrEventSubscriptionNotFound = errors.New("reference: event subscription was not found")
	// ErrEventSubscriptionConflict prevents an existing subscription identity
	// from being replaced or extended.
	ErrEventSubscriptionConflict = errors.New("reference: event subscription identity collided")
	// ErrEventSubscriptionMismatch means an event does not match the resource
	// and agent bound by its subscription.
	ErrEventSubscriptionMismatch = errors.New("reference: event subscription binding does not match")
	// ErrEventSubscriptionExhausted means the subscription has no remaining
	// uses. It is stable so the AP HTTP surface can map it to status 429.
	ErrEventSubscriptionExhausted = errors.New("reference: event subscription is exhausted")
	// ErrNoPendingEventDelivery means the AP inbox has no work to continue.
	ErrNoPendingEventDelivery = errors.New("reference: no pending event delivery")
	// ErrEventDeliveryNotFound means an AP inbox delivery cannot be acknowledged.
	ErrEventDeliveryNotFound = errors.New("reference: event delivery was not found")
	// ErrEventPendingNotFound means the resource has no retained event attempt
	// for the requested subscription.
	ErrEventPendingNotFound = errors.New("reference: pending event delivery was not found")
	// ErrEventPendingConflict prevents different exact tokens from occupying one
	// resource delivery identity.
	ErrEventPendingConflict = errors.New("reference: pending event delivery identity collided")
	// ErrEventContextNotFound means no local context is mapped to the AP event.
	ErrEventContextNotFound = errors.New("reference: agent event context was not found")
	// ErrEventContextConflict prevents an existing local mapping from changing.
	ErrEventContextConflict = errors.New("reference: agent event context identity collided")
	// ErrEventProcessingNotFound means no processing record exists for an action.
	ErrEventProcessingNotFound = errors.New("reference: agent event processing was not found")
	// ErrEventProcessingConflict means an action or trusted delivery identity is
	// already bound to different processing work.
	ErrEventProcessingConflict = errors.New("reference: agent event processing identity collided")
	// ErrEventProcessingTransition means the requested state change would hide
	// or regress an already recorded consequence.
	ErrEventProcessingTransition = errors.New("reference: agent event processing transition is invalid")
	// ErrEventDispositionNotFound means the trusted delivery key has no durable
	// processing disposition.
	ErrEventDispositionNotFound = errors.New("reference: agent event disposition was not found")
)

type APEventSubscription struct {
	APIssuer    string    `json:"ap_issuer"`
	EventID     string    `json:"event_id"`
	Resource    string    `json:"resource"`
	Agent       string    `json:"agent"`
	ActiveUntil time.Time `json:"active_until"`
	MaxUses     int       `json:"max_uses"`
	UseCount    int       `json:"use_count"`
}

type AcceptedEventInput struct {
	Resource   string    `json:"resource"`
	Agent      string    `json:"agent"`
	EventID    string    `json:"event_id"`
	Token      string    `json:"token"`
	AcceptedAt time.Time `json:"accepted_at"`
}

type AcceptedEvent struct {
	Delivery   EventDeliveryKey `json:"delivery"`
	APIssuer   string           `json:"ap_issuer"`
	Token      string           `json:"token"`
	AcceptedAt time.Time        `json:"accepted_at"`
}

type ResourceEventSubscription struct {
	APIssuer    string    `json:"ap_issuer"`
	EventID     string    `json:"event_id"`
	Resource    string    `json:"resource"`
	Agent       string    `json:"agent"`
	ActiveUntil time.Time `json:"active_until"`
}

type PendingEventDelivery struct {
	APIssuer  string    `json:"ap_issuer"`
	EventID   string    `json:"event_id"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
}

type AgentEventContext struct {
	APIssuer string          `json:"ap_issuer"`
	EventID  string          `json:"event_id"`
	Value    json.RawMessage `json:"value"`
}

type EventActionKey struct {
	ResourceIssuer string `json:"resource_issuer"`
	APIssuer       string `json:"ap_issuer"`
	EventID        string `json:"event_id"`
}

type EventProcessingState string

const (
	EventPending    EventProcessingState = "pending"
	EventDispatched EventProcessingState = "dispatched"
	EventCompleted  EventProcessingState = "completed"
	EventRefused    EventProcessingState = "refused"
)

type EventRefusalReason string

const (
	EventRefusalInvalid        EventRefusalReason = "invalid"
	EventRefusalExpired        EventRefusalReason = "expired"
	EventRefusalUnknownContext EventRefusalReason = "unknown_context"
	EventRefusalNotApplied     EventRefusalReason = "not_applied"
)

type AgentEventProcessing struct {
	Delivery  EventDeliveryKey     `json:"delivery"`
	Action    EventActionKey       `json:"action"`
	State     EventProcessingState `json:"state"`
	ExpiresAt time.Time            `json:"expires_at"`
}

type EventDeliveryKey struct {
	APIssuer    string `json:"ap_issuer"`
	DeliveryID  string `json:"delivery_id"`
	TokenDigest string `json:"token_digest"`
}

type EventActionInput struct {
	Key     EventActionKey         `json:"key"`
	Context AgentEventContext      `json:"context"`
	Event   aauth.EventTokenClaims `json:"event"`
}

type EventActionOutcome string

const (
	EventActionCompleted  EventActionOutcome = "completed"
	EventActionNotApplied EventActionOutcome = "not_applied"
	EventActionUnknown    EventActionOutcome = "unknown"
)

type APEventStore interface {
	CreateSubscription(context.Context, APEventSubscription) error
	AcceptEvent(context.Context, AcceptedEventInput) (AcceptedEvent, int, error)
	NextDelivery(context.Context) (AcceptedEvent, error)
	AcknowledgeDelivery(context.Context, string) error
}

type ResourceEventStore interface {
	Register(context.Context, ResourceEventSubscription) error
	Load(context.Context, string, string) (ResourceEventSubscription, error)
	RetainPending(context.Context, PendingEventDelivery) error
	LoadPending(context.Context, string, string) (PendingEventDelivery, error)
	CompletePending(context.Context, string, string) error
}

type AgentEventStore interface {
	PutContext(context.Context, AgentEventContext) error
	LookupContext(context.Context, string, string) (AgentEventContext, error)
	AdmitProcessing(context.Context, AgentEventProcessing) error
	MarkDispatched(context.Context, EventActionKey) error
	MarkCompleted(context.Context, EventActionKey) error
	MarkRefused(context.Context, EventDeliveryKey, EventRefusalReason) error
	LoadProcessing(context.Context, EventActionKey) (AgentEventProcessing, error)
	LoadDisposition(context.Context, EventDeliveryKey) (EventProcessingState, error)
}

type EventAction interface {
	Dispatch(context.Context, EventActionInput) (EventActionOutcome, error)
	Reconcile(context.Context, EventActionKey) (EventActionOutcome, error)
}

type eventSubscriptionKey struct {
	APIssuer string
	EventID  string
}

// MemoryAPEventStore is a process-local qualification implementation of the
// same atomic authority contract implemented by durable deployment stores.
type MemoryAPEventStore struct {
	mu            sync.Mutex
	issuer        string
	nextDelivery  uint64
	subscriptions map[string]APEventSubscription
	inbox         map[string]AcceptedEvent
	inboxOrder    []string
}

func NewMemoryAPEventStore(issuer string) *MemoryAPEventStore {
	return &MemoryAPEventStore{
		issuer:        issuer,
		subscriptions: make(map[string]APEventSubscription),
		inbox:         make(map[string]AcceptedEvent),
	}
}

func (store *MemoryAPEventStore) CreateSubscription(
	ctx context.Context,
	subscription APEventSubscription,
) error {
	if err := eventContextError(ctx); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("%w: AP event store is required", ErrEventRecordInvalid)
	}
	if err := validateAPEventSubscription(subscription); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.issuer == "" || subscription.APIssuer != store.issuer {
		return fmt.Errorf("%w: AP issuer does not match store authority", ErrEventRecordInvalid)
	}
	if store.subscriptions == nil {
		store.subscriptions = make(map[string]APEventSubscription)
	}
	if _, exists := store.subscriptions[subscription.EventID]; exists {
		return ErrEventSubscriptionConflict
	}
	store.subscriptions[subscription.EventID] = subscription
	return nil
}

func (store *MemoryAPEventStore) AcceptEvent(
	ctx context.Context,
	input AcceptedEventInput,
) (AcceptedEvent, int, error) {
	var zero AcceptedEvent
	if err := eventContextError(ctx); err != nil {
		return zero, 0, err
	}
	if store == nil {
		return zero, 0, fmt.Errorf("%w: AP event store is required", ErrEventRecordInvalid)
	}
	if err := validateAcceptedEventInput(input); err != nil {
		return zero, 0, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	subscription, exists := store.subscriptions[input.EventID]
	if !exists || !subscription.ActiveUntil.After(input.AcceptedAt) {
		return zero, 0, ErrEventSubscriptionNotFound
	}
	if subscription.Resource != input.Resource || subscription.Agent != input.Agent {
		return zero, 0, ErrEventSubscriptionMismatch
	}
	if subscription.UseCount >= subscription.MaxUses {
		return zero, 0, ErrEventSubscriptionExhausted
	}

	// The final-use check, increment, unique delivery allocation, and exact
	// token inbox insert are one lock-protected transaction boundary.
	subscription.UseCount++
	store.nextDelivery++
	deliveryID := "event-delivery-" + strconv.FormatUint(store.nextDelivery, 10)
	digest := sha256.Sum256([]byte(input.Token))
	accepted := AcceptedEvent{
		Delivery: EventDeliveryKey{
			APIssuer:    store.issuer,
			DeliveryID:  deliveryID,
			TokenDigest: base64.RawURLEncoding.EncodeToString(digest[:]),
		},
		APIssuer:   store.issuer,
		Token:      input.Token,
		AcceptedAt: input.AcceptedAt.UTC(),
	}
	if store.inbox == nil {
		store.inbox = make(map[string]AcceptedEvent)
	}
	store.subscriptions[input.EventID] = subscription
	store.inbox[deliveryID] = accepted
	store.inboxOrder = append(store.inboxOrder, deliveryID)
	return accepted, subscription.MaxUses - subscription.UseCount, nil
}

func (store *MemoryAPEventStore) NextDelivery(ctx context.Context) (AcceptedEvent, error) {
	var zero AcceptedEvent
	if err := eventContextError(ctx); err != nil {
		return zero, err
	}
	if store == nil {
		return zero, fmt.Errorf("%w: AP event store is required", ErrEventRecordInvalid)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, deliveryID := range store.inboxOrder {
		if accepted, exists := store.inbox[deliveryID]; exists {
			return accepted, nil
		}
	}
	return zero, ErrNoPendingEventDelivery
}

func (store *MemoryAPEventStore) AcknowledgeDelivery(ctx context.Context, deliveryID string) error {
	if err := eventContextError(ctx); err != nil {
		return err
	}
	if store == nil || deliveryID == "" {
		return fmt.Errorf("%w: AP delivery identity is invalid", ErrEventRecordInvalid)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.inbox[deliveryID]; !exists {
		return ErrEventDeliveryNotFound
	}
	delete(store.inbox, deliveryID)
	return nil
}

// MemoryResourceEventStore is a process-local resource authority. The
// subscription and pending maps are always mutated under one lock.
type MemoryResourceEventStore struct {
	mu            sync.Mutex
	subscriptions map[eventSubscriptionKey]ResourceEventSubscription
	pending       map[eventSubscriptionKey]PendingEventDelivery
}

func NewMemoryResourceEventStore() *MemoryResourceEventStore {
	return &MemoryResourceEventStore{
		subscriptions: make(map[eventSubscriptionKey]ResourceEventSubscription),
		pending:       make(map[eventSubscriptionKey]PendingEventDelivery),
	}
}

func (store *MemoryResourceEventStore) Register(
	ctx context.Context,
	subscription ResourceEventSubscription,
) error {
	if err := eventContextError(ctx); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("%w: resource event store is required", ErrEventRecordInvalid)
	}
	if err := validateResourceEventSubscription(subscription); err != nil {
		return err
	}
	key := eventSubscriptionKey{APIssuer: subscription.APIssuer, EventID: subscription.EventID}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.subscriptions == nil {
		store.subscriptions = make(map[eventSubscriptionKey]ResourceEventSubscription)
	}
	if _, exists := store.subscriptions[key]; exists {
		return ErrEventSubscriptionConflict
	}
	store.subscriptions[key] = subscription
	return nil
}

func (store *MemoryResourceEventStore) Load(
	ctx context.Context,
	apIssuer string,
	eventID string,
) (ResourceEventSubscription, error) {
	var zero ResourceEventSubscription
	if err := eventContextError(ctx); err != nil {
		return zero, err
	}
	if store == nil || validateEventSubscriptionKey(apIssuer, eventID) != nil {
		return zero, fmt.Errorf("%w: resource subscription identity is invalid", ErrEventRecordInvalid)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	subscription, exists := store.subscriptions[eventSubscriptionKey{APIssuer: apIssuer, EventID: eventID}]
	if !exists {
		return zero, ErrEventSubscriptionNotFound
	}
	return subscription, nil
}

func (store *MemoryResourceEventStore) RetainPending(
	ctx context.Context,
	pending PendingEventDelivery,
) error {
	if err := eventContextError(ctx); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("%w: resource event store is required", ErrEventRecordInvalid)
	}
	if err := validatePendingEventDelivery(pending); err != nil {
		return err
	}
	key := eventSubscriptionKey{APIssuer: pending.APIssuer, EventID: pending.EventID}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.subscriptions[key]; !exists {
		return ErrEventSubscriptionNotFound
	}
	if existing, exists := store.pending[key]; exists {
		if exactPendingEvent(existing, pending) {
			return nil
		}
		return ErrEventPendingConflict
	}
	if store.pending == nil {
		store.pending = make(map[eventSubscriptionKey]PendingEventDelivery)
	}
	store.pending[key] = pending
	return nil
}

func (store *MemoryResourceEventStore) LoadPending(
	ctx context.Context,
	apIssuer string,
	eventID string,
) (PendingEventDelivery, error) {
	var zero PendingEventDelivery
	if err := eventContextError(ctx); err != nil {
		return zero, err
	}
	if store == nil || validateEventSubscriptionKey(apIssuer, eventID) != nil {
		return zero, fmt.Errorf("%w: pending event identity is invalid", ErrEventRecordInvalid)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	pending, exists := store.pending[eventSubscriptionKey{APIssuer: apIssuer, EventID: eventID}]
	if !exists {
		return zero, ErrEventPendingNotFound
	}
	return pending, nil
}

func (store *MemoryResourceEventStore) CompletePending(
	ctx context.Context,
	apIssuer string,
	eventID string,
) error {
	if err := eventContextError(ctx); err != nil {
		return err
	}
	if store == nil || validateEventSubscriptionKey(apIssuer, eventID) != nil {
		return fmt.Errorf("%w: resource subscription identity is invalid", ErrEventRecordInvalid)
	}
	key := eventSubscriptionKey{APIssuer: apIssuer, EventID: eventID}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.pending[key]; !exists {
		return ErrEventPendingNotFound
	}
	delete(store.pending, key)
	delete(store.subscriptions, key)
	return nil
}

// MemoryAgentEventStore is a process-local agent authority. Processing is
// indexed separately by the trusted action and delivery identities so
// unverified token claims never determine refusal deduplication.
type MemoryAgentEventStore struct {
	mu            sync.Mutex
	contexts      map[eventSubscriptionKey]AgentEventContext
	processing    map[EventActionKey]AgentEventProcessing
	dispositions  map[EventDeliveryKey]EventProcessingState
	refusalReason map[EventDeliveryKey]EventRefusalReason
	deliveryOwner map[EventDeliveryKey]EventActionKey
}

func NewMemoryAgentEventStore() *MemoryAgentEventStore {
	return &MemoryAgentEventStore{
		contexts:      make(map[eventSubscriptionKey]AgentEventContext),
		processing:    make(map[EventActionKey]AgentEventProcessing),
		dispositions:  make(map[EventDeliveryKey]EventProcessingState),
		refusalReason: make(map[EventDeliveryKey]EventRefusalReason),
		deliveryOwner: make(map[EventDeliveryKey]EventActionKey),
	}
}

func (store *MemoryAgentEventStore) PutContext(ctx context.Context, value AgentEventContext) error {
	if err := eventContextError(ctx); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("%w: agent event store is required", ErrEventRecordInvalid)
	}
	if err := validateAgentEventContext(value); err != nil {
		return err
	}
	value.Value = cloneRawMessage(value.Value)
	key := eventSubscriptionKey{APIssuer: value.APIssuer, EventID: value.EventID}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.contexts == nil {
		store.contexts = make(map[eventSubscriptionKey]AgentEventContext)
	}
	if existing, exists := store.contexts[key]; exists {
		if subtle.ConstantTimeCompare(existing.Value, value.Value) == 1 {
			return nil
		}
		return ErrEventContextConflict
	}
	store.contexts[key] = value
	return nil
}

func (store *MemoryAgentEventStore) LookupContext(
	ctx context.Context,
	apIssuer string,
	eventID string,
) (AgentEventContext, error) {
	var zero AgentEventContext
	if err := eventContextError(ctx); err != nil {
		return zero, err
	}
	if store == nil || validateEventSubscriptionKey(apIssuer, eventID) != nil {
		return zero, fmt.Errorf("%w: agent context identity is invalid", ErrEventRecordInvalid)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.contexts[eventSubscriptionKey{APIssuer: apIssuer, EventID: eventID}]
	if !exists {
		return zero, ErrEventContextNotFound
	}
	value.Value = cloneRawMessage(value.Value)
	return value, nil
}

func (store *MemoryAgentEventStore) AdmitProcessing(
	ctx context.Context,
	processing AgentEventProcessing,
) error {
	if err := eventContextError(ctx); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("%w: agent event store is required", ErrEventRecordInvalid)
	}
	if err := validateAgentEventProcessing(processing); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, exists := store.processing[processing.Action]; exists {
		if existing == processing {
			return nil
		}
		return ErrEventProcessingConflict
	}
	if existingAction, exists := store.deliveryOwner[processing.Delivery]; exists && existingAction != processing.Action {
		return ErrEventProcessingConflict
	}
	if existingState, exists := store.dispositions[processing.Delivery]; exists && existingState != EventPending {
		return ErrEventProcessingConflict
	}
	if store.processing == nil {
		store.processing = make(map[EventActionKey]AgentEventProcessing)
	}
	if store.deliveryOwner == nil {
		store.deliveryOwner = make(map[EventDeliveryKey]EventActionKey)
	}
	if store.dispositions == nil {
		store.dispositions = make(map[EventDeliveryKey]EventProcessingState)
	}
	store.processing[processing.Action] = processing
	store.deliveryOwner[processing.Delivery] = processing.Action
	store.dispositions[processing.Delivery] = EventPending
	return nil
}

func (store *MemoryAgentEventStore) MarkDispatched(ctx context.Context, key EventActionKey) error {
	return store.transitionProcessing(ctx, key, EventPending, EventDispatched)
}

func (store *MemoryAgentEventStore) MarkCompleted(ctx context.Context, key EventActionKey) error {
	return store.transitionProcessing(ctx, key, EventDispatched, EventCompleted)
}

func (store *MemoryAgentEventStore) MarkRefused(
	ctx context.Context,
	delivery EventDeliveryKey,
	reason EventRefusalReason,
) error {
	if err := eventContextError(ctx); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("%w: agent event store is required", ErrEventRecordInvalid)
	}
	if err := validateEventDeliveryKey(delivery); err != nil || !validEventRefusalReason(reason) {
		return fmt.Errorf("%w: refusal disposition is incomplete", ErrEventRecordInvalid)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, exists := store.dispositions[delivery]; exists {
		switch existing {
		case EventRefused:
			if store.refusalReason[delivery] == reason {
				return nil
			}
			return ErrEventProcessingConflict
		case EventCompleted:
			return ErrEventProcessingTransition
		case EventPending:
			if reason == EventRefusalNotApplied {
				return ErrEventProcessingTransition
			}
		case EventDispatched:
			if reason != EventRefusalNotApplied {
				return ErrEventProcessingTransition
			}
		}
	} else if reason == EventRefusalNotApplied {
		return ErrEventProcessingTransition
	}
	if action, exists := store.deliveryOwner[delivery]; exists {
		processing := store.processing[action]
		if processing.State != EventPending && processing.State != EventDispatched {
			return ErrEventProcessingTransition
		}
		processing.State = EventRefused
		store.processing[action] = processing
	}
	if store.dispositions == nil {
		store.dispositions = make(map[EventDeliveryKey]EventProcessingState)
	}
	if store.refusalReason == nil {
		store.refusalReason = make(map[EventDeliveryKey]EventRefusalReason)
	}
	store.dispositions[delivery] = EventRefused
	store.refusalReason[delivery] = reason
	return nil
}

func (store *MemoryAgentEventStore) LoadProcessing(
	ctx context.Context,
	key EventActionKey,
) (AgentEventProcessing, error) {
	var zero AgentEventProcessing
	if err := eventContextError(ctx); err != nil {
		return zero, err
	}
	if store == nil || validateEventActionKey(key) != nil {
		return zero, fmt.Errorf("%w: action identity is invalid", ErrEventRecordInvalid)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	processing, exists := store.processing[key]
	if !exists {
		return zero, ErrEventProcessingNotFound
	}
	return processing, nil
}

func (store *MemoryAgentEventStore) LoadDisposition(
	ctx context.Context,
	delivery EventDeliveryKey,
) (EventProcessingState, error) {
	if err := eventContextError(ctx); err != nil {
		return "", err
	}
	if store == nil || validateEventDeliveryKey(delivery) != nil {
		return "", fmt.Errorf("%w: delivery identity is invalid", ErrEventRecordInvalid)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	state, exists := store.dispositions[delivery]
	if !exists {
		return "", ErrEventDispositionNotFound
	}
	return state, nil
}

func (store *MemoryAgentEventStore) transitionProcessing(
	ctx context.Context,
	key EventActionKey,
	from EventProcessingState,
	to EventProcessingState,
) error {
	if err := eventContextError(ctx); err != nil {
		return err
	}
	if store == nil || validateEventActionKey(key) != nil {
		return fmt.Errorf("%w: action identity is invalid", ErrEventRecordInvalid)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	processing, exists := store.processing[key]
	if !exists {
		return ErrEventProcessingNotFound
	}
	if processing.State == to {
		return nil
	}
	if processing.State != from {
		return ErrEventProcessingTransition
	}
	processing.State = to
	store.processing[key] = processing
	store.dispositions[processing.Delivery] = to
	return nil
}

func validateAPEventSubscription(subscription APEventSubscription) error {
	if err := validateEventSubscriptionKey(subscription.APIssuer, subscription.EventID); err != nil {
		return err
	}
	if err := aauth.ValidateServerIdentifier(subscription.Resource); err != nil {
		return fmt.Errorf("%w: resource: %v", ErrEventRecordInvalid, err)
	}
	if err := aauth.ValidateAgentIdentifier(subscription.Agent); err != nil {
		return fmt.Errorf("%w: agent: %v", ErrEventRecordInvalid, err)
	}
	if subscription.ActiveUntil.IsZero() || subscription.MaxUses <= 0 || subscription.UseCount != 0 {
		return fmt.Errorf("%w: AP subscription policy is incomplete", ErrEventRecordInvalid)
	}
	return nil
}

func validateAcceptedEventInput(input AcceptedEventInput) error {
	if err := aauth.ValidateServerIdentifier(input.Resource); err != nil {
		return fmt.Errorf("%w: resource: %v", ErrEventRecordInvalid, err)
	}
	if err := aauth.ValidateAgentIdentifier(input.Agent); err != nil {
		return fmt.Errorf("%w: agent: %v", ErrEventRecordInvalid, err)
	}
	if input.EventID == "" || input.Token == "" || input.AcceptedAt.IsZero() {
		return fmt.Errorf("%w: accepted event is incomplete", ErrEventRecordInvalid)
	}
	return nil
}

func validateResourceEventSubscription(subscription ResourceEventSubscription) error {
	if err := validateEventSubscriptionKey(subscription.APIssuer, subscription.EventID); err != nil {
		return err
	}
	if err := aauth.ValidateServerIdentifier(subscription.Resource); err != nil {
		return fmt.Errorf("%w: resource: %v", ErrEventRecordInvalid, err)
	}
	if err := aauth.ValidateAgentIdentifier(subscription.Agent); err != nil {
		return fmt.Errorf("%w: agent: %v", ErrEventRecordInvalid, err)
	}
	if subscription.ActiveUntil.IsZero() {
		return fmt.Errorf("%w: resource subscription lifetime is required", ErrEventRecordInvalid)
	}
	return nil
}

func validatePendingEventDelivery(pending PendingEventDelivery) error {
	if err := validateEventSubscriptionKey(pending.APIssuer, pending.EventID); err != nil {
		return err
	}
	if pending.Token == "" || pending.CreatedAt.IsZero() {
		return fmt.Errorf("%w: pending event is incomplete", ErrEventRecordInvalid)
	}
	return nil
}

func validateAgentEventContext(value AgentEventContext) error {
	if err := validateEventSubscriptionKey(value.APIssuer, value.EventID); err != nil {
		return err
	}
	if len(value.Value) == 0 || !json.Valid(value.Value) {
		return fmt.Errorf("%w: agent event context must be valid JSON", ErrEventRecordInvalid)
	}
	return nil
}

func validateAgentEventProcessing(processing AgentEventProcessing) error {
	if err := validateEventDeliveryKey(processing.Delivery); err != nil {
		return err
	}
	if err := validateEventActionKey(processing.Action); err != nil {
		return err
	}
	if processing.Delivery.APIssuer != processing.Action.APIssuer ||
		processing.State != EventPending || processing.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: agent processing is incomplete", ErrEventRecordInvalid)
	}
	return nil
}

func validateEventDeliveryKey(delivery EventDeliveryKey) error {
	if err := aauth.ValidateServerIdentifier(delivery.APIssuer); err != nil {
		return fmt.Errorf("%w: AP issuer: %v", ErrEventRecordInvalid, err)
	}
	digest, err := base64.RawURLEncoding.DecodeString(delivery.TokenDigest)
	if delivery.DeliveryID == "" || len(digest) != sha256.Size || err != nil ||
		base64.RawURLEncoding.EncodeToString(digest) != delivery.TokenDigest {
		return fmt.Errorf("%w: trusted delivery identity is incomplete", ErrEventRecordInvalid)
	}
	return nil
}

func validateEventActionKey(key EventActionKey) error {
	if err := aauth.ValidateServerIdentifier(key.ResourceIssuer); err != nil {
		return fmt.Errorf("%w: resource issuer: %v", ErrEventRecordInvalid, err)
	}
	return validateEventSubscriptionKey(key.APIssuer, key.EventID)
}

func validateEventSubscriptionKey(apIssuer string, eventID string) error {
	if err := aauth.ValidateServerIdentifier(apIssuer); err != nil {
		return fmt.Errorf("%w: AP issuer: %v", ErrEventRecordInvalid, err)
	}
	if eventID == "" {
		return fmt.Errorf("%w: event identity is required", ErrEventRecordInvalid)
	}
	return nil
}

func validEventRefusalReason(reason EventRefusalReason) bool {
	switch reason {
	case EventRefusalInvalid, EventRefusalExpired, EventRefusalUnknownContext, EventRefusalNotApplied:
		return true
	default:
		return false
	}
}

func exactPendingEvent(left PendingEventDelivery, right PendingEventDelivery) bool {
	return left.APIssuer == right.APIssuer && left.EventID == right.EventID &&
		left.Token == right.Token && left.CreatedAt.Equal(right.CreatedAt)
}

func cloneRawMessage(value json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), value...)
}

func eventContextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrEventRecordInvalid)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

var (
	_ APEventStore       = (*MemoryAPEventStore)(nil)
	_ ResourceEventStore = (*MemoryResourceEventStore)(nil)
	_ AgentEventStore    = (*MemoryAgentEventStore)(nil)
)
