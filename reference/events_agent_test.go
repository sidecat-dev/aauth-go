package reference

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestAgentEventProcessingReconcilesDispatchedUnknownHonestly(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-events-key")
	store := NewMemoryAgentEventStore()
	putAgentEventTestContext(t, store, "event-one")
	action := &scriptedEventAction{
		dispatchOutcome:  EventActionUnknown,
		dispatchErr:      errors.New("test: dispatch result was lost"),
		reconcileOutcome: EventActionCompleted,
	}
	agent := newAgentEventTestAgent(t, store, action, resourceKey, clock)
	accepted, _ := acceptedAgentEventTest(t, resourceKey, now, "event-one", "delivery-one")

	state, err := agent.AcceptEvent(ctx, accepted)
	if err == nil || state != EventDispatched {
		t.Fatalf("first acceptance state/error = %q, %v, want dispatched/error", state, err)
	}
	processing, err := store.LoadProcessingByDelivery(ctx, accepted.Delivery)
	if err != nil || processing.State != EventDispatched {
		t.Fatalf("processing after unknown dispatch = %#v, %v", processing, err)
	}

	// Completion proof wins after expiry; expiry cannot erase a dispatched
	// consequence whose original result was unknown.
	now = now.Add(10 * time.Minute)
	agent = newAgentEventTestAgent(t, store, action, resourceKey, clock)
	if err := agent.ResumeEvents(ctx); err != nil {
		t.Fatal(err)
	}
	processing, err = store.LoadProcessingByDelivery(ctx, accepted.Delivery)
	if err != nil || processing.State != EventCompleted {
		t.Fatalf("processing after reconciliation = %#v, %v", processing, err)
	}
	state, err = agent.AcceptEvent(ctx, accepted)
	if err != nil || state != EventCompleted {
		t.Fatalf("terminal duplicate state/error = %q, %v", state, err)
	}
	if dispatches, reconciliations := action.counts(); dispatches != 1 || reconciliations != 1 {
		t.Fatalf("dispatch/reconcile counts = %d/%d, want 1/1", dispatches, reconciliations)
	}
}

func TestAgentEventProcessingResumesPendingAndProvenNotApplied(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	resourceKey := eventsProviderTestSigningKey(t, "resource-events-key")

	t.Run("durable pending dispatches after reconstruction", func(t *testing.T) {
		now := base
		clock := aauth.ClockFunc(func() time.Time { return now })
		store := NewMemoryAgentEventStore()
		putAgentEventTestContext(t, store, "event-pending")
		accepted, claims := acceptedAgentEventTest(t, resourceKey, now, "event-pending", "delivery-pending")
		admitAgentEventTestProcessing(t, store, accepted, claims)
		action := &scriptedEventAction{dispatchOutcome: EventActionCompleted}
		agent := newAgentEventTestAgent(t, store, action, resourceKey, clock)

		if err := agent.ResumeEvents(ctx); err != nil {
			t.Fatal(err)
		}
		state, err := store.LoadDisposition(ctx, accepted.Delivery)
		if err != nil || state != EventCompleted {
			t.Fatalf("pending resume disposition = %q, %v", state, err)
		}
		if dispatches, _ := action.counts(); dispatches != 1 {
			t.Fatalf("pending resume dispatches = %d, want 1", dispatches)
		}
	})

	t.Run("proven not applied retries only while unexpired", func(t *testing.T) {
		now := base
		clock := aauth.ClockFunc(func() time.Time { return now })
		store := NewMemoryAgentEventStore()
		putAgentEventTestContext(t, store, "event-retry")
		accepted, claims := acceptedAgentEventTest(t, resourceKey, now, "event-retry", "delivery-retry")
		admitAgentEventTestProcessing(t, store, accepted, claims)
		if claimed, err := store.BeginDispatch(ctx, eventActionKeyForTest(claims, accepted)); err != nil || !claimed {
			t.Fatalf("initial dispatch claim = %v, %v", claimed, err)
		}
		action := &scriptedEventAction{reconcileOutcome: EventActionNotApplied, dispatchOutcome: EventActionCompleted}
		agent := newAgentEventTestAgent(t, store, action, resourceKey, clock)

		if err := agent.ResumeEvents(ctx); err == nil {
			t.Fatal("retryable not-applied result was reported terminal")
		}
		processing, err := store.LoadProcessingByDelivery(ctx, accepted.Delivery)
		if err != nil || processing.State != EventPending {
			t.Fatalf("unexpired not-applied processing = %#v, %v", processing, err)
		}
		if err := agent.ResumeEvents(ctx); err != nil {
			t.Fatal(err)
		}
		state, err := store.LoadDisposition(ctx, accepted.Delivery)
		if err != nil || state != EventCompleted {
			t.Fatalf("retried processing disposition = %q, %v", state, err)
		}
		if dispatches, reconciliations := action.counts(); dispatches != 1 || reconciliations != 1 {
			t.Fatalf("retry dispatch/reconcile counts = %d/%d, want 1/1", dispatches, reconciliations)
		}
	})

	t.Run("proven not applied after expiry is refused", func(t *testing.T) {
		now := base
		clock := aauth.ClockFunc(func() time.Time { return now })
		store := NewMemoryAgentEventStore()
		putAgentEventTestContext(t, store, "event-expired")
		accepted, claims := acceptedAgentEventTest(t, resourceKey, now, "event-expired", "delivery-expired")
		admitAgentEventTestProcessing(t, store, accepted, claims)
		if claimed, err := store.BeginDispatch(ctx, eventActionKeyForTest(claims, accepted)); err != nil || !claimed {
			t.Fatalf("initial dispatch claim = %v, %v", claimed, err)
		}
		now = time.Unix(claims.ExpiresAt, 0)
		action := &scriptedEventAction{reconcileOutcome: EventActionNotApplied}
		agent := newAgentEventTestAgent(t, store, action, resourceKey, clock)

		if err := agent.ResumeEvents(ctx); err != nil {
			t.Fatal(err)
		}
		state, err := store.LoadDisposition(ctx, accepted.Delivery)
		if err != nil || state != EventRefused {
			t.Fatalf("expired not-applied disposition = %q, %v", state, err)
		}
		if dispatches, reconciliations := action.counts(); dispatches != 0 || reconciliations != 1 {
			t.Fatalf("expired dispatch/reconcile counts = %d/%d, want 0/1", dispatches, reconciliations)
		}
	})

	t.Run("unknown after expiry remains dispatched", func(t *testing.T) {
		now := base
		clock := aauth.ClockFunc(func() time.Time { return now })
		store := NewMemoryAgentEventStore()
		putAgentEventTestContext(t, store, "event-unknown")
		accepted, claims := acceptedAgentEventTest(t, resourceKey, now, "event-unknown", "delivery-unknown")
		admitAgentEventTestProcessing(t, store, accepted, claims)
		if claimed, err := store.BeginDispatch(ctx, eventActionKeyForTest(claims, accepted)); err != nil || !claimed {
			t.Fatalf("initial dispatch claim = %v, %v", claimed, err)
		}
		now = time.Unix(claims.ExpiresAt, 0).Add(time.Hour)
		action := &scriptedEventAction{reconcileOutcome: EventActionUnknown, reconcileErr: errors.New("test: still unknown")}
		agent := newAgentEventTestAgent(t, store, action, resourceKey, clock)

		if err := agent.ResumeEvents(ctx); err == nil {
			t.Fatal("unknown expired dispatch was reported terminal")
		}
		state, err := store.LoadDisposition(ctx, accepted.Delivery)
		if err != nil || state != EventDispatched {
			t.Fatalf("unknown expired disposition = %q, %v", state, err)
		}
	})
}

func TestAgentEventProcessingPersistsTerminalRefusalWithoutAction(t *testing.T) {
	base := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	resourceKey := eventsProviderTestSigningKey(t, "resource-events-key")

	for _, test := range []struct {
		name       string
		claims     aauth.EventTokenClaims
		advance    time.Duration
		corrupt    bool
		putContext bool
		wantReason EventRefusalReason
	}{
		{name: "forged expired claim is invalid", claims: agentEventTestClaims(base, "event-forged", "aauth:subscriber@ap.example"), advance: 10 * time.Minute, corrupt: true, putContext: true, wantReason: EventRefusalInvalid},
		{name: "verified expired token", claims: agentEventTestClaims(base, "event-expired", "aauth:subscriber@ap.example"), advance: 10 * time.Minute, putContext: true, wantReason: EventRefusalExpired},
		{name: "wrong audience", claims: agentEventTestClaims(base, "event-audience", "aauth:other@ap.example"), putContext: true, wantReason: EventRefusalInvalid},
		{name: "unknown context", claims: agentEventTestClaims(base, "event-context", "aauth:subscriber@ap.example"), wantReason: EventRefusalUnknownContext},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			now := base.Add(test.advance)
			clock := aauth.ClockFunc(func() time.Time { return now })
			store := NewMemoryAgentEventStore()
			if test.putContext {
				putAgentEventTestContext(t, store, test.claims.EventID)
			}
			action := &scriptedEventAction{}
			agent := newAgentEventTestAgent(t, store, action, resourceKey, clock)
			compact, err := aauth.MintEventToken(resourceKey, test.claims)
			if err != nil {
				t.Fatal(err)
			}
			if test.corrupt {
				compact = corruptAgentEventTestSignature(compact)
			}
			accepted := acceptedAgentEventTestToken(compact, now, test.claims.EventID)

			state, err := agent.AcceptEvent(context.Background(), accepted)
			if err != nil || state != EventRefused {
				t.Fatalf("refusal state/error = %q, %v", state, err)
			}
			if got := store.refusalReason[accepted.Delivery]; got != test.wantReason {
				t.Fatalf("refusal reason = %q, want %q", got, test.wantReason)
			}
			if dispatches, reconciliations := action.counts(); dispatches != 0 || reconciliations != 0 {
				t.Fatalf("refused action counts = %d/%d", dispatches, reconciliations)
			}
		})
	}

	t.Run("unavailable resolver remains retryable", func(t *testing.T) {
		now := base
		clock := aauth.ClockFunc(func() time.Time { return now })
		store := NewMemoryAgentEventStore()
		putAgentEventTestContext(t, store, "event-unavailable")
		action := &scriptedEventAction{}
		agent := newAgentEventTestAgentWithResolver(t, store, action, unavailableEventKeyResolver{}, clock)
		accepted, _ := acceptedAgentEventTest(t, resourceKey, now, "event-unavailable", "delivery-unavailable")

		if state, err := agent.AcceptEvent(context.Background(), accepted); err == nil || state != "" {
			t.Fatalf("unavailable resolver state/error = %q, %v", state, err)
		}
		if _, err := store.LoadDisposition(context.Background(), accepted.Delivery); !errors.Is(err, ErrEventDispositionNotFound) {
			t.Fatalf("unavailable resolver disposition error = %v", err)
		}
	})

	t.Run("corrupt trusted envelope remains unacknowledgeable", func(t *testing.T) {
		now := base
		clock := aauth.ClockFunc(func() time.Time { return now })
		store := NewMemoryAgentEventStore()
		putAgentEventTestContext(t, store, "event-envelope")
		action := &scriptedEventAction{}
		agent := newAgentEventTestAgent(t, store, action, resourceKey, clock)
		accepted, _ := acceptedAgentEventTest(t, resourceKey, now, "event-envelope", "delivery-envelope")
		accepted.Delivery.TokenDigest = testEventTokenDigest("different-token")

		if state, err := agent.AcceptEvent(context.Background(), accepted); err == nil || state != "" {
			t.Fatalf("corrupt envelope state/error = %q, %v", state, err)
		}
		if _, err := store.LoadDisposition(context.Background(), accepted.Delivery); !errors.Is(err, ErrEventDispositionNotFound) {
			t.Fatalf("corrupt envelope disposition error = %v", err)
		}
	})
}

func TestAgentEventProcessingDispatchesOnceUnderConcurrentAcceptance(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-events-key")
	store := NewMemoryAgentEventStore()
	putAgentEventTestContext(t, store, "event-concurrent")
	action := &scriptedEventAction{dispatchOutcome: EventActionCompleted, reconcileOutcome: EventActionCompleted}
	agent := newAgentEventTestAgent(t, store, action, resourceKey, clock)
	accepted, _ := acceptedAgentEventTest(t, resourceKey, now, "event-concurrent", "delivery-concurrent")

	const callers = 12
	start := make(chan struct{})
	errorsSeen := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			state, err := agent.AcceptEvent(ctx, accepted)
			if err == nil && state != EventCompleted {
				err = errors.New("test: concurrent acceptance returned a nonterminal success")
			}
			errorsSeen <- err
		}()
	}
	close(start)
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if dispatches, _ := action.counts(); dispatches != 1 {
		t.Fatalf("concurrent dispatches = %d, want 1", dispatches)
	}
}

func TestEventAdapterAcknowledgesOnlyDurableTerminalDisposition(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-events-key")
	baseAgentStore := NewMemoryAgentEventStore()
	putAgentEventTestContext(t, baseAgentStore, "event-adapter")
	agentStore := &terminalReloadFailureAgentStore{AgentEventStore: baseAgentStore, fail: true}
	action := &scriptedEventAction{dispatchOutcome: EventActionCompleted}
	agent := newAgentEventTestAgent(t, agentStore, action, resourceKey, clock)
	apStore := NewMemoryAPEventStore("https://ap.example")
	if err := apStore.CreateSubscription(ctx, APEventSubscription{
		APIssuer: "https://ap.example", EventID: "event-adapter",
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		ActiveUntil: now.Add(time.Hour), MaxUses: 1,
	}); err != nil {
		t.Fatal(err)
	}
	compact, err := aauth.MintEventToken(resourceKey, agentEventTestClaims(now, "event-adapter", "aauth:subscriber@ap.example"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, _, err := apStore.AcceptEvent(ctx, AcceptedEventInput{
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		EventID: "event-adapter", Token: compact, AcceptedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewEventAdapter(apStore, agent)
	if err != nil {
		t.Fatal(err)
	}

	if err := adapter.Continue(ctx); err == nil {
		t.Fatal("terminal disposition reload failure allowed acknowledgement")
	}
	if pending, err := apStore.NextDelivery(ctx); err != nil || pending.Delivery != accepted.Delivery {
		t.Fatalf("AP inbox after reload failure = %#v, %v", pending, err)
	}
	if err := adapter.Continue(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := apStore.NextDelivery(ctx); !errors.Is(err, ErrNoPendingEventDelivery) {
		t.Fatalf("AP inbox after durable terminal acknowledgement error = %v", err)
	}
	if dispatches, _ := action.counts(); dispatches != 1 {
		t.Fatalf("adapter dispatches = %d, want 1", dispatches)
	}
}

func newAgentEventTestAgent(t *testing.T, store AgentEventStore, action EventAction, resourceKey aauth.SigningKey, clock aauth.Clock) *Agent {
	t.Helper()
	return newAgentEventTestAgentWithResolver(t, store, action, aauth.StaticKeyResolver{
		"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
	}, clock)
}

func newAgentEventTestAgentWithResolver(t *testing.T, store AgentEventStore, action EventAction, resolver aauth.KeyResolver, clock aauth.Clock) *Agent {
	t.Helper()
	agentKey := eventsProviderTestSigningKey(t, "agent-events-key")
	agent, err := NewAgent(AgentConfig{
		Identifier: "aauth:subscriber@ap.example", SigningKey: agentKey,
		AgentToken: "test-agent-token", KeyResolver: resolver,
		HTTPClient: &http.Client{}, Clock: clock,
		Events: &AgentEventsConfig{Store: store, Action: action},
	})
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

func putAgentEventTestContext(t *testing.T, store AgentEventStore, eventID string) {
	t.Helper()
	if err := store.PutContext(context.Background(), AgentEventContext{
		APIssuer: "https://ap.example", EventID: eventID,
		Value: []byte(`{"purpose":"agent event test"}`),
	}); err != nil {
		t.Fatal(err)
	}
}

func acceptedAgentEventTest(t *testing.T, resourceKey aauth.SigningKey, now time.Time, eventID, deliveryID string) (AcceptedEvent, aauth.EventTokenClaims) {
	t.Helper()
	claims := agentEventTestClaims(now, eventID, "aauth:subscriber@ap.example")
	compact, err := aauth.MintEventToken(resourceKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	accepted := acceptedAgentEventTestToken(compact, now, eventID)
	accepted.Delivery.DeliveryID = deliveryID
	return accepted, claims
}

func acceptedAgentEventTestToken(compact string, now time.Time, eventID string) AcceptedEvent {
	return AcceptedEvent{
		Delivery: EventDeliveryKey{
			APIssuer: "https://ap.example", DeliveryID: "delivery-" + eventID,
			TokenDigest: testEventTokenDigest(compact),
		},
		APIssuer: "https://ap.example", Token: compact, AcceptedAt: now,
	}
}

func agentEventTestClaims(now time.Time, eventID, audience string) aauth.EventTokenClaims {
	return aauth.EventTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: audience, EventID: eventID,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
}

func admitAgentEventTestProcessing(t *testing.T, store AgentEventStore, accepted AcceptedEvent, claims aauth.EventTokenClaims) {
	t.Helper()
	if err := store.AdmitProcessing(context.Background(), AgentEventProcessing{
		Delivery: accepted.Delivery, Action: eventActionKeyForTest(claims, accepted),
		State: EventPending, ExpiresAt: time.Unix(claims.ExpiresAt, 0),
		Token: accepted.Token, Event: claims,
	}); err != nil {
		t.Fatal(err)
	}
}

func eventActionKeyForTest(claims aauth.EventTokenClaims, accepted AcceptedEvent) EventActionKey {
	return EventActionKey{
		ResourceIssuer: claims.Issuer, APIssuer: accepted.APIssuer, EventID: claims.EventID,
	}
}

func corruptAgentEventTestSignature(compact string) string {
	signature := strings.LastIndexByte(compact, '.') + 1
	if signature <= 0 || signature >= len(compact) {
		return compact + "A"
	}
	replacement := byte('A')
	if compact[signature] == replacement {
		replacement = 'B'
	}
	return compact[:signature] + string(replacement) + compact[signature+1:]
}

type scriptedEventAction struct {
	mu               sync.Mutex
	dispatchOutcome  EventActionOutcome
	dispatchErr      error
	reconcileOutcome EventActionOutcome
	reconcileErr     error
	dispatches       int
	reconciliations  int
}

func (action *scriptedEventAction) Dispatch(context.Context, EventActionInput) (EventActionOutcome, error) {
	action.mu.Lock()
	defer action.mu.Unlock()
	action.dispatches++
	return action.dispatchOutcome, action.dispatchErr
}

func (action *scriptedEventAction) Reconcile(context.Context, EventActionKey) (EventActionOutcome, error) {
	action.mu.Lock()
	defer action.mu.Unlock()
	action.reconciliations++
	return action.reconcileOutcome, action.reconcileErr
}

func (action *scriptedEventAction) counts() (int, int) {
	action.mu.Lock()
	defer action.mu.Unlock()
	return action.dispatches, action.reconciliations
}

type unavailableEventKeyResolver struct{}

func (unavailableEventKeyResolver) ResolveKey(context.Context, string, string, string) (aauth.JWK, error) {
	return aauth.JWK{}, &aauth.KeyResolutionError{Code: aauth.KeyResolutionUnavailable, Cause: errors.New("test: resolver unavailable")}
}

type terminalReloadFailureAgentStore struct {
	AgentEventStore
	mu   sync.Mutex
	fail bool
}

func (store *terminalReloadFailureAgentStore) LoadDisposition(ctx context.Context, delivery EventDeliveryKey) (EventProcessingState, error) {
	state, err := store.AgentEventStore.LoadDisposition(ctx, delivery)
	if err != nil || (state != EventCompleted && state != EventRefused) {
		return state, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.fail {
		store.fail = false
		return "", errors.New("test: terminal disposition reload failed")
	}
	return state, nil
}
