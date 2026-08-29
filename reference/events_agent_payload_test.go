package reference

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestAgentEventPayloadIndependentlyValidatesAndReachesExactAction(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 11, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-agent-payload-key")
	store := NewMemoryAgentEventStore()
	document := protectedEventsTestDocument()
	eventID := "event-agent-payload"
	if err := store.PutContext(ctx, protectedAgentPayloadContext(eventID, document)); err != nil {
		t.Fatal(err)
	}
	accepted, claims := acceptedAgentEventTest(t, resourceKey, now, eventID, "delivery-agent-payload")
	accepted.ContentType = "application/json"
	accepted.Payload = []byte(" \n" + `{"event_type":"slot.available","slot_time":"2026-08-04T12:30:00Z"}` + "\n ")
	accepted.PayloadDigest = eventPayloadDigest(accepted.Payload)
	action := &capturingPayloadEventAction{dispatchOutcome: EventActionCompleted}
	agent := newAgentEventTestAgentWithResolver(t, store, action, signaturekey.StaticKeyResolver{
		claims.Issuer: {resourceKey.ID(): resourceKey.PublicJWK()},
	}, clock)
	state, err := agent.AcceptEvent(ctx, accepted)
	if err != nil || state != EventCompleted {
		t.Fatalf("payload event state = %q, %v", state, err)
	}
	input, calls := action.captured()
	if calls != 1 || input.ContentType != accepted.ContentType || input.PayloadDigest != accepted.PayloadDigest ||
		!bytes.Equal(input.Payload, accepted.Payload) || input.Event != claims ||
		input.Context.ContractDigest != r3.S256(document) {
		t.Fatalf("captured payload action = %#v, calls %d", input, calls)
	}
	accepted.Payload[1] = 'X'
	input.Payload[1] = 'Y'
	processing, err := store.LoadProcessing(ctx, eventActionKeyForTest(claims, accepted))
	if err != nil || !bytes.Equal(processing.Payload, []byte(" \n"+`{"event_type":"slot.available","slot_time":"2026-08-04T12:30:00Z"}`+"\n ")) {
		t.Fatalf("durable processing payload = %q, %v", processing.Payload, err)
	}
}

func TestAgentEventPayloadRefusalsAreDurableAndNeverDispatch(t *testing.T) {
	base := time.Date(2026, 8, 3, 11, 0, 0, 0, time.UTC)
	resourceKey := eventsProviderTestSigningKey(t, "resource-agent-payload-key")
	document := protectedEventsTestDocument()
	validPayload := []byte(`{"event_type":"slot.available","slot_time":"2026-08-04T12:30:00Z"}`)
	for index, test := range []struct {
		name           string
		context        func(string) AgentEventContext
		mutate         func(*AcceptedEvent)
		withoutPayload bool
	}{
		{name: "digest mismatch", context: func(eventID string) AgentEventContext { return protectedAgentPayloadContext(eventID, document) }, mutate: func(accepted *AcceptedEvent) { accepted.PayloadDigest = eventPayloadDigest([]byte("different")) }},
		{name: "wrong media type", context: func(eventID string) AgentEventContext { return protectedAgentPayloadContext(eventID, document) }, mutate: func(accepted *AcceptedEvent) { accepted.ContentType = "application/problem+json" }},
		{name: "schema mismatch", context: func(eventID string) AgentEventContext { return protectedAgentPayloadContext(eventID, document) }, mutate: func(accepted *AcceptedEvent) {
			accepted.Payload = []byte(`{"event_type":"other","slot_time":"2026-08-04T12:30:00Z"}`)
			accepted.PayloadDigest = eventPayloadDigest(accepted.Payload)
		}},
		{name: "retained document rejects payload", context: func(eventID string) AgentEventContext {
			rotated := bytes.Replace(document,
				[]byte(`"required":["event_type","slot_time"]`),
				[]byte(`"required":["event_type","slot_time","rotation_marker"]`), 1)
			return protectedAgentPayloadContext(eventID, rotated)
		}},
		{name: "contract payload missing", context: func(eventID string) AgentEventContext { return protectedAgentPayloadContext(eventID, document) }, withoutPayload: true},
		{name: "payload without contract", context: func(eventID string) AgentEventContext {
			return AgentEventContext{APIssuer: "https://ap.example", EventID: eventID, Value: []byte(`{"purpose":"M5 context"}`)}
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			now := base
			clock := aauth.ClockFunc(func() time.Time { return now })
			store := NewMemoryAgentEventStore()
			eventID := fmt.Sprintf("event-payload-refusal-%d", index)
			if err := store.PutContext(ctx, test.context(eventID)); err != nil {
				t.Fatal(err)
			}
			accepted, claims := acceptedAgentEventTest(t, resourceKey, now, eventID, fmt.Sprintf("delivery-payload-refusal-%d", index))
			if !test.withoutPayload {
				accepted.ContentType = "application/json"
				accepted.Payload = append([]byte(nil), validPayload...)
				accepted.PayloadDigest = eventPayloadDigest(accepted.Payload)
			}
			if test.mutate != nil {
				test.mutate(&accepted)
			}
			action := &capturingPayloadEventAction{dispatchOutcome: EventActionCompleted}
			agent := newAgentEventTestAgentWithResolver(t, store, action, signaturekey.StaticKeyResolver{
				claims.Issuer: {resourceKey.ID(): resourceKey.PublicJWK()},
			}, clock)
			state, err := agent.AcceptEvent(ctx, accepted)
			if err != nil || state != EventRefused {
				t.Fatalf("refusal state = %q, %v", state, err)
			}
			if _, calls := action.captured(); calls != 0 {
				t.Fatalf("refusal dispatched %d actions", calls)
			}
			if disposition, err := store.LoadDisposition(ctx, accepted.Delivery); err != nil || disposition != EventRefused {
				t.Fatalf("durable refusal = %q, %v", disposition, err)
			}
		})
	}
}

func TestAgentEventPayloadFileProcessingReopensBeforeDispatch(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 11, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-agent-payload-key")
	document := protectedEventsTestDocument()
	eventID := "event-agent-payload-reopen"
	config := FileAgentEventStoreConfig{Directory: filepath.Join(t.TempDir(), "agent")}
	store, err := OpenFileAgentEventStore(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutContext(ctx, protectedAgentPayloadContext(eventID, document)); err != nil {
		t.Fatal(err)
	}
	accepted, claims := acceptedAgentEventTest(t, resourceKey, now, eventID, "delivery-agent-payload-reopen")
	payload := []byte("\n" + `{"event_type":"slot.available","slot_time":"2026-08-04T12:30:00Z"}` + "\n")
	processing := AgentEventProcessing{
		Delivery: accepted.Delivery, Action: eventActionKeyForTest(claims, accepted),
		State: EventPending, ExpiresAt: time.Unix(claims.ExpiresAt, 0),
		Token: accepted.Token, Event: claims, ContentType: "application/json",
		Payload: payload, PayloadDigest: eventPayloadDigest(payload),
	}
	if err := store.AdmitProcessing(ctx, processing); err != nil {
		t.Fatal(err)
	}
	payload[1] = 'X'
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenFileAgentEventStore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	action := &capturingPayloadEventAction{dispatchOutcome: EventActionCompleted}
	agent := newAgentEventTestAgentWithResolver(t, store, action, signaturekey.StaticKeyResolver{
		claims.Issuer: {resourceKey.ID(): resourceKey.PublicJWK()},
	}, clock)
	if err := agent.ResumeEvents(ctx); err != nil {
		t.Fatal(err)
	}
	input, calls := action.captured()
	wantPayload := []byte("\n" + `{"event_type":"slot.available","slot_time":"2026-08-04T12:30:00Z"}` + "\n")
	if calls != 1 || !bytes.Equal(input.Payload, wantPayload) || input.PayloadDigest != eventPayloadDigest(wantPayload) {
		t.Fatalf("reopened action input = %#v, calls %d", input, calls)
	}
	loaded, err := store.LoadProcessing(ctx, processing.Action)
	if err != nil || loaded.State != EventCompleted || !bytes.Equal(loaded.Payload, wantPayload) {
		t.Fatalf("reopened terminal processing = %#v, %v", loaded, err)
	}
}

func TestEventAdapterPayloadAcknowledgesOnlyAfterTerminalAgentValidation(t *testing.T) {
	for index, test := range []struct {
		name           string
		payload        []byte
		wantDispatches int
		wantState      EventProcessingState
	}{
		{name: "valid", payload: []byte(`{"event_type":"slot.available","slot_time":"2026-08-04T12:30:00Z"}`), wantDispatches: 1, wantState: EventCompleted},
		{name: "schema refusal", payload: []byte(`{"event_type":"other","slot_time":"2026-08-04T12:30:00Z"}`), wantState: EventRefused},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 8, 3, 11, 0, 0, 0, time.UTC)
			clock := aauth.ClockFunc(func() time.Time { return now })
			resourceKey := eventsProviderTestSigningKey(t, "resource-agent-payload-key")
			document := protectedEventsTestDocument()
			eventID := fmt.Sprintf("event-adapter-payload-%d", index)
			apStore := NewMemoryAPEventStore("https://ap.example")
			if err := apStore.CreateSubscription(ctx, APEventSubscription{
				APIssuer: "https://ap.example", EventID: eventID,
				Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
				ActiveUntil: now.Add(time.Hour), MaxUses: 1, ContractDigest: r3.S256(document),
				OperationID: "subscribeProtectedWaitlist", MessageID: "slotAvailable",
			}); err != nil {
				t.Fatal(err)
			}
			compact := mintDeliveryTestEvent(t, resourceKey, now, "aauth:subscriber@ap.example", eventID)
			accepted, _, err := apStore.AcceptEvent(ctx, AcceptedEventInput{
				Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
				EventID: eventID, Token: compact, ContentType: "application/json",
				Payload: test.payload, PayloadDigest: eventPayloadDigest(test.payload), AcceptedAt: now,
			})
			if err != nil {
				t.Fatal(err)
			}
			agentStore := NewMemoryAgentEventStore()
			if err := agentStore.PutContext(ctx, protectedAgentPayloadContext(eventID, document)); err != nil {
				t.Fatal(err)
			}
			action := &capturingPayloadEventAction{dispatchOutcome: EventActionCompleted}
			agent := newAgentEventTestAgentWithResolver(t, agentStore, action, signaturekey.StaticKeyResolver{
				"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
			}, clock)
			adapter, err := NewEventAdapter(apStore, agent)
			if err != nil {
				t.Fatal(err)
			}
			if err := adapter.Continue(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := apStore.NextDelivery(ctx); !errors.Is(err, ErrNoPendingEventDelivery) {
				t.Fatalf("adapter did not acknowledge terminal payload: %v", err)
			}
			if state, err := agentStore.LoadDisposition(ctx, accepted.Delivery); err != nil || state != test.wantState {
				t.Fatalf("agent terminal state = %q, %v", state, err)
			}
			if _, calls := action.captured(); calls != test.wantDispatches {
				t.Fatalf("payload adapter dispatches = %d, want %d", calls, test.wantDispatches)
			}
		})
	}
}

func protectedAgentPayloadContext(eventID string, document []byte) AgentEventContext {
	return AgentEventContext{
		APIssuer: "https://ap.example", EventID: eventID,
		Value:    []byte(`{"purpose":"protected payload action"}`),
		Contract: append([]byte(nil), document...), ContractDigest: r3.S256(document),
		OperationID: "subscribeProtectedWaitlist", MessageID: "slotAvailable",
	}
}

type capturingPayloadEventAction struct {
	mu              sync.Mutex
	dispatchOutcome EventActionOutcome
	dispatchErr     error
	input           EventActionInput
	dispatches      int
}

func (action *capturingPayloadEventAction) Dispatch(_ context.Context, input EventActionInput) (EventActionOutcome, error) {
	action.mu.Lock()
	defer action.mu.Unlock()
	input.Payload = append([]byte(nil), input.Payload...)
	action.input = input
	action.dispatches++
	return action.dispatchOutcome, action.dispatchErr
}

func (action *capturingPayloadEventAction) Reconcile(context.Context, EventActionKey) (EventActionOutcome, error) {
	return EventActionUnknown, errors.New("unused")
}

func (action *capturingPayloadEventAction) captured() (EventActionInput, int) {
	action.mu.Lock()
	defer action.mu.Unlock()
	input := action.input
	input.Payload = append([]byte(nil), input.Payload...)
	return input, action.dispatches
}
