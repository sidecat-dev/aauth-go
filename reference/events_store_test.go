package reference

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestMemoryAPEventStoreCommitsUseAndInboxAtomically(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryAPEventStore("https://ap.example")
	subscription := APEventSubscription{
		APIssuer:    "https://ap.example",
		EventID:     "event-one",
		Resource:    "https://resource.example",
		Agent:       "aauth:subscriber@ap.example",
		ActiveUntil: time.Date(2026, 8, 3, 5, 0, 0, 0, time.UTC),
		MaxUses:     1,
	}
	preused := subscription
	preused.EventID = "preused-event"
	preused.UseCount = 1
	if err := store.CreateSubscription(ctx, preused); !errors.Is(err, ErrEventRecordInvalid) {
		t.Fatalf("pre-used new subscription error = %v, want invalid record", err)
	}
	if err := store.CreateSubscription(ctx, subscription); err != nil {
		t.Fatal(err)
	}

	inputs := []AcceptedEventInput{
		{
			Resource:   subscription.Resource,
			Agent:      subscription.Agent,
			EventID:    subscription.EventID,
			Token:      "exact-event-token-one",
			AcceptedAt: subscription.ActiveUntil.Add(-time.Minute),
		},
		{
			Resource:   subscription.Resource,
			Agent:      subscription.Agent,
			EventID:    subscription.EventID,
			Token:      "exact-event-token-two",
			AcceptedAt: subscription.ActiveUntil.Add(-time.Minute),
		},
	}
	type result struct {
		accepted  AcceptedEvent
		remaining int
		err       error
	}
	results := make(chan result, len(inputs))
	start := make(chan struct{})
	var group sync.WaitGroup
	for _, input := range inputs {
		input := input
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			accepted, remaining, err := store.AcceptEvent(ctx, input)
			results <- result{accepted: accepted, remaining: remaining, err: err}
		}()
	}
	close(start)
	group.Wait()
	close(results)

	var winner AcceptedEvent
	acceptedCount := 0
	exhaustedCount := 0
	for result := range results {
		switch {
		case result.err == nil:
			acceptedCount++
			winner = result.accepted
			if result.remaining != 0 {
				t.Fatalf("accepted remaining uses = %d, want 0", result.remaining)
			}
		case errors.Is(result.err, ErrEventSubscriptionExhausted):
			exhaustedCount++
		default:
			t.Fatalf("unexpected concurrent acceptance error: %v", result.err)
		}
	}
	if acceptedCount != 1 || exhaustedCount != 1 {
		t.Fatalf("accepted/exhausted results = %d/%d, want 1/1", acceptedCount, exhaustedCount)
	}
	if winner.APIssuer != subscription.APIssuer ||
		winner.Delivery.APIssuer != subscription.APIssuer ||
		winner.Delivery.DeliveryID == "" || winner.Delivery.TokenDigest != testEventTokenDigest(winner.Token) ||
		(winner.Token != inputs[0].Token && winner.Token != inputs[1].Token) {
		t.Fatalf("accepted event = %#v", winner)
	}

	pending, err := store.NextDelivery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending != winner {
		t.Fatalf("pending delivery = %#v, want %#v", pending, winner)
	}
	if err := store.AcknowledgeDelivery(ctx, winner.Delivery.DeliveryID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.NextDelivery(ctx); !errors.Is(err, ErrNoPendingEventDelivery) {
		t.Fatalf("empty inbox error = %v, want no pending event delivery", err)
	}

	if _, _, err := store.AcceptEvent(ctx, AcceptedEventInput{
		Resource:   "https://other-resource.example",
		Agent:      subscription.Agent,
		EventID:    subscription.EventID,
		Token:      "mismatched-event-token",
		AcceptedAt: subscription.ActiveUntil.Add(-time.Minute),
	}); !errors.Is(err, ErrEventSubscriptionMismatch) {
		t.Fatalf("mismatched subscription error = %v", err)
	}
}

func TestMemoryResourceEventStoreKeysSubscriptionsByAPIssuerAndEID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryResourceEventStore()
	activeUntil := time.Date(2026, 8, 3, 5, 0, 0, 0, time.UTC)
	first := ResourceEventSubscription{
		APIssuer:    "https://first-ap.example",
		EventID:     "shared-event-id",
		Resource:    "https://resource.example",
		Agent:       "aauth:first@first-ap.example",
		ActiveUntil: activeUntil,
	}
	second := ResourceEventSubscription{
		APIssuer:    "https://second-ap.example",
		EventID:     first.EventID,
		Resource:    first.Resource,
		Agent:       "aauth:second@second-ap.example",
		ActiveUntil: activeUntil.Add(time.Hour),
	}
	if err := store.Register(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Register(ctx, second); err != nil {
		t.Fatal(err)
	}

	for _, want := range []ResourceEventSubscription{first, second} {
		got, err := store.Load(ctx, want.APIssuer, want.EventID)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("loaded subscription = %#v, want %#v", got, want)
		}
	}

	replacement := first
	replacement.Agent = "aauth:replacement@first-ap.example"
	if err := store.Register(ctx, replacement); !errors.Is(err, ErrEventSubscriptionConflict) {
		t.Fatalf("replacement registration error = %v, want conflict", err)
	}
	got, err := store.Load(ctx, first.APIssuer, first.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if got != first {
		t.Fatalf("conflict replaced first subscription: %#v", got)
	}

	pending := PendingEventDelivery{
		APIssuer:  first.APIssuer,
		EventID:   first.EventID,
		Token:     "exact-pending-event-token",
		CreatedAt: activeUntil.Add(-time.Minute),
	}
	if err := store.RetainPending(ctx, pending); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.LoadPending(ctx, pending.APIssuer, pending.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered != pending {
		t.Fatalf("recovered pending delivery = %#v, want %#v", recovered, pending)
	}
	if err := store.RetainPending(ctx, PendingEventDelivery{
		APIssuer:  pending.APIssuer,
		EventID:   pending.EventID,
		Token:     "different-token",
		CreatedAt: pending.CreatedAt,
	}); !errors.Is(err, ErrEventPendingConflict) {
		t.Fatalf("pending replacement error = %v, want conflict", err)
	}
	if err := store.CompletePending(ctx, pending.APIssuer, pending.EventID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, pending.APIssuer, pending.EventID); !errors.Is(err, ErrEventSubscriptionNotFound) {
		t.Fatalf("completed subscription error = %v, want not found", err)
	}
}

func TestMemoryAgentEventStorePreservesUnknownDispatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryAgentEventStore()
	contextValue := json.RawMessage(`{"purpose":"first"}`)
	localContext := AgentEventContext{
		APIssuer: "https://ap.example",
		EventID:  "event-one",
		Value:    contextValue,
	}
	if err := store.PutContext(ctx, localContext); err != nil {
		t.Fatal(err)
	}
	contextValue[0] = '['
	loadedContext, err := store.LookupContext(ctx, localContext.APIssuer, localContext.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if string(loadedContext.Value) != `{"purpose":"first"}` {
		t.Fatalf("stored context aliased caller bytes: %s", loadedContext.Value)
	}
	loadedContext.Value[0] = '['
	reloadedContext, err := store.LookupContext(ctx, localContext.APIssuer, localContext.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if string(reloadedContext.Value) != `{"purpose":"first"}` {
		t.Fatalf("loaded context exposed store bytes: %s", reloadedContext.Value)
	}

	delivery := EventDeliveryKey{
		APIssuer:    localContext.APIssuer,
		DeliveryID:  "delivery-one",
		TokenDigest: testEventTokenDigest("token-one"),
	}
	action := EventActionKey{
		ResourceIssuer: "https://resource.example",
		APIssuer:       localContext.APIssuer,
		EventID:        localContext.EventID,
	}
	processing := AgentEventProcessing{
		Delivery:  delivery,
		Action:    action,
		State:     EventPending,
		ExpiresAt: time.Date(2026, 8, 3, 5, 0, 0, 0, time.UTC),
		Token:     "token-one",
		Event: aauth.EventTokenClaims{
			Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
			Audience: "aauth:subscriber@ap.example", EventID: localContext.EventID,
			IssuedAt:  time.Date(2026, 8, 3, 4, 55, 0, 0, time.UTC).Unix(),
			ExpiresAt: time.Date(2026, 8, 3, 5, 0, 0, 0, time.UTC).Unix(),
		},
	}
	if err := store.AdmitProcessing(ctx, processing); err != nil {
		t.Fatal(err)
	}
	if claimed, err := store.BeginDispatch(ctx, action); err != nil || !claimed {
		t.Fatalf("begin dispatch = %v, %v", claimed, err)
	}
	got, err := store.LoadProcessing(ctx, action)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != EventDispatched {
		t.Fatalf("processing state after reconstruction = %q, want dispatched", got.State)
	}
	if state, err := store.LoadDisposition(ctx, delivery); err != nil || state != EventDispatched {
		t.Fatalf("unknown dispatch disposition = %q, %v", state, err)
	}
	if err := store.MarkRefused(ctx, delivery, EventRefusalExpired); !errors.Is(err, ErrEventProcessingTransition) {
		t.Fatalf("outcome-unknown expiry refusal error = %v, want invalid transition", err)
	}
	if state, err := store.LoadDisposition(ctx, delivery); err != nil || state != EventDispatched {
		t.Fatalf("outcome-unknown disposition after refusal attempt = %q, %v, want dispatched", state, err)
	}
	if err := store.MarkRefused(ctx, delivery, EventRefusalNotApplied); err != nil {
		t.Fatalf("reconciled not-applied refusal: %v", err)
	}
	if state, err := store.LoadDisposition(ctx, delivery); err != nil || state != EventRefused {
		t.Fatalf("reconciled not-applied disposition = %q, %v, want refused", state, err)
	}

	sameOpaqueEventFromAnotherResource := action
	sameOpaqueEventFromAnotherResource.ResourceIssuer = "https://other-resource.example"
	if _, err := store.LoadProcessing(ctx, sameOpaqueEventFromAnotherResource); !errors.Is(err, ErrEventProcessingNotFound) {
		t.Fatalf("cross-resource processing lookup error = %v, want not found", err)
	}

	untrustedDelivery := EventDeliveryKey{
		APIssuer:    delivery.APIssuer,
		DeliveryID:  delivery.DeliveryID,
		TokenDigest: testEventTokenDigest("different-token"),
	}
	if _, err := store.LoadDisposition(ctx, untrustedDelivery); !errors.Is(err, ErrEventDispositionNotFound) {
		t.Fatalf("different-token disposition error = %v, want not found", err)
	}
	refused := EventDeliveryKey{
		APIssuer:    "https://ap.example",
		DeliveryID:  "delivery-invalid",
		TokenDigest: testEventTokenDigest("invalid-token"),
	}
	malformedDigest := refused
	malformedDigest.DeliveryID = "delivery-malformed-digest"
	malformedDigest.TokenDigest = "not-a-sha256-digest"
	if err := store.MarkRefused(ctx, malformedDigest, EventRefusalInvalid); !errors.Is(err, ErrEventRecordInvalid) {
		t.Fatalf("malformed token digest error = %v, want invalid record", err)
	}
	if err := store.MarkRefused(ctx, refused, EventRefusalInvalid); err != nil {
		t.Fatal(err)
	}
	if state, err := store.LoadDisposition(ctx, refused); err != nil || state != EventRefused {
		t.Fatalf("refused disposition = %q, %v", state, err)
	}
}

func testEventTokenDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
