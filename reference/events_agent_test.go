package reference

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
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

	t.Run("never-dispatched pending expires without action", func(t *testing.T) {
		now := base
		clock := aauth.ClockFunc(func() time.Time { return now })
		store := NewMemoryAgentEventStore()
		putAgentEventTestContext(t, store, "event-pending-expired")
		accepted, claims := acceptedAgentEventTest(t, resourceKey, now, "event-pending-expired", "delivery-pending-expired")
		admitAgentEventTestProcessing(t, store, accepted, claims)
		now = time.Unix(claims.ExpiresAt, 0)
		action := &scriptedEventAction{dispatchOutcome: EventActionCompleted}
		agent := newAgentEventTestAgent(t, store, action, resourceKey, clock)

		if err := agent.ResumeEvents(ctx); err != nil {
			t.Fatal(err)
		}
		state, err := store.LoadDisposition(ctx, accepted.Delivery)
		if err != nil || state != EventRefused {
			t.Fatalf("expired pending disposition = %q, %v", state, err)
		}
		if dispatches, reconciliations := action.counts(); dispatches != 0 || reconciliations != 0 {
			t.Fatalf("expired pending action counts = %d/%d, want 0/0", dispatches, reconciliations)
		}
	})

	t.Run("proven not applied retries only while unexpired", func(t *testing.T) {
		now := base
		clock := aauth.ClockFunc(func() time.Time { return now })
		store := NewMemoryAgentEventStore()
		putAgentEventTestContext(t, store, "event-retry")
		accepted, claims := acceptedAgentEventTest(t, resourceKey, now, "event-retry", "delivery-retry")
		admitAgentEventTestProcessing(t, store, accepted, claims)
		if claimed, err := store.BeginDispatch(ctx, eventActionKeyForTest(claims, accepted), now); err != nil || !claimed {
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
		if claimed, err := store.BeginDispatch(ctx, eventActionKeyForTest(claims, accepted), now); err != nil || !claimed {
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
		if claimed, err := store.BeginDispatch(ctx, eventActionKeyForTest(claims, accepted), now); err != nil || !claimed {
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

	for _, test := range []struct {
		name   string
		claims aauth.EventTokenClaims
	}{
		{name: "wrong agent audience", claims: agentEventTestClaims(base, "event-wrong-agent", "aauth:other@ap.example")},
		{name: "excessive lifetime", claims: func() aauth.EventTokenClaims {
			claims := agentEventTestClaims(base, "event-long", "aauth:subscriber@ap.example")
			claims.ExpiresAt = base.Add(referenceEventTokenLifetime + time.Minute).Unix()
			return claims
		}()},
	} {
		test := test
		t.Run("restart refuses "+test.name, func(t *testing.T) {
			now := base
			clock := aauth.ClockFunc(func() time.Time { return now })
			store := NewMemoryAgentEventStore()
			putAgentEventTestContext(t, store, test.claims.EventID)
			compact, err := aauth.MintEventToken(resourceKey, test.claims)
			if err != nil {
				t.Fatal(err)
			}
			accepted := acceptedAgentEventTestToken(compact, now, test.claims.EventID)
			admitAgentEventTestProcessing(t, store, accepted, test.claims)
			action := &scriptedEventAction{dispatchOutcome: EventActionCompleted}
			agent := newAgentEventTestAgent(t, store, action, resourceKey, clock)

			if err := agent.ResumeEvents(ctx); err != nil {
				t.Fatal(err)
			}
			state, err := store.LoadDisposition(ctx, accepted.Delivery)
			if err != nil || state != EventRefused {
				t.Fatalf("policy-violating restart disposition = %q, %v", state, err)
			}
			if dispatches, reconciliations := action.counts(); dispatches != 0 || reconciliations != 0 {
				t.Fatalf("policy-violating restart action counts = %d/%d", dispatches, reconciliations)
			}
		})
	}
}

func TestAgentEventRefusalMatrixSurvivesStoreReconstruction(t *testing.T) {
	base := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	trustedKey, trustedPrivate := rawEventsTestSigningKey(t, "resource-events-key")
	_, untrustedPrivate := rawEventsTestSigningKey(t, "resource-events-key")
	resolver := aauth.StaticKeyResolver{
		"https://resource.example": {trustedKey.ID(): trustedKey.PublicJWK()},
	}

	for _, test := range []struct {
		name       string
		header     aauth.TokenHeader
		claims     map[string]any
		privateKey ed25519.PrivateKey
		advance    time.Duration
		putContext bool
		wantReason EventRefusalReason
	}{
		{name: "wrong type", header: rawEventsTestHeader(aauth.SubscribeTokenType, trustedKey.ID()), claims: rawAgentEventTestClaims(base, "event-wrong-type"), privateKey: trustedPrivate, putContext: true, wantReason: EventRefusalInvalid},
		{name: "wrong key", header: rawEventsTestHeader(aauth.EventTokenType, trustedKey.ID()), claims: rawAgentEventTestClaims(base, "event-wrong-key"), privateKey: untrustedPrivate, putContext: true, wantReason: EventRefusalInvalid},
		{name: "wrong discovery document", header: rawEventsTestHeader(aauth.EventTokenType, trustedKey.ID()), claims: mutateRawEventsTestClaim(rawAgentEventTestClaims(base, "event-wrong-dwk"), "dwk", aauth.AgentDiscoveryDocument), privateKey: trustedPrivate, putContext: true, wantReason: EventRefusalInvalid},
		{name: "absent issued time", header: rawEventsTestHeader(aauth.EventTokenType, trustedKey.ID()), claims: mutateRawEventsTestClaim(rawAgentEventTestClaims(base, "event-no-iat"), "iat", nil), privateKey: trustedPrivate, putContext: true, wantReason: EventRefusalInvalid},
		{name: "malformed issued time", header: rawEventsTestHeader(aauth.EventTokenType, trustedKey.ID()), claims: mutateRawEventsTestClaim(rawAgentEventTestClaims(base, "event-bad-iat"), "iat", "now"), privateKey: trustedPrivate, putContext: true, wantReason: EventRefusalInvalid},
		{name: "wrong audience", header: rawEventsTestHeader(aauth.EventTokenType, trustedKey.ID()), claims: mutateRawEventsTestClaim(rawAgentEventTestClaims(base, "event-wrong-audience"), "aud", "aauth:other@ap.example"), privateKey: trustedPrivate, putContext: true, wantReason: EventRefusalInvalid},
		{name: "expired before processing", header: rawEventsTestHeader(aauth.EventTokenType, trustedKey.ID()), claims: rawAgentEventTestClaims(base, "event-expired-before-agent"), privateKey: trustedPrivate, advance: 10 * time.Minute, putContext: true, wantReason: EventRefusalExpired},
		{name: "unknown context", header: rawEventsTestHeader(aauth.EventTokenType, trustedKey.ID()), claims: rawAgentEventTestClaims(base, "event-unknown-context"), privateKey: trustedPrivate, wantReason: EventRefusalUnknownContext},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			now := base.Add(test.advance)
			clock := aauth.ClockFunc(func() time.Time { return now })
			eventID, _ := test.claims["eid"].(string)
			compact := mintRawEventsTestToken(t, test.privateKey, test.header, test.claims)

			directory := filepath.Join(t.TempDir(), "store")
			agentStore, err := OpenFileAgentEventStore(FileAgentEventStoreConfig{Directory: directory})
			if err != nil {
				t.Fatal(err)
			}
			if test.putContext {
				putAgentEventTestContext(t, agentStore, eventID)
			}
			apStore := NewMemoryAPEventStore("https://ap.example")
			agentAudience, _ := test.claims["aud"].(string)
			if agentAudience == "" {
				agentAudience = "aauth:subscriber@ap.example"
			}
			if err := apStore.CreateSubscription(ctx, APEventSubscription{
				APIssuer: "https://ap.example", EventID: eventID,
				Resource: "https://resource.example", Agent: agentAudience,
				ActiveUntil: now.Add(time.Hour), MaxUses: 1,
			}); err != nil {
				t.Fatal(err)
			}
			accepted, _, err := apStore.AcceptEvent(ctx, AcceptedEventInput{
				Resource: "https://resource.example", Agent: agentAudience,
				EventID: eventID, Token: compact, AcceptedAt: now,
			})
			if err != nil {
				t.Fatal(err)
			}
			action := &scriptedEventAction{dispatchOutcome: EventActionCompleted}
			agent := newAgentEventTestAgentWithResolver(t, agentStore, action, resolver, clock)
			state, err := agent.AcceptEvent(ctx, accepted)
			if err != nil || state != EventRefused {
				t.Fatalf("initial refusal state/error = %q, %v", state, err)
			}
			if got := agentStore.memory.refusalReason[accepted.Delivery]; got != test.wantReason {
				t.Fatalf("refusal reason = %q, want %q", got, test.wantReason)
			}
			if dispatches, reconciliations := action.counts(); dispatches != 0 || reconciliations != 0 {
				t.Fatalf("refused action counts = %d/%d, want 0/0", dispatches, reconciliations)
			}
			if err := agentStore.Close(); err != nil {
				t.Fatal(err)
			}

			agentStore, err = OpenFileAgentEventStore(FileAgentEventStoreConfig{Directory: directory})
			if err != nil {
				t.Fatal(err)
			}
			defer agentStore.Close()
			if got := agentStore.memory.refusalReason[accepted.Delivery]; got != test.wantReason {
				t.Fatalf("reopened refusal reason = %q, want %q", got, test.wantReason)
			}
			agent = newAgentEventTestAgentWithResolver(t, agentStore, action, resolver, clock)
			adapter, err := NewEventAdapter(apStore, agent)
			if err != nil {
				t.Fatal(err)
			}
			if err := adapter.Continue(ctx); err != nil {
				t.Fatal(err)
			}
			if state, err := agentStore.LoadDisposition(ctx, accepted.Delivery); err != nil || state != EventRefused {
				t.Fatalf("reopened refusal state/error = %q, %v", state, err)
			}
			if _, err := apStore.NextDelivery(ctx); !errors.Is(err, ErrNoPendingEventDelivery) {
				t.Fatalf("durable refusal did not acknowledge AP work: %v", err)
			}
			if dispatches, reconciliations := action.counts(); dispatches != 0 || reconciliations != 0 {
				t.Fatalf("reopened refusal action counts = %d/%d, want 0/0", dispatches, reconciliations)
			}
		})
	}
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

func TestEventAdapterRecoversAfterDedupCustodyFailure(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := eventsProviderTestSigningKey(t, "resource-events-key")
	baseStore := NewMemoryAgentEventStore()
	putAgentEventTestContext(t, baseStore, "event-dedup-recovery")
	storeFailure := errors.New("test: dedup authority unavailable")
	agentStore := &failOnceAdmitProcessingAgentStore{AgentEventStore: baseStore, err: storeFailure}
	action := &scriptedEventAction{dispatchOutcome: EventActionCompleted}
	agent := newAgentEventTestAgent(t, agentStore, action, resourceKey, clock)
	apStore := NewMemoryAPEventStore("https://ap.example")
	if err := apStore.CreateSubscription(ctx, APEventSubscription{
		APIssuer: "https://ap.example", EventID: "event-dedup-recovery",
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		ActiveUntil: now.Add(time.Hour), MaxUses: 1,
	}); err != nil {
		t.Fatal(err)
	}
	compact, err := aauth.MintEventToken(resourceKey, agentEventTestClaims(now, "event-dedup-recovery", "aauth:subscriber@ap.example"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, _, err := apStore.AcceptEvent(ctx, AcceptedEventInput{
		Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example",
		EventID: "event-dedup-recovery", Token: compact, AcceptedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewEventAdapter(apStore, agent)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Continue(ctx); !errors.Is(err, storeFailure) {
		t.Fatalf("dedup failure = %v, want %v", err, storeFailure)
	}
	if dispatches, _ := action.counts(); dispatches != 0 {
		t.Fatalf("dedup failure dispatched %d actions", dispatches)
	}
	if pending, err := apStore.NextDelivery(ctx); err != nil || pending.Delivery != accepted.Delivery {
		t.Fatalf("dedup failure AP work = %#v, %v", pending, err)
	}

	agent = newAgentEventTestAgent(t, agentStore, action, resourceKey, clock)
	adapter, err = NewEventAdapter(apStore, agent)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Continue(ctx); err != nil {
		t.Fatal(err)
	}
	if state, err := baseStore.LoadDisposition(ctx, accepted.Delivery); err != nil || state != EventCompleted {
		t.Fatalf("healthy dedup retry state/error = %q, %v", state, err)
	}
	if _, err := apStore.NextDelivery(ctx); !errors.Is(err, ErrNoPendingEventDelivery) {
		t.Fatalf("healthy dedup retry left AP work: %v", err)
	}
	if dispatches, _ := action.counts(); dispatches != 1 {
		t.Fatalf("healthy dedup retry dispatches = %d, want 1", dispatches)
	}
}

func TestEventAdapterReconstructedPendingReappliesAgentPolicy(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	resourceKey := eventsProviderTestSigningKey(t, "resource-events-key")

	for _, test := range []struct {
		name   string
		claims aauth.EventTokenClaims
	}{
		{name: "different agent", claims: agentEventTestClaims(base, "event-adapter-agent", "aauth:original@ap.example")},
		{name: "excessive lifetime", claims: func() aauth.EventTokenClaims {
			claims := agentEventTestClaims(base, "event-adapter-lifetime", "aauth:subscriber@ap.example")
			claims.ExpiresAt = base.Add(referenceEventTokenLifetime + time.Minute).Unix()
			return claims
		}()},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			clock := aauth.ClockFunc(func() time.Time { return base })
			agentStore := NewMemoryAgentEventStore()
			putAgentEventTestContext(t, agentStore, test.claims.EventID)
			apStore := NewMemoryAPEventStore("https://ap.example")
			if err := apStore.CreateSubscription(ctx, APEventSubscription{
				APIssuer: "https://ap.example", EventID: test.claims.EventID,
				Resource: "https://resource.example", Agent: test.claims.Audience,
				ActiveUntil: base.Add(2 * time.Hour), MaxUses: 1,
			}); err != nil {
				t.Fatal(err)
			}
			compact, err := aauth.MintEventToken(resourceKey, test.claims)
			if err != nil {
				t.Fatal(err)
			}
			accepted, _, err := apStore.AcceptEvent(ctx, AcceptedEventInput{
				Resource: "https://resource.example", Agent: test.claims.Audience,
				EventID: test.claims.EventID, Token: compact, AcceptedAt: base,
			})
			if err != nil {
				t.Fatal(err)
			}
			admitAgentEventTestProcessing(t, agentStore, accepted, test.claims)

			action := &scriptedEventAction{dispatchOutcome: EventActionCompleted}
			agent := newAgentEventTestAgent(t, agentStore, action, resourceKey, clock)
			adapter, err := NewEventAdapter(apStore, agent)
			if err != nil {
				t.Fatal(err)
			}
			if err := adapter.Continue(ctx); err != nil {
				t.Fatal(err)
			}
			state, err := agentStore.LoadDisposition(ctx, accepted.Delivery)
			if err != nil || state != EventRefused {
				t.Fatalf("reconstructed adapter disposition = %q, %v, want refused", state, err)
			}
			if dispatches, reconciliations := action.counts(); dispatches != 0 || reconciliations != 0 {
				t.Fatalf("reconstructed adapter action counts = %d/%d, want 0/0", dispatches, reconciliations)
			}
			if _, err := apStore.NextDelivery(ctx); !errors.Is(err, ErrNoPendingEventDelivery) {
				t.Fatalf("terminal refusal did not acknowledge AP delivery: %v", err)
			}
		})
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

type failOnceAdmitProcessingAgentStore struct {
	AgentEventStore
	err error
}

func (store *failOnceAdmitProcessingAgentStore) AdmitProcessing(ctx context.Context, processing AgentEventProcessing) error {
	if store.err != nil {
		err := store.err
		store.err = nil
		return err
	}
	return store.AgentEventStore.AdmitProcessing(ctx, processing)
}

func rawEventsTestSigningKey(t *testing.T, id string) (aauth.SigningKey, ed25519.PrivateKey) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := aauth.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, privateKey
}

func rawEventsTestHeader(tokenType, keyID string) aauth.TokenHeader {
	return aauth.TokenHeader{Algorithm: "EdDSA", Type: tokenType, KeyID: keyID}
}

func rawAgentEventTestClaims(now time.Time, eventID string) map[string]any {
	return map[string]any{
		"iss": "https://resource.example", "dwk": aauth.ResourceDiscoveryDocument,
		"aud": "aauth:subscriber@ap.example", "eid": eventID,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
}

func mutateRawEventsTestClaim(claims map[string]any, name string, value any) map[string]any {
	mutated := make(map[string]any, len(claims))
	for key, original := range claims {
		mutated[key] = original
	}
	if value == nil {
		delete(mutated, name)
	} else {
		mutated[name] = value
	}
	return mutated
}

func mintRawEventsTestToken(t *testing.T, privateKey ed25519.PrivateKey, header aauth.TokenHeader, claims map[string]any) string {
	t.Helper()
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	signingInput := encode(headerBytes) + "." + encode(claimsBytes)
	return signingInput + "." + encode(ed25519.Sign(privateKey, []byte(signingInput)))
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
