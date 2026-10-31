package storetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// EventInboxContract constructs a fresh empty Agent Provider Events inbox.
// Delivery reads one accepted delivery back by fingerprint through the same
// path the host's AP-to-Agent transport uses to hand it to the Agent.
type EventInboxContract struct {
	New      func(testing.TB) agentprovider.EventInboxStore
	Delivery func(testing.TB, agentprovider.EventInboxStore, events.DeliveryFingerprint) (agentprovider.EventDelivery, error)
}

// RunEventInbox checks subscription retention, the subscribed Resource and
// Agent binding, the max_uses bound including under concurrent delivery,
// exact replay, and that an accepted delivery's token and payload are
// retained unchanged and independent of caller memory.
func RunEventInbox(t *testing.T, contract EventInboxContract) {
	t.Helper()
	if contract.New == nil || contract.Delivery == nil {
		t.Fatal("storetest: EventInboxContract.New and Delivery are required")
	}
	ctx := context.Background()
	now := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	const (
		agent    = "aauth:agent@ap.example"
		resource = "https://resource.example"
	)
	store := contract.New(t)
	bounded := eventInboxSubscription("event-bounded", agent, resource, 2, now)
	if err := store.CommitSubscription(ctx, bounded); err != nil {
		t.Fatalf("CommitSubscription = %v", err)
	}
	if err := store.CommitSubscription(ctx, bounded); err != nil {
		t.Fatalf("exact CommitSubscription repeat = %v", err)
	}
	changed := bounded
	changed.Resource = "https://other-resource.example"
	if err := store.CommitSubscription(ctx, changed); err == nil {
		t.Fatal("CommitSubscription replaced a retained subscription with a different Resource")
	}

	if _, err := store.AcceptEvent(ctx, eventInboxDelivery("event-unknown", agent, resource, "token-unknown", nil, now)); !errors.Is(err, agentprovider.ErrEventSubscriptionNotFound) {
		t.Fatalf("unknown eid = %v, want ErrEventSubscriptionNotFound", err)
	}
	otherResource := eventInboxDelivery(bounded.EventID, agent, "https://other-resource.example", "token-other-resource", []byte(`{}`), now)
	if _, err := store.AcceptEvent(ctx, otherResource); !errors.Is(err, agentprovider.ErrEventResourceMismatch) {
		t.Fatalf("delivery by another Resource = %v, want ErrEventResourceMismatch", err)
	}
	otherAgent := eventInboxDelivery(bounded.EventID, "aauth:other@ap.example", resource, "token-other-agent", []byte(`{}`), now)
	if _, err := store.AcceptEvent(ctx, otherAgent); !errors.Is(err, agentprovider.ErrEventAgentMismatch) {
		t.Fatalf("delivery to another Agent = %v, want ErrEventAgentMismatch", err)
	}

	// The refused deliveries above consumed no use: the first accepted
	// delivery still reports one remaining.
	firstPayload := []byte(`{"event_type":"slot.available","slot":"10:00"}`)
	first := eventInboxDelivery(bounded.EventID, agent, resource, "token-1", firstPayload, now)
	accepted, err := store.AcceptEvent(ctx, first)
	if err != nil || accepted.Duplicate || accepted.MaximumUses != 2 || accepted.RemainingUses != 1 {
		t.Fatalf("first delivery = %#v, %v; want maximum 2 and remaining 1", accepted, err)
	}
	original := append([]byte(nil), firstPayload...)
	firstPayload[0] = 'x'
	retained, err := contract.Delivery(t, store, first.Fingerprint)
	if err != nil {
		t.Fatalf("read first delivery = %v", err)
	}
	if retained.Token != "token-1" || !bytes.Equal(retained.Payload, original) ||
		retained.ContentType != "application/json" || retained.EventID != bounded.EventID ||
		retained.Agent != agent || retained.Resource != resource {
		t.Fatalf("retained delivery = %#v; want the exact accepted token and payload", retained)
	}
	if len(retained.Payload) > 0 {
		retained.Payload[0] = 'y'
		again, err := contract.Delivery(t, store, first.Fingerprint)
		if err != nil || !bytes.Equal(again.Payload, original) {
			t.Fatalf("retained payload aliases a returned copy: %q, %v", again.Payload, err)
		}
	}

	replay := eventInboxDelivery(bounded.EventID, agent, resource, "token-1", original, now)
	replayed, err := store.AcceptEvent(ctx, replay)
	if err != nil || !replayed.Duplicate || replayed.RemainingUses != 1 {
		t.Fatalf("exact replay = %#v, %v; want the first result as a duplicate", replayed, err)
	}
	second := eventInboxDelivery(bounded.EventID, agent, resource, "token-2", []byte(`{"slot":"11:00"}`), now)
	accepted, err = store.AcceptEvent(ctx, second)
	if err != nil || accepted.Duplicate || accepted.RemainingUses != 0 {
		t.Fatalf("second delivery = %#v, %v; want remaining 0", accepted, err)
	}
	third := eventInboxDelivery(bounded.EventID, agent, resource, "token-3", []byte(`{"slot":"12:00"}`), now)
	if _, err := store.AcceptEvent(ctx, third); !errors.Is(err, agentprovider.ErrEventUsesExceeded) {
		t.Fatalf("delivery beyond max_uses = %v, want ErrEventUsesExceeded", err)
	}
	if _, err := contract.Delivery(t, store, third.Fingerprint); err == nil {
		t.Fatal("a refused delivery beyond max_uses was retained")
	}
	replayed, err = store.AcceptEvent(ctx, replay)
	if err != nil || !replayed.Duplicate || replayed.RemainingUses != 1 {
		t.Fatalf("exact replay after exhaustion = %#v, %v", replayed, err)
	}

	unlimited := eventInboxSubscription("event-unlimited", agent, resource, 0, now)
	if err := store.CommitSubscription(ctx, unlimited); err != nil {
		t.Fatalf("CommitSubscription unlimited = %v", err)
	}
	for index := range 3 {
		delivery := eventInboxDelivery(unlimited.EventID, agent, resource, fmt.Sprintf("token-unlimited-%d", index), nil, now)
		accepted, err := store.AcceptEvent(ctx, delivery)
		if err != nil || accepted.Duplicate || accepted.MaximumUses != 0 || accepted.RemainingUses != 0 {
			t.Fatalf("unlimited delivery %d = %#v, %v", index, accepted, err)
		}
	}

	concurrent := eventInboxSubscription("event-concurrent", agent, resource, 1, now)
	if err := store.CommitSubscription(ctx, concurrent); err != nil {
		t.Fatalf("CommitSubscription concurrent = %v", err)
	}
	const contenders = 8
	results := make(chan error, contenders)
	for index := range contenders {
		delivery := eventInboxDelivery(concurrent.EventID, agent, resource, fmt.Sprintf("token-concurrent-%d", index), []byte(`{}`), now)
		go func() {
			_, err := store.AcceptEvent(ctx, delivery)
			results <- err
		}()
	}
	var successes, exhausted int
	for range contenders {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, agentprovider.ErrEventUsesExceeded):
			exhausted++
		default:
			t.Fatalf("concurrent delivery = %v", err)
		}
	}
	if successes != 1 || exhausted != contenders-1 {
		t.Fatalf("concurrent deliveries with max_uses 1: accepted=%d exhausted=%d", successes, exhausted)
	}
}

func eventInboxSubscription(eventID, agent, resource string, maxUses int64, now time.Time) agentprovider.EventSubscription {
	compact := "subscribe-token-" + eventID
	return agentprovider.EventSubscription{
		EventID: eventID, Agent: agent, Resource: resource,
		ConfirmationKey: jose.JWK{
			Kty: "OKP", Crv: "Ed25519", Alg: "Ed25519",
			X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		TokenExpiresAt: now.Add(time.Hour), MaxUses: maxUses,
		CompactToken: compact, TokenSHA256: sha256.Sum256([]byte(compact)),
	}
}

func eventInboxDelivery(eventID, agent, resource, token string, payload []byte, now time.Time) agentprovider.EventDelivery {
	contentType := ""
	if len(payload) > 0 {
		contentType = "application/json"
	}
	return agentprovider.EventDelivery{
		Fingerprint: events.Fingerprint(token, contentType, payload),
		EventID:     eventID, Agent: agent, Resource: resource,
		Token: token, TokenSHA256: sha256.Sum256([]byte(token)),
		Payload: payload, PayloadSHA256: sha256.Sum256(payload),
		ContentType: contentType, ReceivedAt: now,
	}
}

// EventInboxReaderStore is an Events inbox with its AP-to-Agent read path.
type EventInboxReaderStore interface {
	agentprovider.EventInboxStore
	agentprovider.EventInboxReader
}

// EventInboxReaderContract constructs a fresh empty inbox that also
// implements agentprovider.EventInboxReader.
type EventInboxReaderContract struct {
	New func(testing.TB) EventInboxReaderStore
}

// RunEventInboxReader checks the read path from the inbox to its Agents:
// accepted deliveries are pending for their own Agent only, oldest first,
// with the exact token and payload bytes and independent of caller memory;
// an exact replay is not queued twice; and an acknowledged delivery leaves
// the pending list while its replay stays a duplicate.
func RunEventInboxReader(t *testing.T, contract EventInboxReaderContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: EventInboxReaderContract.New is required")
	}
	ctx := context.Background()
	now := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	const (
		agent    = "aauth:agent@ap.example"
		other    = "aauth:other@ap.example"
		resource = "https://resource.example"
	)
	store := contract.New(t)
	if pending, err := store.PendingEvents(ctx, agent); err != nil || len(pending) != 0 {
		t.Fatalf("PendingEvents on an empty inbox = %d, %v", len(pending), err)
	}
	mine := eventInboxSubscription("event-mine", agent, resource, 0, now)
	theirs := eventInboxSubscription("event-theirs", other, resource, 0, now)
	for _, subscription := range []agentprovider.EventSubscription{mine, theirs} {
		if err := store.CommitSubscription(ctx, subscription); err != nil {
			t.Fatalf("CommitSubscription %s = %v", subscription.EventID, err)
		}
	}
	firstPayload := []byte(`{"slot":"10:00"}`)
	first := eventInboxDelivery(mine.EventID, agent, resource, "token-first", firstPayload, now)
	second := eventInboxDelivery(mine.EventID, agent, resource, "token-second", nil, now.Add(time.Second))
	foreign := eventInboxDelivery(theirs.EventID, other, resource, "token-foreign", []byte(`{}`), now)
	for _, delivery := range []agentprovider.EventDelivery{first, second, foreign} {
		if _, err := store.AcceptEvent(ctx, delivery); err != nil {
			t.Fatalf("AcceptEvent %s = %v", delivery.Token, err)
		}
	}
	original := append([]byte(nil), firstPayload...)
	firstPayload[0] = 'x'
	replay := eventInboxDelivery(mine.EventID, agent, resource, "token-first", original, now)
	if accepted, err := store.AcceptEvent(ctx, replay); err != nil || !accepted.Duplicate {
		t.Fatalf("exact replay = %#v, %v; want a duplicate", accepted, err)
	}

	pending, err := store.PendingEvents(ctx, agent)
	if err != nil {
		t.Fatalf("PendingEvents = %v", err)
	}
	if len(pending) != 2 || pending[0].Fingerprint != first.Fingerprint || pending[1].Fingerprint != second.Fingerprint {
		t.Fatalf("PendingEvents = %d deliveries; want the two accepted for this Agent, oldest first", len(pending))
	}
	if pending[0].Token != "token-first" || !bytes.Equal(pending[0].Payload, original) ||
		pending[0].ContentType != "application/json" || pending[0].EventID != mine.EventID ||
		pending[0].Resource != resource || pending[0].Agent != agent {
		t.Fatalf("pending delivery = %#v; want the exact accepted token and payload", pending[0])
	}
	if len(pending[1].Payload) != 0 || pending[1].ContentType != "" {
		t.Fatalf("bodyless pending delivery = %#v", pending[1])
	}
	pending[0].Payload[0] = 'y'
	again, err := store.PendingEvents(ctx, agent)
	if err != nil || len(again) != 2 || !bytes.Equal(again[0].Payload, original) {
		t.Fatalf("pending payload aliases a returned copy: %v", err)
	}

	if err := store.AcknowledgeEvent(ctx, other, first.Fingerprint); err != nil {
		t.Fatalf("AcknowledgeEvent for another Agent = %v", err)
	}
	if err := store.AcknowledgeEvent(ctx, agent, first.Fingerprint); err != nil {
		t.Fatalf("AcknowledgeEvent = %v", err)
	}
	if err := store.AcknowledgeEvent(ctx, agent, first.Fingerprint); err != nil {
		t.Fatalf("repeated AcknowledgeEvent = %v", err)
	}
	pending, err = store.PendingEvents(ctx, agent)
	if err != nil || len(pending) != 1 || pending[0].Fingerprint != second.Fingerprint {
		t.Fatalf("PendingEvents after acknowledgment = %d, %v; want only the second delivery", len(pending), err)
	}
	if accepted, err := store.AcceptEvent(ctx, replay); err != nil || !accepted.Duplicate {
		t.Fatalf("replay after acknowledgment = %#v, %v; want a duplicate", accepted, err)
	}
	if pending, err = store.PendingEvents(ctx, agent); err != nil || len(pending) != 1 {
		t.Fatalf("replay after acknowledgment queued the delivery again: %d, %v", len(pending), err)
	}
	foreignPending, err := store.PendingEvents(ctx, other)
	if err != nil || len(foreignPending) != 1 || foreignPending[0].Fingerprint != foreign.Fingerprint {
		t.Fatalf("PendingEvents for the other Agent = %d, %v", len(foreignPending), err)
	}
}
