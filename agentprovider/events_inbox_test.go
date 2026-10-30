package agentprovider_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestAgentProviderHandsTheAgentTheExactAcceptedBytes(t *testing.T) {
	t.Parallel()

	fixture := newEventEndpointFixture(t)
	store := &readableEventInbox{}
	server, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "provider-reader-key", 0x49),
		Clock: fixture.clock, NewID: func() string { return "unused" },
		Events: &agentprovider.EventsConfig{
			EventEndpoint: "https://ap.example/events", NewEventID: func() string { return "unused" },
			KeyResolver: signaturekey.StaticKeyResolver{
				{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: fixture.resourceKey.ID()}: fixture.resourceKey.PublicJWK(),
			},
			Store: store,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const agent = "aauth:agent@ap.example"
	payload := []byte(`{"event_type":"slot.available","slot":"10:00"}`)
	compact := fixture.mint(t, events.EventTokenRequest{
		Agent: agent, EventID: "event-1", JTI: "jti-1", Payload: payload, Lifetime: time.Minute,
	}, fixture.now)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, fixture.signed(t, compact, fixture.resourceKey, payload, "application/json"))
	if response.Code != http.StatusAccepted {
		t.Fatalf("delivery status = %d, body %s", response.Code, response.Body.String())
	}

	pending, err := server.PendingEvents(context.Background(), agent)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Token != compact || !bytes.Equal(pending[0].Payload, payload) ||
		pending[0].ContentType != "application/json" {
		t.Fatalf("pending deliveries = %#v", pending)
	}
	if other, err := server.PendingEvents(context.Background(), "aauth:other@ap.example"); err != nil || len(other) != 0 {
		t.Fatalf("another Agent's pending deliveries = %d, %v", len(other), err)
	}

	store.pending[0].Payload = []byte(`{"event_type":"slot.available","slot":"altered"}`)
	if _, err := server.PendingEvents(context.Background(), agent); err == nil {
		t.Fatal("PendingEvents handed over a payload that no longer matches what the AP accepted")
	}
	store.pending[0].Payload = append([]byte(nil), payload...)
	store.misroute = true
	store.pending[0].Agent = "aauth:other@ap.example"
	if _, err := server.PendingEvents(context.Background(), agent); err == nil {
		t.Fatal("PendingEvents handed over a delivery the store returned for another Agent")
	}
	store.misroute = false
	store.pending[0].Agent = agent

	if err := server.AcknowledgeEvent(context.Background(), agent, pending[0].Fingerprint); err != nil {
		t.Fatal(err)
	}
	if pending, err := server.PendingEvents(context.Background(), agent); err != nil || len(pending) != 0 {
		t.Fatalf("pending deliveries after acknowledgment = %d, %v", len(pending), err)
	}

	if _, err := fixture.server.PendingEvents(context.Background(), agent); !errors.Is(err, agentprovider.ErrEventInboxNotReadable) {
		t.Fatalf("PendingEvents on a store without a read path = %v, want ErrEventInboxNotReadable", err)
	}
}

// readableEventInbox is an inbox with a read path. With misroute set it
// returns every delivery to any Agent, as a faulty store might.
type readableEventInbox struct {
	pending  []agentprovider.EventDelivery
	misroute bool
}

func (*readableEventInbox) CommitSubscription(context.Context, agentprovider.EventSubscription) error {
	return nil
}

func (store *readableEventInbox) AcceptEvent(_ context.Context, delivery agentprovider.EventDelivery) (agentprovider.EventAcceptance, error) {
	delivery.Payload = append([]byte(nil), delivery.Payload...)
	store.pending = append(store.pending, delivery)
	return agentprovider.EventAcceptance{}, nil
}

func (store *readableEventInbox) PendingEvents(_ context.Context, agent string) ([]agentprovider.EventDelivery, error) {
	var pending []agentprovider.EventDelivery
	for _, delivery := range store.pending {
		if delivery.Agent == agent || store.misroute {
			delivery.Payload = append([]byte(nil), delivery.Payload...)
			pending = append(pending, delivery)
		}
	}
	return pending, nil
}

func (store *readableEventInbox) AcknowledgeEvent(_ context.Context, agent string, fingerprint events.DeliveryFingerprint) error {
	kept := store.pending[:0]
	for _, delivery := range store.pending {
		if delivery.Agent != agent || delivery.Fingerprint != fingerprint {
			kept = append(kept, delivery)
		}
	}
	store.pending = kept
	return nil
}
