package agent_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/events"
)

func TestAgentRegistersContextBeforePublicSubscriptionAndAcceptsDistinctEvents(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	store := &agentEventStore{}
	registrationCalls := 0
	httpClient := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		registrationCalls++
		if store.context.EventID != "event-1" {
			t.Fatal("registration became visible before Agent context was retained")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if request.Method != http.MethodPost || request.URL.String() != protocol.resourceID+"/events/subscribe" ||
			string(body) != `{"event_types":["slot.available"]}` {
			t.Fatalf("registration = %s %s %q", request.Method, request.URL, body)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    request,
		}, nil
	})}
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: protocol.agentID, SigningKey: protocol.agentKey,
		AgentToken: protocol.agentToken, KeyResolver: protocol.resolver,
		HTTPClient: httpClient, Clock: protocol.clock,
		Events: &agent.EventsConfig{Store: store},
	})
	if err != nil {
		t.Fatal(err)
	}
	subscribeToken, err := events.MintSubscribeToken(protocol.agentProviderID, protocol.agentProviderKey, events.SubscribeTokenRequest{
		Agent: protocol.agentID, Resource: protocol.resourceID,
		ConfirmationKey: protocol.agentKey.PublicJWK(), EventID: "event-1", Lifetime: time.Hour, MaxUses: 2,
	}, protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	contextValue := []byte(`{"purpose":"appointment waitlist"}`)
	subscription, err := client.RegisterPublicSubscription(context.Background(), agent.PublicSubscriptionInput{
		Endpoint: protocol.resourceID + "/events/subscribe", SubscribeToken: subscribeToken,
		Parameters: []byte(`{"event_types":["slot.available"]}`), ContentType: "application/json",
		Context: contextValue,
	})
	if err != nil {
		t.Fatal(err)
	}
	if subscription.EventID != "event-1" || subscription.Resource != protocol.resourceID || registrationCalls != 1 {
		t.Fatalf("subscription = %#v, calls = %d", subscription, registrationCalls)
	}
	contextValue[0] = 'x'
	if bytes.Equal(contextValue, store.context.Context) {
		t.Fatal("Agent event context aliases caller memory")
	}

	firstToken, err := events.MintEventToken(protocol.resourceID, protocol.resourceKey, events.EventTokenRequest{
		Agent: protocol.agentID, EventID: "event-1", Lifetime: 5 * time.Minute,
	}, protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	firstPayload := []byte(`{"event_type":"slot.available","slot":"10:00"}`)
	first, err := client.AcceptEvent(context.Background(), agent.EventDeliveryInput{
		EventToken: firstToken, Payload: firstPayload, ContentType: "application/json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Duplicate || first.EventID != "event-1" || first.Resource != protocol.resourceID ||
		string(first.Context) != `{"purpose":"appointment waitlist"}` || !bytes.Equal(first.Payload, firstPayload) {
		t.Fatalf("first received event = %#v", first)
	}
	replayed, err := client.AcceptEvent(context.Background(), agent.EventDeliveryInput{
		EventToken: firstToken, Payload: firstPayload, ContentType: "application/json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Duplicate {
		t.Fatal("exact delivery replay was returned as new")
	}

	protocol.now = protocol.now.Add(time.Second)
	secondToken, err := events.MintEventToken(protocol.resourceID, protocol.resourceKey, events.EventTokenRequest{
		Agent: protocol.agentID, EventID: "event-1", Lifetime: 5 * time.Minute,
	}, protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	secondPayload := []byte(`{"event_type":"slot.available","slot":"11:00"}`)
	second, err := client.AcceptEvent(context.Background(), agent.EventDeliveryInput{
		EventToken: secondToken, Payload: secondPayload, ContentType: "application/json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Duplicate || store.acceptedCount != 2 {
		t.Fatalf("second received event = %#v, accepted = %d", second, store.acceptedCount)
	}
}

func TestAgentRegistersProtectedSubscriptionAtOpaqueTicketURL(t *testing.T) {
	t.Parallel()
	protocol := newTestProtocol(t)
	store := &agentEventStore{}
	calls := 0
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: protocol.agentID, SigningKey: protocol.agentKey,
		AgentToken: protocol.agentToken, KeyResolver: protocol.resolver,
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			if request.Method != http.MethodPost || request.URL.String() != protocol.resourceID+"/events/protected/ticket-1" ||
				store.context.EventID != "event-protected" {
				t.Fatalf("protected registration = %s %s context=%#v", request.Method, request.URL, store.context)
			}
			return &http.Response{
				StatusCode: http.StatusOK, Header: http.Header{"Cache-Control": []string{"no-store"}},
				Body: io.NopCloser(strings.NewReader("")), Request: request,
			}, nil
		})},
		Clock: protocol.clock, Events: &agent.EventsConfig{Store: store},
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := events.MintSubscribeToken(protocol.agentProviderID, protocol.agentProviderKey, events.SubscribeTokenRequest{
		Agent: protocol.agentID, Resource: protocol.resourceID,
		ConfirmationKey: protocol.agentKey.PublicJWK(), EventID: "event-protected", Lifetime: time.Hour,
	}, protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.RegisterProtectedSubscription(context.Background(), agent.ProtectedSubscriptionInput{
		TicketURL: protocol.resourceID + "/events/protected/ticket-1", SubscribeToken: compact,
		Context: []byte(`{"purpose":"protected waitlist"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.EventID != "event-protected" || result.Resource != protocol.resourceID || calls != 1 {
		t.Fatalf("subscription = %#v, calls=%d", result, calls)
	}
}

type agentEventStore struct {
	context       agent.EventContext
	accepted      map[events.DeliveryFingerprint]agent.AcceptedEvent
	acceptedCount int
}

func (store *agentEventStore) BindContext(_ context.Context, record agent.EventContext) error {
	record.Context = append([]byte(nil), record.Context...)
	store.context = record
	if store.accepted == nil {
		store.accepted = make(map[events.DeliveryFingerprint]agent.AcceptedEvent)
	}
	return nil
}

func (store *agentEventStore) AcceptEvent(_ context.Context, candidate agent.AcceptedEvent) (agent.EventAcceptance, error) {
	if candidate.EventID != store.context.EventID || candidate.Resource != store.context.Resource {
		return agent.EventAcceptance{}, agent.ErrEventContextNotFound
	}
	if _, exists := store.accepted[candidate.Fingerprint]; exists {
		return agent.EventAcceptance{Context: cloneAgentEventContext(store.context), Duplicate: true}, nil
	}
	candidate.EventToken = strings.Clone(candidate.EventToken)
	candidate.Payload = append([]byte(nil), candidate.Payload...)
	store.accepted[candidate.Fingerprint] = candidate
	store.acceptedCount++
	return agent.EventAcceptance{Context: cloneAgentEventContext(store.context)}, nil
}

func cloneAgentEventContext(record agent.EventContext) agent.EventContext {
	record.Context = append([]byte(nil), record.Context...)
	return record
}
