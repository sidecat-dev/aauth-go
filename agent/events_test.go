package agent_test

import (
	"bytes"
	"context"
	"errors"
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

	firstPayload := []byte(`{"event_type":"slot.available","slot":"10:00"}`)
	firstToken, err := events.MintEventToken(protocol.resourceID, protocol.resourceKey, events.EventTokenRequest{
		Agent: protocol.agentID, EventID: "event-1", Payload: firstPayload, Lifetime: 5 * time.Minute,
	}, protocol.now)
	if err != nil {
		t.Fatal(err)
	}
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
	secondPayload := []byte(`{"event_type":"slot.available","slot":"11:00"}`)
	secondToken, err := events.MintEventToken(protocol.resourceID, protocol.resourceKey, events.EventTokenRequest{
		Agent: protocol.agentID, EventID: "event-1", Payload: secondPayload, Lifetime: 5 * time.Minute,
	}, protocol.now)
	if err != nil {
		t.Fatal(err)
	}
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

func TestAgentRefusesEventsItMustNotActOn(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	store := &agentEventStore{}
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: protocol.agentID, SigningKey: protocol.agentKey,
		AgentToken: protocol.agentToken, KeyResolver: protocol.resolver,
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
		})},
		Clock: protocol.clock, Events: &agent.EventsConfig{Store: store},
	})
	if err != nil {
		t.Fatal(err)
	}
	subscribeToken, err := events.MintSubscribeToken(protocol.agentProviderID, protocol.agentProviderKey, events.SubscribeTokenRequest{
		Agent: protocol.agentID, Resource: protocol.resourceID,
		ConfirmationKey: protocol.agentKey.PublicJWK(), EventID: "event-1", Lifetime: time.Hour,
	}, protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RegisterPublicSubscription(context.Background(), agent.PublicSubscriptionInput{
		Endpoint: protocol.resourceID + "/events/subscribe", SubscribeToken: subscribeToken,
		Context: []byte(`{"purpose":"appointment waitlist"}`),
	}); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"event_type":"slot.available","slot":"10:00"}`)
	mint := func(agentID string, payload []byte, at time.Time) string {
		t.Helper()
		compact, err := events.MintEventToken(protocol.resourceID, protocol.resourceKey, events.EventTokenRequest{
			Agent: agentID, EventID: "event-1", Payload: payload, Lifetime: 5 * time.Minute,
		}, at)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	tests := []struct {
		name    string
		input   agent.EventDeliveryInput
		wantErr error
	}{
		{
			name: "expired event token",
			input: agent.EventDeliveryInput{
				EventToken: mint(protocol.agentID, payload, protocol.now.Add(-5*time.Minute)), Payload: payload, ContentType: "application/json",
			},
		},
		{
			name: "audience differs only in case",
			input: agent.EventDeliveryInput{
				EventToken: mint("aauth:Reader@ap.example", payload, protocol.now), Payload: payload, ContentType: "application/json",
			},
		},
		{
			name: "audience names another Agent",
			input: agent.EventDeliveryInput{
				EventToken: mint("aauth:other@ap.example", payload, protocol.now), Payload: payload, ContentType: "application/json",
			},
		},
		{
			name: "payload altered after the Resource signed it",
			input: agent.EventDeliveryInput{
				EventToken: mint(protocol.agentID, payload, protocol.now),
				Payload:    []byte(`{"event_type":"slot.available","slot":"11:00"}`), ContentType: "application/json",
			},
			wantErr: events.ErrEventBodyMismatch,
		},
		{
			name: "declared payload not delivered",
			input: agent.EventDeliveryInput{
				EventToken: mint(protocol.agentID, payload, protocol.now),
			},
			wantErr: events.ErrEventBodyMismatch,
		},
		{
			name: "payload added to a bodyless event",
			input: agent.EventDeliveryInput{
				EventToken: mint(protocol.agentID, nil, protocol.now), Payload: payload, ContentType: "application/json",
			},
			wantErr: events.ErrEventBodyMismatch,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := store.acceptedCount
			received, err := client.AcceptEvent(context.Background(), test.input)
			if err == nil {
				t.Fatalf("AcceptEvent() = %#v; want refusal", received)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("AcceptEvent() error = %v, want %v", err, test.wantErr)
			}
			if store.acceptedCount != before || len(received.Payload) != 0 || received.EventID != "" {
				t.Fatalf("refused event reached the store or the caller: %#v, accepted=%d", received, store.acceptedCount)
			}
		})
	}
	accepted, err := client.AcceptEvent(context.Background(), agent.EventDeliveryInput{
		EventToken: mint(protocol.agentID, payload, protocol.now), Payload: payload, ContentType: "application/json",
	})
	if err != nil || accepted.Duplicate || !bytes.Equal(accepted.Payload, payload) || store.acceptedCount != 1 {
		t.Fatalf("verified event = %#v, %v, accepted=%d", accepted, err, store.acceptedCount)
	}
	bodyless, err := client.AcceptEvent(context.Background(), agent.EventDeliveryInput{
		EventToken: mint(protocol.agentID, nil, protocol.now),
	})
	if err != nil || bodyless.Duplicate || len(bodyless.Payload) != 0 || store.acceptedCount != 2 {
		t.Fatalf("verified bodyless event = %#v, %v, accepted=%d", bodyless, err, store.acceptedCount)
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
