package resource

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestProtectedEventTicketBindsPriorAgentAndRegistersOnce(t *testing.T) {
	now := time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "protected-event-resource", 0xd1)
	providerKey := testSigningKey(t, "protected-event-provider", 0xd2)
	agentKey := testSigningKey(t, "protected-event-agent", 0xd3)
	store := newProtectedEventStore()
	policyCalls := 0
	service, err := NewEventService(EventServiceConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey,
		KeyResolver: signaturekey.StaticKeyResolver{
			{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
		},
		Clock: clock, SubscriptionEndpoint: resourceIssuer + "/events/public", Store: store,
		RegisterPublic: func(context.Context, PublicSubscriptionRequest) (PublicSubscriptionDecision, error) {
			return PublicSubscriptionDecision{}, nil
		},
		Protected: &ProtectedSubscriptionConfig{
			EndpointPrefix:        resourceIssuer + "/events/protected/",
			NewTicketID:           func() string { return "ticket-1" },
			MaximumTicketLifetime: 5 * time.Minute,
			Register: func(_ context.Context, request ProtectedSubscriptionRequest) (PublicSubscriptionDecision, error) {
				policyCalls++
				if policyCalls > 1 {
					return PublicSubscriptionDecision{}, ErrEventSubscriptionDenied
				}
				if request.Ticket.Agent != "aauth:agent@ap.example" || string(request.Ticket.Context) != `{"operation":"appointments.create"}` ||
					request.Token.EventID != "event-1" {
					t.Fatalf("protected request = %#v", request)
				}
				return PublicSubscriptionDecision{ExpiresAt: now.Add(time.Hour)}, nil
			},
		},
		ResolveEventEndpoint: EventEndpointResolverFunc(func(context.Context, string) (string, error) {
			return "https://ap.example/events", nil
		}),
		AdmitEventEndpoint: func(context.Context, string) error { return nil },
		HTTPClient:         &http.Client{},
	})
	if err != nil {
		t.Fatal(err)
	}
	contextValue := []byte(`{"operation":"appointments.create"}`)
	ticket, err := service.IssueProtectedSubscriptionTicket(context.Background(), ProtectedSubscriptionTicketRequest{
		Agent: "aauth:agent@ap.example", Context: contextValue, Lifetime: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ticket.URL != resourceIssuer+"/events/protected/ticket-1" || !ticket.ExpiresAt.Equal(now.Add(2*time.Minute)) || store.createCalls != 1 {
		t.Fatalf("ticket = %#v, create calls=%d", ticket, store.createCalls)
	}
	contextValue[0] = 'x'
	if store.ticket.Context[0] != '{' {
		t.Fatal("ticket context aliases caller memory")
	}
	subscribeToken, err := events.MintSubscribeToken("https://ap.example", providerKey, events.SubscribeTokenRequest{
		Agent: "aauth:agent@ap.example", Resource: resourceIssuer,
		ConfirmationKey: agentKey.PublicJWK(), EventID: "event-1", Lifetime: time.Hour,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"event_types":["slot.available"]}`)
	register := func(token string, key jose.SigningKey, body []byte) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, ticket.URL, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := signaturekey.SignJWTRequestWithOptions(
			request, key, token, clock,
			signaturekey.SignOptions{AdditionalComponents: []string{"content-type", "content-digest"}},
		); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		service.ProtectedSubscriptionHandler().ServeHTTP(response, request)
		return response
	}
	first := register(subscribeToken, agentKey, body)
	if first.Code != http.StatusOK || store.committed.EventID != "event-1" || store.commitCalls != 1 {
		t.Fatalf("first registration = %d %s, committed=%#v calls=%d", first.Code, first.Body.String(), store.committed, store.commitCalls)
	}
	now = now.Add(2 * time.Minute)
	replay := register(subscribeToken, agentKey, body)
	if replay.Code != http.StatusOK || store.commitCalls != 1 || policyCalls != 1 {
		t.Fatalf("exact replay = %d %s, commits=%d policy=%d", replay.Code, replay.Body.String(), store.commitCalls, policyCalls)
	}
	changed := register(subscribeToken, agentKey, []byte(`{"event_types":["other"]}`))
	if changed.Code != http.StatusConflict {
		t.Fatalf("changed replay = %d %s", changed.Code, changed.Body.String())
	}
}

func TestProtectedEventTicketCloaksWrongAgentAndRefusesExpiry(t *testing.T) {
	now := time.Date(2026, 9, 1, 1, 15, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "protected-event-resource-errors", 0xd4)
	providerKey := testSigningKey(t, "protected-event-provider-errors", 0xd5)
	agentKey := testSigningKey(t, "protected-event-agent-errors", 0xd6)
	otherKey := testSigningKey(t, "protected-event-other-errors", 0xd7)
	store := newProtectedEventStore()
	policyCalls := 0
	service, err := NewEventService(EventServiceConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey,
		KeyResolver: signaturekey.StaticKeyResolver{
			{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
		},
		Clock: clock, SubscriptionEndpoint: resourceIssuer + "/events/public", Store: store,
		RegisterPublic: func(context.Context, PublicSubscriptionRequest) (PublicSubscriptionDecision, error) {
			return PublicSubscriptionDecision{}, nil
		},
		Protected: &ProtectedSubscriptionConfig{
			EndpointPrefix: resourceIssuer + "/events/protected/", NewTicketID: func() string { return "ticket-errors" },
			MaximumTicketLifetime: time.Minute,
			Register: func(context.Context, ProtectedSubscriptionRequest) (PublicSubscriptionDecision, error) {
				policyCalls++
				return PublicSubscriptionDecision{}, nil
			},
		},
		ResolveEventEndpoint: EventEndpointResolverFunc(func(context.Context, string) (string, error) {
			return "https://ap.example/events", nil
		}),
		AdmitEventEndpoint: func(context.Context, string) error { return nil },
		HTTPClient:         &http.Client{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := service.IssueProtectedSubscriptionTicket(context.Background(), ProtectedSubscriptionTicketRequest{
		Agent: "aauth:agent@ap.example", Context: []byte("authorized interaction"), Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	register := func(agent string, key jose.SigningKey) *httptest.ResponseRecorder {
		compact, err := events.MintSubscribeToken("https://ap.example", providerKey, events.SubscribeTokenRequest{
			Agent: agent, Resource: resourceIssuer, ConfirmationKey: key.PublicJWK(),
			EventID: "event-errors", Lifetime: time.Hour,
		}, time.Date(2026, 9, 1, 1, 15, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, ticket.URL, nil)
		if err := signaturekey.SignJWTRequestWithOptions(
			request, key, compact, clock,
			signaturekey.SignOptions{AdditionalComponents: []string{"content-digest"}},
		); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		service.ProtectedSubscriptionHandler().ServeHTTP(response, request)
		return response
	}
	wrongAgent := register("aauth:other@ap.example", otherKey)
	if wrongAgent.Code != http.StatusNotFound || !strings.Contains(wrongAgent.Body.String(), `"error":"event_ticket_not_found"`) {
		t.Fatalf("wrong Agent registration = %d %s", wrongAgent.Code, wrongAgent.Body.String())
	}
	now = now.Add(time.Minute)
	expired := register("aauth:agent@ap.example", agentKey)
	if expired.Code != http.StatusGone || !strings.Contains(expired.Body.String(), `"error":"event_ticket_expired"`) {
		t.Fatalf("expired registration = %d %s", expired.Code, expired.Body.String())
	}
	if policyCalls != 0 {
		t.Fatalf("policy calls = %d, want 0", policyCalls)
	}
}

type protectedEventStore struct {
	mu          sync.Mutex
	ticket      ProtectedSubscriptionTicket
	committed   EventSubscription
	createCalls int
	commitCalls int
}

func newProtectedEventStore() *protectedEventStore { return &protectedEventStore{} }

func (store *protectedEventStore) CreateProtectedSubscriptionTicket(_ context.Context, ticket ProtectedSubscriptionTicket) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.createCalls++
	if store.ticket.ID != "" {
		return ErrProtectedSubscriptionConflict
	}
	store.ticket = cloneProtectedSubscriptionTicket(ticket)
	return nil
}

func (store *protectedEventStore) LoadProtectedSubscriptionTicket(_ context.Context, id, agent string, at time.Time) (ProtectedSubscriptionTicket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.ticket.ID != id || store.ticket.Agent != agent {
		return ProtectedSubscriptionTicket{}, ErrProtectedSubscriptionNotFound
	}
	if !at.Before(store.ticket.ExpiresAt) && store.ticket.UsedAt.IsZero() {
		return ProtectedSubscriptionTicket{}, ErrProtectedSubscriptionExpired
	}
	return cloneProtectedSubscriptionTicket(store.ticket), nil
}

func (store *protectedEventStore) CommitProtectedSubscription(_ context.Context, expected ProtectedSubscriptionTicket, candidate EventSubscription) (EventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.commitCalls++
	if !reflect.DeepEqual(store.ticket, expected) {
		return EventSubscription{}, ErrProtectedSubscriptionConflict
	}
	if store.committed.EventID != "" {
		if store.committed.RegistrationSHA256 == candidate.RegistrationSHA256 {
			return cloneEventSubscription(store.committed), nil
		}
		return EventSubscription{}, ErrProtectedSubscriptionConflict
	}
	store.committed = cloneEventSubscription(candidate)
	store.ticket.UsedAt = candidate.RegisteredAt
	store.ticket.RegistrationSHA256 = candidate.RegistrationSHA256
	return cloneEventSubscription(store.committed), nil
}

func (store *protectedEventStore) Commit(_ context.Context, record EventSubscription) (EventSubscription, error) {
	return EventSubscription{}, errors.New("public commit is not used")
}

func (store *protectedEventStore) Load(_ context.Context, ref EventSubscriptionRef) (EventSubscription, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.committed.AgentProvider != ref.AgentProvider || store.committed.EventID != ref.EventID {
		return EventSubscription{}, ErrEventSubscriptionNotFound
	}
	return cloneEventSubscription(store.committed), nil
}

var _ ProtectedSubscriptionStore = (*protectedEventStore)(nil)
