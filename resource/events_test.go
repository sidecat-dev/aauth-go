package resource

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestResourceRegistersAndDeliversPublicEventSubscription(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC)
	resourceKey := testSigningKey(t, "events-resource-key", 0x51)
	providerKey := testSigningKey(t, "events-provider-key", 0x52)
	agentKey := testSigningKey(t, "events-agent-key", 0x53)
	store := &eventSubscriptionStore{}
	endpointCalls := 0
	deliveryCalls := 0
	service, err := NewEventService(EventServiceConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey,
		KeyResolver: signaturekey.StaticKeyResolver{
			{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
		},
		Clock:                aauth.ClockFunc(func() time.Time { return now }),
		SubscriptionEndpoint: "https://resource.example/events/subscribe",
		Store:                store,
		RegisterPublic: func(_ context.Context, request PublicSubscriptionRequest) (PublicSubscriptionDecision, error) {
			if request.Token.EventID != "event-1" || request.ContentType != "application/json" {
				t.Fatalf("public subscription request = %#v", request)
			}
			return PublicSubscriptionDecision{ExpiresAt: now.Add(24 * time.Hour)}, nil
		},
		ResolveEventEndpoint: EventEndpointResolverFunc(func(_ context.Context, provider string) (string, error) {
			endpointCalls++
			if provider != "https://ap.example" {
				t.Fatalf("provider = %q", provider)
			}
			return "https://ap.example/events", nil
		}),
		AdmitEventEndpoint: func(context.Context, string) error { return nil },
		HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			deliveryCalls++
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			if request.URL.String() != "https://ap.example/events" || string(body) != `{"event_type":"slot.available"}` ||
				!strings.Contains(request.Header.Get("Signature-Key"), "self-jwt") {
				t.Fatalf("delivery request = %s %q headers=%v", request.URL, body, request.Header)
			}
			return &http.Response{
				StatusCode: http.StatusAccepted,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"remaining_uses":1}`)),
				Request:    request,
			}, nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	subscribeToken, err := events.MintSubscribeToken("https://ap.example", providerKey, events.SubscribeTokenRequest{
		Agent: "aauth:agent@ap.example", Resource: resourceIssuer,
		ConfirmationKey: agentKey.PublicJWK(), EventID: "event-1", Lifetime: time.Hour, MaxUses: 2,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	registrationBody := []byte(`{"event_types":["slot.available"]}`)
	registration, err := http.NewRequest(
		http.MethodPost,
		"https://resource.example/events/subscribe",
		bytes.NewReader(registrationBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	registration.Header.Set("Content-Type", "application/json")
	registration.Header.Set("X-Registration-ID", "registration-1")
	registration.Host = "resource.example"
	registration.URL.Scheme = ""
	registration.URL.Host = ""
	if err := signaturekey.SignJWTRequestWithOptions(
		registration, agentKey, subscribeToken, aauth.ClockFunc(func() time.Time { return now }),
		signaturekey.SignOptions{AdditionalComponents: []string{"content-type", "content-digest", "x-registration-id"}},
	); err != nil {
		t.Fatal(err)
	}
	registrationResponse := &responseRecorder{header: make(http.Header)}
	service.PublicSubscriptionHandler().ServeHTTP(registrationResponse, registration)
	if registrationResponse.status != http.StatusOK {
		t.Fatalf("registration response = %d %s", registrationResponse.status, registrationResponse.body.String())
	}
	if store.committed.EventID != "event-1" || store.committed.AgentProvider != "https://ap.example" ||
		store.committed.Agent != "aauth:agent@ap.example" || store.committed.MaxUses != 2 ||
		!bytes.Equal(store.committed.Parameters, registrationBody) || !store.committed.ExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("committed subscription = %#v", store.committed)
	}

	prepared, err := service.PrepareEvent(context.Background(), EventInput{
		AgentProvider: "https://ap.example", EventID: "event-1", ContentType: "application/json",
		Payload: []byte(`{"event_type":"slot.available"}`), Lifetime: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if endpointCalls != 0 || deliveryCalls != 0 {
		t.Fatalf("preparation performed delivery I/O: endpoint=%d delivery=%d", endpointCalls, deliveryCalls)
	}
	result, err := service.DeliverEvent(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Limited || result.RemainingUses != 1 || endpointCalls != 1 || deliveryCalls != 1 {
		t.Fatalf("delivery result = %#v, endpoint=%d delivery=%d", result, endpointCalls, deliveryCalls)
	}
	if _, err := service.DeliverEvent(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	if endpointCalls != 2 || deliveryCalls != 2 {
		t.Fatalf("exact retry calls: endpoint=%d delivery=%d", endpointCalls, deliveryCalls)
	}
}

func TestResourceSeparatesBodylessRegistrationsWithSameEventIDByAgentProvider(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 22, 15, 0, 0, time.UTC)
	resourceKey := testSigningKey(t, "events-shared-id-resource-key", 0x54)
	providerAKey := testSigningKey(t, "events-provider-a-key", 0x55)
	providerBKey := testSigningKey(t, "events-provider-b-key", 0x56)
	agentAKey := testSigningKey(t, "events-agent-a-key", 0x57)
	agentBKey := testSigningKey(t, "events-agent-b-key", 0x58)
	store := &multiEventSubscriptionStore{records: make(map[string]EventSubscription)}
	service, err := NewEventService(EventServiceConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey,
		KeyResolver: signaturekey.StaticKeyResolver{
			{Issuer: "https://ap-a.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerAKey.ID()}: providerAKey.PublicJWK(),
			{Issuer: "https://ap-b.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerBKey.ID()}: providerBKey.PublicJWK(),
		},
		Clock:                aauth.ClockFunc(func() time.Time { return now }),
		SubscriptionEndpoint: resourceIssuer,
		Store:                store,
		RegisterPublic: func(_ context.Context, request PublicSubscriptionRequest) (PublicSubscriptionDecision, error) {
			if len(request.Parameters) != 0 || request.ContentType != "" {
				t.Fatalf("bodyless registration = %#v", request)
			}
			return PublicSubscriptionDecision{}, nil
		},
		ResolveEventEndpoint: EventEndpointResolverFunc(func(_ context.Context, provider string) (string, error) {
			return provider + "/", nil
		}),
		AdmitEventEndpoint: func(context.Context, string) error { return nil },
		HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	register := func(provider, agent string, providerKey, agentKey jose.SigningKey) {
		t.Helper()
		compact, err := events.MintSubscribeToken(provider, providerKey, events.SubscribeTokenRequest{
			Agent: agent, Resource: resourceIssuer, ConfirmationKey: agentKey.PublicJWK(),
			EventID: "shared-event", Lifetime: time.Hour,
		}, now)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodPost, resourceIssuer, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := signaturekey.SignJWTRequestWithOptions(
			request, agentKey, compact, aauth.ClockFunc(func() time.Time { return now }),
			signaturekey.SignOptions{AdditionalComponents: []string{"content-digest"}},
		); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		service.PublicSubscriptionHandler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("registration for %s = %d %s", provider, response.Code, response.Body.String())
		}
	}
	register("https://ap-a.example", "aauth:agent-a@ap-a.example", providerAKey, agentAKey)
	register("https://ap-b.example", "aauth:agent-b@ap-b.example", providerBKey, agentBKey)
	if len(store.records) != 2 {
		t.Fatalf("retained subscriptions = %d, want 2", len(store.records))
	}
	preparedA, err := service.PrepareEvent(context.Background(), EventInput{
		AgentProvider: "https://ap-a.example", EventID: "shared-event", Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	preparedB, err := service.PrepareEvent(context.Background(), EventInput{
		AgentProvider: "https://ap-b.example", EventID: "shared-event", Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if preparedA.agentProvider == preparedB.agentProvider || preparedA.agent == preparedB.agent {
		t.Fatalf("same-eid subscriptions collapsed: A=%#v B=%#v", preparedA, preparedB)
	}
	result, err := service.DeliverEvent(context.Background(), preparedA)
	if err != nil {
		t.Fatal(err)
	}
	if result.Limited {
		t.Fatalf("unlimited root-endpoint delivery = %#v", result)
	}
}

type multiEventSubscriptionStore struct {
	records map[string]EventSubscription
}

func (store *multiEventSubscriptionStore) Commit(_ context.Context, record EventSubscription) (EventSubscription, error) {
	key := record.AgentProvider + "\x00" + record.EventID
	if retained, ok := store.records[key]; ok {
		if retained.RegistrationSHA256 == record.RegistrationSHA256 {
			return cloneEventSubscription(retained), nil
		}
		return EventSubscription{}, ErrEventSubscriptionConflict
	}
	store.records[key] = cloneEventSubscription(record)
	return cloneEventSubscription(record), nil
}

func (store *multiEventSubscriptionStore) Load(_ context.Context, ref EventSubscriptionRef) (EventSubscription, error) {
	record, ok := store.records[ref.AgentProvider+"\x00"+ref.EventID]
	if !ok {
		return EventSubscription{}, ErrEventSubscriptionNotFound
	}
	return cloneEventSubscription(record), nil
}

type eventSubscriptionStore struct {
	committed EventSubscription
}

func (store *eventSubscriptionStore) Commit(_ context.Context, subscription EventSubscription) (EventSubscription, error) {
	store.committed = cloneEventSubscription(subscription)
	return cloneEventSubscription(store.committed), nil
}

func (store *eventSubscriptionStore) Load(_ context.Context, ref EventSubscriptionRef) (EventSubscription, error) {
	if ref.EventID != store.committed.EventID || ref.AgentProvider != store.committed.AgentProvider {
		return EventSubscription{}, ErrEventSubscriptionNotFound
	}
	return cloneEventSubscription(store.committed), nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type responseRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (response *responseRecorder) Header() http.Header { return response.header }
func (response *responseRecorder) WriteHeader(status int) {
	response.status = status
}
func (response *responseRecorder) Write(body []byte) (int, error) {
	if response.status == 0 {
		response.status = http.StatusOK
	}
	return response.body.Write(body)
}

func TestEventDeliveryValidatesBoundedRemainingUsesResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		want    int64
		wantErr bool
	}{
		{name: "valid", body: `{"remaining_uses":1}`, want: 1},
		{name: "missing", body: `{}`, wantErr: true},
		{name: "negative", body: `{"remaining_uses":-1}`, wantErr: true},
		{name: "not decremented", body: `{"remaining_uses":2}`, wantErr: true},
		{name: "above maximum", body: `{"remaining_uses":3}`, wantErr: true},
		{name: "ambiguous", body: `{"remaining_uses":1,"remaining_uses":0}`, wantErr: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			now := time.Date(2026, 8, 31, 22, 30, 0, 0, time.UTC)
			key := testSigningKey(t, "feedback-key-"+test.name, byte(len(test.name)+0x60))
			store := &eventSubscriptionStore{committed: EventSubscription{
				EventID: "event-1", AgentProvider: "https://ap.example", Agent: "aauth:agent@ap.example",
				MaxUses: 2,
			}}
			service, err := NewEventService(EventServiceConfig{
				Issuer: "https://resource.example", SigningKey: key,
				KeyResolver: signaturekey.StaticKeyResolver{}, Clock: aauth.ClockFunc(func() time.Time { return now }),
				SubscriptionEndpoint: "https://resource.example/events/subscribe", Store: store,
				RegisterPublic: func(context.Context, PublicSubscriptionRequest) (PublicSubscriptionDecision, error) {
					return PublicSubscriptionDecision{}, nil
				},
				ResolveEventEndpoint: EventEndpointResolverFunc(func(context.Context, string) (string, error) {
					return "https://ap.example/events", nil
				}),
				AdmitEventEndpoint: func(context.Context, string) error { return nil },
				HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusAccepted,
						Header:     http.Header{"Content-Type": []string{"application/json"}},
						Body:       io.NopCloser(strings.NewReader(test.body)),
						Request:    request,
					}, nil
				})},
			})
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := service.PrepareEvent(context.Background(), EventInput{
				AgentProvider: "https://ap.example", EventID: "event-1", ContentType: "application/json", Payload: []byte(`{}`), Lifetime: time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.DeliverEvent(context.Background(), prepared)
			if test.wantErr {
				var failure *EventDeliveryError
				if !errors.As(err, &failure) || !failure.Accepted {
					t.Fatalf("DeliverEvent() error = %#v, want accepted feedback error", err)
				}
				return
			}
			if err != nil || result.RemainingUses != test.want {
				t.Fatalf("DeliverEvent() = %#v, %v", result, err)
			}
		})
	}
}

func TestEventDeliveryAdmitsDiscoveredEndpointBeforePOST(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 22, 45, 0, 0, time.UTC)
	key := testSigningKey(t, "delivery-admission-key", 0x79)
	posts := 0
	store := &eventSubscriptionStore{committed: EventSubscription{
		EventID: "event-1", AgentProvider: "https://ap.example", Agent: "aauth:agent@ap.example",
	}}
	service, err := NewEventService(EventServiceConfig{
		Issuer: "https://resource.example", SigningKey: key,
		KeyResolver: signaturekey.StaticKeyResolver{}, Clock: aauth.ClockFunc(func() time.Time { return now }),
		SubscriptionEndpoint: "https://resource.example/events/subscribe", Store: store,
		RegisterPublic: func(context.Context, PublicSubscriptionRequest) (PublicSubscriptionDecision, error) {
			return PublicSubscriptionDecision{}, nil
		},
		ResolveEventEndpoint: EventEndpointResolverFunc(func(context.Context, string) (string, error) {
			return "https://inbox.example/events", nil
		}),
		AdmitEventEndpoint: func(_ context.Context, endpoint string) error {
			if endpoint != "https://inbox.example/events" {
				t.Fatalf("admitted endpoint = %q", endpoint)
			}
			return errors.New("private network refused")
		},
		HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			posts++
			return nil, errors.New("must not post")
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := service.PrepareEvent(context.Background(), EventInput{
		AgentProvider: "https://ap.example", EventID: "event-1", ContentType: "application/json", Payload: []byte(`{}`), Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.DeliverEvent(context.Background(), prepared); err == nil || posts != 0 {
		t.Fatalf("DeliverEvent() error = %v, posts = %d", err, posts)
	}
}
