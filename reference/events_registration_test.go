package reference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestPublicEventRegistrationRequiresExactSubscribeTokenAndAgentProof(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 7, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := eventsProviderTestSigningKey(t, "ap-events-key")
	agentKey := eventsProviderTestSigningKey(t, "agent-events-key")
	otherAgentKey := eventsProviderTestSigningKey(t, "other-agent-key")
	resolver := aauth.StaticKeyResolver{
		"https://ap.example": {apKey.ID(): apKey.PublicJWK()},
	}

	validClaims := aauth.SubscribeTokenClaims{
		Issuer:       "https://ap.example",
		DWK:          aauth.AgentDiscoveryDocument,
		Subject:      "aauth:subscriber@ap.example",
		Audience:     "https://resource.example",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		EventID:      "event-one",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		MaxUses:      eventRegistrationMaxUses(1),
	}
	mint := func(t *testing.T, claims aauth.SubscribeTokenClaims, key aauth.SigningKey) string {
		t.Helper()
		compact, err := aauth.MintSubscribeToken(key, claims)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}

	for _, test := range []struct {
		name       string
		claims     aauth.SubscribeTokenClaims
		token      func(*testing.T) string
		requestKey aauth.SigningKey
	}{
		{name: "wrong audience", claims: eventRegistrationClaims(validClaims, func(value *aauth.SubscribeTokenClaims) { value.Audience = "https://other-resource.example" }), requestKey: agentKey},
		{name: "absent max uses", claims: eventRegistrationClaims(validClaims, func(value *aauth.SubscribeTokenClaims) { value.MaxUses = nil }), requestKey: agentKey},
		{name: "other max uses", claims: eventRegistrationClaims(validClaims, func(value *aauth.SubscribeTokenClaims) { value.MaxUses = eventRegistrationMaxUses(2) }), requestKey: agentKey},
		{name: "expired", claims: eventRegistrationClaims(validClaims, func(value *aauth.SubscribeTokenClaims) {
			value.IssuedAt = now.Add(-2 * time.Minute).Unix()
			value.ExpiresAt = now.Add(-time.Minute).Unix()
		}), requestKey: agentKey},
		{name: "future issued time", claims: eventRegistrationClaims(validClaims, func(value *aauth.SubscribeTokenClaims) {
			value.IssuedAt = now.Add(time.Minute).Unix()
			value.ExpiresAt = now.Add(2 * time.Minute).Unix()
		}), requestKey: agentKey},
		{name: "untrusted AP signature", claims: validClaims, token: func(t *testing.T) string { return mint(t, validClaims, eventsProviderTestSigningKey(t, apKey.ID())) }, requestKey: agentKey},
		{name: "wrong HTTP proof key", claims: validClaims, requestKey: otherAgentKey},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			store := NewMemoryResourceEventStore()
			resource := newRegistrationTestResource(t, resolver, clock, store, now.Add(48*time.Hour))
			compact := ""
			if test.token != nil {
				compact = test.token(t)
			} else {
				compact = mint(t, test.claims, apKey)
			}
			request := httptest.NewRequest(http.MethodPost, "https://resource.example/events/subscriptions", nil)
			if err := aauth.SignRequest(request, test.requestKey, compact, clock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			resource.Handler().ServeHTTP(response, request)
			if response.Code >= 200 && response.Code < 300 {
				t.Fatalf("mutation status = %d, want refusal", response.Code)
			}
			if _, err := store.Load(context.Background(), validClaims.Issuer, validClaims.EventID); !errors.Is(err, ErrEventSubscriptionNotFound) {
				t.Fatalf("mutation store error = %v, want no registration", err)
			}
		})
	}

	resourceStore := NewMemoryResourceEventStore()
	resource := newRegistrationTestResource(t, resolver, clock, resourceStore, now.Add(48*time.Hour))
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/events/subscriptions", nil)
	wrongType, err := aauth.MintAgentToken("https://ap.example", apKey, aauth.AgentTokenRequest{
		Agent:        validClaims.Subject,
		PersonServer: "https://ps.example",
		PublicKey:    agentKey.PublicJWK(),
		Lifetime:     time.Minute,
	}, now, "wrong-type-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequest(request, agentKey, wrongType, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	resource.Handler().ServeHTTP(response, request)
	if response.Code >= 200 && response.Code < 300 {
		t.Fatalf("wrong type status = %d, want refusal", response.Code)
	}

	validToken := mint(t, validClaims, apKey)
	transportCalls := 0
	agentStore := NewMemoryAgentEventStore()
	agent := newRegistrationTestAgent(t, resolver, clock, agentKey, agentStore, registrationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		transportCalls++
		if _, err := agentStore.LookupContext(context.Background(), validClaims.Issuer, validClaims.EventID); err != nil {
			t.Fatalf("local context was not committed before send: %v", err)
		}
		if request.Header.Get("Authorization") != "" || strings.Contains(request.Header.Get("Signature-Key"), "unused-agent-token") {
			t.Fatal("registration added an agent credential")
		}
		if !strings.Contains(request.Header.Get("Signature-Key"), validToken) {
			t.Fatal("registration did not use the exact subscribe token")
		}
		return eventRegistrationHTTPResponse(resource.Handler(), request), nil
	}))
	localContext := AgentEventContext{
		APIssuer: validClaims.Issuer,
		EventID:  validClaims.EventID,
		Value:    json.RawMessage(`{"purpose":"registration"}`),
	}
	if err := agent.RegisterPublicEventSubscription(context.Background(), "https://resource.example/events/subscriptions", validToken, localContext); err != nil {
		t.Fatal(err)
	}
	if transportCalls != 1 {
		t.Fatalf("transport calls = %d, want 1", transportCalls)
	}
	stored, err := resourceStore.Load(context.Background(), validClaims.Issuer, validClaims.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Resource != validClaims.Audience || stored.Agent != validClaims.Subject ||
		!stored.ActiveUntil.Equal(now.Add(48*time.Hour)) {
		t.Fatalf("resource subscription = %#v", stored)
	}

	mismatchedContext := localContext
	mismatchedContext.EventID = "other-event"
	if err := agent.RegisterPublicEventSubscription(context.Background(), "https://resource.example/events/subscriptions", validToken, mismatchedContext); err == nil {
		t.Fatal("agent accepted local context for a different event")
	}
	if transportCalls != 1 {
		t.Fatalf("context mismatch sent a request; calls = %d", transportCalls)
	}

	otherAgentClaims := validClaims
	otherAgentClaims.Subject = "aauth:other@ap.example"
	otherAgentToken := mint(t, otherAgentClaims, apKey)
	if err := agent.RegisterPublicEventSubscription(context.Background(), "https://resource.example/events/subscriptions", otherAgentToken, AgentEventContext{
		APIssuer: otherAgentClaims.Issuer,
		EventID:  otherAgentClaims.EventID,
		Value:    json.RawMessage(`{"purpose":"wrong agent"}`),
	}); err == nil {
		t.Fatal("agent accepted a subscription issued to another agent")
	}
	if transportCalls != 1 {
		t.Fatalf("wrong-agent token sent a request; calls = %d", transportCalls)
	}

	localFailure := errors.New("local context store unavailable")
	failingAgentStore := &eventRegistrationFailingAgentStore{
		AgentEventStore: NewMemoryAgentEventStore(),
		putErr:          localFailure,
	}
	failingAgentTransportCalls := 0
	failingAgent := newRegistrationTestAgent(t, resolver, clock, agentKey, failingAgentStore, registrationRoundTripFunc(func(*http.Request) (*http.Response, error) {
		failingAgentTransportCalls++
		return nil, errors.New("request must not be sent")
	}))
	if err := failingAgent.RegisterPublicEventSubscription(context.Background(), "https://resource.example/events/subscriptions", validToken, localContext); !errors.Is(err, localFailure) {
		t.Fatalf("local store failure = %v, want %v", err, localFailure)
	}
	if failingAgentTransportCalls != 0 {
		t.Fatalf("local store failure sent %d requests", failingAgentTransportCalls)
	}

	resourceFailure := errors.New("resource subscription store unavailable")
	failingResourceStore := &eventRegistrationFailingResourceStore{
		ResourceEventStore: NewMemoryResourceEventStore(),
		registerErr:        resourceFailure,
	}
	failingResource := newRegistrationTestResource(t, resolver, clock, failingResourceStore, now.Add(48*time.Hour))
	resourceFailureAgent := newRegistrationTestAgent(t, resolver, clock, agentKey, NewMemoryAgentEventStore(), registrationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return eventRegistrationHTTPResponse(failingResource.Handler(), request), nil
	}))
	if err := resourceFailureAgent.RegisterPublicEventSubscription(context.Background(), "https://resource.example/events/subscriptions", validToken, localContext); err == nil {
		t.Fatal("resource store failure was reported as successful registration")
	}
	if failingResourceStore.calls != 1 {
		t.Fatalf("resource Register calls = %d, want 1", failingResourceStore.calls)
	}
}

func TestPublicEventRegistrationCustodySurvivesReconstruction(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 3, 7, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := eventsProviderTestSigningKey(t, "ap-events-key")
	agentKey := eventsProviderTestSigningKey(t, "agent-events-key")
	resolver := aauth.StaticKeyResolver{"https://ap.example": {apKey.ID(): apKey.PublicJWK()}}
	claims := aauth.SubscribeTokenClaims{
		Issuer:       "https://ap.example",
		DWK:          aauth.AgentDiscoveryDocument,
		Subject:      "aauth:subscriber@ap.example",
		Audience:     "https://resource.example",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		EventID:      "restart-event",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		MaxUses:      eventRegistrationMaxUses(1),
	}
	compact, err := aauth.MintSubscribeToken(apKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	agentStore := NewMemoryAgentEventStore()
	resourceStore := NewMemoryResourceEventStore()
	activeUntil := now.Add(72 * time.Hour)
	resource := newRegistrationTestResource(t, resolver, clock, resourceStore, activeUntil)
	transport := registrationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return eventRegistrationHTTPResponse(resource.Handler(), request), nil
	})
	agent := newRegistrationTestAgent(t, resolver, clock, agentKey, agentStore, transport)
	localContext := AgentEventContext{APIssuer: claims.Issuer, EventID: claims.EventID, Value: json.RawMessage(`{"work":"durable"}`)}
	if err := agent.RegisterPublicEventSubscription(ctx, claims.Audience+"/events/subscriptions", compact, localContext); err != nil {
		t.Fatal(err)
	}

	// Both reconstructed hosts receive only their external stores and ordinary
	// configuration. No process-local registration state is copied.
	resource = newRegistrationTestResource(t, resolver, clock, resourceStore, now.Add(96*time.Hour))
	_ = newRegistrationTestAgent(t, resolver, clock, agentKey, agentStore, transport)
	gotContext, err := agentStore.LookupContext(ctx, claims.Issuer, claims.EventID)
	if err != nil || !bytes.Equal(gotContext.Value, localContext.Value) {
		t.Fatalf("recovered agent context = %#v, %v", gotContext, err)
	}
	gotSubscription, err := resourceStore.Load(ctx, claims.Issuer, claims.EventID)
	if err != nil || !gotSubscription.ActiveUntil.Equal(activeUntil) {
		t.Fatalf("recovered resource subscription = %#v, %v", gotSubscription, err)
	}

	request := httptest.NewRequest(http.MethodPost, claims.Audience+"/events/subscriptions", nil)
	if err := aauth.SignRequest(request, agentKey, compact, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	resource.Handler().ServeHTTP(response, request)
	if response.Code >= 200 && response.Code < 300 {
		t.Fatalf("duplicate registration status = %d, want collision", response.Code)
	}
	unchanged, err := resourceStore.Load(ctx, claims.Issuer, claims.EventID)
	if err != nil || !unchanged.ActiveUntil.Equal(activeUntil) {
		t.Fatalf("duplicate replaced authority = %#v, %v", unchanged, err)
	}
}

func newRegistrationTestResource(t *testing.T, resolver aauth.KeyResolver, clock aauth.Clock, store ResourceEventStore, activeUntil time.Time) *Resource {
	t.Helper()
	resource, err := NewResource(ResourceConfig{
		Identifier:  "https://resource.example",
		SigningKey:  eventsProviderTestSigningKey(t, "resource-events-key"),
		KeyResolver: resolver,
		Clock:       clock,
		NewID:       func() string { return "unused" },
		Scopes:      []string{"qualification.read"},
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{}, errors.New("unused")
		},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) { return nil, errors.New("unused") },
		Events: &ResourceEventsConfig{
			PublicSubscriptionPath: "/events/subscriptions",
			Store:                  store,
			HTTPClient:             &http.Client{},
			ActiveUntil: func(context.Context, aauth.SubscribeTokenClaims) (time.Time, error) {
				return activeUntil, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func newRegistrationTestAgent(t *testing.T, resolver aauth.KeyResolver, clock aauth.Clock, key aauth.SigningKey, store AgentEventStore, transport http.RoundTripper) *Agent {
	t.Helper()
	agent, err := NewAgent(AgentConfig{
		Identifier:  "aauth:subscriber@ap.example",
		SigningKey:  key,
		AgentToken:  "unused-agent-token",
		KeyResolver: resolver,
		HTTPClient:  &http.Client{Transport: transport},
		Clock:       clock,
		Events:      &AgentEventsConfig{Store: store, Action: unusedEventAction{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

func eventRegistrationClaims(claims aauth.SubscribeTokenClaims, mutate func(*aauth.SubscribeTokenClaims)) aauth.SubscribeTokenClaims {
	mutate(&claims)
	return claims
}

func eventRegistrationMaxUses(value int) *int { return &value }

type registrationRoundTripFunc func(*http.Request) (*http.Response, error)

func (function registrationRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func eventRegistrationHTTPResponse(handler http.Handler, request *http.Request) *http.Response {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	if response.Body == nil {
		response.Body = io.NopCloser(strings.NewReader(""))
	}
	return response
}

type unusedEventAction struct{}

func (unusedEventAction) Dispatch(context.Context, EventActionInput) (EventActionOutcome, error) {
	return EventActionUnknown, errors.New("unused")
}

func (unusedEventAction) Reconcile(context.Context, EventActionKey) (EventActionOutcome, error) {
	return EventActionUnknown, errors.New("unused")
}

type eventRegistrationFailingAgentStore struct {
	AgentEventStore
	putErr error
}

func (store *eventRegistrationFailingAgentStore) PutContext(context.Context, AgentEventContext) error {
	return store.putErr
}

type eventRegistrationFailingResourceStore struct {
	ResourceEventStore
	registerErr error
	calls       int
}

func (store *eventRegistrationFailingResourceStore) Register(context.Context, ResourceEventSubscription) error {
	store.calls++
	return store.registerErr
}
