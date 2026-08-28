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
	bodyRequest := httptest.NewRequest(
		http.MethodPost,
		"https://resource.example/events/subscriptions",
		strings.NewReader(`{"unexpected":"body"}`),
	)
	bodyRequest.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(bodyRequest, agentKey, mint(t, validClaims, apKey), clock); err != nil {
		t.Fatal(err)
	}
	bodyResponse := httptest.NewRecorder()
	resource.Handler().ServeHTTP(bodyResponse, bodyRequest)
	if bodyResponse.Code >= 200 && bodyResponse.Code < 300 {
		t.Fatalf("body-bearing registration status = %d, want refusal", bodyResponse.Code)
	}
	if _, err := resourceStore.Load(context.Background(), validClaims.Issuer, validClaims.EventID); !errors.Is(err, ErrEventSubscriptionNotFound) {
		t.Fatalf("body-bearing request mutated resource store: %v", err)
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

	agentRecoveryClaims := validClaims
	agentRecoveryClaims.EventID = "event-agent-store-recovery"
	agentRecoveryToken := mint(t, agentRecoveryClaims, apKey)
	agentRecoveryContext := AgentEventContext{
		APIssuer: agentRecoveryClaims.Issuer,
		EventID:  agentRecoveryClaims.EventID,
		Value:    json.RawMessage(`{"purpose":"agent store recovery"}`),
	}
	agentRecoveryResourceStore := NewMemoryResourceEventStore()
	agentRecoveryResource := newRegistrationTestResource(t, resolver, clock, agentRecoveryResourceStore, now.Add(48*time.Hour))
	localFailure := errors.New("local context store unavailable")
	failingAgentStore := &eventRegistrationFailingAgentStore{
		AgentEventStore: NewMemoryAgentEventStore(),
		putErr:          localFailure,
	}
	failingAgentTransportCalls := 0
	failingAgent := newRegistrationTestAgent(t, resolver, clock, agentKey, failingAgentStore, registrationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		failingAgentTransportCalls++
		return eventRegistrationHTTPResponse(agentRecoveryResource.Handler(), request), nil
	}))
	if err := failingAgent.RegisterPublicEventSubscription(context.Background(), "https://resource.example/events/subscriptions", agentRecoveryToken, agentRecoveryContext); !errors.Is(err, localFailure) {
		t.Fatalf("local store failure = %v, want %v", err, localFailure)
	}
	if failingAgentTransportCalls != 0 {
		t.Fatalf("local store failure sent %d requests", failingAgentTransportCalls)
	}
	failingAgentStore.putErr = nil
	if err := failingAgent.RegisterPublicEventSubscription(context.Background(), "https://resource.example/events/subscriptions", agentRecoveryToken, agentRecoveryContext); err != nil {
		t.Fatalf("healthy agent-store retry failed: %v", err)
	}
	if failingAgentTransportCalls != 1 {
		t.Fatalf("healthy agent-store retry requests = %d, want 1", failingAgentTransportCalls)
	}
	if _, err := agentRecoveryResourceStore.Load(context.Background(), agentRecoveryClaims.Issuer, agentRecoveryClaims.EventID); err != nil {
		t.Fatalf("healthy agent-store retry did not register exact subscription: %v", err)
	}

	wrongSuccessAgent := newRegistrationTestAgent(t, resolver, clock, agentKey, NewMemoryAgentEventStore(), registrationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    request,
		}, nil
	}))
	if err := wrongSuccessAgent.RegisterPublicEventSubscription(context.Background(), "https://resource.example/events/subscriptions", validToken, localContext); err == nil {
		t.Fatal("agent accepted 200 as a completed public registration")
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
	failingResourceStore.registerErr = nil
	if err := resourceFailureAgent.RegisterPublicEventSubscription(context.Background(), "https://resource.example/events/subscriptions", validToken, localContext); err != nil {
		t.Fatalf("healthy resource-store retry failed: %v", err)
	}
	if failingResourceStore.calls != 2 {
		t.Fatalf("resource Register calls after recovery = %d, want 2", failingResourceStore.calls)
	}
	if _, err := failingResourceStore.ResourceEventStore.Load(context.Background(), validClaims.Issuer, validClaims.EventID); err != nil {
		t.Fatalf("healthy resource-store retry did not retain exact subscription: %v", err)
	}
}

func TestPublicEventRegistrationRejectsRawSubscribeMutationsWithoutCustody(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 7, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey, apPrivate := rawEventsTestSigningKey(t, "ap-events-key")
	agentKey := eventsProviderTestSigningKey(t, "agent-events-key")
	resolver := aauth.StaticKeyResolver{
		"https://ap.example": {apKey.ID(): apKey.PublicJWK()},
	}
	maxUses := 1
	valid := aauth.SubscribeTokenClaims{
		Issuer: "https://ap.example", DWK: aauth.AgentDiscoveryDocument,
		Subject: "aauth:subscriber@ap.example", Audience: "https://resource.example",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()}, EventID: "event-raw-mutations",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), MaxUses: &maxUses,
	}
	validClaims := rawSubscribeRegistrationTestClaims(t, valid)

	for _, test := range []struct {
		name   string
		header aauth.TokenHeader
		claims map[string]any
	}{
		{name: "algorithm none", header: aauth.TokenHeader{Algorithm: "none", Type: aauth.SubscribeTokenType, KeyID: apKey.ID()}, claims: validClaims},
		{name: "wrong discovery document", header: rawEventsTestHeader(aauth.SubscribeTokenType, apKey.ID()), claims: mutateRawEventsTestClaim(validClaims, "dwk", aauth.ResourceDiscoveryDocument)},
		{name: "absent subject", header: rawEventsTestHeader(aauth.SubscribeTokenType, apKey.ID()), claims: mutateRawEventsTestClaim(validClaims, "sub", nil)},
		{name: "malformed subject", header: rawEventsTestHeader(aauth.SubscribeTokenType, apKey.ID()), claims: mutateRawEventsTestClaim(validClaims, "sub", "subscriber")},
		{name: "absent issued time", header: rawEventsTestHeader(aauth.SubscribeTokenType, apKey.ID()), claims: mutateRawEventsTestClaim(validClaims, "iat", nil)},
		{name: "malformed issued time", header: rawEventsTestHeader(aauth.SubscribeTokenType, apKey.ID()), claims: mutateRawEventsTestClaim(validClaims, "iat", "now")},
		{name: "absent expiry", header: rawEventsTestHeader(aauth.SubscribeTokenType, apKey.ID()), claims: mutateRawEventsTestClaim(validClaims, "exp", nil)},
		{name: "malformed expiry", header: rawEventsTestHeader(aauth.SubscribeTokenType, apKey.ID()), claims: mutateRawEventsTestClaim(validClaims, "exp", "later")},
		{name: "absent confirmation", header: rawEventsTestHeader(aauth.SubscribeTokenType, apKey.ID()), claims: mutateRawEventsTestClaim(validClaims, "cnf", nil)},
		{name: "absent event id", header: rawEventsTestHeader(aauth.SubscribeTokenType, apKey.ID()), claims: mutateRawEventsTestClaim(validClaims, "eid", nil)},
		{name: "zero max uses", header: rawEventsTestHeader(aauth.SubscribeTokenType, apKey.ID()), claims: mutateRawEventsTestClaim(validClaims, "max_uses", 0)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			store := NewMemoryResourceEventStore()
			resource := newRegistrationTestResource(t, resolver, clock, store, now.Add(24*time.Hour))
			before, _, err := encodeFileResourceSnapshot(store)
			if err != nil {
				t.Fatal(err)
			}
			compact := mintRawEventsTestToken(t, apPrivate, test.header, test.claims)
			request := httptest.NewRequest(http.MethodPost, "https://resource.example/events/subscriptions", nil)
			if err := aauth.SignRequest(request, agentKey, compact, clock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			resource.Handler().ServeHTTP(response, request)
			if response.Code >= 200 && response.Code < 300 {
				t.Fatalf("raw mutation status = %d, want refusal", response.Code)
			}
			after, _, err := encodeFileResourceSnapshot(store)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("raw mutation changed resource custody\nbefore: %s\nafter:  %s", before, after)
			}
			if _, err := store.Load(context.Background(), valid.Issuer, valid.EventID); !errors.Is(err, ErrEventSubscriptionNotFound) {
				t.Fatalf("raw mutation became reachable: %v", err)
			}
		})
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

	now = now.Add(6 * time.Minute)
	request := httptest.NewRequest(http.MethodPost, claims.Audience+"/events/subscriptions", nil)
	if err := aauth.SignRequest(request, agentKey, compact, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	resource.Handler().ServeHTTP(response, request)
	if response.Code >= 200 && response.Code < 300 {
		t.Fatalf("expired duplicate registration status = %d, want refusal", response.Code)
	}
	unchanged, err := resourceStore.Load(ctx, claims.Issuer, claims.EventID)
	if err != nil || !unchanged.ActiveUntil.Equal(activeUntil) {
		t.Fatalf("expired duplicate replaced authority = %#v, %v", unchanged, err)
	}

	freshDuplicate := claims
	freshDuplicate.IssuedAt = now.Unix()
	freshDuplicate.ExpiresAt = now.Add(5 * time.Minute).Unix()
	freshCompact, err := aauth.MintSubscribeToken(apKey, freshDuplicate)
	if err != nil {
		t.Fatal(err)
	}
	freshRequest := httptest.NewRequest(http.MethodPost, claims.Audience+"/events/subscriptions", nil)
	if err := aauth.SignRequest(freshRequest, agentKey, freshCompact, clock); err != nil {
		t.Fatal(err)
	}
	freshResponse := httptest.NewRecorder()
	resource.Handler().ServeHTTP(freshResponse, freshRequest)
	if freshResponse.Code >= 200 && freshResponse.Code < 300 {
		t.Fatalf("fresh duplicate registration status = %d, want collision", freshResponse.Code)
	}
	unchanged, err = resourceStore.Load(ctx, claims.Issuer, claims.EventID)
	if err != nil || unchanged != gotSubscription {
		t.Fatalf("fresh duplicate replaced authority = %#v, %v; want %#v", unchanged, err, gotSubscription)
	}
}

func TestPublicEventRegistrationsKeyOpaqueEventIDByAPIssuer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 3, 7, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	agentKey := eventsProviderTestSigningKey(t, "shared-agent-key")
	apKeys := map[string]aauth.SigningKey{
		"https://ap-one.example": eventsProviderTestSigningKey(t, "ap-one-key"),
		"https://ap-two.example": eventsProviderTestSigningKey(t, "ap-two-key"),
	}
	resolver := aauth.StaticKeyResolver{}
	for issuer, key := range apKeys {
		resolver[issuer] = map[string]aauth.JWK{key.ID(): key.PublicJWK()}
	}
	store := NewMemoryResourceEventStore()
	activeUntil := now.Add(24 * time.Hour)
	resource := newRegistrationTestResource(t, resolver, clock, store, activeUntil)
	const eventID = "shared-opaque-event"

	claimsByIssuer := make(map[string]aauth.SubscribeTokenClaims)
	for issuer, key := range apKeys {
		claims := aauth.SubscribeTokenClaims{
			Issuer: issuer, DWK: aauth.AgentDiscoveryDocument,
			Subject:  strings.Replace(issuer, "https://", "aauth:subscriber@", 1),
			Audience: "https://resource.example", Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
			EventID: eventID, IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(),
			MaxUses: eventRegistrationMaxUses(1),
		}
		claimsByIssuer[issuer] = claims
		compact, err := aauth.MintSubscribeToken(key, claims)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, claims.Audience+"/events/subscriptions", nil)
		if err := aauth.SignRequest(request, agentKey, compact, clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		resource.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusCreated {
			t.Fatalf("%s registration status = %d, want 201", issuer, response.Code)
		}
	}

	resource = newRegistrationTestResource(t, resolver, clock, store, now.Add(72*time.Hour))
	now = now.Add(time.Minute)
	for issuer, key := range apKeys {
		stored, err := store.Load(ctx, issuer, eventID)
		if err != nil || stored.APIssuer != issuer || !stored.ActiveUntil.Equal(activeUntil) {
			t.Fatalf("%s recovered subscription = %#v, %v", issuer, stored, err)
		}
		duplicate := claimsByIssuer[issuer]
		duplicate.IssuedAt = now.Unix()
		duplicate.ExpiresAt = now.Add(5 * time.Minute).Unix()
		compact, err := aauth.MintSubscribeToken(key, duplicate)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, duplicate.Audience+"/events/subscriptions", nil)
		if err := aauth.SignRequest(request, agentKey, compact, clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		resource.Handler().ServeHTTP(response, request)
		if response.Code >= 200 && response.Code < 300 {
			t.Fatalf("%s duplicate registration status = %d, want refusal", issuer, response.Code)
		}
		unchanged, err := store.Load(ctx, issuer, eventID)
		if err != nil || unchanged != stored {
			t.Fatalf("%s duplicate replaced subscription = %#v, %v; want %#v", issuer, unchanged, err, stored)
		}
	}
}

func newRegistrationTestResource(t *testing.T, resolver aauth.KeyResolver, clock aauth.Clock, store ResourceEventStore, activeUntil time.Time) *Resource {
	t.Helper()
	resource, err := NewResource(ResourceConfig{
		Identifier:               "https://resource.example",
		AccessMode:               aauth.AccessModeSessionToken,
		SigningKey:               eventsProviderTestSigningKey(t, "resource-events-key"),
		KeyResolver:              resolver,
		Clock:                    clock,
		NewID:                    func() string { return "unused" },
		Scopes:                   []string{"qualification.read"},
		RequiredScopesForRequest: testRequiredResourceScopes("qualification.read"),
		ReplayStore:              testResourceReplayStore(t, clock),
		AuthorizationStore:       testAuthorizationStateStore(t),
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
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:subscriber@ap.example",
		SigningKey:         key,
		AgentToken:         "unused-agent-token",
		KeyResolver:        resolver,
		HTTPClient:         &http.Client{Transport: transport},
		Clock:              clock,
		Events:             &AgentEventsConfig{Store: store, Action: unusedEventAction{}},
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

func rawSubscribeRegistrationTestClaims(t *testing.T, claims aauth.SubscribeTokenClaims) map[string]any {
	t.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

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

func (store *eventRegistrationFailingAgentStore) PutContext(ctx context.Context, value AgentEventContext) error {
	if store.putErr != nil {
		return store.putErr
	}
	return store.AgentEventStore.PutContext(ctx, value)
}

type eventRegistrationFailingResourceStore struct {
	ResourceEventStore
	registerErr error
	calls       int
}

func (store *eventRegistrationFailingResourceStore) Register(ctx context.Context, subscription ResourceEventSubscription) error {
	store.calls++
	if store.registerErr != nil {
		return store.registerErr
	}
	return store.ResourceEventStore.Register(ctx, subscription)
}
