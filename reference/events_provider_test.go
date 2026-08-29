package reference

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestAgentProviderIssuesOnlyAfterDurableSubscriptionCommit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 3, 6, 0, 0, 0, time.UTC)
	activeUntil := now.Add(24 * time.Hour)
	providerKey := eventsProviderTestSigningKey(t, "ap-events-key")
	agentKey := eventsProviderTestSigningKey(t, "subscribed-agent-key")
	store := &recordingAPEventStore{}
	provider := newEventsTestAgentProvider(t, providerKey, store, func() string {
		return "event-one"
	}, now, activeUntil, "https://ap.example/events")

	compact, err := provider.IssueEventSubscription(ctx, EventSubscriptionRequest{
		Resource: "https://resource.example",
		Agent:    "aauth:subscriber@ap.example",
		AgentKey: agentKey.PublicJWK(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if compact == "" {
		t.Fatal("IssueEventSubscription returned no token after a successful commit")
	}
	if store.calls != 1 {
		t.Fatalf("CreateSubscription calls = %d, want 1", store.calls)
	}
	wantRecord := APEventSubscription{
		APIssuer:    "https://ap.example",
		EventID:     "event-one",
		Resource:    "https://resource.example",
		Agent:       "aauth:subscriber@ap.example",
		ActiveUntil: activeUntil,
		MaxUses:     1,
	}
	if store.created != wantRecord {
		t.Fatalf("durable subscription = %#v, want %#v", store.created, wantRecord)
	}

	claims, err := aauth.VerifySubscribeToken(ctx, compact, signaturekey.StaticKeyResolver{
		"https://ap.example": {providerKey.ID(): providerKey.PublicJWK()},
	}, aauth.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != wantRecord.APIssuer || claims.DWK != aauth.AgentDiscoveryDocument ||
		claims.Subject != wantRecord.Agent || claims.Audience != wantRecord.Resource ||
		claims.EventID != wantRecord.EventID || claims.IssuedAt != now.Unix() ||
		claims.ExpiresAt != now.Add(5*time.Minute).Unix() ||
		claims.MaxUses == nil || *claims.MaxUses != 1 ||
		!claims.Confirmation.JWK.Equal(agentKey.PublicJWK()) {
		t.Fatalf("subscribe claims = %#v", claims)
	}
	if !wantRecord.ActiveUntil.After(time.Unix(claims.ExpiresAt, 0)) {
		t.Fatalf("active_until %v must be independent of token expiry %v", wantRecord.ActiveUntil, time.Unix(claims.ExpiresAt, 0))
	}

	// A reconstructed provider uses the same external authority. Reusing the
	// event id must fail closed rather than replacing the durable subscription.
	memory := NewMemoryAPEventStore("https://ap.example")
	first := newEventsTestAgentProvider(t, providerKey, memory, func() string { return "stable-event" }, now, activeUntil, "https://ap.example/events")
	request := EventSubscriptionRequest{
		Resource: "https://resource.example",
		Agent:    "aauth:subscriber@ap.example",
		AgentKey: agentKey.PublicJWK(),
	}
	if token, issueErr := first.IssueEventSubscription(ctx, request); issueErr != nil || token == "" {
		t.Fatalf("first issuance = %q, %v", token, issueErr)
	}
	restarted := newEventsTestAgentProvider(t, providerKey, memory, func() string { return "stable-event" }, now, activeUntil, "https://ap.example/events")
	if token, issueErr := restarted.IssueEventSubscription(ctx, request); token != "" || !errors.Is(issueErr, ErrEventSubscriptionConflict) {
		t.Fatalf("collision issuance = %q, %v, want empty token and conflict", token, issueErr)
	}

	commitFailure := errors.New("durable store unavailable")
	recoveryAuthority := NewMemoryAPEventStore("https://ap.example")
	failing := &failOnceCreateAPEventStore{APEventStore: recoveryAuthority, err: commitFailure}
	failingProvider := newEventsTestAgentProvider(t, providerKey, failing, func() string { return "event-two" }, now, activeUntil, "https://ap.example/events")
	if token, issueErr := failingProvider.IssueEventSubscription(ctx, request); token != "" || !errors.Is(issueErr, commitFailure) {
		t.Fatalf("failed commit issuance = %q, %v, want empty token and store error", token, issueErr)
	}
	if len(recoveryAuthority.subscriptions) != 0 {
		t.Fatalf("failed commit retained partial authority: %#v", recoveryAuthority.subscriptions)
	}
	recoveredToken, issueErr := failingProvider.IssueEventSubscription(ctx, request)
	if issueErr != nil || recoveredToken == "" {
		t.Fatalf("healthy retry issuance = %q, %v", recoveredToken, issueErr)
	}
	wantRecoveredRecord := wantRecord
	wantRecoveredRecord.EventID = "event-two"
	if got := recoveryAuthority.subscriptions["event-two"]; got != wantRecoveredRecord {
		t.Fatalf("healthy retry authority = %#v, want %#v", got, wantRecoveredRecord)
	}
	recoveredClaims, err := aauth.VerifySubscribeToken(ctx, recoveredToken, signaturekey.StaticKeyResolver{
		"https://ap.example": {providerKey.ID(): providerKey.PublicJWK()},
	}, aauth.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if recoveredClaims.Issuer != wantRecoveredRecord.APIssuer ||
		recoveredClaims.DWK != aauth.AgentDiscoveryDocument ||
		recoveredClaims.Subject != wantRecoveredRecord.Agent ||
		recoveredClaims.Audience != wantRecoveredRecord.Resource ||
		recoveredClaims.EventID != wantRecoveredRecord.EventID ||
		recoveredClaims.IssuedAt != now.Unix() ||
		recoveredClaims.ExpiresAt != now.Add(5*time.Minute).Unix() ||
		recoveredClaims.MaxUses == nil || *recoveredClaims.MaxUses != wantRecoveredRecord.MaxUses ||
		!recoveredClaims.Confirmation.JWK.Equal(agentKey.PublicJWK()) {
		t.Fatalf("healthy retry subscribe claims = %#v", recoveredClaims)
	}
	if !wantRecoveredRecord.ActiveUntil.After(time.Unix(recoveredClaims.ExpiresAt, 0)) {
		t.Fatalf("healthy retry active_until %v must be independent of token expiry %v", wantRecoveredRecord.ActiveUntil, time.Unix(recoveredClaims.ExpiresAt, 0))
	}
	reconstructed := newEventsTestAgentProvider(t, providerKey, recoveryAuthority, func() string { return "event-two" }, now, activeUntil, "https://ap.example/events")
	if token, issueErr := reconstructed.IssueEventSubscription(ctx, request); token != "" || !errors.Is(issueErr, ErrEventSubscriptionConflict) {
		t.Fatalf("reconstructed duplicate issuance = %q, %v", token, issueErr)
	}
}

func TestAgentProviderEventsRejectsInvalidConfigurationAndBindings(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 6, 0, 0, 0, time.UTC)
	providerKey := eventsProviderTestSigningKey(t, "ap-events-key")
	agentKey := eventsProviderTestSigningKey(t, "subscribed-agent-key")
	base := AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: providerKey,
		Clock:      aauth.ClockFunc(func() time.Time { return now }),
		NewID:      func() string { return "event-one" },
	}
	for _, test := range []struct {
		name   string
		events *AgentProviderEventsConfig
	}{
		{name: "non-https endpoint", events: &AgentProviderEventsConfig{EventEndpoint: "http://ap.example/events", Store: NewMemoryAPEventStore(base.Identifier), SubscriptionActiveUntil: func(context.Context, string, string) (time.Time, error) { return now.Add(time.Hour), nil }, TokenLifetime: time.Minute}},
		{name: "missing store", events: &AgentProviderEventsConfig{EventEndpoint: "https://ap.example/events", SubscriptionActiveUntil: func(context.Context, string, string) (time.Time, error) { return now.Add(time.Hour), nil }, TokenLifetime: time.Minute}},
		{name: "missing active-until policy", events: &AgentProviderEventsConfig{EventEndpoint: "https://ap.example/events", Store: NewMemoryAPEventStore(base.Identifier), TokenLifetime: time.Minute}},
		{name: "non-positive token lifetime", events: &AgentProviderEventsConfig{EventEndpoint: "https://ap.example/events", Store: NewMemoryAPEventStore(base.Identifier), SubscriptionActiveUntil: func(context.Context, string, string) (time.Time, error) { return now.Add(time.Hour), nil }, TokenLifetime: -time.Second}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			config := base
			config.Events = test.events
			if _, err := NewAgentProvider(config); err == nil {
				t.Fatal("NewAgentProvider accepted invalid Events configuration")
			}
		})
	}

	provider := newEventsTestAgentProvider(t, providerKey, NewMemoryAPEventStore(base.Identifier), func() string { return "event-one" }, now, now.Add(time.Hour), "https://ap.example/events")
	for _, test := range []struct {
		name    string
		request EventSubscriptionRequest
	}{
		{name: "invalid resource", request: EventSubscriptionRequest{Resource: "resource", Agent: "aauth:subscriber@ap.example", AgentKey: agentKey.PublicJWK()}},
		{name: "invalid agent", request: EventSubscriptionRequest{Resource: "https://resource.example", Agent: "subscriber", AgentKey: agentKey.PublicJWK()}},
		{name: "invalid key", request: EventSubscriptionRequest{Resource: "https://resource.example", Agent: "aauth:subscriber@ap.example", AgentKey: jose.JWK{Kty: "OKP"}}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if token, err := provider.IssueEventSubscription(context.Background(), test.request); err == nil || token != "" {
				t.Fatalf("IssueEventSubscription = %q, %v, want empty token and error", token, err)
			}
		})
	}

	expiredPolicy := newEventsTestAgentProvider(t, providerKey, NewMemoryAPEventStore(base.Identifier), func() string { return "event-two" }, now, now, "https://ap.example/events")
	if token, err := expiredPolicy.IssueEventSubscription(context.Background(), EventSubscriptionRequest{
		Resource: "https://resource.example",
		Agent:    "aauth:subscriber@ap.example",
		AgentKey: agentKey.PublicJWK(),
	}); err == nil || token != "" {
		t.Fatalf("non-future active_until issuance = %q, %v, want empty token and error", token, err)
	}
}

func TestAgentProviderEventsMetadataRotatesWithHTTPFreshness(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 6, 0, 0, 0, time.UTC)
	providerKey := eventsProviderTestSigningKey(t, "ap-events-key")
	store := NewMemoryAPEventStore("https://ap.example")

	readMetadata := func(endpoint string) map[string]any {
		t.Helper()
		provider := newEventsTestAgentProvider(t, providerKey, store, func() string { return "event-one" }, now, now.Add(time.Hour), endpoint)
		request := httptest.NewRequest(http.MethodGet, "https://ap.example/.well-known/aauth-agent.json", nil)
		response := httptest.NewRecorder()
		provider.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("metadata status = %d", response.Code)
		}
		var metadata map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
			t.Fatal(err)
		}
		return metadata
	}

	first := readMetadata("https://ap.example/events/one")
	if first["event_endpoint"] != "https://ap.example/events/one" {
		t.Fatalf("first event_endpoint = %#v", first["event_endpoint"])
	}
	rotated := readMetadata("https://events.example/receive")
	if rotated["event_endpoint"] != "https://events.example/receive" {
		t.Fatalf("rotated event_endpoint = %#v", rotated["event_endpoint"])
	}

	unconfigured, err := NewAgentProvider(AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: providerKey,
		Clock:      aauth.ClockFunc(func() time.Time { return now }),
		NewID:      func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://ap.example/.well-known/aauth-agent.json", nil)
	response := httptest.NewRecorder()
	unconfigured.Handler().ServeHTTP(response, request)
	var metadata map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if _, exists := metadata["event_endpoint"]; exists {
		t.Fatalf("unconfigured metadata advertised event_endpoint: %#v", metadata)
	}
}

func newEventsTestAgentProvider(
	t *testing.T,
	key jose.SigningKey,
	store APEventStore,
	newID func() string,
	now time.Time,
	activeUntil time.Time,
	endpoint string,
) *AgentProvider {
	t.Helper()
	provider, err := NewAgentProvider(AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: key,
		Clock:      aauth.ClockFunc(func() time.Time { return now }),
		NewID:      newID,
		Events: &AgentProviderEventsConfig{
			EventEndpoint: endpoint,
			Store:         store,
			KeyResolver:   signaturekey.StaticKeyResolver{},
			SubscriptionActiveUntil: func(context.Context, string, string) (time.Time, error) {
				return activeUntil, nil
			},
			TokenLifetime: 5 * time.Minute,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func eventsProviderTestSigningKey(t *testing.T, id string) jose.SigningKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type recordingAPEventStore struct {
	calls   int
	created APEventSubscription
	err     error
}

type failOnceCreateAPEventStore struct {
	APEventStore
	err error
}

func (store *failOnceCreateAPEventStore) CreateSubscription(ctx context.Context, subscription APEventSubscription) error {
	if store.err != nil {
		err := store.err
		store.err = nil
		return err
	}
	return store.APEventStore.CreateSubscription(ctx, subscription)
}

func (store *recordingAPEventStore) CreateSubscription(_ context.Context, subscription APEventSubscription) error {
	store.calls++
	store.created = subscription
	return store.err
}

func (*recordingAPEventStore) AcceptEvent(context.Context, AcceptedEventInput) (AcceptedEvent, int, error) {
	return AcceptedEvent{}, 0, errors.New("not implemented")
}

func (*recordingAPEventStore) NextDelivery(context.Context) (AcceptedEvent, error) {
	return AcceptedEvent{}, errors.New("not implemented")
}

func (*recordingAPEventStore) AcknowledgeDelivery(context.Context, string) error {
	return errors.New("not implemented")
}
