package agentprovider_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestAgentProviderIssuesSubscribeTokenOnlyAfterRetainingSubscription(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 21, 0, 0, 0, time.UTC)
	providerKey := testSigningKey(t, "provider-events-key", 0x41)
	agentKey := testSigningKey(t, "agent-events-key", 0x42)
	store := &eventInboxStore{}
	server, err := agentprovider.New(agentprovider.Config{
		Issuer:     "https://ap.example",
		SigningKey: providerKey,
		Clock:      aauth.ClockFunc(func() time.Time { return now }),
		NewID:      func() string { return "event-1" },
		Events: &agentprovider.EventsConfig{
			EventEndpoint: "https://ap.example/events",
			NewEventID:    func() string { return "event-1" },
			KeyResolver: signaturekey.StaticKeyResolver{
				{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: "resource-key"}: testSigningKey(t, "resource-key", 0x43).PublicJWK(),
			},
			Store: store,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := server.IssueSubscribeToken(context.Background(), agentprovider.SubscribeRequest{
		Agent:           "aauth:agent@ap.example",
		Resource:        "https://resource.example",
		ConfirmationKey: agentKey.PublicJWK(),
		Lifetime:        time.Hour,
		MaxUses:         2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.subscription.EventID != "event-1" || store.subscription.Agent != "aauth:agent@ap.example" ||
		store.subscription.Resource != "https://resource.example" || store.subscription.MaxUses != 2 ||
		store.subscription.CompactToken != issued.Compact ||
		!store.subscription.TokenExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("retained subscription = %#v", store.subscription)
	}
	if issued.EventID != "event-1" || issued.MaxUses != 2 || !issued.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("issued subscribe token = %#v", issued)
	}

	store.commitSubscriptionError = errors.New("retention unavailable")
	if issued, err := server.IssueSubscribeToken(context.Background(), agentprovider.SubscribeRequest{
		Agent: "aauth:agent@ap.example", Resource: "https://resource.example",
		ConfirmationKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	}); err == nil || issued.Compact != "" {
		t.Fatalf("IssueSubscribeToken() = %#v, %v; want no token after retention failure", issued, err)
	}
}

func TestAgentProviderRefusesEmptyEventIDBeforeRetention(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 21, 5, 0, 0, time.UTC)
	store := &eventInboxStore{}
	server, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "empty-event-id-provider-key", 0x43),
		Clock: aauth.ClockFunc(func() time.Time { return now }), NewID: func() string { return "unused" },
		Events: &agentprovider.EventsConfig{
			EventEndpoint: "https://ap.example/events", NewEventID: func() string { return "" },
			KeyResolver: signaturekey.StaticKeyResolver{}, Store: store,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := server.IssueSubscribeToken(context.Background(), agentprovider.SubscribeRequest{
		Agent: "aauth:agent@ap.example", Resource: "https://resource.example",
		ConfirmationKey: testSigningKey(t, "empty-event-id-agent-key", 0x44).PublicJWK(), Lifetime: time.Minute,
	})
	if err == nil || issued.Compact != "" || store.subscription.EventID != "" {
		t.Fatalf("IssueSubscribeToken() = %#v, %v; retained = %#v", issued, err, store.subscription)
	}
}

func TestAgentProviderAcceptsEventOnlyAfterDurableInboxCommit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 21, 0, 0, 0, time.UTC)
	providerKey := testSigningKey(t, "provider-delivery-key", 0x44)
	resourceKey := testSigningKey(t, "resource-delivery-key", 0x45)
	store := &eventInboxStore{
		acceptResult: agentprovider.EventAcceptance{MaximumUses: 1, RemainingUses: 0},
	}
	server, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: providerKey,
		Clock: aauth.ClockFunc(func() time.Time { return now }), NewID: func() string { return "unused" },
		Events: &agentprovider.EventsConfig{
			EventEndpoint: "https://ap.example/events",
			NewEventID:    func() string { return "unused" },
			KeyResolver: signaturekey.StaticKeyResolver{
				{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
			},
			Store: store,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := events.MintEventToken("https://resource.example", resourceKey, events.EventTokenRequest{
		Agent: "aauth:agent@ap.example", EventID: "event-1", Lifetime: 5 * time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"event_type":"slot.available"}`)
	request := httptest.NewRequest(http.MethodPost, "https://ap.example/events", bytes.NewReader(payload))
	request.Host = "ap.example"
	request.URL.Scheme = ""
	request.URL.Host = ""
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Delivery-ID", "delivery-1")
	credential, err := signaturekey.NewSelfJWTCredential(compact)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, resourceKey, credential, aauth.ClockFunc(func() time.Time { return now }), signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest", "x-delivery-id"},
	}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("event response = %d %s", response.Code, response.Body.String())
	}
	if !store.accepted || store.delivery.Token != compact || !bytes.Equal(store.delivery.Payload, payload) ||
		store.delivery.TokenSHA256 != sha256.Sum256([]byte(compact)) ||
		store.delivery.PayloadSHA256 != sha256.Sum256(payload) ||
		store.delivery.Resource != "https://resource.example" || store.delivery.Agent != "aauth:agent@ap.example" ||
		store.delivery.EventID != "event-1" {
		t.Fatalf("durable delivery = %#v", store.delivery)
	}
	var body struct {
		RemainingUses int64 `json:"remaining_uses"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.RemainingUses != 0 {
		t.Fatalf("event response body = %s, error = %v", response.Body.String(), err)
	}

	store.acceptError = agentprovider.ErrEventUsesExceeded
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("exhausted response = %d %s", response.Code, response.Body.String())
	}
	store.acceptError = nil
	for _, invalid := range []agentprovider.EventAcceptance{
		{MaximumUses: -1},
		{MaximumUses: 1, RemainingUses: -1},
		{MaximumUses: 0, RemainingUses: 1},
		{MaximumUses: 1, RemainingUses: 1},
		{MaximumUses: 1, RemainingUses: 2},
	} {
		store.acceptResult = invalid
		response = httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("invalid acceptance %#v produced %d %s", invalid, response.Code, response.Body.String())
		}
	}
}

func TestAgentProviderMetadataAdvertisesConfiguredEventEndpoint(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 21, 0, 0, 0, time.UTC)
	server, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "metadata-events-key", 0x46),
		Clock: aauth.ClockFunc(func() time.Time { return now }), NewID: func() string { return "unused" },
		Events: &agentprovider.EventsConfig{
			EventEndpoint: "https://ap.example/events",
			NewEventID:    func() string { return "unused" },
			KeyResolver:   signaturekey.StaticKeyResolver{},
			Store:         &eventInboxStore{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://ap.example/.well-known/aauth-agent.json", nil))
	var metadata map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["event_endpoint"] != "https://ap.example/events" {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestAgentProviderAcceptsAndNormalizesRootEventEndpoint(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 21, 15, 0, 0, time.UTC)
	server, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "root-events-key", 0x4a),
		Clock: aauth.ClockFunc(func() time.Time { return now }), NewID: func() string { return "unused" },
		Events: &agentprovider.EventsConfig{
			EventEndpoint: "https://ap.example", NewEventID: func() string { return "unused" },
			KeyResolver: signaturekey.StaticKeyResolver{}, Store: &eventInboxStore{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://ap.example/.well-known/aauth-agent.json", nil))
	var metadata map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["event_endpoint"] != "https://ap.example/" {
		t.Fatalf("event endpoint = %q", metadata["event_endpoint"])
	}
}

func TestAgentProviderEventEndpointSeparatesMalformedInputFromFailedAuthentication(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 21, 30, 0, 0, time.UTC)
	providerKey := testSigningKey(t, "provider-stage-key", 0x47)
	resourceKey := testSigningKey(t, "resource-stage-key", 0x48)
	forgedKey := testSigningKey(t, "forged-stage-key", 0x49)
	store := &eventInboxStore{acceptResult: agentprovider.EventAcceptance{MaximumUses: 1}}
	server, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: providerKey,
		Clock: aauth.ClockFunc(func() time.Time { return now }), NewID: func() string { return "unused" },
		Events: &agentprovider.EventsConfig{
			EventEndpoint: "https://ap.example/events", NewEventID: func() string { return "unused" },
			KeyResolver: signaturekey.StaticKeyResolver{
				{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
			},
			Store: store,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	valid, err := events.MintEventToken("https://resource.example", resourceKey, events.EventTokenRequest{
		Agent: "aauth:agent@ap.example", EventID: "event-1", Lifetime: time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := events.MintEventToken("https://resource.example", resourceKey, events.EventTokenRequest{
		Agent: "aauth:agent@ap.example", EventID: "event-1", Lifetime: time.Minute,
	}, now.Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	missingEventIDPayload, err := json.Marshal(map[string]any{
		"iss": "https://resource.example", "dwk": aauth.ResourceDiscoveryDocument,
		"aud": "aauth:agent@ap.example", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	missingEventID, err := jose.SignCompact(resourceKey, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: events.EventTokenType, KeyID: resourceKey.ID(),
	}, missingEventIDPayload)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		compact    string
		requestKey jose.SigningKey
		unsigned   bool
		wantStatus int
	}{
		{name: "missing signature input", unsigned: true, wantStatus: http.StatusBadRequest},
		{name: "expired token", compact: expired, requestKey: resourceKey, wantStatus: http.StatusBadRequest},
		{name: "malformed claims", compact: missingEventID, requestKey: resourceKey, wantStatus: http.StatusBadRequest},
		{name: "forged outer signature", compact: valid, requestKey: forgedKey, wantStatus: http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store.calls = 0
			request := httptest.NewRequest(http.MethodPost, "https://ap.example/events", bytes.NewReader([]byte(`{}`)))
			request.Header.Set("Content-Type", "application/json")
			if !test.unsigned {
				credential, err := signaturekey.NewSelfJWTCredential(test.compact)
				if err != nil {
					t.Fatal(err)
				}
				if err := signaturekey.SignRequest(request, test.requestKey, credential, aauth.ClockFunc(func() time.Time { return now }), signaturekey.SignOptions{
					AdditionalComponents: []string{"content-type", "content-digest"},
				}); err != nil {
					t.Fatal(err)
				}
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("response = %d %s, want %d", response.Code, response.Body.String(), test.wantStatus)
			}
			if store.calls != 0 {
				t.Fatalf("malformed request reached store %d times", store.calls)
			}
		})
	}
}

func TestAgentProviderEventEndpointMapsStoreOutcomes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 31, 21, 45, 0, 0, time.UTC)
	providerKey := testSigningKey(t, "provider-outcome-key", 0x4b)
	resourceKey := testSigningKey(t, "resource-outcome-key", 0x4c)
	store := &eventInboxStore{acceptResult: agentprovider.EventAcceptance{MaximumUses: 1}}
	server, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: providerKey,
		Clock: aauth.ClockFunc(func() time.Time { return now }), NewID: func() string { return "unused" },
		Events: &agentprovider.EventsConfig{
			EventEndpoint: "https://ap.example/events", NewEventID: func() string { return "unused" },
			KeyResolver: signaturekey.StaticKeyResolver{
				{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
			},
			Store: store,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := events.MintEventToken("https://resource.example", resourceKey, events.EventTokenRequest{
		Agent: "aauth:agent@ap.example", EventID: "event-1", Lifetime: time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	newRequest := func(t *testing.T) *http.Request {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "https://ap.example/events", bytes.NewReader([]byte(`{}`)))
		request.Header.Set("Content-Type", "application/json")
		credential, err := signaturekey.NewSelfJWTCredential(compact)
		if err != nil {
			t.Fatal(err)
		}
		if err := signaturekey.SignRequest(request, resourceKey, credential, aauth.ClockFunc(func() time.Time { return now }), signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
		}); err != nil {
			t.Fatal(err)
		}
		return request
	}
	tests := []struct {
		name       string
		storeError error
		wantStatus int
	}{
		{name: "resource mismatch", storeError: agentprovider.ErrEventResourceMismatch, wantStatus: http.StatusForbidden},
		{name: "agent mismatch", storeError: agentprovider.ErrEventAgentMismatch, wantStatus: http.StatusForbidden},
		{name: "unknown", storeError: agentprovider.ErrEventSubscriptionNotFound, wantStatus: http.StatusNotFound},
		{name: "inactive", storeError: agentprovider.ErrEventSubscriptionInactive, wantStatus: http.StatusNotFound},
		{name: "uses exceeded", storeError: agentprovider.ErrEventUsesExceeded, wantStatus: http.StatusTooManyRequests},
		{name: "store failure", storeError: errors.New("storage unavailable"), wantStatus: http.StatusInternalServerError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store.acceptError = test.storeError
			store.calls = 0
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, newRequest(t))
			if response.Code != test.wantStatus || store.calls != 1 {
				t.Fatalf("response = %d %s, store calls = %d; want %d and 1", response.Code, response.Body.String(), store.calls, test.wantStatus)
			}
		})
	}
}

type eventInboxStore struct {
	subscription            agentprovider.EventSubscription
	commitSubscriptionError error
	delivery                agentprovider.EventDelivery
	acceptResult            agentprovider.EventAcceptance
	acceptError             error
	accepted                bool
	calls                   int
}

func (store *eventInboxStore) CommitSubscription(_ context.Context, record agentprovider.EventSubscription) error {
	store.subscription = record
	return store.commitSubscriptionError
}

func (store *eventInboxStore) AcceptEvent(_ context.Context, delivery agentprovider.EventDelivery) (agentprovider.EventAcceptance, error) {
	store.calls++
	store.delivery = delivery
	if store.acceptError != nil {
		return agentprovider.EventAcceptance{}, store.acceptError
	}
	store.accepted = true
	return store.acceptResult, nil
}
