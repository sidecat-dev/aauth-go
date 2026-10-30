package agentprovider_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	claims, err := events.VerifySubscribeToken(context.Background(), issued.Compact, signaturekey.StaticKeyResolver{
		{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
	}, aauth.ClockFunc(func() time.Time { return now }))
	if err != nil || claims.JTI == "" || claims.EventID != "event-1" {
		t.Fatalf("issued subscribe-token claims = %#v, %v", claims, err)
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
	payload := []byte(`{"event_type":"slot.available"}`)
	compact, err := events.MintEventToken("https://resource.example", resourceKey, events.EventTokenRequest{
		Agent: "aauth:agent@ap.example", EventID: "event-1", Payload: payload, Lifetime: 5 * time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
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
		store.delivery.EventID != "event-1" || store.delivery.ContentType != "application/json" {
		t.Fatalf("durable delivery = %#v", store.delivery)
	}
	if response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("bounded acceptance content type = %q", response.Header().Get("Content-Type"))
	}
	var body struct {
		RemainingUses *int64 `json:"remaining_uses"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.RemainingUses == nil || *body.RemainingUses != 0 {
		t.Fatalf("event response body = %s, error = %v", response.Body.String(), err)
	}

	store.acceptError = errors.New("inbox unavailable")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code == http.StatusAccepted || response.Code != http.StatusInternalServerError {
		t.Fatalf("uncommitted delivery response = %d %s; want 500, never 202", response.Code, response.Body.String())
	}
	store.acceptError = agentprovider.ErrEventUsesExceeded
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("exhausted response = %d %s; want 404", response.Code, response.Body.String())
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
	discovered, err := events.DecodeAgentProviderMetadata(response.Body.Bytes(), "https://ap.example")
	if err != nil || discovered.EventEndpoint != "https://ap.example/events" {
		t.Fatalf("published metadata as a Resource reads it = %#v, %v", discovered, err)
	}

	withoutEvents, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "metadata-no-events-key", 0x4d),
		Clock: aauth.ClockFunc(func() time.Time { return now }), NewID: func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	withoutEvents.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://ap.example/.well-known/aauth-agent.json", nil))
	if strings.Contains(response.Body.String(), "event_endpoint") {
		t.Fatalf("metadata without Events = %s", response.Body.String())
	}
}

func TestAgentProviderRefusesANonHTTPSEventEndpoint(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{
		"http://ap.example/events",
		"/events",
		"https://ap.example/events?x=1",
		"https://user@ap.example/events",
	} {
		_, err := agentprovider.New(agentprovider.Config{
			Issuer: "https://ap.example", SigningKey: testSigningKey(t, "plain-endpoint-key", 0x4e),
			Clock: aauth.ClockFunc(time.Now), NewID: func() string { return "unused" },
			Events: &agentprovider.EventsConfig{
				EventEndpoint: endpoint, NewEventID: func() string { return "unused" },
				KeyResolver: signaturekey.StaticKeyResolver{}, Store: &eventInboxStore{},
			},
		})
		if err == nil {
			t.Fatalf("agentprovider.New accepted event endpoint %q", endpoint)
		}
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

func TestAgentProviderAcceptsDeliveriesSignedWithTheDraftComponents(t *testing.T) {
	t.Parallel()

	fixture := newEventEndpointFixture(t)
	fixture.store.acceptResult = agentprovider.EventAcceptance{}

	bodyless := fixture.mint(t, events.EventTokenRequest{Agent: fixtureAgent, EventID: "event-1", Lifetime: time.Minute}, fixture.now)
	request := fixture.signed(t, bodyless, fixture.resourceKey, nil, "")
	if got := request.Header.Get("Signature-Input"); !strings.HasPrefix(got, `sig=("@method" "@authority" "@path" "signature-key");`) {
		t.Fatalf("bodyless Signature-Input = %q; want the base components only", got)
	}
	response := fixture.serve(request)
	if response.Code != http.StatusAccepted || response.Body.Len() != 0 || len(fixture.store.delivery.Payload) != 0 {
		t.Fatalf("bodyless delivery = %d %q, retained payload %q", response.Code, response.Body.String(), fixture.store.delivery.Payload)
	}

	payload := []byte(`{"event_type":"slot.available"}`)
	withBody := fixture.mint(t, events.EventTokenRequest{Agent: fixtureAgent, EventID: "event-1", Payload: payload, Lifetime: time.Minute}, fixture.now)
	request = fixture.signed(t, withBody, fixture.resourceKey, payload, "application/json")
	if got := request.Header.Get("Signature-Input"); !strings.Contains(got, `"content-type"`) || !strings.Contains(got, `"content-digest"`) {
		t.Fatalf("body Signature-Input = %q; want content-type and content-digest", got)
	}
	response = fixture.serve(request)
	if response.Code != http.StatusAccepted || !bytes.Equal(fixture.store.delivery.Payload, payload) || fixture.store.delivery.Token != withBody {
		t.Fatalf("body delivery = %d %s, retained %#v", response.Code, response.Body.String(), fixture.store.delivery)
	}

	// iat is not a validity check: an unexpired token issued slightly ahead
	// of the AP's clock, inside the signature window, is accepted.
	ahead := fixture.mint(t, events.EventTokenRequest{Agent: fixtureAgent, EventID: "event-1", Lifetime: time.Minute}, fixture.now.Add(30*time.Second))
	if response := fixture.serve(fixture.signed(t, ahead, fixture.resourceKey, nil, "")); response.Code != http.StatusAccepted {
		t.Fatalf("token issued 30s ahead = %d %s", response.Code, response.Body.String())
	}
}

func TestAgentProviderEventEndpointValidatesTheDeliveryAsTheDraftOrders(t *testing.T) {
	t.Parallel()

	fixture := newEventEndpointFixture(t)
	forgedKey := testSigningKey(t, "forged-stage-key", 0x49)
	payload := []byte(`{"event_type":"slot.available"}`)
	valid := fixture.mint(t, events.EventTokenRequest{Agent: fixtureAgent, EventID: "event-1", Payload: payload, Lifetime: time.Minute}, fixture.now)
	bodyless := fixture.mint(t, events.EventTokenRequest{Agent: fixtureAgent, EventID: "event-1", Lifetime: time.Minute}, fixture.now)
	expired := fixture.mint(t, events.EventTokenRequest{Agent: fixtureAgent, EventID: "event-1", Payload: payload, Lifetime: time.Minute}, fixture.now.Add(-2*time.Minute))
	issuedAhead := fixture.mint(t, events.EventTokenRequest{Agent: fixtureAgent, EventID: "event-1", Payload: payload, Lifetime: 10 * time.Minute}, fixture.now.Add(5*time.Minute))
	claims := func(changes map[string]any) map[string]any {
		values := map[string]any{
			"iss": "https://resource.example", "dwk": aauth.ResourceDiscoveryDocument,
			"aud": fixtureAgent, "eid": "event-1", "jti": "event-token-1",
			"body_s256": events.BodySHA256(payload),
			"iat":       fixture.now.Unix(), "exp": fixture.now.Add(time.Minute).Unix(),
		}
		for name, value := range changes {
			if value == nil {
				delete(values, name)
				continue
			}
			values[name] = value
		}
		return values
	}
	missingEventID := fixture.signClaims(t, events.EventTokenType, claims(map[string]any{"eid": nil}))
	withConfirmation := fixture.signClaims(t, events.EventTokenType, claims(map[string]any{
		"cnf": map[string]any{"jwk": fixture.resourceKey.PublicJWK()},
	}))
	agentType := fixture.signClaims(t, "aa-agent+jwt", claims(nil))
	agentDocument := fixture.signClaims(t, events.EventTokenType, claims(map[string]any{"dwk": aauth.AgentDiscoveryDocument}))

	tests := []struct {
		name       string
		request    func(*testing.T) *http.Request
		wantStatus int
		wantCode   signaturekey.ErrorCode
	}{
		{
			name: "another delivery target",
			request: func(t *testing.T) *http.Request {
				request := fixture.signed(t, valid, fixture.resourceKey, payload, "application/json")
				request.Host = "other.example"
				return request
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "payload without a content type",
			request: func(t *testing.T) *http.Request {
				return fixture.signed(t, valid, fixture.resourceKey, payload, "")
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "unsigned request",
			request: func(*testing.T) *http.Request {
				request := httptest.NewRequest(http.MethodPost, "https://ap.example/events", bytes.NewReader(payload))
				request.Header.Set("Content-Type", "application/json")
				return request
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "jwt scheme instead of self-jwt",
			request: func(t *testing.T) *http.Request {
				request := httptest.NewRequest(http.MethodPost, "https://ap.example/events", bytes.NewReader(payload))
				request.Header.Set("Content-Type", "application/json")
				if err := signaturekey.SignJWTRequest(request, fixture.resourceKey, valid, fixture.clock); err != nil {
					t.Fatal(err)
				}
				return request
			},
			wantStatus: http.StatusUnauthorized, wantCode: signaturekey.ErrorUnsupportedScheme,
		},
		{
			name: "body added after signing without content-digest",
			request: func(t *testing.T) *http.Request {
				request := fixture.signed(t, valid, fixture.resourceKey, nil, "")
				request.Body = io.NopCloser(bytes.NewReader(payload))
				request.ContentLength = int64(len(payload))
				return request
			},
			wantStatus: http.StatusUnauthorized, wantCode: signaturekey.ErrorInvalidInput,
		},
		{
			name: "content type not covered",
			request: func(t *testing.T) *http.Request {
				request := fixture.signed(t, valid, fixture.resourceKey, payload, "")
				request.Header.Set("Content-Type", "application/json")
				return request
			},
			wantStatus: http.StatusUnauthorized, wantCode: signaturekey.ErrorInvalidInput,
		},
		{
			name: "expired event token",
			request: func(t *testing.T) *http.Request {
				return fixture.signed(t, expired, fixture.resourceKey, payload, "application/json")
			},
			wantStatus: http.StatusUnauthorized, wantCode: signaturekey.ErrorExpiredJWT,
		},
		{
			name: "event token without eid",
			request: func(t *testing.T) *http.Request {
				return fixture.signed(t, missingEventID, fixture.resourceKey, payload, "application/json")
			},
			wantStatus: http.StatusUnauthorized, wantCode: signaturekey.ErrorInvalidJWT,
		},
		{
			name: "event token with cnf",
			request: func(t *testing.T) *http.Request {
				return fixture.signed(t, withConfirmation, fixture.resourceKey, payload, "application/json")
			},
			wantStatus: http.StatusUnauthorized, wantCode: signaturekey.ErrorInvalidJWT,
		},
		{
			name: "agent token type",
			request: func(t *testing.T) *http.Request {
				return fixture.signed(t, agentType, fixture.resourceKey, payload, "application/json")
			},
			wantStatus: http.StatusUnauthorized, wantCode: signaturekey.ErrorInvalidJWT,
		},
		{
			name: "agent discovery document",
			request: func(t *testing.T) *http.Request {
				return fixture.signed(t, agentDocument, fixture.resourceKey, payload, "application/json")
			},
			wantStatus: http.StatusUnauthorized, wantCode: signaturekey.ErrorInvalidJWT,
		},
		{
			name: "outer signature by another key",
			request: func(t *testing.T) *http.Request {
				return fixture.signed(t, valid, forgedKey, payload, "application/json")
			},
			wantStatus: http.StatusUnauthorized, wantCode: signaturekey.ErrorInvalidSignature,
		},
		{
			name: "body does not match body_s256",
			request: func(t *testing.T) *http.Request {
				return fixture.signed(t, valid, fixture.resourceKey, []byte(`{"event_type":"slot.taken"}`), "application/json")
			},
			wantStatus: http.StatusUnauthorized, wantCode: signaturekey.ErrorInvalidJWT,
		},
		{
			name: "declared body missing",
			request: func(t *testing.T) *http.Request {
				return fixture.signed(t, valid, fixture.resourceKey, nil, "")
			},
			wantStatus: http.StatusUnauthorized, wantCode: signaturekey.ErrorInvalidJWT,
		},
		{
			name: "body without body_s256",
			request: func(t *testing.T) *http.Request {
				return fixture.signed(t, bodyless, fixture.resourceKey, payload, "application/json")
			},
			wantStatus: http.StatusUnauthorized, wantCode: signaturekey.ErrorInvalidJWT,
		},
		{
			name: "iat beyond the signature window",
			request: func(t *testing.T) *http.Request {
				return fixture.signed(t, issuedAhead, fixture.resourceKey, payload, "application/json")
			},
			wantStatus: http.StatusUnauthorized, wantCode: signaturekey.ErrorClockSkew,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture.store.calls = 0
			response := fixture.serve(test.request(t))
			if response.Code != test.wantStatus {
				t.Fatalf("response = %d %s, want %d", response.Code, response.Body.String(), test.wantStatus)
			}
			signatureError := response.Header().Get("Signature-Error")
			if test.wantStatus == http.StatusUnauthorized {
				failure, err := signaturekey.ParseError(signatureError)
				if err != nil {
					t.Fatalf("Signature-Error %q: %v", signatureError, err)
				}
				if test.wantCode != "" && failure.Code != test.wantCode {
					t.Fatalf("Signature-Error code = %q, want %q", failure.Code, test.wantCode)
				}
			} else if signatureError != "" {
				t.Fatalf("non-401 response carries Signature-Error %q", signatureError)
			}
			if fixture.store.calls != 0 {
				t.Fatalf("refused delivery reached the inbox store %d times", fixture.store.calls)
			}
		})
	}
}

func TestAgentProviderEventEndpointMapsStoreOutcomes(t *testing.T) {
	t.Parallel()

	fixture := newEventEndpointFixture(t)
	payload := []byte(`{}`)
	compact := fixture.mint(t, events.EventTokenRequest{Agent: fixtureAgent, EventID: "event-1", Payload: payload, Lifetime: time.Minute}, fixture.now)
	tests := []struct {
		name       string
		storeError error
		wantStatus int
		wantCode   signaturekey.ErrorCode
	}{
		{name: "resource mismatch", storeError: agentprovider.ErrEventResourceMismatch, wantStatus: http.StatusForbidden},
		{name: "agent mismatch", storeError: agentprovider.ErrEventAgentMismatch, wantStatus: http.StatusUnauthorized, wantCode: signaturekey.ErrorInvalidJWT},
		{name: "unknown", storeError: agentprovider.ErrEventSubscriptionNotFound, wantStatus: http.StatusNotFound},
		{name: "inactive", storeError: agentprovider.ErrEventSubscriptionInactive, wantStatus: http.StatusNotFound},
		{name: "uses exceeded", storeError: agentprovider.ErrEventUsesExceeded, wantStatus: http.StatusNotFound},
		{name: "store failure", storeError: errors.New("storage unavailable"), wantStatus: http.StatusInternalServerError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture.store.acceptError = test.storeError
			fixture.store.calls = 0
			response := fixture.serve(fixture.signed(t, compact, fixture.resourceKey, payload, "application/json"))
			if response.Code != test.wantStatus || fixture.store.calls != 1 {
				t.Fatalf("response = %d %s, store calls = %d; want %d and 1", response.Code, response.Body.String(), fixture.store.calls, test.wantStatus)
			}
			signatureError := response.Header().Get("Signature-Error")
			if test.wantCode == "" {
				if signatureError != "" {
					t.Fatalf("response carries Signature-Error %q", signatureError)
				}
				return
			}
			failure, err := signaturekey.ParseError(signatureError)
			if err != nil || failure.Code != test.wantCode {
				t.Fatalf("Signature-Error = %q (%v), want %q", signatureError, err, test.wantCode)
			}
		})
	}
}

const fixtureAgent = "aauth:agent@ap.example"

type eventEndpointFixture struct {
	now         time.Time
	clock       aauth.Clock
	resourceKey jose.SigningKey
	store       *eventInboxStore
	server      *agentprovider.Server
}

func newEventEndpointFixture(t *testing.T) *eventEndpointFixture {
	t.Helper()
	fixture := &eventEndpointFixture{
		now:         time.Date(2026, 8, 31, 21, 30, 0, 0, time.UTC),
		resourceKey: testSigningKey(t, "resource-stage-key", 0x48),
		store:       &eventInboxStore{acceptResult: agentprovider.EventAcceptance{MaximumUses: 1}},
	}
	fixture.clock = aauth.ClockFunc(func() time.Time { return fixture.now })
	server, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "provider-stage-key", 0x47),
		Clock: fixture.clock, NewID: func() string { return "unused" },
		Events: &agentprovider.EventsConfig{
			EventEndpoint: "https://ap.example/events", NewEventID: func() string { return "unused" },
			KeyResolver: signaturekey.StaticKeyResolver{
				{Issuer: "https://resource.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: fixture.resourceKey.ID()}: fixture.resourceKey.PublicJWK(),
				{Issuer: "https://resource.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: fixture.resourceKey.ID()}:    fixture.resourceKey.PublicJWK(),
			},
			Store: fixture.store,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.server = server
	return fixture
}

func (fixture *eventEndpointFixture) mint(t *testing.T, request events.EventTokenRequest, at time.Time) string {
	t.Helper()
	compact, err := events.MintEventToken("https://resource.example", fixture.resourceKey, request, at)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (fixture *eventEndpointFixture) signClaims(t *testing.T, tokenType string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.SignCompact(fixture.resourceKey, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: tokenType, KeyID: fixture.resourceKey.ID(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// signed builds one delivery signed under self-jwt with no extra components:
// the signer covers content-digest and Content-Type exactly when a body is
// present, as the Events Request section describes.
func (fixture *eventEndpointFixture) signed(t *testing.T, compact string, key jose.SigningKey, body []byte, contentType string) *http.Request {
	t.Helper()
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	request := httptest.NewRequest(http.MethodPost, "https://ap.example/events", reader)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	credential, err := signaturekey.NewSelfJWTCredential(compact)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, key, credential, fixture.clock, signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	return request
}

func (fixture *eventEndpointFixture) serve(request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(response, request)
	return response
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
