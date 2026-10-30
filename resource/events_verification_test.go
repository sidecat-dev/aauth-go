package resource

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestSubscribeTokenVerificationFailuresAre401WithSignatureError(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 2, 11, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	resourceKey := testSigningKey(t, "verify-events-resource", 0xe1)
	providerKey := testSigningKey(t, "verify-events-provider", 0xe2)
	agentKey := testSigningKey(t, "verify-events-agent", 0xe3)
	otherKey := testSigningKey(t, "verify-events-other", 0xe4)
	store := &multiEventSubscriptionStore{records: make(map[string]EventSubscription)}
	policyCalls := 0
	service, err := NewEventService(EventServiceConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey,
		KeyResolver: signaturekey.StaticKeyResolver{
			{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}:    providerKey.PublicJWK(),
			{Issuer: "https://ap.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
		},
		Clock: clock, SubscriptionEndpoint: resourceIssuer + "/events/subscribe", Store: store,
		RegisterPublic: func(context.Context, PublicSubscriptionRequest) (PublicSubscriptionDecision, error) {
			policyCalls++
			return PublicSubscriptionDecision{}, nil
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
	claims := func(eventID string, changes map[string]any) map[string]any {
		values := map[string]any{
			"iss": "https://ap.example", "dwk": aauth.AgentDiscoveryDocument,
			"sub": "aauth:agent@ap.example", "aud": resourceIssuer,
			"cnf": map[string]any{"jwk": agentKey.PublicJWK()},
			"eid": eventID, "jti": "st-" + eventID,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
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
	sign := func(tokenType string, claims map[string]any) string {
		t.Helper()
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		compact, err := jose.SignCompact(providerKey, jose.Header{
			Algorithm: jose.Ed25519Algorithm, Type: tokenType, KeyID: providerKey.ID(),
		}, payload)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	register := func(compact string, key jose.SigningKey) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, resourceIssuer+"/events/subscribe", nil)
		if err := signaturekey.SignJWTRequest(request, key, compact, clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		service.PublicSubscriptionHandler().ServeHTTP(response, request)
		return response
	}
	tests := []struct {
		name     string
		compact  string
		key      jose.SigningKey
		wantCode signaturekey.ErrorCode
	}{
		{name: "aud names another Resource", compact: sign(events.SubscribeTokenType, claims("event-aud", map[string]any{"aud": "https://other-resource.example"})), key: agentKey, wantCode: signaturekey.ErrorInvalidJWT},
		{name: "exp in the past", compact: sign(events.SubscribeTokenType, claims("event-exp", map[string]any{"iat": now.Add(-2 * time.Hour).Unix(), "exp": now.Add(-time.Hour).Unix()})), key: agentKey, wantCode: signaturekey.ErrorExpiredJWT},
		{name: "exp now", compact: sign(events.SubscribeTokenType, claims("event-exp-now", map[string]any{"iat": now.Add(-time.Hour).Unix(), "exp": now.Unix()})), key: agentKey, wantCode: signaturekey.ErrorExpiredJWT},
		{name: "request signed by a key other than cnf.jwk", compact: sign(events.SubscribeTokenType, claims("event-cnf", nil)), key: otherKey, wantCode: signaturekey.ErrorInvalidSignature},
		{name: "agent token type", compact: sign("aa-agent+jwt", claims("event-typ", nil)), key: agentKey, wantCode: signaturekey.ErrorInvalidJWT},
		{name: "resource discovery document", compact: sign(events.SubscribeTokenType, claims("event-dwk", map[string]any{"dwk": aauth.ResourceDiscoveryDocument})), key: agentKey, wantCode: signaturekey.ErrorInvalidJWT},
		{name: "missing eid", compact: sign(events.SubscribeTokenType, claims("event-missing", map[string]any{"eid": nil})), key: agentKey, wantCode: signaturekey.ErrorInvalidJWT},
		{name: "empty eid", compact: sign(events.SubscribeTokenType, claims("", nil)), key: agentKey, wantCode: signaturekey.ErrorInvalidJWT},
		{name: "missing jti", compact: sign(events.SubscribeTokenType, claims("event-jti", map[string]any{"jti": nil})), key: agentKey, wantCode: signaturekey.ErrorInvalidJWT},
		{name: "iat beyond the signature window", compact: sign(events.SubscribeTokenType, claims("event-iat", map[string]any{"iat": now.Add(5 * time.Minute).Unix()})), key: agentKey, wantCode: signaturekey.ErrorClockSkew},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := register(test.compact, test.key)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("registration = %d %s, want 401", response.Code, response.Body.String())
			}
			failure, err := signaturekey.ParseError(response.Header().Get("Signature-Error"))
			if err != nil || failure.Code != test.wantCode {
				t.Fatalf("Signature-Error = %q (%v), want %q", response.Header().Get("Signature-Error"), err, test.wantCode)
			}
			if len(store.records) != 0 || policyCalls != 0 {
				t.Fatalf("refused registration reached policy %d times and retained %d records", policyCalls, len(store.records))
			}
		})
	}

	// iat is not a validity check: a token issued inside the signature window
	// ahead of the Resource's clock registers.
	accepted := register(sign(events.SubscribeTokenType, claims("event-ahead", map[string]any{"iat": now.Add(30 * time.Second).Unix()})), agentKey)
	if accepted.Code != http.StatusOK || len(store.records) != 1 || policyCalls != 1 {
		t.Fatalf("registration issued 30s ahead = %d %s, records=%d", accepted.Code, accepted.Body.String(), len(store.records))
	}
}

func TestPreparedEventCarriesTheSubscriptionEIDAndBodyDigest(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 2, 11, 30, 0, 0, time.UTC)
	resourceKey := testSigningKey(t, "outbound-events-resource", 0xe5)
	providerKey := testSigningKey(t, "outbound-events-provider", 0xe6)
	agentKey := testSigningKey(t, "outbound-events-agent", 0xe7)
	clock := aauth.ClockFunc(func() time.Time { return now })
	var delivered []*http.Request
	var deliveredBodies [][]byte
	store := &multiEventSubscriptionStore{records: make(map[string]EventSubscription)}
	service, err := NewEventService(EventServiceConfig{
		Issuer: resourceIssuer, SigningKey: resourceKey,
		KeyResolver: signaturekey.StaticKeyResolver{
			{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: providerKey.ID()}: providerKey.PublicJWK(),
		},
		Clock: clock, SubscriptionEndpoint: resourceIssuer + "/events/subscribe", Store: store,
		RegisterPublic: func(context.Context, PublicSubscriptionRequest) (PublicSubscriptionDecision, error) {
			return PublicSubscriptionDecision{}, nil
		},
		ResolveEventEndpoint: EventEndpointResolverFunc(func(context.Context, string) (string, error) {
			return "https://ap.example/events", nil
		}),
		AdmitEventEndpoint: func(context.Context, string) error { return nil },
		HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				return nil, err
			}
			delivered = append(delivered, request)
			deliveredBodies = append(deliveredBodies, body)
			return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	subscribeToken, err := events.MintSubscribeToken("https://ap.example", providerKey, events.SubscribeTokenRequest{
		Agent: "aauth:agent@ap.example", Resource: resourceIssuer,
		ConfirmationKey: agentKey.PublicJWK(), EventID: "evt_8f3k2n9p", Lifetime: time.Hour,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	registration := httptest.NewRequest(http.MethodPost, resourceIssuer+"/events/subscribe", nil)
	if err := signaturekey.SignJWTRequest(registration, agentKey, subscribeToken, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	service.PublicSubscriptionHandler().ServeHTTP(response, registration)
	if response.Code != http.StatusOK {
		t.Fatalf("registration = %d %s", response.Code, response.Body.String())
	}

	resolver := signaturekey.StaticKeyResolver{
		{Issuer: resourceIssuer, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID()}: resourceKey.PublicJWK(),
	}
	payload := []byte(`{"event_type":"slot.available","slot_time":"2026-07-15T10:00:00Z"}`)
	for _, test := range []struct {
		name        string
		payload     []byte
		contentType string
		components  string
	}{
		{name: "with body", payload: payload, contentType: "application/json",
			components: `("@method" "@authority" "@path" "content-type" "content-digest" "signature-key")`},
		{name: "bodyless", components: `("@method" "@authority" "@path" "signature-key")`},
	} {
		t.Run(test.name, func(t *testing.T) {
			delivered, deliveredBodies = nil, nil
			prepared, err := service.PrepareEvent(context.Background(), EventInput{
				AgentProvider: "https://ap.example", EventID: "evt_8f3k2n9p",
				ContentType: test.contentType, Payload: test.payload, Lifetime: 5 * time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			claims, err := events.VerifyEventToken(context.Background(), prepared.compact, resolver, clock)
			if err != nil {
				t.Fatal(err)
			}
			if claims.EventID != "evt_8f3k2n9p" || claims.Audience != "aauth:agent@ap.example" ||
				claims.Issuer != resourceIssuer || claims.JTI == "" {
				t.Fatalf("event-token claims = %#v; want the subscribe token's eid and sub", claims)
			}
			if err := events.VerifyEventBody(claims, test.payload); err != nil {
				t.Fatalf("event token does not bind its own payload: %v", err)
			}
			parsed, err := jose.ParseCompact(prepared.compact)
			if err != nil {
				t.Fatal(err)
			}
			var members map[string]json.RawMessage
			if err := json.Unmarshal(parsed.Payload(), &members); err != nil {
				t.Fatal(err)
			}
			if _, present := members["cnf"]; present {
				t.Fatal("event token carries cnf")
			}
			if _, present := members["body_s256"]; present != (len(test.payload) > 0) {
				t.Fatalf("body_s256 present = %t for a %d-byte body", present, len(test.payload))
			}
			if _, err := service.DeliverEvent(context.Background(), prepared); err != nil {
				t.Fatal(err)
			}
			if len(delivered) != 1 || !bytes.Equal(deliveredBodies[0], test.payload) {
				t.Fatalf("delivered %d requests, body %q", len(delivered), deliveredBodies)
			}
			signatureInput := delivered[0].Header.Get("Signature-Input")
			if !strings.HasPrefix(signatureInput, "sig="+test.components+";") {
				t.Fatalf("Signature-Input = %q; want components %s", signatureInput, test.components)
			}
			if !strings.HasPrefix(delivered[0].Header.Get("Signature-Key"), "sig=self-jwt;") {
				t.Fatalf("Signature-Key = %q", delivered[0].Header.Get("Signature-Key"))
			}
		})
	}
}
