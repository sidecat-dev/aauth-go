package aauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestEventsContractResolverUsesAdmittedExactHTTPFreshness(t *testing.T) {
	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	contractBytes := eventsDiscoveryTestDocument("1.0.0")
	var metadataFetches atomic.Int32
	var contractFetches atomic.Int32

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/.well-known/aauth-resource.json":
				metadataFetches.Add(1)
				response.Header().Set("Cache-Control", "max-age=60")
				response.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(response, `{"issuer":"https://resource.example","r3_vocabularies":{"urn:aauth:vocabulary:asyncapi":"/asyncapi.json"}}`)
			case "/asyncapi.json":
				contractFetches.Add(1)
				response.Header().Set("Cache-Control", "max-age=60")
				response.Header().Set("Content-Type", "application/json")
				_, _ = response.Write(contractBytes)
			default:
				http.NotFound(response, request)
			}
		}),
	})
	defer gateway.Close()

	var admissions atomic.Int32
	resolver, err := aauth.NewHTTPEventsContractResolver(aauth.HTTPEventsContractResolverConfig{
		Client: gateway.Client(), Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if !strings.HasPrefix(endpoint, "https://resource.example/") {
				return fmt.Errorf("test: endpoint outside admitted resource: %s", endpoint)
			}
			admissions.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := resolver.Resolve(context.Background(), "https://resource.example")
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() != aauth.R3S256(contractBytes) {
		t.Fatalf("first contract digest = %q", first.Digest())
	}

	contractBytes = eventsDiscoveryTestDocument("2.0.0")
	now = now.Add(59 * time.Second)
	cached, err := resolver.Resolve(context.Background(), "https://resource.example")
	if err != nil || cached.Digest() != first.Digest() {
		t.Fatalf("fresh cached contract = %q, %v", cached.Digest(), err)
	}
	if metadataFetches.Load() != 1 || contractFetches.Load() != 1 || admissions.Load() != 2 {
		t.Fatalf("fresh fetches/admissions = %d/%d/%d", metadataFetches.Load(), contractFetches.Load(), admissions.Load())
	}

	now = now.Add(2 * time.Second)
	rotated, err := resolver.Resolve(context.Background(), "https://resource.example")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Digest() == first.Digest() || rotated.Digest() != aauth.R3S256(contractBytes) {
		t.Fatalf("rotated contract digest = %q", rotated.Digest())
	}
	if metadataFetches.Load() != 2 || contractFetches.Load() != 2 || admissions.Load() != 4 {
		t.Fatalf("rotated fetches/admissions = %d/%d/%d", metadataFetches.Load(), contractFetches.Load(), admissions.Load())
	}
}

func TestEventsContractResolverRejectsUnsafeOrInvalidDiscovery(t *testing.T) {
	valid := eventsDiscoveryTestDocument("1.0.0")
	for _, test := range []struct {
		name        string
		vocabulary  string
		contentType string
		document    []byte
	}{
		{name: "missing vocabulary", vocabulary: "", contentType: "application/json", document: valid},
		{name: "cross origin", vocabulary: "https://schemas.example/asyncapi.json", contentType: "application/json", document: valid},
		{name: "query endpoint", vocabulary: "/asyncapi.json?version=1", contentType: "application/json", document: valid},
		{name: "wrong media type", vocabulary: "/asyncapi.json", contentType: "text/plain", document: valid},
		{name: "invalid contract", vocabulary: "/asyncapi.json", contentType: "application/json", document: []byte(`{"asyncapi":"3.0.0"}`)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			gateway := newLogicalGateway(t, map[string]http.Handler{
				"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
					switch request.URL.Path {
					case "/.well-known/aauth-resource.json":
						response.Header().Set("Content-Type", "application/json")
						vocabularies := map[string]string{}
						if test.vocabulary != "" {
							vocabularies[aauth.R3VocabularyAsyncAPI] = test.vocabulary
						}
						_ = json.NewEncoder(response).Encode(map[string]any{
							"issuer": "https://resource.example", "r3_vocabularies": vocabularies,
						})
					case "/asyncapi.json":
						response.Header().Set("Content-Type", test.contentType)
						_, _ = response.Write(test.document)
					default:
						http.NotFound(response, request)
					}
				}),
			})
			defer gateway.Close()
			resolver, err := aauth.NewHTTPEventsContractResolver(aauth.HTTPEventsContractResolverConfig{
				Client: gateway.Client(), Clock: aauth.ClockFunc(func() time.Time { return time.Now() }),
				Admit: func(context.Context, string) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.Resolve(context.Background(), "https://resource.example"); err == nil {
				t.Fatal("unsafe or invalid Events discovery was accepted")
			}
		})
	}
}

func TestResourceEventsAsyncAPIDiscoveryServesExactDocument(t *testing.T) {
	document := eventsDiscoveryTestDocument("1.0.0")
	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aauth.AccessModeSessionToken,
		SigningKey:  testSigningKey(t, "resource-key"),
		KeyResolver: signaturekey.StaticKeyResolver{}, Clock: aauth.ClockFunc(func() time.Time { return now }),
		NewID: func() string { return "unused" }, Scopes: []string{"events.read"},
		RequiredScopesForRequest: testRequiredResourceScopes("events.read"),
		ReplayStore:              testResourceReplayStore(t, aauth.ClockFunc(func() time.Time { return now })),
		AuthorizationStore:       testAuthorizationStateStore(t),
		AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{}, nil
		},
		Operation: func(context.Context, aauth.AuthorizedRequest) (any, error) { return map[string]any{}, nil },
		Events: &reference.ResourceEventsConfig{
			PublicSubscriptionPath: "/events/subscriptions", Store: reference.NewMemoryResourceEventStore(),
			HTTPClient: &http.Client{}, ActiveUntil: func(context.Context, aauth.SubscribeTokenClaims) (time.Time, error) {
				return now.Add(time.Hour), nil
			},
			AsyncAPIPath: "/asyncapi.json", AsyncAPIDocument: document,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	metadataRequest := httptest.NewRequest(http.MethodGet, "https://resource.example/.well-known/aauth-resource.json", nil)
	metadataResponse := httptest.NewRecorder()
	resource.Handler().ServeHTTP(metadataResponse, metadataRequest)
	if metadataResponse.Code != http.StatusOK {
		t.Fatalf("metadata status = %d", metadataResponse.Code)
	}
	var metadata struct {
		R3Vocabularies map[string]json.RawMessage `json:"r3_vocabularies"`
	}
	if err := json.Unmarshal(metadataResponse.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if string(metadata.R3Vocabularies[aauth.R3VocabularyAsyncAPI]) != `"/asyncapi.json"` {
		t.Fatalf("AsyncAPI discovery = %s", metadata.R3Vocabularies[aauth.R3VocabularyAsyncAPI])
	}

	documentRequest := httptest.NewRequest(http.MethodGet, "https://resource.example/asyncapi.json", nil)
	documentResponse := httptest.NewRecorder()
	resource.Handler().ServeHTTP(documentResponse, documentRequest)
	if documentResponse.Code != http.StatusOK || documentResponse.Header().Get("Content-Type") != "application/json" ||
		!strings.Contains(documentResponse.Header().Get("Cache-Control"), "max-age=") ||
		string(documentResponse.Body.Bytes()) != string(document) {
		t.Fatalf("document response = %d %q %q %s", documentResponse.Code, documentResponse.Header().Get("Content-Type"), documentResponse.Header().Get("Cache-Control"), documentResponse.Body.Bytes())
	}
}

func eventsDiscoveryTestDocument(version string) []byte {
	return []byte(fmt.Sprintf(`{"asyncapi":"3.0.0","info":{"title":"Appointments Events","version":%q},"channels":{"waitlistProtected":{"address":"/appointments/waitlist/{subscriptionTicket}","description":"Ticket URL from prior authenticated operation.","parameters":{"subscriptionTicket":{"description":"Single-use ticket."}},"messages":{"slotAvailable":{"$ref":"#/components/messages/SlotAvailable"}}}},"operations":{"subscribeProtectedWaitlist":{"action":"receive","channel":{"$ref":"#/channels/waitlistProtected"}}},"components":{"messages":{"SlotAvailable":{"contentType":"application/json","payload":{"type":"object","additionalProperties":false,"properties":{"event_type":{"type":"string","const":"slot.available"},"slot_time":{"type":"string","format":"date-time"}},"required":["event_type","slot_time"]}}},"securitySchemes":{"aauth_subscribe":{"type":"http","scheme":"aauth-subscribe"}}}}`, version))
}
