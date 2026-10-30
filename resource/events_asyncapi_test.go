package resource

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestEventServiceServesOnlyAnAsyncAPIDocumentDeclaringTheSubscribeScheme(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	config := func(document string) EventServiceConfig {
		return EventServiceConfig{
			Issuer: resourceIssuer, SigningKey: testSigningKey(t, "asyncapi-resource", 0xe8),
			KeyResolver: signaturekey.StaticKeyResolver{}, Clock: aauth.ClockFunc(func() time.Time { return now }),
			SubscriptionEndpoint: resourceIssuer + "/events/subscribe", Store: &eventSubscriptionStore{},
			RegisterPublic: func(context.Context, PublicSubscriptionRequest) (PublicSubscriptionDecision, error) {
				return PublicSubscriptionDecision{}, nil
			},
			ResolveEventEndpoint: EventEndpointResolverFunc(func(context.Context, string) (string, error) {
				return "https://ap.example/events", nil
			}),
			AdmitEventEndpoint: func(context.Context, string) error { return nil },
			HTTPClient:         &http.Client{},
			AsyncAPIDocument:   []byte(document),
		}
	}
	declared := `{"asyncapi":"3.0.0","info":{"title":"Events","version":"1.0.0"},` +
		`"components":{"securitySchemes":{"aauth_subscribe":{"type":"http","scheme":"aauth-subscribe"}}}}`
	for name, document := range map[string]string{
		"no security scheme": `{"asyncapi":"3.0.0","info":{"title":"Events","version":"1.0.0"}}`,
		"bearer scheme":      strings.Replace(declared, "aauth-subscribe", "bearer", 1),
		"apiKey type":        strings.Replace(declared, `"type":"http"`, `"type":"apiKey"`, 1),
	} {
		if _, err := NewEventService(config(document)); err == nil {
			t.Fatalf("NewEventService accepted an AsyncAPI document with %s", name)
		}
	}

	exact := []byte(declared)
	service, err := NewEventService(config(declared))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	service.AsyncAPIHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, resourceIssuer+"/asyncapi.json", nil))
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" ||
		!bytes.Equal(response.Body.Bytes(), exact) {
		t.Fatalf("AsyncAPI response = %d %q %s", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}
	if err := events.ValidateAsyncAPIDocument(response.Body.Bytes()); err != nil {
		t.Fatalf("served document = %v", err)
	}
	response = httptest.NewRecorder()
	service.AsyncAPIHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, resourceIssuer+"/asyncapi.json", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST AsyncAPI document = %d", response.Code)
	}

	withoutDocument, err := NewEventService(config(""))
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	withoutDocument.AsyncAPIHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, resourceIssuer+"/asyncapi.json", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("unconfigured AsyncAPI document = %d", response.Code)
	}
}
