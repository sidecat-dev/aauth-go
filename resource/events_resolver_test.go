package resource

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestHTTPEventEndpointResolverFetchesCurrentValidatedMetadata(t *testing.T) {
	t.Parallel()

	admitted := ""
	resolver, err := NewHTTPEventEndpointResolver(HTTPEventEndpointResolverConfig{
		Client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != "https://ap.example/.well-known/aauth-agent.json" || request.Header.Get("Cookie") != "" {
				t.Fatalf("metadata request = %s headers=%v", request.URL, request.Header)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body: io.NopCloser(strings.NewReader(`{
					"issuer":"https://ap.example",
					"jwks_uri":"https://ap.example/.well-known/jwks.json",
					"event_endpoint":"https://inbox.example/events"
				}`)),
				Request: request,
			}, nil
		})},
		Admit: func(_ context.Context, endpoint string) error {
			admitted = endpoint
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := resolver.ResolveEventEndpoint(context.Background(), "https://ap.example")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "https://inbox.example/events" || admitted != "https://ap.example/.well-known/aauth-agent.json" {
		t.Fatalf("endpoint = %q, admitted = %q", endpoint, admitted)
	}
}
