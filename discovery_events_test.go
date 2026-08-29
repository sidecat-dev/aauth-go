package aauth_test

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestAgentEventMetadataUsesAdmittedHTTPFreshness(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	eventEndpoint := "https://ap.example/events-v1"
	var metadataFetches atomic.Int32

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/.well-known/aauth-agent.json":
				metadataFetches.Add(1)
				response.Header().Set("Cache-Control", "max-age=60")
				_, _ = fmt.Fprintf(response, `{"issuer":"https://ap.example","jwks_uri":"https://ap.example/jwks","event_endpoint":%q}`, eventEndpoint)
			default:
				http.NotFound(response, request)
			}
		}),
	})
	defer gateway.Close()

	admissions := 0
	resolver, err := aauth.NewHTTPAgentEventMetadataResolver(aauth.HTTPAgentEventMetadataResolverConfig{
		Client: gateway.Client(),
		Clock:  clock,
		Admit: func(context.Context, string) error {
			admissions++
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := resolver.ResolveAgentEventMetadata(context.Background(), "https://ap.example")
	if err != nil {
		t.Fatal(err)
	}
	if first.Issuer != "https://ap.example" || first.EventEndpoint != eventEndpoint {
		t.Fatalf("first metadata = %#v", first)
	}

	eventEndpoint = "https://events.example/receive"
	now = now.Add(59 * time.Second)
	cached, err := resolver.ResolveAgentEventMetadata(context.Background(), "https://ap.example")
	if err != nil {
		t.Fatal(err)
	}
	if cached != first || metadataFetches.Load() != 1 {
		t.Fatalf("fresh-cache metadata/fetches = %#v, %d", cached, metadataFetches.Load())
	}

	now = now.Add(2 * time.Second)
	rotated, err := resolver.ResolveAgentEventMetadata(context.Background(), "https://ap.example")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.EventEndpoint != eventEndpoint || metadataFetches.Load() != 2 || admissions != 2 {
		t.Fatalf("rotated metadata/fetches/admissions = %#v, %d/%d", rotated, metadataFetches.Load(), admissions)
	}
}

func TestAgentEventMetadataDoesNotCacheWhenCacheControlForbidsIt(t *testing.T) {
	t.Parallel()

	for _, cacheControl := range []string{
		"max-age=60, no-store",
		"no-store, max-age=60",
		"max-age=60, no-cache",
		"no-cache, max-age=60",
	} {
		cacheControl := cacheControl
		t.Run(cacheControl, func(t *testing.T) {
			t.Parallel()

			now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
			var metadataFetches atomic.Int32
			gateway := newLogicalGateway(t, map[string]http.Handler{
				"ap.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
					switch request.URL.Path {
					case "/.well-known/aauth-agent.json":
						fetch := metadataFetches.Add(1)
						response.Header().Set("Cache-Control", cacheControl)
						_, _ = fmt.Fprintf(response, `{"issuer":"https://ap.example","jwks_uri":"https://ap.example/jwks","event_endpoint":"https://ap.example/events-%d"}`, fetch)
					default:
						http.NotFound(response, request)
					}
				}),
			})
			defer gateway.Close()

			resolver, err := aauth.NewHTTPAgentEventMetadataResolver(aauth.HTTPAgentEventMetadataResolverConfig{
				Client: gateway.Client(),
				Clock:  aauth.ClockFunc(func() time.Time { return now }),
				Admit:  func(context.Context, string) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			first, err := resolver.ResolveAgentEventMetadata(context.Background(), "https://ap.example")
			if err != nil {
				t.Fatal(err)
			}
			second, err := resolver.ResolveAgentEventMetadata(context.Background(), "https://ap.example")
			if err != nil {
				t.Fatal(err)
			}
			if first.EventEndpoint == second.EventEndpoint || metadataFetches.Load() != 2 {
				t.Fatalf("forbidden cache retained metadata: first=%q second=%q fetches=%d", first.EventEndpoint, second.EventEndpoint, metadataFetches.Load())
			}
		})
	}
}
