package signaturekey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestHTTPKeyResolverBoundsPositiveAndNegativeState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	key := testDiscoverySigningKey(t, "issuer-key", 0x75).PublicJWK()

	t.Run("positive entries", func(t *testing.T) {
		var requests atomic.Int32
		client := &http.Client{Transport: discoveryRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests.Add(1)
			issuer := request.URL.Scheme + "://" + request.URL.Host
			var body []byte
			switch request.URL.Path {
			case "/.well-known/aauth-access.json":
				body = []byte(fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/jwks"))
			case "/jwks":
				body, _ = json.Marshal(map[string]any{"keys": []jose.JWK{key}})
			default:
				return nil, errors.New("unexpected discovery URL")
			}
			return discoveryResponse(request, body, "max-age=300"), nil
		})}
		resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
			Client: client, Clock: fixedClock(now), Admit: func(context.Context, string) error { return nil },
			Limits: signaturekey.HTTPKeyResolverLimits{PositiveEntries: 1, NegativeEntries: 1, InFlightEntries: 1},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, issuer := range []string{"https://issuer-a.example", "https://issuer-b.example", "https://issuer-a.example"} {
			resolved, err := resolver.ResolveKey(context.Background(), issuer, "aauth-access.json", key.Kid)
			if err != nil || !resolved.Equal(key) {
				t.Fatalf("ResolveKey(%q) = %#v, %v", issuer, resolved, err)
			}
		}
		if got := requests.Load(); got != 6 {
			t.Fatalf("requests = %d, want 6 after bounded-cache eviction", got)
		}
	})

	t.Run("negative entries", func(t *testing.T) {
		var requests atomic.Int32
		client := &http.Client{Transport: discoveryRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests.Add(1)
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable",
				Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil)), Request: request,
			}, nil
		})}
		resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
			Client: client, Clock: fixedClock(now), Admit: func(context.Context, string) error { return nil },
			Limits: signaturekey.HTTPKeyResolverLimits{PositiveEntries: 1, NegativeEntries: 1, InFlightEntries: 1},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, issuer := range []string{"https://issuer-a.example", "https://issuer-b.example", "https://issuer-a.example"} {
			if _, err := resolver.ResolveKey(context.Background(), issuer, "aauth-access.json", "issuer-key"); err == nil {
				t.Fatalf("ResolveKey(%q) unexpectedly succeeded", issuer)
			}
		}
		if got := requests.Load(); got != 3 {
			t.Fatalf("requests = %d, want 3 after bounded-failure eviction", got)
		}
	})
}

func TestHTTPKeyResolverBoundsConcurrentUniqueDiscovery(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var requests atomic.Int32
	client := &http.Client{Transport: discoveryRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		close(started)
		<-release
		return nil, errors.New("released test request")
	})}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client, Clock: fixedClock(time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)),
		Admit:  func(context.Context, string) error { return nil },
		Limits: signaturekey.HTTPKeyResolverLimits{PositiveEntries: 1, NegativeEntries: 1, InFlightEntries: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := resolver.ResolveKey(context.Background(), "https://issuer-a.example", "aauth-access.json", "issuer-key")
		firstDone <- err
	}()
	<-started
	_, err = resolver.ResolveKey(context.Background(), "https://issuer-b.example", "aauth-access.json", "issuer-key")
	var unavailable *signaturekey.ResolutionError
	if !errors.As(err, &unavailable) || unavailable.Code != signaturekey.ResolutionUnavailable {
		t.Fatalf("capacity error = %T %v", err, err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("network requests = %d, want 1", got)
	}
	close(release)
	<-firstDone
}

func TestHTTPKeyResolverEnforcesEgressAndRedirectBoundaries(t *testing.T) {
	t.Parallel()

	t.Run("egress denial precedes network", func(t *testing.T) {
		var requests atomic.Int32
		client := &http.Client{Transport: discoveryRoundTripFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			return nil, errors.New("network must not run")
		})}
		resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
			Client: client, Clock: fixedClock(time.Now()), Admit: func(context.Context, string) error {
				return errors.New("blocked by host policy")
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = resolver.ResolveKey(context.Background(), "https://issuer.example", "aauth-access.json", "issuer-key")
		var denied *signaturekey.ResolutionError
		if !errors.As(err, &denied) || denied.Code != signaturekey.ResolutionDenied {
			t.Fatalf("egress error = %T %v", err, err)
		}
		if requests.Load() != 0 {
			t.Fatal("network ran after egress denial")
		}
	})

	t.Run("redirect", func(t *testing.T) {
		var redirected atomic.Int32
		target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			redirected.Add(1)
		}))
		defer target.Close()
		issuer := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			http.Redirect(response, nil, target.URL, http.StatusFound)
		}))
		defer issuer.Close()
		resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
			Client: issuer.Client(), Clock: fixedClock(time.Now()), Admit: func(context.Context, string) error { return nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = resolver.ResolveKey(context.Background(), issuer.URL, "aauth-access.json", "issuer-key")
		var unavailable *signaturekey.ResolutionError
		if !errors.As(err, &unavailable) || unavailable.Code != signaturekey.ResolutionUnavailable {
			t.Fatalf("redirect error = %T %v", err, err)
		}
		if redirected.Load() != 0 {
			t.Fatal("discovery followed a redirect")
		}
	})
}

func TestHTTPKeyResolverRequiresExactMetadataIssuerBeforeJWKS(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		metadata string
		want     signaturekey.ResolutionCode
	}{
		{name: "missing", metadata: `{"jwks_uri":"https://issuer.example/jwks"}`, want: signaturekey.ResolutionIssuerMissing},
		{name: "mismatch", metadata: `{"issuer":"https://other.example","jwks_uri":"https://issuer.example/jwks"}`, want: signaturekey.ResolutionIssuerMismatch},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var jwksFetches atomic.Int32
			client := &http.Client{Transport: discoveryRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/jwks" {
					jwksFetches.Add(1)
				}
				return discoveryResponse(request, []byte(test.metadata), "max-age=300"), nil
			})}
			resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
				Client: client, Clock: fixedClock(time.Now()), Admit: func(context.Context, string) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = resolver.ResolveKey(context.Background(), "https://issuer.example", "aauth-access.json", "issuer-key")
			var resolution *signaturekey.ResolutionError
			if !errors.As(err, &resolution) || resolution.Code != test.want {
				t.Fatalf("resolution error = %T %v", err, err)
			}
			if jwksFetches.Load() != 0 {
				t.Fatal("resolver fetched JWKS before issuer validation")
			}
		})
	}
}

func discoveryResponse(request *http.Request, body []byte, cacheControl string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header: http.Header{
			"Content-Type":  []string{"application/json"},
			"Cache-Control": []string{cacheControl},
		},
		Body: io.NopCloser(bytes.NewReader(body)), Request: request,
	}
}
