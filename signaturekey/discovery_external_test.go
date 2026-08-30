package signaturekey_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/aauth-dev/auth-go/jose"
	"github.com/aauth-dev/auth-go/signaturekey"
)

func TestStaticKeyResolverIncludesTheDiscoveryDocumentInItsTrustKey(t *testing.T) {
	t.Parallel()

	first := testDiscoverySigningKey(t, "shared-key", 0x31)
	second := testDiscoverySigningKey(t, "shared-key", 0x32)
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://roles.example", DiscoveryDocument: "aauth-person.json", KeyID: "shared-key"}: first.PublicJWK(),
		{Issuer: "https://roles.example", DiscoveryDocument: "aauth-access.json", KeyID: "shared-key"}: second.PublicJWK(),
	}
	resolved, err := resolver.ResolveKey(context.Background(), "https://roles.example", "aauth-access.json", "shared-key")
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.Equal(second.PublicJWK()) {
		t.Fatalf("resolved key = %#v, want access-role key", resolved)
	}
}

func TestStaticKeyResolverClassifiesAlgorithmKeyTypeMismatchAsInvalid(t *testing.T) {
	t.Parallel()

	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://issuer.example", DiscoveryDocument: "aauth-access.json", KeyID: "issuer-key"}: {
			Kty: "EC", Crv: "P-256", Alg: jose.Ed25519Algorithm, Kid: "issuer-key", X: "unused",
		},
	}
	_, err := resolver.ResolveKey(context.Background(), "https://issuer.example", "aauth-access.json", "issuer-key")
	var resolution *signaturekey.ResolutionError
	if !errors.As(err, &resolution) || resolution.Code != signaturekey.ResolutionInvalid {
		t.Fatalf("ResolveKey error = %T %v", err, err)
	}
}

func testDiscoverySigningKey(t *testing.T, id string, fill byte) jose.SigningKey {
	t.Helper()
	key, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestHTTPKeyResolverUsesAdmittedTwoHopDiscoveryAndCache(t *testing.T) {
	now := time.Date(2026, 8, 28, 23, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x45}, ed25519.SeedSize))
	signingKey, err := jose.NewEd25519SigningKey("issuer-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	var metadataFetches atomic.Int32
	var keySetFetches atomic.Int32
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/service-configuration":
			metadataFetches.Add(1)
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("Cache-Control", "max-age=300")
			_, _ = fmt.Fprintf(response, `{"issuer":%q,"jwks_uri":%q}`, server.URL, server.URL+"/jwks")
		case "/jwks":
			keySetFetches.Add(1)
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("Cache-Control", "max-age=300")
			_, _ = fmt.Fprintf(response, `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"issuer-key","use":"sig"}]}`, signingKey.PublicJWK().X)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	var admitted []string
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: server.Client(),
		Clock:  fixedClock(now),
		Admit: func(_ context.Context, endpoint string) error {
			admitted = append(admitted, endpoint)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveKey(context.Background(), server.URL, "service-configuration", signingKey.ID())
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.Equal(signingKey.PublicJWK()) {
		t.Fatal("resolved key does not match issuer key")
	}
	again, err := resolver.ResolveKey(context.Background(), server.URL, "service-configuration", signingKey.ID())
	if err != nil {
		t.Fatal(err)
	}
	if !again.Equal(resolved) || metadataFetches.Load() != 1 || keySetFetches.Load() != 1 {
		t.Fatalf("cache miss: metadata=%d jwks=%d", metadataFetches.Load(), keySetFetches.Load())
	}
	if len(admitted) != 2 || admitted[0] != server.URL+"/.well-known/service-configuration" || admitted[1] != server.URL+"/jwks" {
		t.Fatalf("admitted endpoints = %#v", admitted)
	}
}

func TestHTTPKeyResolverBoundsEveryFetch(t *testing.T) {
	t.Parallel()

	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: &http.Client{Transport: discoveryRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, request.Context().Err()
		})},
		Clock:   fixedClock(time.Date(2026, 8, 29, 22, 0, 0, 0, time.UTC)),
		Admit:   func(context.Context, string) error { return nil },
		Timeout: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = resolver.ResolveKey(context.Background(), "https://issuer.example", "aauth-agent.json", "issuer-key")
	var unavailable *signaturekey.ResolutionError
	if !errors.As(err, &unavailable) || unavailable.Code != signaturekey.ResolutionUnavailable {
		t.Fatalf("ResolveKey error = %T %v", err, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded discovery took %s", elapsed)
	}

	if _, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: http.DefaultClient, Clock: fixedClock(time.Now()),
		Admit: func(context.Context, string) error { return nil }, Timeout: -time.Second,
	}); err == nil {
		t.Fatal("NewHTTPKeyResolver accepted a negative timeout")
	}
}

func TestTokenVerificationRefreshesRotatedSameIDKeyAfterTheFloor(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 22, 0, 0, 0, time.UTC)
	clock := &mutableDiscoveryClock{now: now}
	oldKey := testDiscoverySigningKey(t, "issuer-key", 0x71)
	newKey := testDiscoverySigningKey(t, "issuer-key", 0x72)
	requestKey := testDiscoverySigningKey(t, "request-key", 0x73)
	var keyMu sync.RWMutex
	currentKey := oldKey.PublicJWK()
	var metadataFetches atomic.Int32
	var keySetFetches atomic.Int32
	const issuer = "https://issuer.example"
	client := &http.Client{Transport: discoveryRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body []byte
		switch request.URL.Path {
		case "/.well-known/aauth-access.json":
			metadataFetches.Add(1)
			body = []byte(fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/jwks"))
		case "/jwks":
			keySetFetches.Add(1)
			keyMu.RLock()
			key := currentKey
			keyMu.RUnlock()
			body, _ = json.Marshal(map[string]any{"keys": []jose.JWK{key}})
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("not found")), Request: request}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header: http.Header{
				"Content-Type":  []string{"application/json"},
				"Cache-Control": []string{"max-age=3600"},
			},
			Body: io.NopCloser(bytes.NewReader(body)), Request: request,
		}, nil
	})}

	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client, Clock: clock,
		Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	mint := func(key jose.SigningKey, jti string) string {
		token, err := aauth.MintAuthToken(key, aauth.AuthTokenClaims{
			Issuer: issuer, DWK: aauth.AccessDiscoveryDocument,
			Audience: "https://resource.example", JTI: jti,
			PersonServer: "https://person.example", Subject: "person-1",
			Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
			IssuedAt:     clock.Now().Unix(), ExpiresAt: clock.Now().Add(time.Hour).Unix(),
			Scope: "records.read",
		})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	if _, err := aauth.VerifyAuthToken(context.Background(), mint(oldKey, "old"), resolver, clock); err != nil {
		t.Fatal(err)
	}
	keyMu.Lock()
	currentKey = newKey.PublicJWK()
	keyMu.Unlock()
	rotated := mint(newKey, "new")
	if _, err := aauth.VerifyAuthToken(context.Background(), rotated, resolver, clock); err == nil {
		t.Fatal("same-ID rotation refreshed before the one-minute floor")
	}
	if metadataFetches.Load() != 1 || keySetFetches.Load() != 1 {
		t.Fatalf("pre-floor fetches: metadata=%d keys=%d", metadataFetches.Load(), keySetFetches.Load())
	}
	clock.Advance(61 * time.Second)
	if _, err := aauth.VerifyAuthToken(context.Background(), rotated, resolver, clock); err != nil {
		t.Fatal(err)
	}
	if metadataFetches.Load() != 2 || keySetFetches.Load() != 2 {
		t.Fatalf("post-floor fetches: metadata=%d keys=%d", metadataFetches.Load(), keySetFetches.Load())
	}
}

func TestHTTPKeyResolverUsesStaleCacheOnlyWithinCoreDiscardBound(t *testing.T) {
	t.Parallel()

	clock := &mutableDiscoveryClock{now: time.Date(2026, 8, 29, 22, 0, 0, 0, time.UTC)}
	key := testDiscoverySigningKey(t, "issuer-key", 0x74).PublicJWK()
	const issuer = "https://issuer.example"
	var unavailable atomic.Bool
	var metadataFetches atomic.Int32
	var requests atomic.Int32
	client := &http.Client{Transport: discoveryRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		if unavailable.Load() {
			return nil, errors.New("issuer unavailable")
		}
		var body []byte
		switch request.URL.Path {
		case "/.well-known/aauth-access.json":
			metadataFetches.Add(1)
			body = []byte(fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/jwks"))
		case "/jwks":
			body, _ = json.Marshal(map[string]any{"keys": []jose.JWK{key}})
		default:
			return nil, errors.New("unexpected discovery URL")
		}
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK",
			Header: http.Header{"Content-Type": []string{"application/json"}, "Cache-Control": []string{"max-age=1"}},
			Body:   io.NopCloser(bytes.NewReader(body)), Request: request,
		}, nil
	})}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client, Clock: clock, Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveKey(context.Background(), issuer, "aauth-access.json", "issuer-key")
	if err != nil || !resolved.Equal(key) {
		t.Fatalf("initial resolution = %#v, %v", resolved, err)
	}
	clock.Advance(61 * time.Second)
	unavailable.Store(true)
	stale, err := resolver.ResolveKey(context.Background(), issuer, "aauth-access.json", "issuer-key")
	if err != nil || !stale.Equal(key) {
		t.Fatalf("bounded stale resolution = %#v, %v", stale, err)
	}
	if metadataFetches.Load() != 1 {
		t.Fatalf("successful metadata fetches = %d", metadataFetches.Load())
	}
	if requests.Load() != 3 {
		t.Fatalf("requests after stale fallback = %d, want 3", requests.Load())
	}
	clock.Advance(24*time.Hour + time.Second)
	if _, err := resolver.ResolveKey(context.Background(), issuer, "aauth-access.json", "issuer-key"); err == nil {
		t.Fatal("resolver used a cached key beyond the 24-hour discard bound")
	}
}

type mutableDiscoveryClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *mutableDiscoveryClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *mutableDiscoveryClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

type discoveryRoundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip discoveryRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestHTTPKeyResolverDoesNotReuseOrImmediatelyRefetchNoStoreResponses(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x46}, ed25519.SeedSize))
	signingKey, err := jose.NewEd25519SigningKey("issuer-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}

	var server *httptest.Server
	var metadataFetches atomic.Int32
	var keySetFetches atomic.Int32
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header()["Cache-Control"] = []string{"max-age=300", "no-store"}
		switch request.URL.Path {
		case "/.well-known/service-configuration":
			metadataFetches.Add(1)
			_, _ = fmt.Fprintf(response, `{"issuer":%q,"jwks_uri":%q}`, server.URL, server.URL+"/jwks")
		case "/jwks":
			keySetFetches.Add(1)
			_, _ = fmt.Fprintf(response, `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"issuer-key","use":"sig"}]}`, signingKey.PublicJWK().X)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: server.Client(),
		Clock:  fixedClock(now),
		Admit:  func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveKey(context.Background(), server.URL, "service-configuration", signingKey.ID())
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.Equal(signingKey.PublicJWK()) {
		t.Fatal("resolved key does not match issuer key")
	}
	_, err = resolver.ResolveKey(context.Background(), server.URL, "service-configuration", signingKey.ID())
	var unavailable *signaturekey.ResolutionError
	if !errors.As(err, &unavailable) || unavailable.Code != signaturekey.ResolutionUnavailable {
		t.Fatalf("immediate no-store retry error = %T %v, want unavailable resolution error", err, err)
	}
	if got := metadataFetches.Load(); got != 1 {
		t.Fatalf("metadata fetches = %d, want 1", got)
	}
	if got := keySetFetches.Load(); got != 1 {
		t.Fatalf("JWKS fetches = %d, want 1", got)
	}
}

func TestHTTPKeyResolverNoStoreDominatesNoCacheInAnyOrder(t *testing.T) {
	t.Parallel()

	for _, cacheControl := range []string{"no-cache, no-store", "no-store, no-cache"} {
		cacheControl := cacheControl
		t.Run(cacheControl, func(t *testing.T) {
			t.Parallel()

			key := testDiscoverySigningKey(t, "issuer-key", 0x48).PublicJWK()
			const issuer = "https://issuer.example"
			var requests atomic.Int32
			client := &http.Client{Transport: discoveryRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				requests.Add(1)
				var body []byte
				switch request.URL.Path {
				case "/.well-known/aauth-access.json":
					body = []byte(fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/jwks"))
				case "/jwks":
					body, _ = json.Marshal(map[string]any{"keys": []jose.JWK{key}})
				default:
					return nil, errors.New("unexpected discovery URL")
				}
				return &http.Response{
					StatusCode: http.StatusOK, Status: "200 OK",
					Header: http.Header{
						"Content-Type":  []string{"application/json"},
						"Cache-Control": []string{cacheControl},
					},
					Body: io.NopCloser(bytes.NewReader(body)), Request: request,
				}, nil
			})}
			resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
				Client: client,
				Clock:  fixedClock(time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)),
				Admit:  func(context.Context, string) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.ResolveKey(context.Background(), issuer, "aauth-access.json", key.Kid); err != nil {
				t.Fatal(err)
			}
			_, err = resolver.ResolveKey(context.Background(), issuer, "aauth-access.json", key.Kid)
			var unavailable *signaturekey.ResolutionError
			if !errors.As(err, &unavailable) || unavailable.Code != signaturekey.ResolutionUnavailable {
				t.Fatalf("immediate retry error = %T %v", err, err)
			}
			if got := requests.Load(); got != 2 {
				t.Fatalf("requests = %d, want 2", got)
			}
		})
	}
}

func TestHTTPKeyResolverStoresImmediatelyStaleResponsesForBoundedRevalidation(t *testing.T) {
	t.Parallel()

	for _, cacheControl := range []string{"no-cache", "max-age=0"} {
		cacheControl := cacheControl
		t.Run(cacheControl, func(t *testing.T) {
			t.Parallel()

			clock := &mutableDiscoveryClock{now: time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)}
			key := testDiscoverySigningKey(t, "issuer-key", 0x47).PublicJWK()
			const issuer = "https://issuer.example"
			var fetches atomic.Int32
			client := &http.Client{Transport: discoveryRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				fetches.Add(1)
				var body []byte
				switch request.URL.Path {
				case "/.well-known/aauth-access.json":
					body = []byte(fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/jwks"))
				case "/jwks":
					body, _ = json.Marshal(map[string]any{"keys": []jose.JWK{key}})
				default:
					return nil, errors.New("unexpected discovery URL")
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Header: http.Header{
						"Content-Type":  []string{"application/json"},
						"Cache-Control": []string{cacheControl},
					},
					Body: io.NopCloser(bytes.NewReader(body)), Request: request,
				}, nil
			})}
			resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
				Client: client, Clock: clock, Admit: func(context.Context, string) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			for call := 0; call < 2; call++ {
				resolved, err := resolver.ResolveKey(context.Background(), issuer, "aauth-access.json", key.Kid)
				if err != nil || !resolved.Equal(key) {
					t.Fatalf("immediate resolution %d = %#v, %v", call+1, resolved, err)
				}
			}
			if got := fetches.Load(); got != 2 {
				t.Fatalf("immediate fetches = %d, want 2", got)
			}
			clock.Advance(61 * time.Second)
			if _, err := resolver.ResolveKey(context.Background(), issuer, "aauth-access.json", key.Kid); err != nil {
				t.Fatal(err)
			}
			if got := fetches.Load(); got != 4 {
				t.Fatalf("post-floor fetches = %d, want 4", got)
			}
		})
	}
}

func TestHTTPKeyResolverRejectsAmbiguousDiscoveryJSONNames(t *testing.T) {
	now := time.Date(2026, 8, 29, 21, 30, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4b}, ed25519.SeedSize))
	signingKey, err := jose.NewEd25519SigningKey("issuer-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		metadata func(string) string
		keySet   func(string) string
	}{
		{
			name: "duplicate metadata issuer",
			metadata: func(base string) string {
				return fmt.Sprintf(`{"issuer":%q,"issuer":%q,"jwks_uri":%q}`, base, base, base+"/jwks")
			},
		},
		{
			name: "case-ambiguous metadata issuer",
			metadata: func(base string) string {
				return fmt.Sprintf(`{"issuer":%q,"Issuer":%q,"jwks_uri":%q}`, base, base, base+"/jwks")
			},
		},
		{
			name: "lone case-variant metadata issuer",
			metadata: func(base string) string {
				return fmt.Sprintf(`{"ISSUER":%q,"jwks_uri":%q}`, base, base+"/jwks")
			},
		},
		{
			name: "duplicate metadata jwks_uri",
			metadata: func(base string) string {
				return fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q,"jwks_uri":%q}`, base, base+"/jwks", base+"/jwks")
			},
		},
		{
			name: "case-ambiguous metadata jwks_uri",
			metadata: func(base string) string {
				return fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q,"JWKS_URI":%q}`, base, base+"/jwks", base+"/jwks")
			},
		},
		{
			name: "duplicate JWKS keys",
			keySet: func(key string) string {
				return fmt.Sprintf(`{"keys":[%s],"keys":[%s]}`, key, key)
			},
		},
		{
			name: "case-ambiguous JWKS keys",
			keySet: func(key string) string {
				return fmt.Sprintf(`{"keys":[%s],"Keys":[%s]}`, key, key)
			},
		},
		{
			name: "lone case-variant JWKS keys",
			keySet: func(key string) string {
				return fmt.Sprintf(`{"KEYS":[%s]}`, key)
			},
		},
		{
			name: "duplicate JWK member",
			keySet: func(key string) string {
				return `{"keys":[` + strings.Replace(key, `"kid":"issuer-key"`, `"kid":"issuer-key","kid":"issuer-key"`, 1) + `]}`
			},
		},
		{
			name: "case-ambiguous JWK member",
			keySet: func(key string) string {
				return `{"keys":[` + strings.Replace(key, `"kid":"issuer-key"`, `"kid":"issuer-key","Kid":"issuer-key"`, 1) + `]}`
			},
		},
		{
			name: "lone case-variant JWK member",
			keySet: func(key string) string {
				return `{"keys":[` + strings.Replace(key, `"alg":"Ed25519"`, `"ALG":"Ed25519"`, 1) + `]}`
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				response.Header().Set("Cache-Control", "max-age=300")
				validKey := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"issuer-key","use":"sig"}`, signingKey.PublicJWK().X)
				switch request.URL.Path {
				case "/.well-known/service-configuration":
					if test.metadata != nil {
						_, _ = response.Write([]byte(test.metadata(server.URL)))
						return
					}
					_, _ = fmt.Fprintf(response, `{"issuer":%q,"jwks_uri":%q}`, server.URL, server.URL+"/jwks")
				case "/jwks":
					if test.keySet != nil {
						_, _ = response.Write([]byte(test.keySet(validKey)))
						return
					}
					_, _ = response.Write([]byte(`{"keys":[` + validKey + `]}`))
				default:
					http.NotFound(response, request)
				}
			}))
			defer server.Close()

			resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
				Client: server.Client(),
				Clock:  fixedClock(now),
				Admit:  func(context.Context, string) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = resolver.ResolveKey(context.Background(), server.URL, "service-configuration", signingKey.ID())
			var invalid *signaturekey.ResolutionError
			if !errors.As(err, &invalid) || invalid.Code != signaturekey.ResolutionInvalid {
				t.Fatalf("resolution error = %T %v, want invalid", err, err)
			}
		})
	}
}
