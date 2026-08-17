package aauth_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestHTTPKeyResolverPresenterDirectedEgressPolicy(t *testing.T) {
	t.Parallel()

	key := testSigningKey(t, "issuer-key")
	metadata := func(issuer, jwksURI string) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/.well-known/aauth-resource.json" {
				http.NotFound(response, request)
				return
			}
			response.Header().Set("Cache-Control", "max-age=300")
			_, _ = fmt.Fprintf(response, `{"issuer":%q,"jwks_uri":%q}`, issuer, jwksURI)
		})
	}
	keys := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Cache-Control", "max-age=300")
		_, _ = fmt.Fprintf(response, `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"issuer-key"}]}`, key.PublicJWK().X)
	})
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"public.example":          metadata("https://public.example", "https://keys.example/jwks"),
		"keys.example":            keys,
		"private.example":         metadata("https://private.example", "https://private.example/jwks"),
		"loopback.example":        metadata("https://loopback.example", "https://loopback.example/jwks"),
		"link-local.example":      metadata("https://link-local.example", "https://link-local.example/jwks"),
		"rebound.example":         metadataAndKeys("https://rebound.example", key),
		"origin.example":          metadata("https://origin.example", "https://unapproved-keys.example/jwks"),
		"unapproved-keys.example": keys,
		"approved-origin.example": metadata("https://approved-origin.example", "https://approved-keys.example/jwks"),
		"approved-keys.example":   keys,
	})
	defer gateway.Close()

	public := netip.MustParseAddr("203.0.113.10")
	newResolver := func(transport *discoveryPolicyTransport) *aauth.HTTPKeyResolver {
		t.Helper()
		resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
			Client: &http.Client{Transport: transport},
			Clock: aauth.ClockFunc(func() time.Time {
				return time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
			}),
			Admit: func(context.Context, string) error { return nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		return resolver
	}

	t.Run("public metadata and approved cross-origin JWKS", func(t *testing.T) {
		transport := newDiscoveryPolicyTransport(gateway.Client().Transport, map[string]bool{
			"public.example": true, "keys.example": true,
		}, map[string][][]netip.Addr{
			"public.example": {{public}}, "keys.example": {{public}},
		})
		resolved, err := newResolver(transport).ResolveKey(context.Background(), "https://public.example", aauth.ResourceDiscoveryDocument, "issuer-key")
		if err != nil || !resolved.Equal(key.PublicJWK()) {
			t.Fatalf("public resolution = %#v, %v", resolved, err)
		}
		if transport.forwarded("public.example") != 1 || transport.forwarded("keys.example") != 1 {
			t.Fatalf("public forwarded calls = metadata %d, JWKS %d", transport.forwarded("public.example"), transport.forwarded("keys.example"))
		}
	})

	for _, test := range []struct {
		name string
		host string
		addr netip.Addr
	}{
		{name: "private", host: "private.example", addr: netip.MustParseAddr("10.0.0.7")},
		{name: "loopback", host: "loopback.example", addr: netip.MustParseAddr("127.0.0.1")},
		{name: "ipv6 loopback", host: "loopback.example", addr: netip.MustParseAddr("::1")},
		{name: "link local", host: "link-local.example", addr: netip.MustParseAddr("169.254.169.254")},
		{name: "ipv6 link local", host: "link-local.example", addr: netip.MustParseAddr("fe80::1")},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			transport := newDiscoveryPolicyTransport(gateway.Client().Transport, map[string]bool{test.host: true}, map[string][][]netip.Addr{test.host: {{test.addr}}})
			_, err := newResolver(transport).ResolveKey(context.Background(), "https://"+test.host, aauth.ResourceDiscoveryDocument, "issuer-key")
			requireDiscoveryResolutionCode(t, err, aauth.KeyResolutionDenied)
			if transport.forwarded(test.host) != 0 {
				t.Fatalf("denied %s reached gateway", test.host)
			}
		})
	}

	t.Run("DNS rebound is checked again for JWKS", func(t *testing.T) {
		transport := newDiscoveryPolicyTransport(gateway.Client().Transport, map[string]bool{"rebound.example": true}, map[string][][]netip.Addr{
			"rebound.example": {{public}, {netip.MustParseAddr("10.0.0.8")}},
		})
		_, err := newResolver(transport).ResolveKey(context.Background(), "https://rebound.example", aauth.ResourceDiscoveryDocument, "issuer-key")
		requireDiscoveryResolutionCode(t, err, aauth.KeyResolutionDenied)
		if transport.forwarded("rebound.example") != 1 || transport.attempted("rebound.example") != 2 {
			t.Fatalf("rebound attempts/forwarded = %d/%d, want 2/1", transport.attempted("rebound.example"), transport.forwarded("rebound.example"))
		}
	})

	t.Run("unapproved cross-origin JWKS is denied independently", func(t *testing.T) {
		transport := newDiscoveryPolicyTransport(gateway.Client().Transport, map[string]bool{"origin.example": true}, map[string][][]netip.Addr{
			"origin.example": {{public}}, "unapproved-keys.example": {{public}},
		})
		_, err := newResolver(transport).ResolveKey(context.Background(), "https://origin.example", aauth.ResourceDiscoveryDocument, "issuer-key")
		requireDiscoveryResolutionCode(t, err, aauth.KeyResolutionDenied)
		if transport.forwarded("origin.example") != 1 || transport.forwarded("unapproved-keys.example") != 0 {
			t.Fatalf("unapproved cross-origin forwarded calls = metadata %d, JWKS %d", transport.forwarded("origin.example"), transport.forwarded("unapproved-keys.example"))
		}
	})

	t.Run("explicitly approved cross-origin JWKS succeeds", func(t *testing.T) {
		transport := newDiscoveryPolicyTransport(gateway.Client().Transport, map[string]bool{
			"approved-origin.example": true, "approved-keys.example": true,
		}, map[string][][]netip.Addr{
			"approved-origin.example": {{public}}, "approved-keys.example": {{public}},
		})
		resolved, err := newResolver(transport).ResolveKey(context.Background(), "https://approved-origin.example", aauth.ResourceDiscoveryDocument, "issuer-key")
		if err != nil || !resolved.Equal(key.PublicJWK()) {
			t.Fatalf("approved cross-origin resolution = %#v, %v", resolved, err)
		}
	})
}

func TestSelfJWTExpiryCannotUseWarmDiscoveryCache(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := testSigningKey(t, "resource-key")
	var metadataFetches, keyFetches atomic.Int32
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/.well-known/aauth-resource.json":
				metadataFetches.Add(1)
				response.Header().Set("Cache-Control", "max-age=300")
				_, _ = fmt.Fprint(response, `{"issuer":"https://resource.example","jwks_uri":"https://resource.example/jwks"}`)
			case "/jwks":
				keyFetches.Add(1)
				response.Header().Set("Cache-Control", "max-age=300")
				_, _ = fmt.Fprintf(response, `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"resource-key"}]}`, key.PublicJWK().X)
			default:
				http.NotFound(response, request)
			}
		}),
	})
	defer gateway.Close()
	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: gateway.Client(), Clock: clock,
		Admit: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := aauth.MintEventToken(key, aauth.EventTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "aauth:subscriber@ap.example", EventID: "event-one",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Second).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithSelfJWT(request, key, compact, clock); err != nil {
		t.Fatal(err)
	}
	options := aauth.VerifyRequestOptions{
		AllowedCredentialTypes: []string{aauth.EventTokenType}, AllowedSignatureKeyTypes: []string{aauth.SignatureKeySelfJWT},
		SelfJWTClaimPolicy: func(verified aauth.VerifiedSelfJWT) error {
			_, err := aauth.DecodeVerifiedEventToken(verified, clock)
			return err
		},
	}
	if _, err := aauth.VerifyRequest(context.Background(), request, resolver, clock, options); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	_, err = aauth.VerifyRequest(context.Background(), request, resolver, clock, options)
	var signatureError *aauth.SignatureError
	if !errors.As(err, &signatureError) || signatureError.Code != aauth.SignatureErrorExpiredJWT {
		t.Fatalf("expired warm-cache verification error = %v (%#v)", err, signatureError)
	}
	if metadataFetches.Load() != 1 || keyFetches.Load() != 1 {
		t.Fatalf("expired JWT fetched discovery again: metadata %d, JWKS %d", metadataFetches.Load(), keyFetches.Load())
	}
}

func TestSelfJWTUsesAdmittedHTTPKeyForBothProofs(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := testSigningKey(t, "resource-key")
	var metadataFetches, keyFetches atomic.Int32
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/.well-known/aauth-resource.json":
				metadataFetches.Add(1)
				response.Header().Set("Cache-Control", "max-age=300")
				_, _ = fmt.Fprint(response, `{"issuer":"https://resource.example","jwks_uri":"https://resource.example/jwks"}`)
			case "/jwks":
				keyFetches.Add(1)
				response.Header().Set("Cache-Control", "max-age=300")
				_, _ = fmt.Fprintf(response, `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"resource-key"}]}`, key.PublicJWK().X)
			default:
				http.NotFound(response, request)
			}
		}),
	})
	defer gateway.Close()
	admissions := 0
	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: gateway.Client(), Clock: clock,
		Admit: func(context.Context, string) error { admissions++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := aauth.EventTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "aauth:subscriber@ap.example", EventID: "event-one",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	}
	compact, err := aauth.MintEventToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://ap.example/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithSelfJWT(request, key, compact, clock); err != nil {
		t.Fatal(err)
	}
	verified, err := aauth.VerifyRequest(context.Background(), request, resolver, clock, aauth.VerifyRequestOptions{
		AllowedCredentialTypes: []string{aauth.EventTokenType}, AllowedSignatureKeyTypes: []string{aauth.SignatureKeySelfJWT},
		SelfJWTMaximumLifetime: 2 * time.Minute,
		SelfJWTClaimPolicy: func(verified aauth.VerifiedSelfJWT) error {
			decoded, err := aauth.DecodeVerifiedEventToken(verified, clock)
			if err == nil && decoded != claims {
				return errors.New("test: decoded event claims changed")
			}
			return err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified.SelfJWT == nil || !verified.PublicKey.Equal(key.PublicJWK()) {
		t.Fatalf("verified self-jwt/key = %#v / %#v", verified.SelfJWT, verified.PublicKey)
	}
	if metadataFetches.Load() != 1 || keyFetches.Load() != 1 || admissions != 2 {
		t.Fatalf("two-hop fetches/admissions = %d/%d/%d, want 1/1/2", metadataFetches.Load(), keyFetches.Load(), admissions)
	}
}

func TestHTTPKeyResolverRetainedStateIsBounded(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := testSigningKey(t, "issuer-key")
	var mu sync.Mutex
	calls := make(map[string]int)
	handlers := make(map[string]http.Handler)
	for index := 1; index <= 3; index++ {
		host := fmt.Sprintf("success-%d.example", index)
		hostCopy := host
		handlers[host] = http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			mu.Lock()
			calls[hostCopy+request.URL.Path]++
			mu.Unlock()
			response.Header().Set("Cache-Control", "max-age=300")
			switch request.URL.Path {
			case "/.well-known/aauth-resource.json":
				_, _ = fmt.Fprintf(response, `{"issuer":"https://%s","jwks_uri":"https://%s/jwks"}`, hostCopy, hostCopy)
			case "/jwks":
				_, _ = fmt.Fprintf(response, `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"issuer-key"}]}`, key.PublicJWK().X)
			default:
				http.NotFound(response, request)
			}
		})
		failureHost := fmt.Sprintf("failure-%d.example", index)
		failureCopy := failureHost
		handlers[failureHost] = http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			mu.Lock()
			calls[failureCopy+request.URL.Path]++
			mu.Unlock()
			http.Error(response, "unavailable", http.StatusServiceUnavailable)
		})
	}
	gateway := newLogicalGateway(t, handlers)
	defer gateway.Close()
	admissions := 0
	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: gateway.Client(), Clock: clock,
		Admit:  func(context.Context, string) error { admissions++; return nil },
		Limits: aauth.HTTPKeyResolverLimits{PositiveEntries: 2, NegativeEntries: 2, InFlightEntries: 2},
	})
	if err != nil {
		t.Fatal(err)
	}

	for index := 1; index <= 3; index++ {
		host := fmt.Sprintf("success-%d.example", index)
		if _, err := resolver.ResolveKey(context.Background(), "https://"+host, aauth.ResourceDiscoveryDocument, "issuer-key"); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}
	if _, err := resolver.ResolveKey(context.Background(), "https://success-1.example", aauth.ResourceDiscoveryDocument, "issuer-key"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	firstSuccessFetches := calls["success-1.example/.well-known/aauth-resource.json"]
	mu.Unlock()
	if firstSuccessFetches != 2 {
		t.Fatalf("evicted positive entry metadata fetches = %d, want 2", firstSuccessFetches)
	}

	for index := 1; index <= 3; index++ {
		host := fmt.Sprintf("failure-%d.example", index)
		if _, err := resolver.ResolveKey(context.Background(), "https://"+host, aauth.ResourceDiscoveryDocument, "issuer-key"); err == nil {
			t.Fatalf("%s unexpectedly resolved", host)
		}
		now = now.Add(time.Second)
	}
	if _, err := resolver.ResolveKey(context.Background(), "https://failure-1.example", aauth.ResourceDiscoveryDocument, "issuer-key"); err == nil {
		t.Fatal("evicted negative entry unexpectedly resolved")
	}
	mu.Lock()
	firstFailureFetches := calls["failure-1.example/.well-known/aauth-resource.json"]
	mu.Unlock()
	if firstFailureFetches != 2 {
		t.Fatalf("evicted negative entry metadata fetches = %d, want 2", firstFailureFetches)
	}

	beforeAdmissions := admissions
	_, err = resolver.ResolveKey(context.Background(), "https://success-1.example", strings.Repeat("a", 1024)+".json", "issuer-key")
	requireDiscoveryResolutionCode(t, err, aauth.KeyResolutionInvalid)
	if admissions != beforeAdmissions {
		t.Fatalf("overlong discovery document made %d admission calls", admissions-beforeAdmissions)
	}
	if _, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: gateway.Client(), Clock: clock, Admit: func(context.Context, string) error { return nil },
		Limits: aauth.HTTPKeyResolverLimits{PositiveEntries: -1},
	}); err == nil {
		t.Fatal("negative resolver limit was accepted")
	}
}

func TestHTTPKeyResolverEvictsTiedRetainedStateDeterministically(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	key := testSigningKey(t, "issuer-key")
	var mu sync.Mutex
	calls := make(map[string]int)
	handlers := make(map[string]http.Handler)
	for _, prefix := range []string{"success", "failure"} {
		for _, suffix := range []string{"alpha", "beta", "gamma"} {
			host := prefix + "-" + suffix + ".example"
			hostCopy := host
			handlers[host] = http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				mu.Lock()
				calls[hostCopy+request.URL.Path]++
				mu.Unlock()
				if strings.HasPrefix(hostCopy, "failure-") {
					http.Error(response, "unavailable", http.StatusServiceUnavailable)
					return
				}
				response.Header().Set("Cache-Control", "max-age=300")
				switch request.URL.Path {
				case "/.well-known/aauth-resource.json":
					_, _ = fmt.Fprintf(response, `{"issuer":"https://%s","jwks_uri":"https://%s/jwks"}`, hostCopy, hostCopy)
				case "/jwks":
					_, _ = fmt.Fprintf(response, `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"issuer-key"}]}`, key.PublicJWK().X)
				default:
					http.NotFound(response, request)
				}
			})
		}
	}
	gateway := newLogicalGateway(t, handlers)
	defer gateway.Close()

	for iteration := 0; iteration < 64; iteration++ {
		resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
			Client: gateway.Client(),
			Clock:  aauth.ClockFunc(func() time.Time { return now }),
			Admit:  func(context.Context, string) error { return nil },
			Limits: aauth.HTTPKeyResolverLimits{PositiveEntries: 2, NegativeEntries: 2, InFlightEntries: 2},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, suffix := range []string{"beta", "alpha", "gamma"} {
			host := "success-" + suffix + ".example"
			if _, err := resolver.ResolveKey(context.Background(), "https://"+host, aauth.ResourceDiscoveryDocument, "issuer-key"); err != nil {
				t.Fatal(err)
			}
		}
		mu.Lock()
		beforePositive := calls["success-alpha.example/.well-known/aauth-resource.json"]
		mu.Unlock()
		if _, err := resolver.ResolveKey(context.Background(), "https://success-alpha.example", aauth.ResourceDiscoveryDocument, "issuer-key"); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		afterPositive := calls["success-alpha.example/.well-known/aauth-resource.json"]
		mu.Unlock()
		if afterPositive != beforePositive+1 {
			t.Fatalf("iteration %d retained tied positive alpha entry; fetches %d -> %d", iteration, beforePositive, afterPositive)
		}

		for _, suffix := range []string{"beta", "alpha", "gamma"} {
			host := "failure-" + suffix + ".example"
			if _, err := resolver.ResolveKey(context.Background(), "https://"+host, aauth.ResourceDiscoveryDocument, "issuer-key"); err == nil {
				t.Fatalf("%s unexpectedly resolved", host)
			}
		}
		mu.Lock()
		beforeNegative := calls["failure-alpha.example/.well-known/aauth-resource.json"]
		mu.Unlock()
		if _, err := resolver.ResolveKey(context.Background(), "https://failure-alpha.example", aauth.ResourceDiscoveryDocument, "issuer-key"); err == nil {
			t.Fatal("failure-alpha.example unexpectedly resolved")
		}
		mu.Lock()
		afterNegative := calls["failure-alpha.example/.well-known/aauth-resource.json"]
		mu.Unlock()
		if afterNegative != beforeNegative+1 {
			t.Fatalf("iteration %d retained tied negative alpha entry; fetches %d -> %d", iteration, beforeNegative, afterNegative)
		}
	}
}

func TestHTTPKeyResolverBoundsConcurrentUniqueInflight(t *testing.T) {
	t.Parallel()

	key := testSigningKey(t, "issuer-key")
	transport := &blockingDiscoveryTransport{
		key: key.PublicJWK(), release: make(chan struct{}), metadataStarted: make(chan string, 3),
	}
	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: &http.Client{Transport: transport},
		Clock:  aauth.ClockFunc(func() time.Time { return time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC) }),
		Admit:  func(context.Context, string) error { return nil },
		Limits: aauth.HTTPKeyResolverLimits{PositiveEntries: 2, NegativeEntries: 2, InFlightEntries: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(host string) error {
		_, err := resolver.ResolveKey(context.Background(), "https://"+host, aauth.ResourceDiscoveryDocument, "issuer-key")
		return err
	}
	results := make(chan error, 3)
	go func() { results <- resolve("one.example") }()
	go func() { results <- resolve("two.example") }()
	<-transport.metadataStarted
	<-transport.metadataStarted

	thirdContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = resolver.ResolveKey(thirdContext, "https://three.example", aauth.ResourceDiscoveryDocument, "issuer-key")
	requireDiscoveryResolutionCode(t, err, aauth.KeyResolutionUnavailable)
	if transport.metadataCount.Load() != 2 {
		t.Fatalf("in-flight over-cap started %d metadata requests, want 2", transport.metadataCount.Load())
	}
	waiterStarted := make(chan struct{})
	go func() {
		close(waiterStarted)
		results <- resolve("one.example")
	}()
	<-waiterStarted
	close(transport.release)
	for range 3 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if err := resolve("three.example"); err != nil {
		t.Fatalf("released in-flight capacity was not reusable: %v", err)
	}
}

func metadataAndKeys(issuer string, key aauth.SigningKey) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "max-age=300")
		switch request.URL.Path {
		case "/.well-known/aauth-resource.json":
			_, _ = fmt.Fprintf(response, `{"issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/jwks")
		case "/jwks":
			_, _ = fmt.Fprintf(response, `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"issuer-key"}]}`, key.PublicJWK().X)
		default:
			http.NotFound(response, request)
		}
	})
}

type discoveryPolicyTransport struct {
	base       http.RoundTripper
	approved   map[string]bool
	answers    map[string][][]netip.Addr
	mu         sync.Mutex
	attempts   map[string]int
	forwardedN map[string]int
}

func newDiscoveryPolicyTransport(base http.RoundTripper, approved map[string]bool, answers map[string][][]netip.Addr) *discoveryPolicyTransport {
	return &discoveryPolicyTransport{
		base: base, approved: approved, answers: answers,
		attempts: make(map[string]int), forwardedN: make(map[string]int),
	}
}

func (transport *discoveryPolicyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	host := request.URL.Hostname()
	transport.mu.Lock()
	attempt := transport.attempts[host]
	transport.attempts[host]++
	answers := transport.answers[host]
	approved := transport.approved[host]
	var selected []netip.Addr
	if len(answers) > 0 {
		if attempt >= len(answers) {
			attempt = len(answers) - 1
		}
		selected = answers[attempt]
	}
	transport.mu.Unlock()
	if !approved || len(selected) == 0 {
		return nil, &aauth.KeyResolutionError{Code: aauth.KeyResolutionDenied, Cause: errors.New("test deployment denied discovery origin")}
	}
	for _, address := range selected {
		if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() || address.IsMulticast() {
			return nil, &aauth.KeyResolutionError{Code: aauth.KeyResolutionDenied, Cause: fmt.Errorf("test deployment denied discovery address %s", address)}
		}
	}
	transport.mu.Lock()
	transport.forwardedN[host]++
	transport.mu.Unlock()
	return transport.base.RoundTrip(request)
}

func (transport *discoveryPolicyTransport) attempted(host string) int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.attempts[host]
}

func (transport *discoveryPolicyTransport) forwarded(host string) int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.forwardedN[host]
}

type blockingDiscoveryTransport struct {
	key             aauth.JWK
	release         chan struct{}
	metadataStarted chan string
	metadataCount   atomic.Int32
}

func (transport *blockingDiscoveryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.HasPrefix(request.URL.Path, "/.well-known/") {
		transport.metadataCount.Add(1)
		transport.metadataStarted <- request.URL.Host
		<-transport.release
		return discoveryJSONResponse(request, fmt.Sprintf(`{"issuer":"https://%s","jwks_uri":"https://%s/jwks"}`, request.URL.Host, request.URL.Host)), nil
	}
	return discoveryJSONResponse(request, fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"issuer-key"}]}`, transport.key.X)), nil
}

func discoveryJSONResponse(request *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Cache-Control": {"max-age=300"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: request,
	}
}

func requireDiscoveryResolutionCode(t *testing.T, err error, want aauth.KeyResolutionCode) {
	t.Helper()
	var resolutionError *aauth.KeyResolutionError
	if !errors.As(err, &resolutionError) || resolutionError.Code != want {
		t.Fatalf("resolution error = %v (%#v), want %q", err, resolutionError, want)
	}
}
