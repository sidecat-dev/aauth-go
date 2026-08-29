package aauth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestHTTPKeyResolverUsesAdmittedTwoHopDiscoveryAndCache(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 6, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	signingKey := testSigningKey(t, "issuer-key")
	var metadataFetches atomic.Int32
	var keySetFetches atomic.Int32

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"issuer.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/.well-known/aauth-resource.json":
				metadataFetches.Add(1)
				response.Header().Set("Content-Type", "application/json")
				response.Header().Set("Cache-Control", "max-age=300")
				_, _ = fmt.Fprint(response, `{
					"issuer":"https://issuer.example",
					"jwks_uri":"https://keys.example/resource.jwks"
				}`)
			default:
				http.NotFound(response, request)
			}
		}),
		"keys.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			keySetFetches.Add(1)
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("Cache-Control", "max-age=300")
			_, _ = fmt.Fprintf(response, `{"keys":[
				{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"issuer-key","use":"sig"}
			]}`, signingKey.PublicJWK().X)
		}),
	})
	defer gateway.Close()

	var admitted []string
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: gateway.Client(),
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			admitted = append(admitted, endpoint)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := resolver.ResolveKey(
		context.Background(),
		"https://issuer.example",
		aauth.ResourceDiscoveryDocument,
		"issuer-key",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.Equal(signingKey.PublicJWK()) {
		t.Fatal("resolved key does not match issuer key")
	}
	if metadataFetches.Load() != 1 || keySetFetches.Load() != 1 {
		t.Fatalf("first resolution fetches = metadata %d, JWKS %d", metadataFetches.Load(), keySetFetches.Load())
	}
	if len(admitted) != 2 ||
		admitted[0] != "https://issuer.example/.well-known/aauth-resource.json" ||
		admitted[1] != "https://keys.example/resource.jwks" {
		t.Fatalf("admitted endpoints = %#v", admitted)
	}

	again, err := resolver.ResolveKey(
		context.Background(),
		"https://issuer.example",
		aauth.ResourceDiscoveryDocument,
		"issuer-key",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Equal(resolved) {
		t.Fatal("cached resolution changed the key")
	}
	if metadataFetches.Load() != 1 || keySetFetches.Load() != 1 {
		t.Fatalf("cached resolution fetched again: metadata %d, JWKS %d", metadataFetches.Load(), keySetFetches.Load())
	}
}

func TestHTTPKeyResolverAppliesUnknownKeyRefreshFloor(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 6, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	signingKey := testSigningKey(t, "known-key")
	var fetches atomic.Int32

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"issuer.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			fetches.Add(1)
			if request.URL.Path == "/.well-known/aauth-resource.json" {
				_, _ = fmt.Fprint(response, `{"issuer":"https://issuer.example","jwks_uri":"https://issuer.example/jwks"}`)
				return
			}
			_, _ = fmt.Fprintf(response, `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"known-key"}]}`, signingKey.PublicJWK().X)
		}),
	})
	defer gateway.Close()

	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: gateway.Client(),
		Clock:  clock,
		Admit:  func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveKey(context.Background(), "https://issuer.example", aauth.ResourceDiscoveryDocument, "known-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveKey(context.Background(), "https://issuer.example", aauth.ResourceDiscoveryDocument, "unknown-key"); err == nil {
		t.Fatal("unknown kid was accepted")
	} else {
		var resolutionError *signaturekey.ResolutionError
		if !errors.As(err, &resolutionError) || resolutionError.Code != signaturekey.ResolutionUnknown {
			t.Fatalf("unknown kid error = %v (%#v)", err, resolutionError)
		}
	}
	if fetches.Load() != 2 {
		t.Fatalf("unknown kid bypassed one-minute refresh floor; total fetches = %d", fetches.Load())
	}

	differentKey := testSigningKey(t, "known-key")
	token, err := aauth.MintResourceToken(differentKey, aauth.ResourceTokenClaims{
		Issuer:       "https://issuer.example",
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     "https://ps.example",
		JTI:          "resource-token-with-bad-signature",
		PersonServer: "https://ps.example",
		Subject:      "pairwise-subject",
		PresentedJTI: "person-token-1",
		AgentJKT:     "agent-thumbprint",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Scope:        "documents.read",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aauth.VerifyResourceToken(context.Background(), token, resolver, clock); err == nil {
		t.Fatal("token signed by an untrusted same-kid key was accepted")
	} else {
		var resolutionError *signaturekey.ResolutionError
		if errors.As(err, &resolutionError) {
			t.Fatalf("refresh floor masked bad signature as key resolution failure: %v", err)
		}
	}
	if fetches.Load() != 2 {
		t.Fatalf("bad same-kid signature bypassed refresh floor; total fetches = %d", fetches.Load())
	}
}

func TestHTTPKeyResolverDoesNotFetchBeforeAdmission(t *testing.T) {
	t.Parallel()

	clock := aauth.ClockFunc(func() time.Time {
		return time.Date(2026, 7, 27, 6, 0, 0, 0, time.UTC)
	})
	var fetches atomic.Int32
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"issuer.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			fetches.Add(1)
			http.Error(response, "should not be reached", http.StatusInternalServerError)
		}),
	})
	defer gateway.Close()

	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: gateway.Client(),
		Clock:  clock,
		Admit: func(context.Context, string) error {
			return fmt.Errorf("egress denied")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveKey(context.Background(), "https://issuer.example", aauth.ResourceDiscoveryDocument, "unknown"); err == nil {
		t.Fatal("denied discovery succeeded")
	} else {
		var resolutionError *signaturekey.ResolutionError
		if !errors.As(err, &resolutionError) || resolutionError.Code != signaturekey.ResolutionDenied {
			t.Fatalf("denied discovery error = %v (%#v)", err, resolutionError)
		}
	}
	if fetches.Load() != 0 {
		t.Fatalf("denied discovery made %d requests", fetches.Load())
	}
}

func TestHTTPKeyResolverClassifiesAdmissionCancellationAsUnavailable(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "canceled", err: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
				Client: http.DefaultClient,
				Clock: aauth.ClockFunc(func() time.Time {
					return time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
				}),
				Admit: func(context.Context, string) error {
					return fmt.Errorf("admission interrupted: %w", test.err)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = resolver.ResolveKey(
				context.Background(),
				"https://issuer.example",
				aauth.ResourceDiscoveryDocument,
				"issuer-key",
			)
			var resolutionError *signaturekey.ResolutionError
			if !errors.As(err, &resolutionError) ||
				resolutionError.Code != signaturekey.ResolutionUnavailable ||
				!errors.Is(err, test.err) {
				t.Fatalf("admission cancellation error = %v (%#v)", err, resolutionError)
			}
		})
	}
}

func TestTokenVerificationRefreshesSameKidAfterSignatureFailure(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 6, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	oldKey := testSigningKey(t, "rotating-key")
	newKey := testSigningKey(t, "rotating-key")
	currentKey := oldKey.PublicJWK()
	failRefresh := false
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var signalRefresh sync.Once
	var fetches atomic.Int32

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"issuer.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			fetches.Add(1)
			if failRefresh {
				signalRefresh.Do(func() { close(refreshStarted) })
				<-releaseRefresh
				http.Error(response, "temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			switch request.URL.Path {
			case "/.well-known/aauth-resource.json":
				_, _ = fmt.Fprint(response, `{"issuer":"https://issuer.example","jwks_uri":"https://issuer.example/jwks"}`)
			case "/jwks":
				_, _ = fmt.Fprintf(response, `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"rotating-key"}]}`, currentKey.X)
			default:
				http.NotFound(response, request)
			}
		}),
	})
	defer gateway.Close()

	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: gateway.Client(),
		Clock:  clock,
		Admit:  func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveKey(context.Background(), "https://issuer.example", aauth.ResourceDiscoveryDocument, "rotating-key"); err != nil {
		t.Fatal(err)
	}

	now = now.Add(61 * time.Second)
	currentKey = newKey.PublicJWK()
	token, err := aauth.MintResourceToken(newKey, aauth.ResourceTokenClaims{
		Issuer:       "https://issuer.example",
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     "https://ps.example",
		JTI:          "resource-token-after-rotation",
		PersonServer: "https://ps.example",
		Subject:      "pairwise-subject",
		PresentedJTI: "person-token-1",
		AgentJKT:     "agent-thumbprint",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Scope:        "documents.read",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aauth.VerifyResourceToken(context.Background(), token, resolver, clock); err != nil {
		t.Fatalf("same-kid rotation was not refreshed: %v", err)
	}
	if fetches.Load() != 4 {
		t.Fatalf("same-kid refresh fetches = %d, want initial metadata+JWKS and one refresh", fetches.Load())
	}

	now = now.Add(61 * time.Second)
	failRefresh = true
	anotherKey := testSigningKey(t, "rotating-key")
	token, err = aauth.MintResourceToken(anotherKey, aauth.ResourceTokenClaims{
		Issuer:       "https://issuer.example",
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     "https://ps.example",
		JTI:          "resource-token-after-failed-rotation",
		PersonServer: "https://ps.example",
		Subject:      "pairwise-subject",
		PresentedJTI: "person-token-1",
		AgentJKT:     "agent-thumbprint",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Scope:        "documents.read",
	})
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	go func() {
		_, err := aauth.VerifyResourceToken(context.Background(), token, resolver, clock)
		results <- err
	}()
	<-refreshStarted
	go func() {
		_, err := aauth.VerifyResourceToken(context.Background(), token, resolver, clock)
		results <- err
	}()
	close(releaseRefresh)
	for range 2 {
		err := <-results
		if err == nil {
			t.Fatal("token verification ignored failed same-kid refresh")
		}
		var resolutionError *signaturekey.ResolutionError
		if !errors.As(err, &resolutionError) ||
			resolutionError.Code != signaturekey.ResolutionUnavailable {
			t.Fatalf("failed same-kid refresh error = %v (%#v)", err, resolutionError)
		}
	}
	if fetches.Load() != 5 {
		t.Fatalf("concurrent failed refresh made %d fetches, want one failed attempt after four successful requests", fetches.Load())
	}
	if _, err := aauth.VerifyResourceToken(context.Background(), token, resolver, clock); err == nil {
		t.Fatal("subsequent verification ignored the shared refresh failure")
	} else {
		var resolutionError *signaturekey.ResolutionError
		if !errors.As(err, &resolutionError) ||
			resolutionError.Code != signaturekey.ResolutionUnavailable {
			t.Fatalf("shared failed refresh error = %v (%#v)", err, resolutionError)
		}
	}
	if fetches.Load() != 5 {
		t.Fatalf("subsequent verification bypassed the failed-refresh floor; total fetches = %d", fetches.Load())
	}
}

func TestHTTPKeyResolverCancellationDoesNotPoisonHealthyCaller(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	key := testSigningKey(t, "issuer-key").PublicJWK()
	firstRequestStarted := make(chan struct{})
	var calls atomic.Int32

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"issuer.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			call := calls.Add(1)
			if call == 1 {
				close(firstRequestStarted)
				<-request.Context().Done()
				return
			}
			switch request.URL.Path {
			case "/.well-known/aauth-resource.json":
				_, _ = fmt.Fprint(response, `{"issuer":"https://issuer.example","jwks_uri":"https://issuer.example/jwks"}`)
			case "/jwks":
				_, _ = fmt.Fprintf(
					response,
					`{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"issuer-key"}]}`,
					key.X,
				)
			default:
				http.NotFound(response, request)
			}
		}),
	})
	defer gateway.Close()

	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: gateway.Client(),
		Clock:  aauth.ClockFunc(func() time.Time { return now }),
		Admit:  func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	leaderContext, cancelLeader := context.WithCancel(context.Background())
	leaderResult := make(chan error, 1)
	go func() {
		_, err := resolver.ResolveKey(
			leaderContext,
			"https://issuer.example",
			aauth.ResourceDiscoveryDocument,
			"issuer-key",
		)
		leaderResult <- err
	}()
	<-firstRequestStarted

	healthyResult := make(chan error, 1)
	go func() {
		_, err := resolver.ResolveKey(
			context.Background(),
			"https://issuer.example",
			aauth.ResourceDiscoveryDocument,
			"issuer-key",
		)
		healthyResult <- err
	}()
	cancelLeader()

	if err := <-leaderResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled leader error = %v, want context cancellation", err)
	}
	if err := <-healthyResult; err != nil {
		t.Fatalf("healthy caller inherited canceled leader result: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("discovery calls = %d, want canceled metadata plus healthy metadata and JWKS", calls.Load())
	}

	if _, err := resolver.ResolveKey(
		context.Background(),
		"https://issuer.example",
		aauth.ResourceDiscoveryDocument,
		"issuer-key",
	); err != nil {
		t.Fatalf("cached key unavailable after healthy retry: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("cached lookup made %d discovery calls, want 3", calls.Load())
	}
}

func TestTokenVerificationPreservesOperationalRefreshFailure(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	oldKey := testSigningKey(t, "rotating-key")
	newKey := testSigningKey(t, "rotating-key")
	token, err := aauth.MintResourceToken(newKey, aauth.ResourceTokenClaims{
		Issuer:       "https://issuer.example",
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     "https://ps.example",
		JTI:          "resource-token-after-failed-refresh",
		PersonServer: "https://ps.example",
		Subject:      "pairwise-subject",
		PresentedJTI: "person-token-1",
		AgentJKT:     "agent-thumbprint",
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Scope:        "documents.read",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		err  error
		want signaturekey.ResolutionCode
	}{
		{
			name: "denied",
			err: &signaturekey.ResolutionError{
				Code:  signaturekey.ResolutionDenied,
				Cause: errors.New("private admission detail"),
			},
			want: signaturekey.ResolutionDenied,
		},
		{
			name: "unavailable",
			err: &signaturekey.ResolutionError{
				Code:  signaturekey.ResolutionUnavailable,
				Cause: errors.New("private transport detail"),
			},
			want: signaturekey.ResolutionUnavailable,
		},
		{
			name: "invalid",
			err: &signaturekey.ResolutionError{
				Code:  signaturekey.ResolutionInvalid,
				Cause: errors.New("invalid refreshed metadata"),
			},
			want: signaturekey.ResolutionInvalid,
		},
		{
			name: "untyped",
			err:  errors.New("unclassified refresh failure"),
			want: signaturekey.ResolutionUnavailable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := staleRefreshResolver{
				stale: oldKey.PublicJWK(),
				err:   test.err,
			}
			_, err := aauth.VerifyResourceToken(
				context.Background(),
				token,
				resolver,
				aauth.ClockFunc(func() time.Time { return now }),
			)
			var resolutionError *signaturekey.ResolutionError
			if !errors.As(err, &resolutionError) || resolutionError.Code != test.want {
				t.Fatalf("VerifyResourceToken error = %v (%#v), want %q", err, resolutionError, test.want)
			}
		})
	}
}

type staleRefreshResolver struct {
	stale jose.JWK
	err   error
}

func (resolver staleRefreshResolver) ResolveKey(
	context.Context,
	string,
	string,
	string,
) (jose.JWK, error) {
	return resolver.stale, nil
}

func (resolver staleRefreshResolver) RefreshKey(
	context.Context,
	string,
	string,
	string,
) (jose.JWK, error) {
	return jose.JWK{}, resolver.err
}
