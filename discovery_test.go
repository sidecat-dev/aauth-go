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
				{"kty":"OKP","crv":"Ed25519","x":%q,"alg":"EdDSA","kid":"issuer-key","use":"sig"}
			]}`, signingKey.PublicJWK().X)
		}),
	})
	defer gateway.Close()

	var admitted []string
	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
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
			_, _ = fmt.Fprintf(response, `{"keys":[{"kty":"OKP","crv":"Ed25519","x":%q,"kid":"known-key"}]}`, signingKey.PublicJWK().X)
		}),
	})
	defer gateway.Close()

	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
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
	}
	if fetches.Load() != 2 {
		t.Fatalf("unknown kid bypassed one-minute refresh floor; total fetches = %d", fetches.Load())
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

	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
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
	}
	if fetches.Load() != 0 {
		t.Fatalf("denied discovery made %d requests", fetches.Load())
	}
}

func TestTokenVerificationRefreshesSameKidAfterSignatureFailure(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 6, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	oldKey := testSigningKey(t, "rotating-key")
	newKey := testSigningKey(t, "rotating-key")
	currentKey := oldKey.PublicJWK()
	var fetches atomic.Int32

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"issuer.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			fetches.Add(1)
			switch request.URL.Path {
			case "/.well-known/aauth-resource.json":
				_, _ = fmt.Fprint(response, `{"issuer":"https://issuer.example","jwks_uri":"https://issuer.example/jwks"}`)
			case "/jwks":
				_, _ = fmt.Fprintf(response, `{"keys":[{"kty":"OKP","crv":"Ed25519","x":%q,"kid":"rotating-key"}]}`, currentKey.X)
			default:
				http.NotFound(response, request)
			}
		}),
	})
	defer gateway.Close()

	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
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
		Issuer:    "https://issuer.example",
		DWK:       aauth.ResourceDiscoveryDocument,
		Audience:  "https://ps.example",
		JTI:       "resource-token-after-rotation",
		Agent:     "aauth:planner@ap.example",
		AgentJKT:  "agent-thumbprint",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Scope:     "documents.read",
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
}
