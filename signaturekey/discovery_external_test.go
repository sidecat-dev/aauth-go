package signaturekey_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

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
