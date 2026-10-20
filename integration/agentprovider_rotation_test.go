package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Core at a99d353, JWKS Discovery and Caching, selects kid from a cached set and
// refreshes an unknown kid subject to the one-minute floor. The AP convenience
// server publishes only its active key; an overlap set requires host publication.
func TestAgentProviderKeyReplacementAndHostPublishedOverlap(t *testing.T) {
	for _, overlap := range []bool{false, true} {
		name := "built-in single-key JWKS"
		if overlap {
			name = "host-published overlap JWKS"
		}
		t.Run(name, func(t *testing.T) {
			const issuer = "https://ap.example"
			now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
			clock := aauth.ClockFunc(func() time.Time { return now })
			oldKey, newKey, agentKey := newSigningKey(t, "old-provider-key"), newSigningKey(t, "new-provider-key"), newSigningKey(t, "agent-key")
			makeProvider := func(key jose.SigningKey, jti string) (*agentprovider.Server, string) {
				provider, err := agentprovider.New(agentprovider.Config{Issuer: issuer, SigningKey: key, Clock: clock, NewID: func() string { return jti }})
				if err != nil {
					t.Fatal(err)
				}
				token, err := provider.Issue(aauth.AgentTokenRequest{Agent: "aauth:reader@ap.example", PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour})
				if err != nil {
					t.Fatal(err)
				}
				return provider, token
			}
			oldProvider, oldToken := makeProvider(oldKey, "old-token")
			newProvider, newToken := makeProvider(newKey, "new-token")
			network := newLogicalTransport()
			keyFetches := 0
			serve := func(provider *agentprovider.Server, keys []jose.JWK) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Cache-Control", "max-age=3600")
					if r.URL.Path == "/.well-known/jwks.json" {
						keyFetches++
						if keys != nil {
							w.Header().Set("Content-Type", "application/json")
							if err := json.NewEncoder(w).Encode(map[string]any{"keys": keys}); err != nil {
								t.Error(err)
							}
							return
						}
					}
					provider.Handler().ServeHTTP(w, r)
				})
			}
			network.Handle(issuer, serve(oldProvider, nil))
			resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
				Client: &http.Client{Transport: network}, Clock: clock,
				Admit: func(_ context.Context, endpoint string) error {
					if endpoint == issuer+"/.well-known/aauth-agent.json" || endpoint == issuer+"/.well-known/jwks.json" {
						return nil
					}
					return errors.New("unexpected discovery endpoint")
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			verify := func(token string) error {
				_, err := aauth.VerifyAgentToken(context.Background(), token, resolver, clock)
				return err
			}
			if err := verify(oldToken); err != nil {
				t.Fatal(err)
			}
			var keys []jose.JWK
			if overlap {
				keys = []jose.JWK{newKey.PublicJWK(), oldKey.PublicJWK()}
			}
			network.Handle(issuer, serve(newProvider, keys))
			// Replacement does not instantly invalidate keys already in verifier caches.
			if err := verify(oldToken); err != nil {
				t.Fatalf("cached old token: %v", err)
			}
			if err := verify(newToken); err == nil {
				t.Fatal("new kid refreshed before the fetch floor")
			}
			if keyFetches != 1 {
				t.Fatalf("key fetches before floor=%d", keyFetches)
			}
			now = now.Add(61 * time.Second)
			if err := verify(newToken); err != nil {
				t.Fatalf("new token after refresh: %v", err)
			}
			if keyFetches != 2 {
				t.Fatalf("key fetches after refresh=%d", keyFetches)
			}
			err = verify(oldToken)
			if overlap && err != nil {
				t.Fatalf("old kid in overlap set: %v", err)
			}
			if !overlap && err == nil {
				t.Fatal("old token verified after its only key was removed")
			}
			if !overlap {
				return
			}
			// Retire the old public key and explicitly refresh after the fetch floor.
			// The tokens themselves remain valid for an hour from issuance.
			network.Handle(issuer, serve(newProvider, nil))
			now = now.Add(61 * time.Second)
			if _, err := resolver.RefreshKey(context.Background(), issuer, aauth.AgentDiscoveryDocument, newKey.ID()); err != nil {
				t.Fatal(err)
			}
			if err := verify(oldToken); err == nil {
				t.Fatal("retired kid verified after refresh")
			}
			if err := verify(newToken); err != nil {
				t.Fatalf("new token after retirement: %v", err)
			}
		})
	}
}
