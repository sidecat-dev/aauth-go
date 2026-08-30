package agentprovider_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/aauth-dev/auth-go/agentprovider"
	"github.com/aauth-dev/auth-go/jose"
	"github.com/aauth-dev/auth-go/signaturekey"
)

func TestNewRejectsIncompleteConfiguration(t *testing.T) {
	t.Parallel()

	key := testSigningKey(t, "ap-key", 1)
	clock := aauth.ClockFunc(func() time.Time {
		return time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	})
	valid := agentprovider.Config{
		Issuer:     "https://ap.example",
		SigningKey: key,
		Clock:      clock,
		NewID:      func() string { return "agent-token-1" },
	}

	tests := []struct {
		name   string
		change func(*agentprovider.Config)
	}{
		{name: "issuer", change: func(config *agentprovider.Config) { config.Issuer = "" }},
		{name: "https issuer", change: func(config *agentprovider.Config) { config.Issuer = "http://ap.example" }},
		{name: "signing key", change: func(config *agentprovider.Config) { config.SigningKey = jose.SigningKey{} }},
		{name: "clock", change: func(config *agentprovider.Config) { config.Clock = nil }},
		{name: "id source", change: func(config *agentprovider.Config) { config.NewID = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			if _, err := agentprovider.New(config); err == nil {
				t.Fatal("New succeeded with incomplete configuration")
			}
		})
	}
}

func TestIssueCreatesCurrentAgentToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 12, 30, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "ap-key", 2)
	agentKey := testSigningKey(t, "agent-key", 3)
	server, err := agentprovider.New(agentprovider.Config{
		Issuer:     "https://ap.example",
		SigningKey: apKey,
		Clock:      clock,
		NewID:      func() string { return "agent-token-1" },
	})
	if err != nil {
		t.Fatal(err)
	}

	compact, err := server.Issue(aauth.AgentTokenRequest{
		Agent:        "aauth:planner@ap.example",
		PersonServer: "https://ps.example",
		PublicKey:    agentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAgentToken(
		context.Background(),
		compact,
		signaturekey.StaticKeyResolver{
			{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: "ap-key"}: apKey.PublicJWK(),
		},
		clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "https://ap.example" ||
		claims.DWK != aauth.AgentDiscoveryDocument ||
		claims.Subject != "aauth:planner@ap.example" ||
		claims.PersonServer != "https://ps.example" ||
		claims.JTI != "agent-token-1" ||
		claims.IssuedAt != now.Unix() ||
		claims.ExpiresAt != now.Add(time.Hour).Unix() ||
		!claims.Confirmation.JWK.Equal(agentKey.PublicJWK()) {
		t.Fatalf("agent token claims = %#v", claims)
	}
}

func TestIssueRejectsSubAgentUntilThatProfileIsImplemented(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 12, 30, 0, 0, time.UTC)
	server, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: testSigningKey(t, "ap-key", 21),
		Clock: aauth.ClockFunc(func() time.Time { return now }), NewID: func() string { return "unused" },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.Issue(aauth.AgentTokenRequest{
		Agent: "aauth:planner+child@ap.example", ParentAgent: "aauth:planner@ap.example",
		PersonServer: "https://ps.example", PublicKey: testSigningKey(t, "agent-key", 22).PublicJWK(),
		Lifetime: time.Hour,
	})
	if err == nil {
		t.Fatal("Issue accepted a sub-agent request")
	}
}

func TestHandlerServesAgentMetadataAndJWKS(t *testing.T) {
	t.Parallel()

	apKey := testSigningKey(t, "ap-key", 4)
	server, err := agentprovider.New(agentprovider.Config{
		Issuer:     "https://ap.example",
		SigningKey: apKey,
		Clock:      aauth.SystemClock{},
		NewID:      func() string { return "agent-token-1" },
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("metadata", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://ap.example/.well-known/aauth-agent.json", nil)
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d", response.Code)
		}
		if response.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("Content-Type = %q", response.Header().Get("Content-Type"))
		}
		var metadata map[string]string
		if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{
			"issuer":   "https://ap.example",
			"jwks_uri": "https://ap.example/.well-known/jwks.json",
		}
		if len(metadata) != len(want) || metadata["issuer"] != want["issuer"] || metadata["jwks_uri"] != want["jwks_uri"] {
			t.Fatalf("metadata = %#v, want %#v", metadata, want)
		}
	})

	t.Run("jwks", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://ap.example/.well-known/jwks.json", nil)
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d", response.Code)
		}
		var document struct {
			Keys []jose.JWK `json:"keys"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
			t.Fatal(err)
		}
		if len(document.Keys) != 1 || !document.Keys[0].Equal(apKey.PublicJWK()) || document.Keys[0] != apKey.PublicJWK() {
			t.Fatalf("JWKS = %#v", document.Keys)
		}
	})

	for _, path := range []string{"/", "/.well-known/unknown.json"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://ap.example"+path, nil)
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, response.Code)
		}
	}
}

func testSigningKey(t *testing.T, id string, fill byte) jose.SigningKey {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
