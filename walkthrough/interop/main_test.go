package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestInitializeWritesProviderDocumentsAndPrivateAgentState(t *testing.T) {
	stateDir := t.TempDir()
	issuer := "https://interop.example"
	now := time.Date(2026, 9, 1, 20, 0, 0, 0, time.UTC)
	initialized, err := initializeInterop(stateDir, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	if initialized.Agent != "aauth:go-interop@interop.example" {
		t.Fatalf("agent = %q", initialized.Agent)
	}

	for path, wantMode := range map[string]os.FileMode{
		filepath.Join(stateDir, "private.json"):                              0o600,
		filepath.Join(stateDir, "public", ".well-known", "aauth-agent.json"): 0o644,
		filepath.Join(stateDir, "public", "jwks.json"):                       0o644,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != wantMode {
			t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), wantMode)
		}
	}

	var metadata struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	readInteropJSON(t, filepath.Join(stateDir, "public", ".well-known", "aauth-agent.json"), &metadata)
	if metadata.Issuer != issuer || metadata.JWKSURI != issuer+"/jwks.json" {
		t.Fatalf("metadata = %#v", metadata)
	}

	private, err := loadInteropPrivate(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAgentToken(context.Background(), private.AgentToken, signaturekey.StaticKeyResolver{
		{Issuer: issuer, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: private.ProviderKey.ID()}: private.ProviderKey.PublicJWK(),
	}, aauth.ClockFunc(func() time.Time { return now.Add(time.Minute) }))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != initialized.Agent || !claims.Confirmation.JWK.Equal(private.AgentKey.PublicJWK()) {
		t.Fatalf("claims = %#v", claims)
	}
}

func TestCallTargetSignsAgentIdentityRequestAndChecksResponse(t *testing.T) {
	stateDir := t.TempDir()
	issuer := "https://interop.example"
	now := time.Date(2026, 9, 1, 20, 15, 0, 0, time.UTC)
	initialized, err := initializeInterop(stateDir, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	private, err := loadInteropPrivate(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		prepared, err := signaturekey.PrepareRequest(request, aauth.ClockFunc(func() time.Time { return now.Add(time.Minute) }), signaturekey.VerifyOptions{
			AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeJWT},
			RequiredComponents:     []string{"@method", "@authority", "@path", "signature-key"},
			RequireExactComponents: true,
		})
		if err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		compact, ok := prepared.Credential().JWT()
		if !ok {
			t.Error("request did not carry a JWT Signature-Key")
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		claims, err := aauth.VerifyAgentToken(request.Context(), compact, signaturekey.StaticKeyResolver{
			{Issuer: issuer, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: private.ProviderKey.ID()}: private.ProviderKey.PublicJWK(),
		}, aauth.ClockFunc(func() time.Time { return now.Add(time.Minute) }))
		if err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		if _, err := prepared.Verify(claims.Confirmation.JWK); err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]string{"iss": claims.Issuer, "sub": claims.Subject})
	}))
	defer server.Close()

	result, err := callInteropTarget(context.Background(), stateDir, server.URL, server.Client(), aauth.ClockFunc(func() time.Time { return now.Add(time.Minute) }))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != http.StatusOK || result.Issuer != issuer || result.Agent != initialized.Agent {
		t.Fatalf("result = %#v", result)
	}
}

func TestCallTargetDoesNotForwardCredentialsThroughRedirects(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Date(2026, 9, 1, 20, 30, 0, 0, time.UTC)
	if _, err := initializeInterop(stateDir, "https://interop.example", now); err != nil {
		t.Fatal(err)
	}
	var redirectedCalls atomic.Int32
	redirected := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedCalls.Add(1)
	}))
	defer redirected.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, redirected.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	_, err := callInteropTarget(context.Background(), stateDir, redirector.URL, redirector.Client(), aauth.ClockFunc(func() time.Time { return now.Add(time.Minute) }))
	if err == nil || !strings.Contains(err.Error(), "redirect is not permitted") {
		t.Fatalf("redirect error = %v", err)
	}
	if redirectedCalls.Load() != 0 {
		t.Fatalf("redirected target received %d credential-bearing calls", redirectedCalls.Load())
	}
}

func readInteropJSON(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, value); err != nil {
		t.Fatal(err)
	}
}
