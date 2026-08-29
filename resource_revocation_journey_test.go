package aauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	aa "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/reference"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentAuthTokenRevocationSurvivesResourceRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 22, 0, 0, 0, time.UTC)
	clock := aa.ClockFunc(func() time.Time { return now })
	psKey := testSigningKey(t, "resource-revocation-ps")
	asKey := testSigningKey(t, "resource-revocation-as")
	otherPSKey := testSigningKey(t, "resource-revocation-other-ps")
	resourceKey := testSigningKey(t, "resource-revocation-resource")
	agentKey := testSigningKey(t, "resource-revocation-agent")
	authToken, err := aa.MintAuthToken(asKey, aa.AuthTokenClaims{
		Issuer:       "https://as.example",
		DWK:          aa.AccessDiscoveryDocument,
		Audience:     "https://resource.example",
		JTI:          "auth-token-1",
		Confirmation: aa.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
		Subject:      "person-1",
		Scope:        "records.read",
		PersonServer: "https://ps.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		"https://ps.example":       {psKey.ID(): psKey.PublicJWK()},
		"https://as.example":       {asKey.ID(): asKey.PublicJWK()},
		"https://other-ps.example": {otherPSKey.ID(): otherPSKey.PublicJWK()},
	}
	revocationPath := filepath.Join(t.TempDir(), "resource-revocations.json")
	calls := 0
	newResource := func() *reference.Resource {
		t.Helper()
		store, err := reference.OpenFileTokenRevocationStore(revocationPath)
		if err != nil {
			t.Fatal(err)
		}
		replay, err := reference.NewMemoryProofReplayStore(clock, 32)
		if err != nil {
			t.Fatal(err)
		}
		resource, err := reference.NewResource(reference.ResourceConfig{
			Identifier:   "https://resource.example",
			AccessMode:   aa.AccessModeAuthToken,
			AccessServer: "https://as.example",
			SigningKey:   resourceKey,
			KeyResolver:  resolver,
			Clock:        clock,
			NewID:        func() string { return "resource-id" },
			Scopes:       []string{"records.read"},
			ScopeDescriptions: map[string]string{
				"records.read": "Read records",
			},
			RequiredScopesForRequest: testRequiredResourceScopes("records.read"),
			ReplayStore:              replay,
			ProtectedAuthorizationPolicy: func(context.Context, aa.AuthorizedRequest) error {
				return nil
			},
			Operation: func(context.Context, aa.AuthorizedRequest) (any, error) {
				calls++
				return map[string]bool{"ok": true}, nil
			},
			TokenRevocationStore: store,
			TokenRevocationPolicy: func(_ context.Context, evaluation aa.TokenRevocationEvaluation) error {
				if evaluation.CallerIssuer != evaluation.Request.Issuer && evaluation.CallerIssuer != "https://ps.example" {
					return errors.New("caller is not the token issuer or trusted person server")
				}
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resource
	}
	resource := newResource()
	resourceHandler := resource.Handler()
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			resourceHandler.ServeHTTP(response, request)
		}),
	})
	defer gateway.Close()
	client := gateway.Client()
	metadataResponse, err := client.Get("https://resource.example/.well-known/aauth-resource.json")
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	metadataErr := json.NewDecoder(metadataResponse.Body).Decode(&metadata)
	metadataResponse.Body.Close()
	if metadataResponse.StatusCode != http.StatusOK || metadataErr != nil || metadata["revocation_endpoint"] != "https://resource.example/revoke" {
		t.Fatalf("resource metadata revocation endpoint = %d %#v %v", metadataResponse.StatusCode, metadata, metadataErr)
	}
	protectedRequest := func() *http.Response {
		t.Helper()
		request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://resource.example/records", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := signaturekey.SignJWTRequest(request, agentKey, authToken, clock); err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	firstProtected := protectedRequest()
	firstRaw, err := io.ReadAll(firstProtected.Body)
	firstProtected.Body.Close()
	if firstProtected.StatusCode != http.StatusOK {
		t.Fatalf("first protected response = %d %s", firstProtected.StatusCode, firstRaw)
	}
	var firstBody map[string]bool
	if err != nil || json.Unmarshal(firstRaw, &firstBody) != nil || !firstBody["ok"] || calls != 1 {
		t.Fatalf("first protected response = %d %s, calls=%d", firstProtected.StatusCode, firstRaw, calls)
	}
	revoke := func(key, targetJTI, targetIssuer string, signer jose.SigningKey, signerIssuer, signerDocument string) *http.Response {
		t.Helper()
		body, err := json.Marshal(aa.TokenRevocationRequest{Issuer: targetIssuer, JTI: targetJTI})
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://resource.example/revoke", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		if err := signaturekey.SignJWKSURIRequestWithOptions(request, signer, signerIssuer, signerDocument, clock, signaturekey.SignOptions{Nonce: key}); err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	firstRevoke := revoke("first", "auth-token-1", "https://as.example", psKey, "https://ps.example", aa.PersonDiscoveryDocument)
	if firstRevoke.StatusCode != http.StatusOK {
		t.Fatalf("first revoke status = %d %s", firstRevoke.StatusCode, firstRevoke.Body)
	}
	firstRevoke.Body.Close()
	secondRevoke := revoke("second", "auth-token-1", "https://as.example", asKey, "https://as.example", aa.AccessDiscoveryDocument)
	if secondRevoke.StatusCode != http.StatusOK {
		t.Fatalf("idempotent revoke status = %d", secondRevoke.StatusCode)
	}
	secondRevoke.Body.Close()
	unknownRevoke := revoke("unknown", "unknown-token", "https://as.example", psKey, "https://ps.example", aa.PersonDiscoveryDocument)
	unknownRaw, _ := io.ReadAll(unknownRevoke.Body)
	unknownRevoke.Body.Close()
	if unknownRevoke.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("unknown revoke raw response = %d %q %s", unknownRevoke.StatusCode, unknownRevoke.Header.Get("Content-Type"), unknownRaw)
	}
	unknownRevoke.Body = io.NopCloser(bytes.NewReader(unknownRaw))
	problem, err := aa.DecodeProblemResponse(unknownRevoke)
	unknownRevoke.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if unknownRevoke.StatusCode != http.StatusNotFound || problem.Code != "token_not_found" {
		t.Fatalf("unknown revoke = %d %#v", unknownRevoke.StatusCode, problem)
	}
	unauthorizedRevoke := revoke("unauthorized", "auth-token-1", "https://as.example", otherPSKey, "https://other-ps.example", aa.PersonDiscoveryDocument)
	problem, err = aa.DecodeProblemResponse(unauthorizedRevoke)
	unauthorizedRevoke.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if unauthorizedRevoke.StatusCode != http.StatusForbidden || problem.Code != "revocation_denied" {
		t.Fatalf("unauthorized revoke = %d %#v", unauthorizedRevoke.StatusCode, problem)
	}
	resourceHandler = newResource().Handler()
	secondProtected := protectedRequest()
	problem, err = aa.DecodeProblemResponse(secondProtected)
	secondProtected.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if secondProtected.StatusCode != http.StatusForbidden || problem.Code != "token_revoked" || calls != 1 {
		t.Fatalf("revoked protected response = %d %#v, calls=%d", secondProtected.StatusCode, problem, calls)
	}
}
