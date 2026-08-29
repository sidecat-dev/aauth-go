package aauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aa "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/reference"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentAccessServerAuthTokenRevocationSurvivesRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 23, 0, 0, 0, time.UTC)
	clock := aa.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "access-revocation-ap")
	psKey := testSigningKey(t, "access-revocation-ps")
	asKey := testSigningKey(t, "access-revocation-as")
	resourceKey := testSigningKey(t, "access-revocation-resource")
	agentKey := testSigningKey(t, "access-revocation-agent")
	otherPSKey := testSigningKey(t, "access-revocation-other-ps")
	agentJKT, err := agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := aa.MintAgentToken("https://ap.example", apKey, aa.AgentTokenRequest{
		Agent:        "aauth:access-revocation@ap.example",
		PersonServer: "https://ps.example",
		PublicKey:    agentKey.PublicJWK(),
		Lifetime:     time.Hour,
	}, now, "agent-token-1")
	if err != nil {
		t.Fatal(err)
	}
	resourceToken, err := aa.MintResourceToken(resourceKey, aa.ResourceTokenClaims{
		Issuer:       "https://resource.example",
		DWK:          aa.ResourceDiscoveryDocument,
		Audience:     "https://as.example",
		JTI:          "resource-token-1",
		AgentJKT:     agentJKT,
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Scope:        "records.read",
		PersonServer: "https://ps.example",
		Subject:      "person-1",
		PresentedJTI: "person-token-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver := signaturekey.StaticKeyResolver{
		"https://ap.example":       {apKey.ID(): apKey.PublicJWK()},
		"https://ps.example":       {psKey.ID(): psKey.PublicJWK()},
		"https://as.example":       {asKey.ID(): asKey.PublicJWK()},
		"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()},
		"https://other-ps.example": {otherPSKey.ID(): otherPSKey.PublicJWK()},
	}
	revocationPath := filepath.Join(t.TempDir(), "access-revocations.json")
	newServer := func() (*reference.AccessServer, *reference.FileTokenRevocationStore) {
		t.Helper()
		store, err := reference.OpenFileTokenRevocationStore(revocationPath)
		if err != nil {
			t.Fatal(err)
		}
		server, err := reference.NewAccessServer(reference.AccessServerConfig{
			Identifier: "https://as.example", SigningKey: asKey, KeyResolver: resolver, Clock: clock,
			NewID: sequentialIDs("access-auth-token"),
			TrustedPersonServer: func(_ context.Context, identifier string) error {
				if identifier != "https://ps.example" {
					return errors.New("person server is not trusted")
				}
				return nil
			},
			AuthorizationPolicy: func(_ context.Context, request aa.AuthorizationRequest) (aa.AuthorizationDecision, error) {
				return aa.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
			},
			AuthorizationStore:   testAuthorizationStateStore(t),
			TokenRevocationStore: store,
		})
		if err != nil {
			t.Fatal(err)
		}
		return server, store
	}
	server, store := newServer()
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"as.example": server.Handler(),
	})
	defer gateway.Close()
	client := gateway.Client()

	metadataResponse, err := client.Get("https://as.example/.well-known/aauth-access.json")
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	metadataErr := json.NewDecoder(metadataResponse.Body).Decode(&metadata)
	metadataResponse.Body.Close()
	if metadataResponse.StatusCode != http.StatusOK || metadataErr != nil || metadata["revocation_endpoint"] != "https://as.example/revoke" {
		t.Fatalf("access metadata revocation endpoint = %d %#v %v", metadataResponse.StatusCode, metadata, metadataErr)
	}

	body, err := json.Marshal(map[string]string{"resource_token": resourceToken, "agent_token": agentToken})
	if err != nil {
		t.Fatal(err)
	}
	issueRequest, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://as.example/token", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	issueRequest.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequest(issueRequest, psKey, "https://ps.example", aa.PersonDiscoveryDocument, clock); err != nil {
		t.Fatal(err)
	}
	issueResponse, err := client.Do(issueRequest)
	if err != nil {
		t.Fatal(err)
	}
	issueRaw, err := io.ReadAll(issueResponse.Body)
	issueResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if issueResponse.StatusCode != http.StatusOK {
		t.Fatalf("auth-token issuance = %d %s", issueResponse.StatusCode, issueRaw)
	}
	var issued struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.Unmarshal(issueRaw, &issued); err != nil || issued.AuthToken == "" {
		t.Fatalf("auth-token issuance body = %s, err=%v", issueRaw, err)
	}
	authEvidence, err := aa.VerifyAuthToken(context.Background(), issued.AuthToken, resolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	authClaims, err := authEvidence.Claims()
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.Issuer != "https://as.example" || authClaims.JTI == "" {
		t.Fatalf("issued auth claims = %#v", authClaims)
	}
	if _, err := store.IsRevoked(context.Background(), aa.TokenRevocationRequest{Issuer: authClaims.Issuer, JTI: authClaims.JTI}); err != nil {
		t.Fatal(err)
	}

	revoke := func(nonce, targetJTI, targetIssuer string, signer jose.SigningKey, signerIssuer, signerDocument string) *http.Response {
		t.Helper()
		body, err := json.Marshal(aa.TokenRevocationRequest{Issuer: targetIssuer, JTI: targetJTI})
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://as.example/revoke", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		if err := signaturekey.SignJWKSURIRequestWithOptions(request, signer, signerIssuer, signerDocument, clock, signaturekey.SignOptions{Nonce: nonce}); err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	firstRevoke := revoke("first", authClaims.JTI, authClaims.Issuer, asKey, "https://as.example", aa.AccessDiscoveryDocument)
	if firstRevoke.StatusCode != http.StatusOK {
		t.Fatalf("first revoke = %d", firstRevoke.StatusCode)
	}
	firstRevoke.Body.Close()
	secondRevoke := revoke("second", authClaims.JTI, authClaims.Issuer, asKey, "https://as.example", aa.AccessDiscoveryDocument)
	if secondRevoke.StatusCode != http.StatusOK {
		t.Fatalf("new-proof revoke = %d", secondRevoke.StatusCode)
	}
	secondRevoke.Body.Close()
	unknownRevoke := revoke("unknown", "unknown-token", authClaims.Issuer, asKey, "https://as.example", aa.AccessDiscoveryDocument)
	unknownProblem, err := aa.DecodeProblemResponse(unknownRevoke)
	unknownRevoke.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if unknownRevoke.StatusCode != http.StatusNotFound || unknownProblem.Code != "token_not_found" {
		t.Fatalf("unknown revoke = %d %#v", unknownRevoke.StatusCode, unknownProblem)
	}
	unauthorizedRevoke := revoke("unauthorized", authClaims.JTI, authClaims.Issuer, otherPSKey, "https://other-ps.example", aa.PersonDiscoveryDocument)
	unauthorizedProblem, err := aa.DecodeProblemResponse(unauthorizedRevoke)
	unauthorizedRevoke.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if unauthorizedRevoke.StatusCode != http.StatusForbidden || unauthorizedProblem.Code != "revocation_denied" {
		t.Fatalf("unauthorized revoke = %d %#v", unauthorizedRevoke.StatusCode, unauthorizedProblem)
	}

	_, restartedStore := newServer()
	restarted, err := restartedStore.IsRevoked(context.Background(), aa.TokenRevocationRequest{Issuer: authClaims.Issuer, JTI: authClaims.JTI})
	if err != nil || !restarted {
		t.Fatalf("restarted revocation state = %v, %v", restarted, err)
	}

	failingServer, err := reference.NewAccessServer(reference.AccessServerConfig{
		Identifier: "https://as.example", SigningKey: asKey, KeyResolver: resolver, Clock: clock,
		NewID:               sequentialIDs("failed-observation-auth-token"),
		TrustedPersonServer: func(context.Context, string) error { return nil },
		AuthorizationPolicy: func(_ context.Context, request aa.AuthorizationRequest) (aa.AuthorizationDecision, error) {
			return aa.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		},
		AuthorizationStore:   testAuthorizationStateStore(t),
		TokenRevocationStore: failingTokenObservationStore{},
	})
	if err != nil {
		t.Fatal(err)
	}
	failureRequest, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://as.example/token", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	failureRequest.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequestWithOptions(failureRequest, psKey, "https://ps.example", aa.PersonDiscoveryDocument, clock, signaturekey.SignOptions{Nonce: "failed-observation"}); err != nil {
		t.Fatal(err)
	}
	failureResponse := httptest.NewRecorder()
	failingServer.Handler().ServeHTTP(failureResponse, failureRequest)
	if failureResponse.Code != http.StatusServiceUnavailable || strings.Contains(failureResponse.Body.String(), "auth_token") {
		t.Fatalf("observation failure response = %d %s", failureResponse.Code, failureResponse.Body.String())
	}
}

type failingTokenObservationStore struct{}

func (failingTokenObservationStore) Observe(context.Context, reference.TokenRevocationObservation) error {
	return errors.New("observation store unavailable")
}

func (failingTokenObservationStore) Revoke(context.Context, aa.TokenRevocationRequest, string, time.Time, time.Time) error {
	return errors.New("observation store unavailable")
}

func (failingTokenObservationStore) IsRevoked(context.Context, aa.TokenRevocationRequest) (bool, error) {
	return false, nil
}
