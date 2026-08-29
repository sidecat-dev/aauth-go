package aauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aa "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/reference"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentPersonServerAuthTokenRevocationSurvivesRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	clock := aa.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "person-auth-revocation-ap")
	psKey := testSigningKey(t, "person-auth-revocation-ps")
	otherPSKey := testSigningKey(t, "person-auth-revocation-other-ps")
	resourceKey := testSigningKey(t, "person-auth-revocation-resource")
	agentKey := testSigningKey(t, "person-auth-revocation-agent")
	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example", SigningKey: apKey, Clock: clock,
		NewID: sequentialIDs("person-auth-revocation-agent-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := ap.IssueAgentToken(aa.AgentTokenRequest{
		Agent:        "aauth:person-auth-revocation@ap.example",
		PersonServer: "https://ps.example",
		PublicKey:    agentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			for _, prefix := range []string{"https://ap.example/", "https://ps.example/", "https://other-ps.example/", "https://resource.example/"} {
				if strings.HasPrefix(endpoint, prefix) {
					return nil
				}
			}
			return fmt.Errorf("endpoint outside test trust: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	personTokens, missionIssuances := testCurrentPersonServerCustody(t)
	revocationPath := filepath.Join(t.TempDir(), "person-auth-revocations.json")
	newPersonServer := func() (*reference.PersonServer, *reference.FileTokenRevocationStore) {
		t.Helper()
		revocations, err := reference.OpenFileTokenRevocationStore(revocationPath)
		if err != nil {
			t.Fatal(err)
		}
		server, err := reference.NewPersonServer(reference.PersonServerConfig{
			Identifier: "https://ps.example", SigningKey: psKey, KeyResolver: resolver, Clock: clock,
			NewID:              sequentialIDs("person-auth-revocation-person-token", "person-auth-revocation-auth-token"),
			AuthorizationStore: testAuthorizationStateStore(t), PersonTokenStore: personTokens,
			MissionIssuanceStore: missionIssuances, TokenRevocationStore: revocations,
			PersonTokenPolicy: func(context.Context, aa.PersonTokenRequest) (aa.PersonTokenDecision, error) {
				return aa.PersonTokenDecision{Subject: "person-1", Lifetime: time.Hour}, nil
			},
			CurrentMissionPolicy: func(_ context.Context, evaluation aa.MissionEvaluation) (aa.MissionDecision, error) {
				return aa.MissionDecision{Description: evaluation.Proposal.Description}, nil
			},
			AuthorizationPolicy: func(_ context.Context, request aa.AuthorizationRequest) (aa.AuthorizationDecision, error) {
				return aa.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return server, revocations
	}
	personServer, revocations := newPersonServer()
	operationCalls := 0
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier: "https://resource.example", AccessMode: aa.AccessModeAuthToken,
		PersonServer: "https://ps.example", SigningKey: resourceKey, KeyResolver: resolver,
		Clock: clock, NewID: sequentialIDs("person-auth-revocation-resource-token"),
		Scopes: []string{"records.read"}, ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopesForRequest:     testRequiredResourceScopes("records.read"),
		ReplayStore:                  testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: func(context.Context, aa.AuthorizedRequest) error { return nil },
		Operation: func(context.Context, aa.AuthorizedRequest) (any, error) {
			operationCalls++
			return map[string]bool{"ok": true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var personHandler http.Handler = personServer.Handler()
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) { personHandler.ServeHTTP(response, request) }),
		"other-ps.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/.well-known/aauth-person.json":
				_ = json.NewEncoder(response).Encode(map[string]string{
					"issuer": "https://other-ps.example", "jwks_uri": "https://other-ps.example/jwks",
				})
			case "/jwks":
				_ = json.NewEncoder(response).Encode(map[string]any{"keys": []jose.JWK{otherPSKey.PublicJWK()}})
			default:
				http.NotFound(response, request)
			}
		}),
		"resource.example": resource.Handler(),
	})
	defer gateway.Close()
	client.Transport = gateway.Client().Transport
	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:person-auth-revocation@ap.example", SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: client, Clock: clock, AuthorizationStore: testAuthorizationStateStore(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	person, err := agent.RequestPersonToken(context.Background(), "https://ps.example/person", "https://resource.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	resourceGrant, err := agent.RequestResourceTokenWithPersonToken(
		context.Background(), "https://resource.example/authorize", []string{"records.read"}, person.PersonToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := agent.ExchangeResourceToken(context.Background(), "https://ps.example/token", resourceGrant)
	if err != nil {
		t.Fatal(err)
	}
	response, err := agent.DoAuthorizedRequest(context.Background(), reference.AuthorizedCall{
		Method: http.MethodGet, Endpoint: "https://resource.example/records",
	}, grant)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || operationCalls != 1 {
		t.Fatalf("three-party protected call = %d, operations=%d", response.StatusCode, operationCalls)
	}
	if grant.Claims.Issuer != "https://ps.example" || grant.Claims.JTI == "" {
		t.Fatalf("local auth token claims = %#v", grant.Claims)
	}
	if revoked, err := revocations.IsRevoked(context.Background(), aa.TokenRevocationRequest{Issuer: grant.Claims.Issuer, JTI: grant.Claims.JTI}); err != nil || revoked {
		t.Fatalf("auth token observation before revoke = %v, %v", revoked, err)
	}

	revoke := func(nonce, targetJTI string, signer jose.SigningKey, signerIssuer, signerDocument string) *http.Response {
		t.Helper()
		body, err := json.Marshal(aa.TokenRevocationRequest{Issuer: "https://ps.example", JTI: targetJTI})
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://ps.example/revoke", bytes.NewReader(body))
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
	first := revoke("first", grant.Claims.JTI, psKey, "https://ps.example", aa.PersonDiscoveryDocument)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first local auth-token revoke = %d", first.StatusCode)
	}
	first.Body.Close()
	second := revoke("second", grant.Claims.JTI, psKey, "https://ps.example", aa.PersonDiscoveryDocument)
	if second.StatusCode != http.StatusOK {
		t.Fatalf("new-proof local auth-token revoke = %d", second.StatusCode)
	}
	second.Body.Close()
	unknown := revoke("unknown", "unknown-auth-token", psKey, "https://ps.example", aa.PersonDiscoveryDocument)
	unknownProblem, err := aa.DecodeProblemResponse(unknown)
	unknown.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if unknown.StatusCode != http.StatusNotFound || unknownProblem.Code != "token_not_found" {
		t.Fatalf("unknown local auth-token revoke = %d %#v", unknown.StatusCode, unknownProblem)
	}
	unauthorized := revoke("unauthorized", grant.Claims.JTI, otherPSKey, "https://other-ps.example", aa.PersonDiscoveryDocument)
	unauthorizedProblem, err := aa.DecodeProblemResponse(unauthorized)
	unauthorized.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if unauthorized.StatusCode != http.StatusForbidden || unauthorizedProblem.Code != "revocation_denied" {
		t.Fatalf("unauthorized local auth-token revoke = %d %#v", unauthorized.StatusCode, unauthorizedProblem)
	}

	personServer, restartedStore := newPersonServer()
	personHandler = personServer.Handler()
	restarted, err := restartedStore.IsRevoked(context.Background(), aa.TokenRevocationRequest{Issuer: grant.Claims.Issuer, JTI: grant.Claims.JTI})
	if err != nil || !restarted {
		t.Fatalf("restarted local auth-token revocation = %v, %v", restarted, err)
	}
	postRestart := revoke("post-restart", grant.Claims.JTI, psKey, "https://ps.example", aa.PersonDiscoveryDocument)
	postRestart.Body.Close()
	if postRestart.StatusCode != http.StatusOK {
		t.Fatalf("post-restart local auth-token revoke = %d", postRestart.StatusCode)
	}
}
