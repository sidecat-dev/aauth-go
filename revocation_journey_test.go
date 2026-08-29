package aauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aa "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentAgentTokenRevocationSurvivesPersonServerRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	clock := aa.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "revocation-ap")
	psKey := testSigningKey(t, "revocation-ps")
	agentKey := testSigningKey(t, "revocation-agent")
	revokerKey := testSigningKey(t, "revocation-revoker")
	otherAgentKey := testSigningKey(t, "revocation-other-agent")
	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example", SigningKey: apKey, Clock: clock,
		NewID: sequentialIDs("revocation-revoker-token", "revocation-agent-token", "revocation-other-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	revokerToken, err := ap.IssueAgentToken(aa.AgentTokenRequest{
		Agent: "aauth:revoker@ap.example", PersonServer: "https://ps.example",
		PublicKey: revokerKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := ap.IssueAgentToken(aa.AgentTokenRequest{
		Agent: "aauth:revoked@ap.example", PersonServer: "https://ps.example",
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherAgentToken, err := ap.IssueAgentToken(aa.AgentTokenRequest{
		Agent: "aauth:other@ap.example", PersonServer: "https://ps.example",
		PublicKey: otherAgentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client, Clock: clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasPrefix(endpoint, "https://ap.example/") || strings.HasPrefix(endpoint, "https://ps.example/") {
				return nil
			}
			return fmt.Errorf("endpoint outside trust boundary: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	governancePath := filepath.Join(t.TempDir(), "governance.json")
	revocationPath := filepath.Join(t.TempDir(), "revocations.json")
	newPersonServer := func() *reference.PersonServer {
		t.Helper()
		governanceStore, err := reference.NewFileGovernanceStore(governancePath)
		if err != nil {
			t.Fatal(err)
		}
		revocationStore, err := reference.OpenFileTokenRevocationStore(revocationPath)
		if err != nil {
			t.Fatal(err)
		}
		server, err := reference.NewPersonServer(reference.PersonServerConfig{
			AuthorizationStore:   testAuthorizationStateStore(t),
			Identifier:           "https://ps.example",
			SigningKey:           psKey,
			KeyResolver:          resolver,
			Clock:                clock,
			NewID:                sequentialIDs("revocation-person-token"),
			GovernanceStore:      governanceStore,
			PersonTokenStore:     testPersonTokenStore(t),
			MissionIssuanceStore: testMissionIssuanceStore(t),
			PersonTokenPolicy:    testPersonTokenPolicy,
			TokenRevocationStore: revocationStore,
			TokenRevocationPolicy: func(_ context.Context, evaluation aa.TokenRevocationEvaluation) error {
				if evaluation.CallerIssuer != evaluation.Request.Issuer ||
					(evaluation.CallerAgent != "" && evaluation.CallerAgent != "aauth:revoker@ap.example") {
					return errors.New("caller is not the token issuer")
				}
				return nil
			},
			CurrentMissionPolicy: func(_ context.Context, evaluation aa.MissionEvaluation) (aa.MissionDecision, error) {
				return aa.MissionDecision{Description: evaluation.Proposal.Description}, nil
			},
			AuthorizationPolicy: func(context.Context, aa.AuthorizationRequest) (aa.AuthorizationDecision, error) {
				return aa.AuthorizationDecision{}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	personServer := newPersonServer()
	personHandler := personServer.Handler()
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			personHandler.ServeHTTP(response, request)
		}),
	})
	defer gateway.Close()
	client.Transport = gateway.Client().Transport
	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:revoked@ap.example", SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: client, Clock: clock, AuthorizationStore: testAuthorizationStateStore(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	revoker, err := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:revoker@ap.example", SigningKey: revokerKey, AgentToken: revokerToken,
		KeyResolver: resolver, HTTPClient: client, Clock: clock, AuthorizationStore: testAuthorizationStateStore(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	otherAgent, err := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:other@ap.example", SigningKey: otherAgentKey, AgentToken: otherAgentToken,
		KeyResolver: resolver, HTTPClient: client, Clock: clock, AuthorizationStore: testAuthorizationStateStore(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	metadataResponse, err := client.Get("https://ps.example/.well-known/aauth-person.json")
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	metadataErr := json.NewDecoder(metadataResponse.Body).Decode(&metadata)
	metadataResponse.Body.Close()
	if metadataResponse.StatusCode != http.StatusOK || metadataErr != nil || metadata["revocation_endpoint"] != "https://ps.example/revoke" {
		t.Fatalf("person metadata revocation endpoint = %d %#v %v", metadataResponse.StatusCode, metadata, metadataErr)
	}
	if err := revoker.RevokeToken(context.Background(), "https://ps.example/revoke", aa.TokenRevocationRequest{
		Issuer: "https://ap.example", JTI: "unknown-token",
	}); err == nil {
		t.Fatal("unknown token revocation succeeded")
	} else {
		assertProblemCode(t, err, http.StatusNotFound, "token_not_found")
	}
	malformedRequest, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, "https://ps.example/revoke",
		bytes.NewReader([]byte(`{"iss":"https://ap.example"}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	malformedRequest.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWTRequest(malformedRequest, revokerKey, revokerToken, clock); err != nil {
		t.Fatal(err)
	}
	malformedResponse, err := client.Do(malformedRequest)
	if err != nil {
		t.Fatal(err)
	}
	problem, err := aa.DecodeProblemResponse(malformedResponse)
	malformedResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if malformedResponse.StatusCode != http.StatusBadRequest || problem.Code != "invalid_request" {
		t.Fatalf("malformed revocation response = %d %#v", malformedResponse.StatusCode, problem)
	}
	queryRequest, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, "https://ps.example/revoke?unexpected=1",
		bytes.NewReader([]byte(`{"iss":"https://ap.example","jti":"unknown-token"}`)),
	)
	if err != nil {
		t.Fatal(err)
	}
	queryRequest.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWTRequest(queryRequest, revokerKey, revokerToken, clock); err != nil {
		t.Fatal(err)
	}
	queryResponse, err := client.Do(queryRequest)
	if err != nil {
		t.Fatal(err)
	}
	problem, err = aa.DecodeProblemResponse(queryResponse)
	queryResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if queryResponse.StatusCode != http.StatusBadRequest || problem.Code != "invalid_request" {
		t.Fatalf("query revocation response = %d %#v", queryResponse.StatusCode, problem)
	}
	if _, err := agent.CreateMission(context.Background(), "https://ps.example/mission", aa.MissionProposal{
		Description: "Observe the agent token before revoking it.",
	}); err != nil {
		t.Fatal(err)
	}
	if err := revoker.RevokeToken(context.Background(), "https://ps.example/revoke", aa.TokenRevocationRequest{
		Issuer: "https://ap.example", JTI: "revocation-agent-token",
	}); err != nil {
		t.Fatal(err)
	}
	if err := ap.RevokeToken(context.Background(), client, "https://ps.example/revoke", aa.TokenRevocationRequest{
		Issuer: "https://ap.example", JTI: "revocation-agent-token",
	}); err != nil {
		t.Fatalf("provider server-signed idempotent revoke = %v", err)
	}
	if err := revoker.RevokeToken(context.Background(), "https://ps.example/revoke", aa.TokenRevocationRequest{
		Issuer: "https://ap.example", JTI: "revocation-agent-token",
	}); err != nil {
		t.Fatalf("idempotent revoke = %v", err)
	}
	if err := otherAgent.RevokeToken(context.Background(), "https://ps.example/revoke", aa.TokenRevocationRequest{
		Issuer: "https://ap.example", JTI: "revocation-agent-token",
	}); err == nil {
		t.Fatal("unauthorized issuer mismatch succeeded")
	} else {
		assertProblemCode(t, err, http.StatusForbidden, "revocation_denied")
	}
	personHandler = newPersonServer().Handler()
	if _, err := agent.CreateMission(context.Background(), "https://ps.example/mission", aa.MissionProposal{
		Description: "This must be refused after restart because the token was revoked.",
	}); err == nil {
		t.Fatal("revoked agent token was accepted after restart")
	} else {
		assertProblemCode(t, err, http.StatusForbidden, "token_revoked")
	}
}
