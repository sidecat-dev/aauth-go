package aauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentMissionUpdateRoundTripsAndRecoversAfterRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 20, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "mission-update-ap")
	psKey := testSigningKey(t, "mission-update-ps")
	agentKey := testSigningKey(t, "mission-update-agent")
	otherAgentKey := testSigningKey(t, "mission-update-other-agent")
	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example", SigningKey: apKey, Clock: clock,
		NewID: sequentialIDs("mission-update-agent-token", "mission-update-other-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent: "aauth:mission-updater@ap.example", PersonServer: "https://ps.example",
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherAgentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent: "aauth:other-updater@ap.example", PersonServer: "https://ps.example",
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
	governancePath := t.TempDir() + "/mission-update-governance.json"
	var updateEvaluations []aauth.MissionUpdateEvaluation
	denyUpdate := false
	newPersonServer := func() *reference.PersonServer {
		t.Helper()
		governanceStore, err := reference.NewFileGovernanceStore(governancePath)
		if err != nil {
			t.Fatal(err)
		}
		server, err := reference.NewPersonServer(reference.PersonServerConfig{
			AuthorizationStore:   testAuthorizationStateStore(t),
			Identifier:           "https://ps.example",
			SigningKey:           psKey,
			KeyResolver:          resolver,
			Clock:                clock,
			NewID:                sequentialIDs("mission-update-person-token"),
			GovernanceStore:      governanceStore,
			PersonTokenStore:     testPersonTokenStore(t),
			MissionIssuanceStore: testMissionIssuanceStore(t),
			PersonTokenPolicy:    testPersonTokenPolicy,
			CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
				return aauth.MissionDecision{Description: evaluation.Proposal.Description}, nil
			},
			MissionUpdatePolicy: func(_ context.Context, evaluation aauth.MissionUpdateEvaluation) error {
				updateEvaluations = append(updateEvaluations, evaluation)
				if denyUpdate {
					return fmt.Errorf("deployment policy denied mission update")
				}
				return nil
			},
			AuthorizationPolicy: func(context.Context, aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
				return aauth.AuthorizationDecision{}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	personServer := newPersonServer()
	var personHandler http.Handler = personServer.Handler()
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			personHandler.ServeHTTP(response, request)
		}),
	})
	defer gateway.Close()
	client.Transport = gateway.Client().Transport
	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:mission-updater@ap.example", SigningKey: agentKey, AgentToken: agentToken,
		KeyResolver: resolver, HTTPClient: client, Clock: clock, AuthorizationStore: testAuthorizationStateStore(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	otherAgent, err := reference.NewAgent(reference.AgentConfig{
		Identifier: "aauth:other-updater@ap.example", SigningKey: otherAgentKey, AgentToken: otherAgentToken,
		KeyResolver: resolver, HTTPClient: client, Clock: clock, AuthorizationStore: testAuthorizationStateStore(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	mission, err := agent.CreateMission(context.Background(), "https://ps.example/mission", aauth.MissionProposal{
		Description: "Prepare a reviewed mission update.",
	})
	if err != nil {
		t.Fatal(err)
	}
	description := "The approved work changed in one explicit step."
	capture := &missionUpdateCaptureTransport{base: client.Transport}
	client.Transport = capture
	result, err := agent.UpdateMission(context.Background(), "https://ps.example/mission", mission.Reference, description)
	if err != nil {
		t.Fatal(err)
	}
	if result.S256 != aauth.S256([]byte(description)) || capture.request == nil {
		t.Fatalf("mission update result = %#v, captured request = %#v", result, capture.request)
	}
	capturedRequest := capture.request.Clone(context.Background())
	capturedBody := append([]byte(nil), capture.body...)
	client.Transport = capture.base
	snapshot, err := personServer.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Log) != 1 || snapshot.Log[0].Kind != aauth.MissionLogUpdate ||
		snapshot.Log[0].Agent != "aauth:mission-updater@ap.example" {
		t.Fatalf("mission update snapshot = %#v", snapshot)
	}
	var updateBody aauth.MissionUpdate
	if err := json.Unmarshal(snapshot.Log[0].Request, &updateBody); err != nil {
		t.Fatal(err)
	}
	if updateBody.Action != "update" || updateBody.Description != description {
		t.Fatalf("retained mission update = %#v", updateBody)
	}
	if len(updateEvaluations) != 1 || updateEvaluations[0].Description != description ||
		updateEvaluations[0].Mission.Reference != mission.Reference || len(updateEvaluations[0].Mission.Log) != 0 {
		t.Fatalf("mission update policy evaluations = %#v", updateEvaluations)
	}
	unknownMission := aauth.MissionReference{Approver: "https://ps.example", S256: aauth.S256([]byte("unknown mission"))}
	if _, err := agent.UpdateMission(context.Background(), "https://ps.example/mission", unknownMission, "unknown mission update"); err == nil {
		t.Fatal("unknown mission update succeeded")
	} else {
		assertProblemCode(t, err, http.StatusForbidden, "invalid_mission")
	}
	malformedBody := []byte(`{"action":"completion","description":"wrong action"}`)
	malformedRequest := httptest.NewRequest(http.MethodPost, "https://ps.example/mission/"+mission.Reference.S256, bytes.NewReader(malformedBody))
	malformedRequest.Host = "ps.example"
	malformedRequest.RequestURI = ""
	if err := signaturekey.SignJWTRequestWithOptions(malformedRequest, agentKey, agentToken, clock, signaturekey.SignOptions{Nonce: "malformed-mission-update"}); err != nil {
		t.Fatal(err)
	}
	malformedResponse, err := client.Do(malformedRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer malformedResponse.Body.Close()
	if malformedResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed mission update status = %d", malformedResponse.StatusCode)
	}
	malformedProblem, err := aauth.DecodeProblemResponse(malformedResponse)
	if err != nil {
		t.Fatal(err)
	}
	if malformedProblem.Code != "invalid_request" {
		t.Fatalf("malformed mission update problem = %#v", malformedProblem)
	}
	queryRequest := httptest.NewRequest(http.MethodPost, "https://ps.example/mission/"+mission.Reference.S256+"?unexpected=1", bytes.NewReader([]byte(`{"action":"update","description":"query must be refused"}`)))
	queryRequest.Host = "ps.example"
	queryRequest.RequestURI = ""
	if err := signaturekey.SignJWTRequestWithOptions(queryRequest, agentKey, agentToken, clock, signaturekey.SignOptions{Nonce: "query-mission-update"}); err != nil {
		t.Fatal(err)
	}
	queryResponse, err := client.Do(queryRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer queryResponse.Body.Close()
	if queryResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("query mission update status = %d", queryResponse.StatusCode)
	}
	queryProblem, err := aauth.DecodeProblemResponse(queryResponse)
	if err != nil || queryProblem.Code != "invalid_request" {
		t.Fatalf("query mission update problem = %#v, err=%v", queryProblem, err)
	}
	if _, err := otherAgent.UpdateMission(context.Background(), "https://ps.example/mission", mission.Reference, "an unauthorized update"); err == nil {
		t.Fatal("non-owner mission update succeeded")
	} else {
		assertProblemCode(t, err, http.StatusForbidden, "invalid_mission")
	}
	denyUpdate = true
	if _, err := agent.UpdateMission(context.Background(), "https://ps.example/mission", mission.Reference, "a refused update"); err == nil {
		t.Fatal("policy-refused mission update succeeded")
	} else {
		assertProblemCode(t, err, http.StatusForbidden, "mission_denied")
	}
	denyUpdate = false
	unchanged, err := personServer.MissionSnapshot(mission.Reference)
	if err != nil || len(unchanged.Log) != 1 {
		t.Fatalf("policy refusal changed mission log = %#v, err=%v", unchanged.Log, err)
	}

	personServer = newPersonServer()
	personHandler = personServer.Handler()
	restartedSnapshot, err := personServer.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatalf("mission after restart: %v", err)
	}
	if len(restartedSnapshot.Log) != 1 {
		t.Fatalf("mission log after restart = %#v", restartedSnapshot.Log)
	}
	replayRequest := capturedRequest.Clone(context.Background())
	replayRequest.RequestURI = ""
	replayRequest.Body = io.NopCloser(bytes.NewReader(capturedBody))
	replayResponse, err := (&http.Client{Transport: capture.base}).Do(replayRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer replayResponse.Body.Close()
	if replayResponse.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(replayResponse.Body)
		t.Fatalf("replayed mission update status = %d body=%s", replayResponse.StatusCode, body)
	}
	var replayResult aauth.MissionUpdateResult
	if err := json.NewDecoder(replayResponse.Body).Decode(&replayResult); err != nil {
		t.Fatal(err)
	}
	if replayResult.S256 != result.S256 {
		t.Fatalf("replayed mission update = %#v, want %#v", replayResult, result)
	}
	replayedSnapshot, err := personServer.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if len(replayedSnapshot.Log) != 1 {
		t.Fatalf("replayed mission update log = %#v", replayedSnapshot.Log)
	}
	if len(updateEvaluations) != 2 {
		t.Fatalf("replayed mission update reran policy: %#v", updateEvaluations)
	}

	if err := personServer.TerminateMission(mission.Reference); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.UpdateMission(context.Background(), "https://ps.example/mission", mission.Reference, "after termination"); err == nil {
		t.Fatal("terminated mission update succeeded")
	} else {
		assertProblemCode(t, err, http.StatusForbidden, "mission_terminated")
	}
}

type missionUpdateCaptureTransport struct {
	base    http.RoundTripper
	request *http.Request
	body    []byte
}

func (transport *missionUpdateCaptureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	transport.body = append([]byte(nil), body...)
	transport.request = request.Clone(request.Context())
	transport.request.Body = io.NopCloser(bytes.NewReader(body))
	return transport.base.RoundTrip(request)
}
