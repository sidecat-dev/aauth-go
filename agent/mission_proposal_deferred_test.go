package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
)

func TestClientBeginMissionReturnsVerifiedPendingProposal(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	const missionEndpoint = "https://ps.example/mission"
	const pendingLocation = "https://ps.example/mission/pending/proposal-1"
	posts := 0
	polls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json":
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.personServerID, "jwks_uri": protocol.personServerID + "/.well-known/jwks.json", "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint, "mission_endpoint": missionEndpoint,
			}), nil
		case request.Method == http.MethodPost && request.URL.String() == missionEndpoint:
			posts++
			if request.Header.Get("Prefer") != "wait=0" {
				t.Fatalf("mission proposal Prefer = %q, want wait=0", request.Header.Get("Prefer"))
			}
			verified := verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
			claims, err := verified.AgentClaims()
			if err != nil || claims.Subject != protocol.agentID {
				t.Fatalf("mission Agent = %#v, %v", claims, err)
			}
			response := jsonResponse(request, http.StatusAccepted, map[string]string{"status": "pending"})
			response.Header.Set("Location", pendingLocation)
			response.Header.Set("Retry-After", "7")
			response.Header.Set("Cache-Control", "no-store")
			return response, nil
		case request.Method == http.MethodGet && request.URL.String() == pendingLocation:
			polls++
			return nil, errors.New("BeginMission must not poll")
		default:
			return nil, errors.New("unexpected request: " + request.Method + " " + request.URL.String())
		}
	})})

	result, err := client.BeginMission(context.Background(), agent.MissionRequest{
		PersonServer: protocol.personServerID,
		Proposal: aauth.MissionProposal{
			Description: "Read the records needed for the report.",
			Resources:   []string{protocol.resourceID},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if approval, ok := result.Approval(); ok || approval.Mission().S256 != "" {
		t.Fatalf("pending mission proposal unexpectedly returned approval %#v", approval)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatalf("mission proposal result = %#v, want pending", result)
	}
	if pending.PersonServer() != protocol.personServerID || pending.Location() != pendingLocation || pending.RetryAfter() != 7*time.Second {
		t.Fatalf("pending mission proposal = %#v", pending)
	}
	_, err = client.ProposeMission(context.Background(), agent.MissionRequest{
		PersonServer: protocol.personServerID,
		Proposal: aauth.MissionProposal{
			Description: "Read the records needed for the report.", Resources: []string{protocol.resourceID},
		},
	})
	var pendingFailure *agent.MissionProposalPendingError
	if !errors.As(err, &pendingFailure) || pendingFailure.Pending().Location() != pendingLocation {
		t.Fatalf("ProposeMission pending error = %T %v", err, err)
	}
	if posts != 2 || polls != 0 {
		t.Fatalf("proposal calls = posts %d, polls %d; want two explicit POSTs and no polling", posts, polls)
	}
}

func TestPendingMissionProposalSnapshotRestoresWithSameAgentAndKey(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	const missionEndpoint = "https://ps.example/mission"
	const pendingLocation = "https://ps.example/mission/pending/proposal-1"
	proposal := aauth.MissionProposal{
		Description: "Read the records needed for the report.",
		Resources:   []string{protocol.resourceID},
	}
	mission := mustEncodeMission(t, aauth.MissionBlob{
		Agent: protocol.agentID, ApprovedAt: protocol.now,
		Description: proposal.Description, ApprovedResources: []string{protocol.resourceID},
	})
	httpClient := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json":
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.personServerID, "jwks_uri": protocol.personServerID + "/.well-known/jwks.json", "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint, "mission_endpoint": missionEndpoint,
			}), nil
		case request.Method == http.MethodPost && request.URL.String() == missionEndpoint:
			response := jsonResponse(request, http.StatusAccepted, map[string]string{"status": "pending"})
			response.Header.Set("Location", pendingLocation)
			response.Header.Set("Retry-After", "3")
			response.Header.Set("Cache-Control", "no-store")
			return response, nil
		case request.Method == http.MethodGet && request.URL.String() == pendingLocation:
			return jsonResponse(request, http.StatusOK, aauth.MissionApproval{
				S256: mission.S256, Mission: mission.Encoded,
			}), nil
		default:
			return nil, errors.New("unexpected request: " + request.Method + " " + request.URL.String())
		}
	})}

	started, err := protocol.newClientWithHTTPClient(t, httpClient).BeginMission(context.Background(), agent.MissionRequest{
		PersonServer: protocol.personServerID, Proposal: proposal,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := started.Pending()
	if !ok {
		t.Fatalf("mission proposal result = %#v, want pending", started)
	}
	snapshot, err := pending.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var stored agent.PendingMissionProposalSnapshot
	if err := json.Unmarshal(encoded, &stored); err != nil {
		t.Fatal(err)
	}
	restoredClient := protocol.newClientWithHTTPClient(t, httpClient)
	restored, err := restoredClient.RestorePendingMissionProposal(context.Background(), stored)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := restoredClient.PollMissionProposal(context.Background(), restored)
	if err != nil {
		t.Fatal(err)
	}
	approval, ok := completed.Approval()
	if !ok || approval.Mission().S256 != mission.S256 {
		t.Fatalf("restored mission proposal = %#v, want approval %s", completed, mission.S256)
	}
}

func TestClientProposeMissionReportsUncertainSubmission(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.personServerID, "jwks_uri": protocol.personServerID + "/.well-known/jwks.json", "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint,
				"mission_endpoint":    protocol.personServerID + "/mission",
			}), nil
		}
		return nil, errors.New("connection reset after write")
	})})

	_, err := client.BeginMission(context.Background(), agent.MissionRequest{
		PersonServer: protocol.personServerID,
		Proposal:     aauth.MissionProposal{Description: "Read records"},
	})
	var uncertain *agent.MissionProposalSubmissionUncertainError
	if !errors.As(err, &uncertain) || !strings.Contains(err.Error(), "connection reset after write") {
		t.Fatalf("mission proposal error = %v, want uncertain submission", err)
	}
}

func TestClientProposeMissionTreatsServerFailureAsUncertain(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.personServerID, "jwks_uri": protocol.personServerID + "/.well-known/jwks.json", "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint,
				"mission_endpoint":    protocol.personServerID + "/mission",
			}), nil
		}
		return problemResponse(request, &aauth.ProblemError{
			Status: http.StatusInternalServerError, Code: "server_error", Detail: "retention outcome unavailable",
		}), nil
	})})
	_, err := client.BeginMission(context.Background(), agent.MissionRequest{
		PersonServer: protocol.personServerID,
		Proposal:     aauth.MissionProposal{Description: "Read records"},
	})
	var uncertain *agent.MissionProposalSubmissionUncertainError
	if !errors.As(err, &uncertain) {
		t.Fatalf("mission proposal error = %v, want uncertain submission", err)
	}
}

func TestClientPollMissionProposalReportsUncertainTerminalDelivery(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	const pendingLocation = "https://ps.example/mission/pending/proposal-1"
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json":
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.personServerID, "jwks_uri": protocol.personServerID + "/.well-known/jwks.json", "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint,
				"mission_endpoint":    protocol.personServerID + "/mission",
			}), nil
		case request.Method == http.MethodPost:
			response := jsonResponse(request, http.StatusAccepted, map[string]string{"status": "pending"})
			response.Header.Set("Location", pendingLocation)
			response.Header.Set("Retry-After", "0")
			response.Header.Set("Cache-Control", "no-store")
			return response, nil
		case request.Method == http.MethodGet && request.URL.String() == pendingLocation:
			return nil, errors.New("connection reset after terminal response")
		default:
			return nil, errors.New("unexpected request")
		}
	})})
	started, err := client.BeginMission(context.Background(), agent.MissionRequest{
		PersonServer: protocol.personServerID,
		Proposal:     aauth.MissionProposal{Description: "Read records"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := started.Pending()
	if !ok {
		t.Fatalf("mission proposal = %#v, want pending", started)
	}
	_, err = client.PollMissionProposal(context.Background(), pending)
	var uncertain *agent.MissionProposalPollUncertainError
	if !errors.As(err, &uncertain) ||
		!strings.Contains(err.Error(), "connection reset after terminal response") {
		t.Fatalf("mission proposal poll error = %v, want uncertain terminal delivery", err)
	}
}

func TestClientPollMissionProposalReturnsTypedTerminalProblems(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		status int
		code   aauth.ErrorCode
	}{
		{status: http.StatusForbidden, code: "denied"},
		{status: http.StatusRequestTimeout, code: "expired"},
		{status: http.StatusGone, code: "invalid_code"},
		{status: http.StatusInternalServerError, code: "server_error"},
	} {
		test := test
		t.Run(string(test.code), func(t *testing.T) {
			t.Parallel()
			protocol := newTestProtocol(t)
			const pendingLocation = "https://ps.example/mission/pending/proposal-1"
			polls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				switch {
				case request.Method == http.MethodGet && request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json":
					return jsonResponse(request, http.StatusOK, map[string]any{
						"issuer": protocol.personServerID, "jwks_uri": protocol.personServerID + "/.well-known/jwks.json", "person_token_endpoint": protocol.personTokenEndpoint,
						"auth_token_endpoint": protocol.authTokenEndpoint,
						"mission_endpoint":    protocol.personServerID + "/mission",
					}), nil
				case request.Method == http.MethodPost:
					response := jsonResponse(request, http.StatusAccepted, map[string]string{"status": "pending"})
					response.Header.Set("Location", pendingLocation)
					response.Header.Set("Retry-After", "0")
					response.Header.Set("Cache-Control", "no-store")
					return response, nil
				case request.Method == http.MethodGet && request.URL.String() == pendingLocation:
					polls++
					return problemResponse(request, &aauth.ProblemError{Status: test.status, Code: test.code, Detail: "terminal"}), nil
				default:
					return nil, errors.New("unexpected request")
				}
			})})
			started, err := client.BeginMission(context.Background(), agent.MissionRequest{
				PersonServer: protocol.personServerID,
				Proposal:     aauth.MissionProposal{Description: "Read records"},
			})
			if err != nil {
				t.Fatal(err)
			}
			pending, _ := started.Pending()
			_, err = client.PollMissionProposal(context.Background(), pending)
			if test.status >= http.StatusInternalServerError {
				var uncertain *agent.MissionProposalPollUncertainError
				if !errors.As(err, &uncertain) || polls != 1 {
					t.Fatalf("terminal mission proposal error = %v, polls=%d, want uncertain", err, polls)
				}
				return
			}
			var problem *aauth.ProblemError
			if !errors.As(err, &problem) || problem.Status != test.status || problem.Code != test.code || polls != 1 {
				t.Fatalf("terminal mission proposal = %#v, %v, polls=%d", problem, err, polls)
			}
		})
	}
}

func TestClientProposeMissionDoesNotHideUnsupportedDeferredRequirement(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.personServerID, "jwks_uri": protocol.personServerID + "/.well-known/jwks.json", "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint,
				"mission_endpoint":    protocol.personServerID + "/mission",
			}), nil
		}
		response := jsonResponse(request, http.StatusAccepted, map[string]any{
			"status": "pending", "required_claims": []string{"email"},
		})
		response.Header.Set("Location", "/mission/pending/proposal-1")
		response.Header.Set("Retry-After", "0")
		response.Header.Set("Cache-Control", "no-store")
		response.Header.Set("AAuth-Requirement", "requirement=claims")
		return response, nil
	})})
	_, err := client.BeginMission(context.Background(), agent.MissionRequest{
		PersonServer: protocol.personServerID,
		Proposal:     aauth.MissionProposal{Description: "Read records"},
	})
	var unsupported *agent.UnsupportedRequirementError
	if !errors.As(err, &unsupported) || unsupported.Requirement != aauth.RequirementClaims {
		t.Fatalf("error = %v, want the unsupported claims requirement", err)
	}
}

// Mission review may run a clarification chat with the Agent and send the
// person to an interaction (Core, Mission Creation). The pending proposal
// carries both; the Agent answers on the pending URL and may withdraw it.
func TestClientMissionProposalCarriesClarificationAndInteraction(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	const pendingLocation = "https://ps.example/mission/pending/proposal-1"
	var actions []string
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/.well-known/aauth-person.json":
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.personServerID, "jwks_uri": protocol.personServerID + "/.well-known/jwks.json", "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint,
				"mission_endpoint":    protocol.personServerID + "/mission",
			}), nil
		case request.Method == http.MethodPost && request.URL.String() == protocol.personServerID+"/mission":
			response := jsonResponse(request, http.StatusAccepted, map[string]any{
				"status": "pending", "clarification": "Which dates?",
			})
			response.Header.Set("Location", pendingLocation)
			response.Header.Set("Retry-After", "0")
			response.Header.Set("Cache-Control", "no-store")
			response.Header.Set("AAuth-Requirement", "requirement=clarification")
			return response, nil
		case request.URL.String() == pendingLocation:
			actions = append(actions, request.Method)
			switch request.Method {
			case http.MethodPost:
				verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType,
					[]string{"content-type", "content-digest"})
				var body struct {
					Action                string `json:"action"`
					ClarificationResponse string `json:"clarification_response"`
				}
				decodeRequest(t, request, &body)
				if body.Action != "clarification_response" || body.ClarificationResponse != "7-14 May" {
					t.Fatalf("answer = %#v", body)
				}
				return &http.Response{StatusCode: http.StatusNoContent, Request: request, Header: make(http.Header), Body: http.NoBody}, nil
			case http.MethodGet:
				verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
				requirement, err := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{
					URL: "https://ps.example/review", Code: "ABCD-EFGH",
				})
				if err != nil {
					t.Fatal(err)
				}
				response := jsonResponse(request, http.StatusAccepted, map[string]string{"status": "pending"})
				response.Header.Set("Location", pendingLocation)
				response.Header.Set("Retry-After", "1")
				response.Header.Set("Cache-Control", "no-store")
				response.Header.Set("AAuth-Requirement", requirement)
				return response, nil
			case http.MethodDelete:
				verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
				return &http.Response{StatusCode: http.StatusNoContent, Request: request, Header: make(http.Header), Body: http.NoBody}, nil
			}
		}
		return nil, errors.New("unexpected mission request: " + request.Method + " " + request.URL.String())
	})})
	started, err := client.BeginMission(context.Background(), agent.MissionRequest{
		PersonServer: protocol.personServerID,
		Proposal:     aauth.MissionProposal{Description: "Plan the trip"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, _ := started.Pending()
	if question, ok := pending.Clarification(); !ok || question.Question() != "Which dates?" ||
		pending.Requirement() != aauth.RequirementClarification {
		t.Fatalf("pending proposal = %#v", pending)
	}
	if err := client.AnswerMissionClarification(context.Background(), pending, "7-14 May"); err != nil {
		t.Fatal(err)
	}
	polled, err := client.PollMissionProposal(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	next, _ := polled.Pending()
	if _, asked := next.Clarification(); asked || next.Requirement() != aauth.RequirementInteraction ||
		next.InteractionURL() != "https://ps.example/review" || next.InteractionCode() != "ABCD-EFGH" ||
		next.RetryAfter() != time.Second {
		t.Fatalf("polled proposal = %#v", next)
	}
	if err := client.AnswerMissionClarification(context.Background(), next, "again"); err == nil {
		t.Fatal("answered a proposal that asked no question")
	}
	if err := client.CancelMissionProposal(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if strings.Join(actions, ",") != "POST,GET,DELETE" {
		t.Fatalf("pending URL requests = %v", actions)
	}
}

func TestClientPollMissionProposalReturnsVerifiedApproval(t *testing.T) {
	t.Parallel()

	protocol := newTestProtocol(t)
	const missionEndpoint = "https://ps.example/mission"
	const pendingLocation = "https://ps.example/mission/pending/proposal-1"
	proposal := aauth.MissionProposal{
		Description: "Read the records needed for the report.",
		Resources:   []string{protocol.resourceID},
	}
	expiresAt := protocol.now.Add(15 * time.Minute)
	mission := mustEncodeMission(t, aauth.MissionBlob{
		Agent: protocol.agentID, ApprovedAt: protocol.now,
		ExpiresAt: &expiresAt, Description: proposal.Description,
		ApprovedResources: []string{protocol.resourceID},
	})
	personToken, err := aauth.MintPersonToken(protocol.personServerKey, aauth.PersonTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		JTI:          "mission-person-token", IssuedAt: protocol.now.Unix(), ExpiresAt: expiresAt.Unix(),
		MissionS256: mission.S256,
	})
	if err != nil {
		t.Fatal(err)
	}
	polls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json":
			return jsonResponse(request, http.StatusOK, map[string]any{
				"issuer": protocol.personServerID, "jwks_uri": protocol.personServerID + "/.well-known/jwks.json", "person_token_endpoint": protocol.personTokenEndpoint,
				"auth_token_endpoint": protocol.authTokenEndpoint, "mission_endpoint": missionEndpoint,
			}), nil
		case request.Method == http.MethodPost && request.URL.String() == missionEndpoint:
			response := jsonResponse(request, http.StatusAccepted, map[string]string{"status": "pending"})
			response.Header.Set("Location", pendingLocation)
			response.Header.Set("Retry-After", "0")
			response.Header.Set("Cache-Control", "no-store")
			return response, nil
		case request.Method == http.MethodGet && request.URL.String() == pendingLocation:
			polls++
			verified := verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
			claims, err := verified.AgentClaims()
			if err != nil || claims.Subject != protocol.agentID {
				t.Fatalf("poll Agent = %#v, %v", claims, err)
			}
			return jsonResponse(request, http.StatusOK, aauth.MissionApproval{
				S256: mission.S256, Mission: mission.Encoded,
				Capabilities: []string{"interaction"},
				PersonTokens: map[string]string{protocol.resourceID: personToken},
			}), nil
		default:
			return nil, errors.New("unexpected request: " + request.Method + " " + request.URL.String())
		}
	})})

	started, err := client.BeginMission(context.Background(), agent.MissionRequest{
		PersonServer: protocol.personServerID, Proposal: proposal,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := started.Pending()
	if !ok {
		t.Fatalf("mission proposal result = %#v, want pending", started)
	}
	completed, err := client.PollMissionProposal(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	approval, ok := completed.Approval()
	if !ok || approval.Mission().S256 != mission.S256 {
		t.Fatalf("polled mission proposal = %#v, want approval %s", completed, mission.S256)
	}
	if token, ok := approval.PersonToken(protocol.resourceID); !ok || token != personToken {
		t.Fatalf("polled person token = %q, present=%t", token, ok)
	}
	if polls != 1 {
		t.Fatalf("poll calls = %d, want 1", polls)
	}
}

func TestClientPollMissionProposalReturnsUpdatedPendingWithoutLooping(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		retryAfter string
		want       time.Duration
	}{
		{name: "pending", status: http.StatusAccepted, retryAfter: "9", want: 9 * time.Second},
		{name: "rate limited", status: http.StatusTooManyRequests, want: 6 * time.Second},
		{name: "unavailable default", status: http.StatusServiceUnavailable, want: 5 * time.Second},
		{name: "unavailable", status: http.StatusServiceUnavailable, retryAfter: "11", want: 11 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			protocol := newTestProtocol(t)
			const pendingLocation = "https://ps.example/mission/pending/proposal-1"
			polls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				switch {
				case request.Method == http.MethodGet && request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json":
					return jsonResponse(request, http.StatusOK, map[string]any{
						"issuer": protocol.personServerID, "jwks_uri": protocol.personServerID + "/.well-known/jwks.json", "person_token_endpoint": protocol.personTokenEndpoint,
						"auth_token_endpoint": protocol.authTokenEndpoint,
						"mission_endpoint":    protocol.personServerID + "/mission",
					}), nil
				case request.Method == http.MethodPost:
					response := jsonResponse(request, http.StatusAccepted, map[string]string{"status": "pending"})
					response.Header.Set("Location", pendingLocation)
					response.Header.Set("Retry-After", "1")
					response.Header.Set("Cache-Control", "no-store")
					return response, nil
				case request.Method == http.MethodGet && request.URL.String() == pendingLocation:
					polls++
					response := jsonResponse(request, test.status, map[string]string{"status": "waiting-for-admin"})
					if test.status == http.StatusAccepted {
						response.Header.Set("Location", pendingLocation)
						response.Header.Set("Cache-Control", "no-store")
					}
					if test.retryAfter != "" {
						response.Header.Set("Retry-After", test.retryAfter)
					}
					return response, nil
				default:
					return nil, errors.New("unexpected request")
				}
			})})
			started, err := client.BeginMission(context.Background(), agent.MissionRequest{
				PersonServer: protocol.personServerID,
				Proposal:     aauth.MissionProposal{Description: "Read records"},
			})
			if err != nil {
				t.Fatal(err)
			}
			pending, _ := started.Pending()
			next, err := client.PollMissionProposal(context.Background(), pending)
			if err != nil {
				t.Fatal(err)
			}
			updated, ok := next.Pending()
			if !ok || updated.Location() != pendingLocation || updated.RetryAfter() != test.want || polls != 1 {
				t.Fatalf("updated pending mission proposal = %#v, polls=%d", updated, polls)
			}
		})
	}
}
