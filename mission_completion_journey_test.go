package aauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestMissionCompletionClarificationAndAcceptanceSurviveRestart(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	agentKey := testSigningKey(t, "agent-key")
	otherAgentKey := testSigningKey(t, "other-agent-key")
	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: apKey,
		Clock:      clock,
		NewID:      sequentialIDs("agent-token", "other-agent-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:operator@ap.example",
		PersonServer: "https://ps.example",
		PublicKey:    agentKey.PublicJWK(),
		Lifetime:     2 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherAgentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:other@ap.example",
		PersonServer: "https://ps.example",
		PublicKey:    otherAgentKey.PublicJWK(),
		Lifetime:     2 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{}
	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: client,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasPrefix(endpoint, "https://ap.example/") ||
				strings.HasPrefix(endpoint, "https://ps.example/") {
				return nil
			}
			return fmt.Errorf("endpoint outside trust boundary: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(t.TempDir(), "person-governance.json")
	fileStore, err := reference.NewFileGovernanceStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	store := &toggleGovernanceStore{inner: fileStore}
	config := reference.PersonServerConfig{
		AuthorizationStore:      testAuthorizationStateStore(t),
		Identifier:              "https://ps.example",
		SigningKey:              psKey,
		KeyResolver:             resolver,
		Clock:                   clock,
		NewID:                   sequentialIDs(),
		GovernanceStore:         store,
		CompletionReviewEnabled: true,
		PersonTokenStore:        testPersonTokenStore(t),
		MissionIssuanceStore:    testMissionIssuanceStore(t),
		PersonTokenPolicy:       testPersonTokenPolicy,
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			proposal := evaluation.Proposal
			return aauth.MissionDecision{Description: proposal.Description}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: "unused", Scope: request.Scope}, nil
		},
	}
	newPersonServer := func() *reference.PersonServer {
		t.Helper()
		server, err := reference.NewPersonServer(config)
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
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:operator@ap.example",
		SigningKey:         agentKey,
		AgentToken:         agentToken,
		KeyResolver:        resolver,
		HTTPClient:         client,
		Clock:              clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherAgent, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:other@ap.example",
		SigningKey:         otherAgentKey,
		AgentToken:         otherAgentToken,
		KeyResolver:        resolver,
		HTTPClient:         client,
		Clock:              clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	mission, err := agent.CreateMission(
		context.Background(),
		"https://ps.example/mission",
		aauth.MissionProposal{Description: "Prepare a reviewed, recoverable change."},
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := agent.ProposeMissionCompletion(
		context.Background(),
		"https://ps.example/interaction",
		mission.Reference,
		"Implemented, tested, and checkpointed the change.",
	)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Pending == nil ||
		authorization.Pending.Requirement == nil ||
		authorization.Pending.Requirement.Type != aauth.RequirementApproval {
		t.Fatalf("completion proposal = %#v", authorization)
	}
	pending := authorization.Pending
	history := personServer.InteractionHistory()
	if len(history) != 1 ||
		history[0].PendingID != pending.ID ||
		history[0].Proof == nil ||
		len(history[0].Response) != 0 {
		t.Fatalf("interaction history = %#v", history)
	}

	personServer = newPersonServer()
	personHandler = personServer.Handler()
	if _, err := otherAgent.PollInteraction(context.Background(), pending); err == nil {
		t.Fatal("another agent polled the completion review")
	} else {
		assertProblemCode(t, err, http.StatusForbidden, "invalid_pending")
	}
	waiting, err := agent.PollInteraction(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if waiting.Pending == nil ||
		waiting.Pending.Requirement == nil ||
		waiting.Pending.Requirement.Type != aauth.RequirementApproval {
		t.Fatalf("restored completion review = %#v", waiting)
	}

	if err := personServer.RequestCompletionClarification(
		pending.ID,
		"Did the external notification reach its recipient?",
		"operator",
	); err != nil {
		t.Fatal(err)
	}
	clarification, err := agent.PollInteraction(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if clarification.Pending == nil ||
		clarification.Pending.Requirement == nil ||
		clarification.Pending.Requirement.Type != aauth.RequirementClarification ||
		clarification.Pending.Clarification != "Did the external notification reach its recipient?" {
		t.Fatalf("completion clarification = %#v", clarification)
	}
	if err := otherAgent.RespondToClarification(
		context.Background(),
		pending,
		"Yes.",
	); err == nil {
		t.Fatal("another agent answered the completion clarification")
	} else {
		assertProblemCode(t, err, http.StatusForbidden, "invalid_pending")
	}
	replayedClarification := *pending
	if err := agent.RespondToClarification(
		context.Background(),
		pending,
		"Yes. The provider returned its durable receipt.",
	); err != nil {
		t.Fatal(err)
	}
	if err := agent.RespondToClarification(
		context.Background(),
		&replayedClarification,
		"Yes. The provider returned its durable receipt.",
	); err == nil {
		t.Fatal("exact clarification proof replay succeeded")
	} else {
		assertProblemCode(t, err, http.StatusConflict, "invalid_request")
	}

	personServer = newPersonServer()
	personHandler = personServer.Handler()
	store.setFail(true)
	if err := personServer.AcceptCompletion(pending.ID, "operator"); err == nil {
		t.Fatal("completion acceptance succeeded without durable custody")
	}
	store.setFail(false)
	active, err := personServer.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if active.Status != aauth.MissionActive {
		t.Fatalf("failed completion acceptance changed mission to %s", active.Status)
	}
	if err := personServer.AcceptCompletion(pending.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	completed, err := personServer.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	wantKinds := []aauth.MissionLogKind{
		aauth.MissionLogInteractionRequest,
		aauth.MissionLogClarification,
		aauth.MissionLogClarification,
		aauth.MissionLogInteractionResponse,
		aauth.MissionLogTermination,
	}
	if completed.Status != aauth.MissionTerminated ||
		len(completed.Log) != len(wantKinds) {
		t.Fatalf("completed mission = %#v", completed)
	}
	for index, want := range wantKinds {
		if completed.Log[index].Kind != want {
			t.Fatalf("mission log %d kind = %s, want %s", index, completed.Log[index].Kind, want)
		}
	}
	terminal, err := agent.PollInteraction(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if !terminal.Completed || terminal.Pending != nil {
		t.Fatalf("completion terminal response = %#v", terminal)
	}

	personServer = newPersonServer()
	personHandler = personServer.Handler()
	if _, err := agent.PollInteraction(context.Background(), pending); err == nil {
		t.Fatal("served completion continuation revived after restart")
	} else {
		assertProblemCode(t, err, http.StatusGone, "gone")
	}
	history = personServer.InteractionHistory()
	if len(history) != 1 ||
		history[0].DecidedBy != "operator" ||
		len(history[0].Response) == 0 {
		t.Fatalf("terminal interaction history = %#v", history)
	}
	history[0].Response[0] ^= 1
	history[0].Proof.Signature = "mutated"
	history = personServer.InteractionHistory()
	if history[0].Response[0] != '{' || history[0].Proof.Signature == "mutated" {
		t.Fatal("interaction history exposed mutable governance custody")
	}

	now = now.Add(time.Second)
	lostResponseMission, err := agent.CreateMission(
		context.Background(),
		"https://ps.example/mission",
		aauth.MissionProposal{Description: "Measure lost completion-response behavior."},
	)
	if err != nil {
		t.Fatal(err)
	}
	lostResponse, err := agent.ProposeMissionCompletion(
		context.Background(),
		"https://ps.example/interaction",
		lostResponseMission.Reference,
		"Ready for a completion response that the transport will drop.",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := personServer.AcceptCompletion(lostResponse.Pending.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	baseTransport := client.Transport
	client.Transport = &dropFirstResponseTransport{
		base:   baseTransport,
		target: "/interaction/pending/" + lostResponse.Pending.ID,
	}
	if _, err := agent.PollInteraction(context.Background(), lostResponse.Pending); err == nil {
		t.Fatal("lost completion response was reported as delivered")
	}
	client.Transport = baseTransport
	if _, err := agent.PollInteraction(context.Background(), lostResponse.Pending); err == nil {
		t.Fatal("completion response remained recoverable after transport loss")
	} else {
		assertProblemCode(t, err, http.StatusGone, "gone")
	}

	now = now.Add(time.Second)
	expiringMission, err := agent.CreateMission(
		context.Background(),
		"https://ps.example/mission",
		aauth.MissionProposal{Description: "Expire a completion review without terminating its mission."},
	)
	if err != nil {
		t.Fatal(err)
	}
	expiring, err := agent.ProposeMissionCompletion(
		context.Background(),
		"https://ps.example/interaction",
		expiringMission.Reference,
		"Ready for review, but no decision arrived.",
	)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Minute)
	if err := personServer.AcceptCompletion(
		expiring.Pending.ID,
		"operator",
	); !errors.Is(err, reference.ErrCompletionExpired) {
		t.Fatalf("accept expired completion error = %v", err)
	}
	if _, err := agent.PollInteraction(context.Background(), expiring.Pending); err == nil {
		t.Fatal("expired completion review remained pending")
	} else {
		assertProblemCode(t, err, http.StatusRequestTimeout, "expired")
	}
	expiredMission, err := personServer.MissionSnapshot(expiringMission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if expiredMission.Status != aauth.MissionActive ||
		len(expiredMission.Log) != 2 ||
		expiredMission.Log[1].Kind != aauth.MissionLogInteractionResponse {
		t.Fatalf("expired completion mission = %#v", expiredMission)
	}
	personServer = newPersonServer()
	personHandler = personServer.Handler()
	if _, err := agent.PollInteraction(context.Background(), expiring.Pending); err == nil {
		t.Fatal("expired completion continuation revived after restart")
	} else {
		assertProblemCode(t, err, http.StatusGone, "gone")
	}

	now = now.Add(time.Second)
	expiringClarificationMission, err := agent.CreateMission(
		context.Background(),
		"https://ps.example/mission",
		aauth.MissionProposal{Description: "Reject a clarification submitted after review expiry."},
	)
	if err != nil {
		t.Fatal(err)
	}
	expiringClarification, err := agent.ProposeMissionCompletion(
		context.Background(),
		"https://ps.example/interaction",
		expiringClarificationMission.Reference,
		"Ready for clarification within a bounded review window.",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := personServer.RequestCompletionClarification(
		expiringClarification.Pending.ID,
		"Can you provide the final receipt?",
		"operator",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.PollInteraction(
		context.Background(),
		expiringClarification.Pending,
	); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Minute)
	if err := agent.RespondToClarification(
		context.Background(),
		expiringClarification.Pending,
		"Here is the receipt.",
	); err == nil {
		t.Fatal("clarification response succeeded after completion review expiry")
	} else {
		assertProblemCode(t, err, http.StatusRequestTimeout, "expired")
	}
	expiredClarificationMission, err := personServer.MissionSnapshot(
		expiringClarificationMission.Reference,
	)
	if err != nil {
		t.Fatal(err)
	}
	if expiredClarificationMission.Status != aauth.MissionActive ||
		len(expiredClarificationMission.Log) != 3 ||
		expiredClarificationMission.Log[2].Kind != aauth.MissionLogInteractionResponse {
		t.Fatalf("expired clarification mission = %#v", expiredClarificationMission)
	}

	now = now.Add(time.Second)
	rollbackMission, err := agent.CreateMission(
		context.Background(),
		"https://ps.example/mission",
		aauth.MissionProposal{Description: "Roll completion changes back on definite storage failure."},
	)
	if err != nil {
		t.Fatal(err)
	}
	store.setFail(true)
	if _, err := agent.ProposeMissionCompletion(
		context.Background(),
		"https://ps.example/interaction",
		rollbackMission.Reference,
		"Retry this exact proposal after durable storage recovers.",
	); err == nil {
		t.Fatal("completion proposal succeeded without durable custody")
	} else {
		assertProblemCode(t, err, http.StatusInternalServerError, "server_error")
	}
	store.setFail(false)
	rollbackReview, err := agent.ProposeMissionCompletion(
		context.Background(),
		"https://ps.example/interaction",
		rollbackMission.Reference,
		"Retry this exact proposal after durable storage recovers.",
	)
	if err != nil {
		t.Fatal(err)
	}
	store.setFail(true)
	if err := personServer.RequestCompletionClarification(
		rollbackReview.Pending.ID,
		"Can this host decision survive a failed save?",
		"operator",
	); err == nil {
		t.Fatal("completion clarification succeeded without durable custody")
	}
	store.setFail(false)
	stillWaiting, err := agent.PollInteraction(context.Background(), rollbackReview.Pending)
	if err != nil {
		t.Fatal(err)
	}
	if stillWaiting.Pending == nil ||
		stillWaiting.Pending.Requirement == nil ||
		stillWaiting.Pending.Requirement.Type != aauth.RequirementApproval {
		t.Fatalf("failed clarification changed pending state = %#v", stillWaiting)
	}
	if err := personServer.RequestCompletionClarification(
		rollbackReview.Pending.ID,
		"Can this host decision survive a failed save?",
		"operator",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.PollInteraction(
		context.Background(),
		rollbackReview.Pending,
	); err != nil {
		t.Fatal(err)
	}
	store.setFail(true)
	if err := agent.RespondToClarification(
		context.Background(),
		rollbackReview.Pending,
		"Yes. The retry observes the original clarification state.",
	); err == nil {
		t.Fatal("clarification answer succeeded without durable custody")
	} else {
		assertProblemCode(t, err, http.StatusInternalServerError, "server_error")
	}
	store.setFail(false)
	if err := agent.RespondToClarification(
		context.Background(),
		rollbackReview.Pending,
		"Yes. The retry observes the original clarification state.",
	); err != nil {
		t.Fatal(err)
	}
	store.setUncertain(true)
	if err := personServer.AcceptCompletion(
		rollbackReview.Pending.ID,
		"operator",
	); !errors.Is(err, reference.ErrGovernanceStateUncertain) {
		t.Fatalf("uncertain completion acceptance error = %v", err)
	}
	store.setUncertain(false)
	personServer = newPersonServer()
	personHandler = personServer.Handler()
	uncertainTerminal, err := agent.PollInteraction(
		context.Background(),
		rollbackReview.Pending,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !uncertainTerminal.Completed {
		t.Fatalf("uncertain published completion = %#v", uncertainTerminal)
	}

	now = now.Add(time.Second)
	roundLimitMission, err := agent.CreateMission(
		context.Background(),
		"https://ps.example/mission",
		aauth.MissionProposal{Description: "Bound completion clarification rounds."},
	)
	if err != nil {
		t.Fatal(err)
	}
	roundLimit, err := agent.ProposeMissionCompletion(
		context.Background(),
		"https://ps.example/interaction",
		roundLimitMission.Reference,
		"Ready for bounded clarification review.",
	)
	if err != nil {
		t.Fatal(err)
	}
	for round := 1; round <= 5; round++ {
		if err := personServer.RequestCompletionClarification(
			roundLimit.Pending.ID,
			fmt.Sprintf("Clarification round %d?", round),
			"operator",
		); err != nil {
			t.Fatal(err)
		}
		clarification, err := agent.PollInteraction(context.Background(), roundLimit.Pending)
		if err != nil {
			t.Fatal(err)
		}
		if clarification.Pending == nil ||
			clarification.Pending.Requirement == nil ||
			clarification.Pending.Requirement.Type != aauth.RequirementClarification {
			t.Fatalf("clarification round %d = %#v", round, clarification)
		}
		if err := agent.RespondToClarification(
			context.Background(),
			roundLimit.Pending,
			fmt.Sprintf("Clarification answer %d.", round),
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := personServer.RequestCompletionClarification(
		roundLimit.Pending.ID,
		"Unbounded clarification?",
		"operator",
	); err == nil || !strings.Contains(err.Error(), "round limit") {
		t.Fatalf("sixth clarification request error = %v", err)
	}

	validState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	semanticallyCorruptGovernanceInteractionLink(t, statePath, validState)
	if _, err := reference.NewPersonServer(config); err == nil {
		t.Fatal("person server accepted semantically inconsistent completion custody")
	}
}

func semanticallyCorruptGovernanceInteractionLink(
	t *testing.T,
	path string,
	envelopeBody []byte,
) {
	t.Helper()
	var envelope struct {
		Schema      string          `json:"schema"`
		StateSHA256 string          `json:"state_sha256"`
		State       json.RawMessage `json:"state"`
	}
	if err := json.Unmarshal(envelopeBody, &envelope); err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(envelope.State, &state); err != nil {
		t.Fatal(err)
	}
	interactions, ok := state["interactions"].([]any)
	if !ok || len(interactions) == 0 {
		t.Fatal("valid governance fixture has no interaction records")
	}
	first, ok := interactions[0].(map[string]any)
	if !ok {
		t.Fatal("valid governance interaction record has the wrong shape")
	}
	first["pending_id"] = "AAAAAAAAAAAAAAAAAAAAAA"
	stateBody, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(stateBody)
	envelope.State = stateBody
	envelope.StateSHA256 = hex.EncodeToString(digest[:])
	corruptBody, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, corruptBody, 0o600); err != nil {
		t.Fatal(err)
	}
}
