package aauth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestMissionPermissionAndAuditVertical(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 16, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs("agent-token", "other-agent-token")
	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	agentKey := testSigningKey(t, "agent-key")
	otherKey := testSigningKey(t, "other-agent-key")

	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: apKey,
		Clock:      clock,
		NewID:      ids,
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
	otherToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:other@ap.example",
		PersonServer: "https://ps.example",
		PublicKey:    otherKey.PublicJWK(),
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
			for _, allowed := range []string{
				"https://ap.example/",
				"https://ps.example/",
			} {
				if strings.HasPrefix(endpoint, allowed) {
					return nil
				}
			}
			return fmt.Errorf("endpoint outside trust boundary: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var policyCalls int
	var evaluated aauth.PermissionEvaluation
	ps, err := reference.NewPersonServer(reference.PersonServerConfig{
		AuthorizationStore:   testAuthorizationStateStore(t),
		Identifier:           "https://ps.example",
		SigningKey:           psKey,
		KeyResolver:          resolver,
		Clock:                clock,
		NewID:                ids,
		PersonTokenStore:     testPersonTokenStore(t),
		MissionIssuanceStore: testMissionIssuanceStore(t),
		PersonTokenPolicy:    testPersonTokenPolicy,
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			proposal := evaluation.Proposal
			return aauth.MissionDecision{
				Description: proposal.Description,
				Tools:       proposal.Tools,
			}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Subject: "unused", Scope: request.Scope}, nil
		},
		PermissionPolicy: func(_ context.Context, input aauth.PermissionEvaluation) (aauth.PermissionDecision, error) {
			policyCalls++
			evaluated = input
			switch input.Request.Action {
			case "filesystem.write":
				return aauth.PermissionDecision{
					Permission: aauth.PermissionGranted,
					DecidedBy:  "operator",
				}, nil
			case "message.send":
				return aauth.PermissionDecision{
					Permission: aauth.PermissionGranted,
					DecidedBy:  "operator",
				}, nil
			case "network.send":
				return aauth.PermissionDecision{
					Permission: aauth.PermissionDenied,
					Reason:     "network use was not approved",
					DecidedBy:  "operator",
				}, nil
			default:
				return aauth.PermissionDecision{}, errors.New("unexpected action")
			}
		},
		PermissionInteractionRequired: func(_ context.Context, input aauth.PermissionEvaluation) (bool, error) {
			return input.Request.Action == "message.send", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": ps.Handler(),
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
	other, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:other@ap.example",
		SigningKey:         otherKey,
		AgentToken:         otherToken,
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
		aauth.MissionProposal{
			Description: "Prepare a recoverable source change.",
			Tools: []aauth.Tool{{
				Name:        "filesystem.read",
				Description: "Read source files.",
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	permissionRequest := aauth.PermissionRequest{
		Action:      "filesystem.write",
		Description: "Write the reviewed source change.",
		Parameters: map[string]any{
			"path": "internal/change.go",
		},
		Mission: &mission.Reference,
	}
	permission, err := agent.RequestPermission(
		context.Background(),
		"https://ps.example/permission",
		permissionRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if permission.Decision == nil ||
		permission.Decision.Permission != aauth.PermissionGranted ||
		permission.Pending != nil {
		t.Fatalf("permission = %#v, want an immediate grant", permission)
	}
	if policyCalls != 1 ||
		evaluated.Agent != "aauth:operator@ap.example" ||
		evaluated.Mission == nil ||
		evaluated.Mission.Reference != mission.Reference ||
		string(evaluated.Mission.Bytes) != string(mission.Bytes) ||
		len(evaluated.Mission.ApprovedTools) != 1 ||
		evaluated.Mission.ApprovedTools[0].Name != "filesystem.read" ||
		len(evaluated.Mission.Log) != 0 {
		t.Fatalf("permission evaluation = %#v", evaluated)
	}

	now = now.Add(time.Second)
	err = agent.RecordAudit(
		context.Background(),
		"https://ps.example/audit",
		aauth.AuditRequest{
			Mission:     mission.Reference,
			Action:      "filesystem.write",
			Description: "Wrote the reviewed source change.",
			Parameters: map[string]any{
				"path": "internal/change.go",
			},
			Result: map[string]any{
				"status": "completed",
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := ps.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != aauth.MissionActive ||
		len(snapshot.Log) != 3 ||
		snapshot.Log[0].Sequence != 1 ||
		snapshot.Log[0].Kind != aauth.MissionLogPermissionRequest ||
		snapshot.Log[1].Sequence != 2 ||
		snapshot.Log[1].Kind != aauth.MissionLogPermissionDecision ||
		snapshot.Log[2].Sequence != 3 ||
		snapshot.Log[2].Kind != aauth.MissionLogAudit {
		t.Fatalf("mission snapshot = %#v", snapshot)
	}
	if !strings.Contains(string(snapshot.Log[0].Request), `"filesystem.write"`) ||
		!strings.Contains(string(snapshot.Log[1].Response), `"granted"`) ||
		!strings.Contains(string(snapshot.Log[2].Request), `"completed"`) {
		t.Fatalf("mission log did not retain permission/audit evidence: %#v", snapshot.Log)
	}
	for _, entry := range []aauth.MissionLogEntry{snapshot.Log[0], snapshot.Log[2]} {
		if entry.Proof == nil ||
			entry.Proof.Method != http.MethodPost ||
			entry.Proof.Authority != "ps.example" ||
			entry.Proof.SignatureInput == "" ||
			entry.Proof.Signature == "" ||
			entry.Proof.SignatureKey == "" ||
			entry.Proof.ContentDigest == "" ||
			entry.Proof.Agent != "aauth:operator@ap.example" ||
			entry.Proof.Created.IsZero() ||
			entry.Proof.VerifiedAt.IsZero() ||
			!entry.Proof.PublicKey.Equal(agentKey.PublicJWK()) {
			t.Fatalf("mission log request proof = %#v", entry.Proof)
		}
	}
	if snapshot.Log[0].Proof.Target != "/permission" ||
		snapshot.Log[2].Proof.Target != "/audit" {
		t.Fatalf("mission log proof targets = %q, %q", snapshot.Log[0].Proof.Target, snapshot.Log[2].Proof.Target)
	}

	snapshot.Bytes[0] ^= 1
	snapshot.Log[0].Request[0] ^= 1
	snapshot.Log[0].Proof.Signature = "mutated"
	unchanged, err := ps.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged.Bytes) != string(mission.Bytes) ||
		!strings.HasPrefix(string(unchanged.Log[0].Request), "{") ||
		unchanged.Log[0].Proof.Signature == "mutated" {
		t.Fatal("caller mutation changed retained mission custody")
	}

	now = now.Add(time.Second)
	deferred, err := agent.RequestPermission(
		context.Background(),
		"https://ps.example/permission",
		aauth.PermissionRequest{
			Action:      "message.send",
			Description: "Send the completed change summary.",
			Parameters: map[string]any{
				"channel": "project",
			},
			Mission: &mission.Reference,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if deferred.Decision != nil ||
		deferred.Pending == nil ||
		deferred.Pending.ID == "" ||
		deferred.Pending.Requirement == nil ||
		deferred.Pending.Requirement.Type != aauth.RequirementInteraction {
		t.Fatalf("deferred permission = %#v", deferred)
	}
	pending := deferred.Pending
	if err := ps.ApprovePermission(context.Background(), pending.ID); err == nil {
		t.Fatal("permission was approved before interaction correlation")
	}
	otherPending := *pending
	if _, err := other.PollPermission(context.Background(), &otherPending); err == nil {
		t.Fatal("another agent polled the permission continuation")
	}
	waiting, err := agent.PollPermission(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if waiting.Pending == nil || waiting.Pending.Status != "pending" {
		t.Fatalf("waiting permission = %#v", waiting)
	}
	interaction, err := client.Get(
		pending.Requirement.InteractionURL +
			"?code=" + strings.ToLower(pending.Requirement.InteractionCode),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer interaction.Body.Close()
	if interaction.StatusCode != http.StatusOK {
		t.Fatalf("permission interaction status = %d", interaction.StatusCode)
	}
	if err := ps.ApprovePermission(context.Background(), pending.ID); err != nil {
		t.Fatal(err)
	}
	if policyCalls != 2 {
		t.Fatalf("permission policy calls after deferred approval = %d", policyCalls)
	}
	approved, err := agent.PollPermission(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Pending != nil ||
		approved.Decision == nil ||
		approved.Decision.Permission != aauth.PermissionGranted {
		t.Fatalf("approved deferred permission = %#v", approved)
	}
	if _, err := agent.PollPermission(context.Background(), pending); err == nil {
		t.Fatal("terminal permission continuation remained reusable")
	}

	now = now.Add(time.Second)
	_, err = other.RequestPermission(
		context.Background(),
		"https://ps.example/permission",
		permissionRequest,
	)
	assertProblemCode(t, err, http.StatusForbidden, "invalid_mission")
	if policyCalls != 2 {
		t.Fatalf("permission policy ran for another agent's mission; calls = %d", policyCalls)
	}

	now = now.Add(time.Second)
	missionless, err := agent.RequestPermission(
		context.Background(),
		"https://ps.example/permission",
		aauth.PermissionRequest{
			Action:      "network.send",
			Description: "Send without a mission.",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if missionless.Decision == nil ||
		missionless.Decision.Permission != aauth.PermissionDenied ||
		missionless.Decision.Reason != "network use was not approved" {
		t.Fatalf("missionless permission = %#v", missionless)
	}
	unchanged, err = ps.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if len(unchanged.Log) != 5 {
		t.Fatalf("missionless permission entered mission log: %#v", unchanged.Log)
	}

	now = now.Add(time.Second)
	rejected, err := agent.RequestPermission(
		context.Background(),
		"https://ps.example/permission",
		aauth.PermissionRequest{
			Action:      "message.send",
			Description: "Send only if the user confirms.",
			Mission:     &mission.Reference,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if rejected.Pending == nil {
		t.Fatalf("permission to reject = %#v, want pending", rejected)
	}
	rejectedPending := rejected.Pending
	rejectionInteraction, err := client.Get(
		rejectedPending.Requirement.InteractionURL +
			"?code=" + rejectedPending.Requirement.InteractionCode,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer rejectionInteraction.Body.Close()
	if rejectionInteraction.StatusCode != http.StatusOK {
		t.Fatalf("rejection interaction status = %d", rejectionInteraction.StatusCode)
	}
	if err := ps.RejectPermission(rejectedPending.ID, aauth.PollingDenied); err != nil {
		t.Fatal(err)
	}
	_, err = agent.PollPermission(context.Background(), rejectedPending)
	assertProblemCode(t, err, http.StatusForbidden, aauth.PollingDenied)
	afterRejection, err := ps.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterRejection.Log) != 7 ||
		afterRejection.Log[6].Kind != aauth.MissionLogPermissionDecision ||
		!strings.Contains(string(afterRejection.Log[6].Response), `"denied"`) {
		t.Fatalf("rejected permission log = %#v", afterRejection.Log)
	}

	now = now.Add(time.Second)
	approvedBeforeTermination, err := agent.RequestPermission(
		context.Background(),
		"https://ps.example/permission",
		aauth.PermissionRequest{
			Action:      "message.send",
			Description: "Send after one more confirmation.",
			Mission:     &mission.Reference,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if approvedBeforeTermination.Pending == nil {
		t.Fatalf("permission before termination = %#v, want pending", approvedBeforeTermination)
	}
	endingPending := approvedBeforeTermination.Pending
	endingInteraction, err := client.Get(
		endingPending.Requirement.InteractionURL +
			"?code=" + endingPending.Requirement.InteractionCode,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer endingInteraction.Body.Close()
	if endingInteraction.StatusCode != http.StatusOK {
		t.Fatalf("ending permission interaction status = %d", endingInteraction.StatusCode)
	}
	if err := ps.ApprovePermission(context.Background(), endingPending.ID); err != nil {
		t.Fatal(err)
	}
	if err := ps.TerminateMission(mission.Reference); err != nil {
		t.Fatal(err)
	}
	terminated, err := ps.MissionSnapshot(mission.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if terminated.Status != aauth.MissionTerminated ||
		len(terminated.Log) != 9 ||
		terminated.Log[8].Kind != aauth.MissionLogTermination {
		t.Fatalf("terminated mission = %#v", terminated)
	}

	now = now.Add(time.Second)
	_, err = agent.PollPermission(context.Background(), endingPending)
	assertMissionTerminated(t, err)

	now = now.Add(time.Second)
	_, err = agent.RequestPermission(
		context.Background(),
		"https://ps.example/permission",
		permissionRequest,
	)
	assertMissionTerminated(t, err)

	now = now.Add(time.Second)
	err = agent.RecordAudit(
		context.Background(),
		"https://ps.example/audit",
		aauth.AuditRequest{
			Mission: mission.Reference,
			Action:  "filesystem.write",
		},
	)
	assertMissionTerminated(t, err)
	if policyCalls != 4 {
		t.Fatalf("permission policy ran after mission termination; calls = %d", policyCalls)
	}
}

func assertProblemCode(t *testing.T, err error, status int, code aauth.PollingErrorCode) {
	t.Helper()
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) {
		t.Fatalf("error = %v, want AAuth problem", err)
	}
	if problem.Status != status || problem.Code != code {
		t.Fatalf("problem = %#v, want status %d code %q", problem, status, code)
	}
}

func assertMissionTerminated(t *testing.T, err error) {
	t.Helper()
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) {
		t.Fatalf("error = %v, want mission_terminated problem", err)
	}
	if problem.Status != http.StatusForbidden ||
		problem.Code != "mission_terminated" ||
		problem.MissionStatus != string(aauth.MissionTerminated) {
		t.Fatalf("problem = %#v, want terminated mission status", problem)
	}
}
