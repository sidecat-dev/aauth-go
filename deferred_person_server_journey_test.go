package aauth_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestPersonServerDeferredAuthorizationVertical(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 14, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs(
		"agent-token",
		"other-agent-token",
		"resource-token",
		"auth-token",
		"resource-token-denied",
		"resource-token-expired",
		"resource-token-invalid-code",
	)
	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	resourceKey := testSigningKey(t, "resource-key")
	agentKey := testSigningKey(t, "agent-key")
	otherKey := testSigningKey(t, "other-key")

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
		Agent:        "aauth:planner@ap.example",
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
				"https://resource.example/",
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
	ps, err := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier:  "https://ps.example",
		SigningKey:  psKey,
		KeyResolver: resolver,
		Clock:       clock,
		NewID:       ids,
		MissionPolicy: func(_ context.Context, proposal aauth.MissionProposal) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: proposal.Description}, nil
		},
		InteractionRequired: func(_ context.Context, request aauth.AuthorizationRequest) (bool, error) {
			return request.Agent == "aauth:planner@ap.example", nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			policyCalls++
			return aauth.AuthorizationDecision{
				Subject: "pairwise-user-for-resource",
				Scope:   request.Scope,
			}, nil
		},
		Random: bytes.NewReader(bytes.Join([][]byte{
			make([]byte, 16),
			{0, 1, 2, 3, 4},
			bytes.Repeat([]byte{1}, 16),
			{5, 6, 7, 8, 9},
			bytes.Repeat([]byte{2}, 16),
			{10, 11, 12, 13, 14},
			bytes.Repeat([]byte{3}, 16),
			{15, 16, 17, 18, 19},
		}, nil)),
		PendingLifetime: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	var executionCount int
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier:   "https://resource.example",
		PersonServer: "https://ps.example",
		SigningKey:   resourceKey,
		KeyResolver:  resolver,
		Clock:        clock,
		NewID:        ids,
		Scopes:       []string{"documents.read"},
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			executionCount++
			return map[string]string{
				"agent":   request.Agent,
				"subject": request.Subject,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	psHandler := ps.Handler()
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodPost && request.URL.Path == "/token" &&
				request.Header.Get("Prefer") != "wait=0" {
				http.Error(response, "missing Prefer wait", http.StatusBadRequest)
				return
			}
			psHandler.ServeHTTP(response, request)
		}),
		"resource.example": resource.Handler(),
	})
	defer gateway.Close()
	client.Transport = gateway.Client().Transport

	agent, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:planner@ap.example",
		SigningKey:  agentKey,
		AgentToken:  agentToken,
		KeyResolver: resolver,
		HTTPClient:  client,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:other@ap.example",
		SigningKey:  otherKey,
		AgentToken:  otherToken,
		KeyResolver: resolver,
		HTTPClient:  client,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	mission, err := agent.CreateMission(context.Background(), "https://ps.example/mission", aauth.MissionProposal{
		Description: "Read the design document after explicit approval.",
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceGrant, err := agent.RequestResourceToken(
		context.Background(),
		"https://resource.example/authorize",
		[]string{"documents.read"},
		mission,
	)
	if err != nil {
		t.Fatal(err)
	}

	authorization, err := agent.RequestTokenAuthorization(
		context.Background(),
		"https://ps.example/token",
		resourceGrant,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Grant != nil || authorization.Pending == nil {
		t.Fatalf("initial authorization = %#v", authorization)
	}
	pending := authorization.Pending
	if pending.PersonServer != "https://ps.example" ||
		pending.Location != "https://ps.example/pending/"+pending.ID ||
		pending.Requirement == nil ||
		pending.Requirement.Type != aauth.RequirementInteraction ||
		pending.Requirement.InteractionURL != "https://ps.example/interaction/"+pending.ID {
		t.Fatalf("pending authorization = %#v", pending)
	}
	if policyCalls != 0 {
		t.Fatalf("authorization policy ran before trusted approval; calls = %d", policyCalls)
	}
	if err := ps.ApproveAuthorization(context.Background(), pending.ID); err == nil {
		t.Fatal("person server approved before the interaction code was correlated")
	}
	if _, err := agent.RequestTokenAuthorization(
		context.Background(),
		"https://ps.example/token",
		resourceGrant,
	); err == nil {
		t.Fatal("person server accepted an exact replay of the initial token request")
	} else {
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) || problem.Code != "invalid_signature" {
			t.Fatalf("replayed token-request error = %#v", err)
		}
	}

	otherPending := *pending
	if _, err := other.PollTokenAuthorization(context.Background(), &otherPending); err == nil {
		t.Fatal("another agent polled the person-server authorization")
	}

	waiting, err := agent.PollTokenAuthorization(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if waiting.Pending == nil || waiting.Pending.Status != "pending" {
		t.Fatalf("waiting poll = %#v", waiting)
	}

	interaction, err := client.Get(
		pending.Requirement.InteractionURL +
			"?code=" + strings.ToLower(strings.ReplaceAll(
			pending.Requirement.InteractionCode,
			"0",
			"o",
		)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer interaction.Body.Close()
	if interaction.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(interaction.Body)
		t.Fatalf("interaction status = %d, body = %s", interaction.StatusCode, body)
	}
	reusedCode, err := client.Get(
		pending.Requirement.InteractionURL +
			"?code=" + pending.Requirement.InteractionCode,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer reusedCode.Body.Close()
	if reusedCode.StatusCode != http.StatusGone {
		body, _ := io.ReadAll(reusedCode.Body)
		t.Fatalf("reused interaction code status = %d, body = %s", reusedCode.StatusCode, body)
	}

	interacting, err := agent.PollTokenAuthorization(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if interacting.Pending == nil || interacting.Pending.Status != "interacting" {
		t.Fatalf("interacting poll = %#v", interacting)
	}
	if policyCalls != 0 {
		t.Fatalf("interaction code conferred policy authority; calls = %d", policyCalls)
	}

	if err := ps.ApproveAuthorization(context.Background(), pending.ID); err != nil {
		t.Fatal(err)
	}
	if policyCalls != 1 {
		t.Fatalf("authorization policy calls after approval = %d", policyCalls)
	}

	approved, err := agent.PollTokenAuthorization(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Pending != nil || approved.Grant == nil {
		t.Fatalf("approved poll = %#v", approved)
	}
	if approved.Grant.Claims.Subject != "pairwise-user-for-resource" ||
		approved.Grant.Claims.Agent != "aauth:planner@ap.example" {
		t.Fatalf("approved grant = %#v", approved.Grant)
	}
	if _, err := agent.PollTokenAuthorization(context.Background(), pending); err == nil {
		t.Fatal("terminal pending URL remained reusable")
	}

	protected, err := agent.DoAuthorized(
		context.Background(),
		http.MethodGet,
		"https://resource.example/documents",
		*approved.Grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer protected.Body.Close()
	if protected.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(protected.Body)
		t.Fatalf("protected status = %d, body = %s", protected.StatusCode, body)
	}
	if executionCount != 1 {
		t.Fatalf("protected operation executions = %d", executionCount)
	}

	newPending := func() *reference.PendingTokenAuthorization {
		t.Helper()
		now = now.Add(time.Second)
		nextResourceGrant, err := agent.RequestResourceToken(
			context.Background(),
			"https://resource.example/authorize",
			[]string{"documents.read"},
			mission,
		)
		if err != nil {
			t.Fatal(err)
		}
		next, err := agent.RequestTokenAuthorization(
			context.Background(),
			"https://ps.example/token",
			nextResourceGrant,
		)
		if err != nil {
			t.Fatal(err)
		}
		if next.Pending == nil {
			t.Fatalf("next authorization = %#v", next)
		}
		return next.Pending
	}
	enterInteraction := func(pending *reference.PendingTokenAuthorization, code string) {
		t.Helper()
		response, err := client.Get(pending.Requirement.InteractionURL + "?code=" + code)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(response.Body)
			t.Fatalf("interaction status = %d, body = %s", response.StatusCode, body)
		}
	}

	denied := newPending()
	enterInteraction(denied, denied.Requirement.InteractionCode)
	if err := ps.RejectAuthorization(denied.ID, aauth.PollingDenied); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.PollTokenAuthorization(context.Background(), denied); err == nil {
		t.Fatal("denied authorization returned a grant")
	} else {
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) ||
			problem.Status != http.StatusForbidden ||
			problem.Code != aauth.PollingDenied {
			t.Fatalf("denied polling error = %#v", err)
		}
	}
	if _, err := agent.PollTokenAuthorization(context.Background(), denied); err == nil {
		t.Fatal("denied pending URL returned a second terminal response")
	}

	expired := newPending()
	now = now.Add(time.Minute)
	if _, err := agent.PollTokenAuthorization(context.Background(), expired); err == nil {
		t.Fatal("expired authorization remained pending")
	} else {
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) ||
			problem.Status != http.StatusRequestTimeout ||
			problem.Code != aauth.PollingExpired {
			t.Fatalf("expired polling error = %#v", err)
		}
	}
	if _, err := agent.PollTokenAuthorization(context.Background(), expired); err == nil {
		t.Fatal("expired pending URL returned a second terminal response")
	}

	invalidCode := newPending()
	for attempt := 1; attempt <= 3; attempt++ {
		response, err := client.Get(invalidCode.Requirement.InteractionURL + "?code=ZZZZ-ZZZZ")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		expectedStatus := http.StatusBadRequest
		if attempt == 3 {
			expectedStatus = http.StatusGone
		}
		if response.StatusCode != expectedStatus {
			t.Fatalf(
				"invalid code attempt %d status = %d, want %d; body = %s",
				attempt,
				response.StatusCode,
				expectedStatus,
				body,
			)
		}
	}
	if _, err := agent.PollTokenAuthorization(context.Background(), invalidCode); err == nil {
		t.Fatal("invalid-code authorization remained pending")
	} else {
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) ||
			problem.Status != http.StatusGone ||
			problem.Code != aauth.PollingInvalidCode {
			t.Fatalf("invalid-code polling error = %#v", err)
		}
	}
}
