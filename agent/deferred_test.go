package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	deferredInteractionURL  = "https://interact.example/review"
	deferredInteractionCode = "ABCD-EFGH"
)

// Every Agent request a server may defer polls its 202 the same way: the
// Begin method returns the verified pending URL and interaction, a poll
// before Retry-After is refused without a request, a 429 adds five seconds,
// Prefer: wait is sent when asked, interacting is reported, and the terminal
// answer is verified as the immediate answer would be. Each poll is one
// bodyless GET signed with the original request's credential, and a finished
// request is never polled again.
func TestEveryDeferredAgentRequestPollsToItsVerifiedResult(t *testing.T) {
	t.Parallel()
	missionS256 := aauth.MissionS256([]byte("approved mission"))
	for _, test := range []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "mission update", run: func(t *testing.T) {
			protocol := newTestProtocol(t)
			updateS256 := aauth.MissionS256([]byte("accepted update"))
			server := protocol.personServerDeferral(t, "/missions/"+missionS256, func(request *http.Request) *http.Response {
				return jsonResponse(request, http.StatusOK, aauth.MissionUpdateResponse{S256: updateS256})
			})
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: server})
			update := driveDeferred(t, server, protocol.advance, protocol.clock.Now, func() (agent.Result[agent.MissionUpdateResult], error) {
				return client.BeginMissionUpdate(context.Background(), agent.MissionUpdateRequest{
					PersonServer: protocol.personServerID, MissionS256: missionS256, Description: "Changed work",
				})
			})
			if update.S256() != updateS256 {
				t.Fatalf("update digest = %q", update.S256())
			}
		}},
		{name: "mission completion", run: func(t *testing.T) {
			protocol := newTestProtocol(t)
			server := protocol.personServerDeferral(t, "/missions/"+missionS256, func(request *http.Request) *http.Response {
				return jsonResponse(request, http.StatusOK, map[string]any{})
			})
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: server})
			completion := driveDeferred(t, server, protocol.advance, protocol.clock.Now, func() (agent.Result[agent.MissionCompletionResult], error) {
				return client.BeginMissionCompletion(context.Background(), agent.MissionCompletionRequest{
					PersonServer: protocol.personServerID, MissionS256: missionS256, Summary: "Done",
				})
			})
			if completion.MissionS256() != missionS256 {
				t.Fatalf("completed mission = %q", completion.MissionS256())
			}
		}},
		{name: "audit", run: func(t *testing.T) {
			protocol := newTestProtocol(t)
			server := protocol.personServerDeferral(t, "/audit", func(request *http.Request) *http.Response {
				return jsonResponse(request, http.StatusCreated, map[string]any{})
			})
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: server})
			driveDeferred(t, server, protocol.advance, protocol.clock.Now, func() (agent.Result[agent.AuditResult], error) {
				return client.BeginAudit(context.Background(), agent.AuditRequest{
					PersonServer: protocol.personServerID, Entry: validAgentAuditEntry(),
				})
			})
		}},
		{name: "sub-agent token", run: func(t *testing.T) {
			protocol := newTestProtocol(t)
			childKey := testSigningKey(t, "deferred-child-key", 61)
			child, err := aauth.MintAgentToken(protocol.agentProviderID, protocol.agentProviderKey, aauth.AgentTokenRequest{
				Agent: "aauth:reader+review@ap.example", ParentAgent: protocol.agentID,
				PersonServer: protocol.personServerID, PublicKey: childKey.PublicJWK(), Lifetime: 30 * time.Minute,
			}, protocol.now, "deferred-child-token")
			if err != nil {
				t.Fatal(err)
			}
			server := protocol.deferral(t, protocol.agentProviderID+"/subagents", protocol.agentToken,
				func(request *http.Request) *http.Response {
					return jsonResponse(request, http.StatusOK, map[string]string{"agent_token": child})
				})
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: server})
			token := driveDeferred(t, server, protocol.advance, protocol.clock.Now, func() (agent.Result[string], error) {
				return client.BeginSubagentToken(context.Background(), agent.SubagentTokenRequest{
					Endpoint: protocol.agentProviderID + "/subagents", PublicKey: childKey.PublicJWK(),
				})
			})
			if token != child {
				t.Fatal("deferred sub-agent token changed")
			}
		}},
		{name: "public event subscription", run: func(t *testing.T) {
			testDeferredEventSubscription(t, false)
		}},
		{name: "protected event subscription", run: func(t *testing.T) {
			testDeferredEventSubscription(t, true)
		}},
		{name: "authorization with a resource token", run: func(t *testing.T) {
			protocol := newTestProtocol(t)
			personToken := requestImmediatePersonToken(t, protocol.newClient(t), agent.PersonTokenRequest{
				PersonServer: protocol.personServerID, Resource: protocol.resourceID,
			})
			resourceToken := protocol.authorizedResourceToken(t, personToken)
			server := protocol.deferral(t, protocol.authorizationEndpoint, personToken, func(request *http.Request) *http.Response {
				return jsonResponse(request, http.StatusOK, map[string]string{"resource_token": resourceToken})
			})
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: server})
			authorization := driveDeferred(t, server, protocol.advance, protocol.clock.Now, func() (agent.Result[agent.AuthorizationResult], error) {
				return client.BeginAuthorize(context.Background(), agent.AuthorizeRequest{
					Resource: protocol.resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
				})
			})
			if token, ok := authorization.ResourceToken(); !ok || token != resourceToken {
				t.Fatalf("authorization = %#v", authorization)
			}
		}},
		{name: "authorization the Resource handles itself", run: func(t *testing.T) {
			protocol := newTestProtocol(t)
			personToken := requestImmediatePersonToken(t, protocol.newClient(t), agent.PersonTokenRequest{
				PersonServer: protocol.personServerID, Resource: protocol.resourceID,
			})
			server := protocol.deferral(t, protocol.authorizationEndpoint, personToken, func(request *http.Request) *http.Response {
				response := jsonResponse(request, http.StatusOK, map[string]string{"status": "authorized", "scope": "records.read"})
				response.Header.Set("AAuth-Access", "session-token-1")
				return response
			})
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: server})
			authorization := driveDeferred(t, server, protocol.advance, protocol.clock.Now, func() (agent.Result[agent.AuthorizationResult], error) {
				return client.BeginAuthorize(context.Background(), agent.AuthorizeRequest{
					Resource: protocol.resourceID, PersonToken: personToken, Scopes: []string{"records.read"},
				})
			})
			session, ok := authorization.Session()
			if _, issued := authorization.ResourceToken(); issued || !ok || session.Token() != "session-token-1" ||
				session.Resource() != protocol.resourceID || strings.Join(authorization.Scope(), " ") != "records.read" {
				t.Fatalf("resource-managed authorization = %#v", authorization)
			}
		}},
		{name: "bootstrap enrollment", run: func(t *testing.T) {
			fixture := newDeferredBootstrapFixture(t)
			fixture.server.original = "https://ap.example/custom/enrollment"
			fixture.server.verifyPoll = hwkPollProof(fixture.durable.PublicJWK(), fixture.clock)
			fixture.server.terminal = func(*http.Request) *http.Response {
				return bootstrapJSONResponse(http.StatusCreated, `{"agent":"aauth:reference@ap.example"}`)
			}
			enrollment := driveDeferred(t, fixture.server, fixture.advance, fixture.clock.Now, func() (agent.Result[agent.EnrollmentResult], error) {
				return fixture.client.BeginEnroll(context.Background(), json.RawMessage(`{"account":"person-1"}`))
			})
			if enrollment.Agent != "aauth:reference@ap.example" {
				t.Fatalf("enrollment = %#v", enrollment)
			}
		}},
		{name: "bootstrap refresh", run: func(t *testing.T) {
			fixture := newDeferredBootstrapFixture(t)
			fixture.server.original = "https://ap.example/custom/refresh"
			fixture.server.verifyPoll = jktJWTPollProof(fixture.durable.PublicJWK(), fixture.ephemeral.PublicJWK(), fixture.clock)
			fixture.server.terminal = fixture.refreshedAgentToken(fixture.ephemeral.PublicJWK())
			start := fixture.now
			refreshed := driveDeferred(t, fixture.server, fixture.advance, fixture.clock.Now, func() (agent.Result[agent.RefreshAgentTokenResult], error) {
				return fixture.client.BeginRefresh(context.Background(), agent.RefreshAgentTokenInput{
					Agent: "aauth:reference@ap.example", PersonServer: "https://ps.example",
					Evidence: json.RawMessage(`{"posture":"current"}`), SigningKey: fixture.ephemeral,
					DelegationJTI: "refresh-1", DelegationIssuedAt: start, DelegationExpiresAt: start.Add(10 * time.Minute),
				})
			})
			if !refreshed.Claims.Confirmation.JWK.Equal(fixture.ephemeral.PublicJWK()) {
				t.Fatalf("refreshed claims = %#v", refreshed.Claims)
			}
		}},
		{name: "bootstrap single-key refresh", run: func(t *testing.T) {
			fixture := newDeferredBootstrapFixture(t)
			fixture.server.original = "https://ap.example/custom/refresh"
			fixture.server.verifyPoll = hwkPollProof(fixture.durable.PublicJWK(), fixture.clock)
			fixture.server.terminal = fixture.refreshedAgentToken(fixture.durable.PublicJWK())
			start := fixture.now
			refreshed := driveDeferred(t, fixture.server, fixture.advance, fixture.clock.Now, func() (agent.Result[agent.RefreshAgentTokenResult], error) {
				return fixture.client.BeginRefreshSingleKey(context.Background(), agent.SingleKeyRefreshAgentTokenInput{
					Agent: "aauth:reference@ap.example", PersonServer: "https://ps.example",
					Evidence: json.RawMessage(`{"posture":"current"}`), RefreshJTI: "refresh-1",
					RefreshExpiresAt: start.Add(time.Hour),
				})
			})
			if !refreshed.Claims.Confirmation.JWK.Equal(fixture.durable.PublicJWK()) {
				t.Fatalf("refreshed claims = %#v", refreshed.Claims)
			}
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			test.run(t)
		})
	}
}

// The immediate-only methods do not lose a request the server retained: the
// error carries the same verified pending request.
func TestImmediateAgentMethodsReturnTheDeferredRequest(t *testing.T) {
	t.Parallel()
	protocol := newTestProtocol(t)
	missionS256 := aauth.MissionS256([]byte("approved mission"))
	server := protocol.personServerDeferral(t, "/missions/"+missionS256, func(request *http.Request) *http.Response {
		return jsonResponse(request, http.StatusOK, map[string]any{})
	})
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: server})
	err := client.CompleteMission(context.Background(), agent.MissionCompletionRequest{
		PersonServer: protocol.personServerID, MissionS256: missionS256, Summary: "Done",
	})
	var deferred *agent.PendingError[agent.MissionCompletionResult]
	if !errors.As(err, &deferred) || deferred.Pending().Location() != server.location || server.originals != 1 {
		t.Fatalf("CompleteMission error = %v", err)
	}
	protocol.advance(2 * time.Second)
	if _, err := deferred.Pending().Poll(context.Background(), agent.PollOptions{}); err != nil || server.polls != 1 {
		t.Fatalf("poll from the immediate method's error = %v, polls = %d", err, server.polls)
	}
}

// Terminal polling errors end the request with a typed problem, a relocated
// 202 ends it as malformed, a cancellation sends one signed DELETE, and a
// transport failure leaves the request pending because its outcome is unknown.
func TestPendingRequestTerminalErrorsCancellationAndLostAnswers(t *testing.T) {
	t.Parallel()
	missionS256 := aauth.MissionS256([]byte("approved mission"))
	begin := func(t *testing.T, poll func(*http.Request) (*http.Response, error)) (agent.Pending[agent.MissionUpdateResult], *int) {
		t.Helper()
		protocol := newTestProtocol(t)
		polls := 0
		client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			switch {
			case request.Method == http.MethodGet && request.URL.Path == "/.well-known/aauth-person.json":
				return protocol.personServerMetadata(request), nil
			case request.Method == http.MethodPost && request.URL.Path == "/missions/"+missionS256:
				return deferredPendingResponse(request, "0", "pending", ""), nil
			case request.URL.Path == "/pending/flow":
				polls++
				verifyProof(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
				return poll(request)
			}
			return nil, fmt.Errorf("unexpected request %s %s", request.Method, request.URL)
		})})
		result, err := client.BeginMissionUpdate(context.Background(), agent.MissionUpdateRequest{
			PersonServer: protocol.personServerID, MissionS256: missionS256, Description: "Changed work",
		})
		if err != nil {
			t.Fatal(err)
		}
		pending, ok := result.Pending()
		if !ok || pending.Requirement() != "" || pending.RetryAfter() != 0 {
			t.Fatalf("pending update = %#v", result)
		}
		return pending, &polls
	}
	for _, test := range []struct {
		status int
		code   aauth.ErrorCode
	}{
		{http.StatusForbidden, "denied"},
		{http.StatusForbidden, "abandoned"},
		{http.StatusRequestTimeout, "expired"},
		{http.StatusGone, "invalid_code"},
		{http.StatusInternalServerError, "server_error"},
	} {
		test := test
		t.Run(string(test.code), func(t *testing.T) {
			t.Parallel()
			pending, polls := begin(t, func(request *http.Request) (*http.Response, error) {
				return problemResponse(request, &aauth.ProblemError{Status: test.status, Code: test.code}), nil
			})
			_, err := pending.Poll(context.Background(), agent.PollOptions{})
			var problem *aauth.ProblemError
			if !errors.As(err, &problem) || problem.Status != test.status || problem.Code != test.code {
				t.Fatalf("terminal poll = %v", err)
			}
			if _, err := pending.Poll(context.Background(), agent.PollOptions{}); !errors.Is(err, agent.ErrPendingFinished) || *polls != 1 {
				t.Fatalf("poll after %s = %v, polls = %d", test.code, err, *polls)
			}
		})
	}
	t.Run("relocated 202", func(t *testing.T) {
		t.Parallel()
		pending, polls := begin(t, func(request *http.Request) (*http.Response, error) {
			response := deferredPendingResponse(request, "0", "pending", "")
			response.Header.Set("Location", "/pending/elsewhere")
			return response, nil
		})
		if _, err := pending.Poll(context.Background(), agent.PollOptions{}); err == nil || !strings.Contains(err.Error(), "Location changed") {
			t.Fatalf("relocated poll = %v", err)
		}
		if _, err := pending.Poll(context.Background(), agent.PollOptions{}); !errors.Is(err, agent.ErrPendingFinished) || *polls != 1 {
			t.Fatalf("poll after a relocated 202 = %v, polls = %d", err, *polls)
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		t.Parallel()
		var methods []string
		pending, polls := begin(t, func(request *http.Request) (*http.Response, error) {
			methods = append(methods, request.Method)
			return &http.Response{StatusCode: http.StatusNoContent, Request: request, Header: make(http.Header), Body: http.NoBody}, nil
		})
		if err := pending.Cancel(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := pending.Poll(context.Background(), agent.PollOptions{}); !errors.Is(err, agent.ErrPendingFinished) ||
			*polls != 1 || strings.Join(methods, ",") != http.MethodDelete {
			t.Fatalf("after cancellation: %v, requests %v", err, methods)
		}
	})
	t.Run("lost answer", func(t *testing.T) {
		t.Parallel()
		lost := errors.New("connection reset")
		pending, polls := begin(t, func(request *http.Request) (*http.Response, error) {
			if request.Header.Get("Prefer") != "wait=1" {
				t.Fatalf("Prefer = %q", request.Header.Get("Prefer"))
			}
			return nil, lost
		})
		for attempt := 1; attempt <= 2; attempt++ {
			if _, err := pending.Poll(context.Background(), agent.PollOptions{Wait: 500 * time.Millisecond}); !errors.Is(err, lost) || *polls != attempt {
				t.Fatalf("poll %d = %v, polls = %d", attempt, err, *polls)
			}
		}
	})
}

// A Person Server reviewing a completion may ask the Agent a question. The
// answer is one signed clarification_response POST to the pending URL, made
// before the question's deadline; polling then delivers the outcome.
func TestPendingCompletionAnswersAClarificationBeforeItsDeadline(t *testing.T) {
	t.Parallel()
	protocol := newTestProtocol(t)
	missionS256 := aauth.MissionS256([]byte("approved mission"))
	var answers []string
	server := protocol.personServerDeferral(t, "/missions/"+missionS256, nil)
	server.initial = func(request *http.Request) *http.Response {
		response := jsonResponse(request, http.StatusAccepted, map[string]any{
			"status": "pending", "clarification": "Did you send the itinerary?", "timeout": 60,
			"options": []string{"yes", "no"},
		})
		response.Header.Set("Location", "/pending/flow")
		response.Header.Set("Retry-After", "0")
		response.Header.Set("Cache-Control", "no-store")
		response.Header.Set("AAuth-Requirement", "requirement=clarification")
		return response
	}
	server.answer = func(request *http.Request) *http.Response {
		verified := verifyProofWithComponents(t, request, protocol.resolver, protocol.clock, aauth.AgentTokenType,
			[]string{"content-type", "content-digest"})
		if _, err := verified.AgentClaims(); err != nil {
			t.Fatal(err)
		}
		var body struct {
			Action                string `json:"action"`
			ClarificationResponse string `json:"clarification_response"`
		}
		decodeRequest(t, request, &body)
		if body.Action != "clarification_response" {
			t.Fatalf("answer action = %q", body.Action)
		}
		answers = append(answers, body.ClarificationResponse)
		return &http.Response{StatusCode: http.StatusNoContent, Request: request, Header: make(http.Header), Body: http.NoBody}
	}
	server.terminal = func(request *http.Request) *http.Response {
		return jsonResponse(request, http.StatusOK, map[string]any{})
	}
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: server})
	result, err := client.BeginMissionCompletion(context.Background(), agent.MissionCompletionRequest{
		PersonServer: protocol.personServerID, MissionS256: missionS256, Summary: "Booked flights and hotel.",
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, _ := result.Pending()
	question, ok := pending.Clarification()
	answerBefore, timed := question.AnswerBefore()
	if !ok || question.Question() != "Did you send the itinerary?" || strings.Join(question.Options(), ",") != "yes,no" ||
		!timed || !answerBefore.Equal(protocol.now.Add(time.Minute)) {
		t.Fatalf("clarification = %#v, %t", question, ok)
	}
	if err := pending.AnswerClarification(context.Background(), "Yes, on Tuesday."); err != nil {
		t.Fatal(err)
	}
	protocol.advance(time.Minute)
	if err := pending.AnswerClarification(context.Background(), "Late answer"); err == nil || len(answers) != 1 {
		t.Fatalf("answer after the deadline = %v, answers = %q", err, answers)
	}
	server.polls = 2 // the next poll is the terminal one
	completed, err := pending.Poll(context.Background(), agent.PollOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := completed.Value(); !ok || value.MissionS256() != missionS256 || answers[0] != "Yes, on Tuesday." {
		t.Fatalf("completion = %#v, answers = %q", completed, answers)
	}
}

// deferralServer answers one original POST with a 202 naming an interaction,
// then its polls with a 429, a 202 reporting interacting, and the terminal
// answer.
type deferralServer struct {
	t          *testing.T
	original   string
	location   string
	initial    func(*http.Request) *http.Response
	answer     func(*http.Request) *http.Response
	verifyPoll func(*testing.T, *http.Request)
	terminal   func(*http.Request) *http.Response
	fallback   func(*http.Request) (*http.Response, error)
	originals  int
	polls      int
}

func (server *deferralServer) RoundTrip(request *http.Request) (*http.Response, error) {
	t := server.t
	switch {
	case request.Method == http.MethodPost && request.URL.String() == server.original:
		server.originals++
		if server.initial != nil {
			return server.initial(request), nil
		}
		requirement, err := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{
			URL: deferredInteractionURL, Code: deferredInteractionCode,
		})
		if err != nil {
			t.Fatal(err)
		}
		return deferredPendingResponse(request, "2", "pending", requirement), nil
	case request.Method == http.MethodPost && request.URL.String() == server.location && server.answer != nil:
		return server.answer(request), nil
	case request.URL.String() == server.location:
		server.polls++
		if request.Method != http.MethodGet || request.ContentLength != 0 ||
			(request.Body != nil && request.Body != http.NoBody) {
			t.Fatalf("poll %d is %s with content length %d", server.polls, request.Method, request.ContentLength)
		}
		if server.verifyPoll != nil {
			server.verifyPoll(t, request)
		}
		switch server.polls {
		case 1:
			return problemResponse(request, &aauth.ProblemError{Status: http.StatusTooManyRequests, Code: "slow_down"}), nil
		case 2:
			if prefer := request.Header.Get("Prefer"); prefer != "wait=30" {
				t.Fatalf("Prefer on poll 2 = %q", prefer)
			}
			return deferredPendingResponse(request, "0", "interacting", ""), nil
		case 3:
			return server.terminal(request), nil
		}
		t.Fatalf("poll %d after the terminal answer", server.polls)
	case server.fallback != nil:
		return server.fallback(request)
	}
	return nil, fmt.Errorf("unexpected request %s %s", request.Method, request.URL)
}

func driveDeferred[T any](
	t *testing.T,
	server *deferralServer,
	advance func(time.Duration),
	now func() time.Time,
	begin func() (agent.Result[T], error),
) T {
	t.Helper()
	ctx := context.Background()
	result, err := begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, done := result.Value(); done {
		t.Fatal("deferred request completed immediately")
	}
	pending, ok := result.Pending()
	if !ok || pending.Location() != server.location || pending.RetryAfter() != 2*time.Second ||
		!pending.NextPollAt().Equal(now().Add(2*time.Second)) || pending.Requirement() != aauth.RequirementInteraction ||
		pending.InteractionURL() != deferredInteractionURL || pending.InteractionCode() != deferredInteractionCode ||
		pending.Interacting() {
		t.Fatalf("pending = %#v, %t", pending, ok)
	}
	var early *agent.PollTooEarlyError
	if _, err := pending.Poll(ctx, agent.PollOptions{}); !errors.As(err, &early) ||
		!early.NextPollAt.Equal(pending.NextPollAt()) || server.polls != 0 {
		t.Fatalf("early poll = %v after %d polls", err, server.polls)
	}
	advance(2 * time.Second)
	result, err = pending.Poll(ctx, agent.PollOptions{})
	if err != nil {
		t.Fatal(err)
	}
	slowed, ok := result.Pending()
	if !ok || slowed.Location() != server.location || slowed.RetryAfter() != 7*time.Second ||
		!slowed.NextPollAt().Equal(now().Add(7*time.Second)) {
		t.Fatalf("after 429 = %#v, %t", slowed, ok)
	}
	advance(7 * time.Second)
	result, err = slowed.Poll(ctx, agent.PollOptions{Wait: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	interacting, ok := result.Pending()
	if !ok || !interacting.Interacting() || interacting.Requirement() != "" || interacting.RetryAfter() != 0 {
		t.Fatalf("interacting = %#v, %t", interacting, ok)
	}
	result, err = interacting.Poll(ctx, agent.PollOptions{})
	if err != nil {
		t.Fatal(err)
	}
	value, ok := result.Value()
	if !ok {
		t.Fatalf("terminal poll = %#v", result)
	}
	if _, err := pending.Poll(ctx, agent.PollOptions{}); !errors.Is(err, agent.ErrPendingFinished) || server.polls != 3 {
		t.Fatalf("poll after the terminal answer = %v, polls = %d", err, server.polls)
	}
	if server.originals != 1 {
		t.Fatalf("original requests = %d", server.originals)
	}
	return value
}

func deferredPendingResponse(request *http.Request, retryAfter, status, requirement string) *http.Response {
	response := jsonResponse(request, http.StatusAccepted, map[string]string{"status": status})
	response.Header.Set("Location", "/pending/flow")
	response.Header.Set("Retry-After", retryAfter)
	response.Header.Set("Cache-Control", "no-store")
	if requirement != "" {
		response.Header.Set("AAuth-Requirement", requirement)
	}
	return response
}

func (protocol *testProtocol) advance(duration time.Duration) {
	protocol.now = protocol.now.Add(duration)
}

func (protocol *testProtocol) personServerMetadata(request *http.Request) *http.Response {
	return jsonResponse(request, http.StatusOK, map[string]any{
		"issuer": protocol.personServerID, "person_token_endpoint": protocol.personTokenEndpoint,
		"auth_token_endpoint": protocol.authTokenEndpoint,
		"mission_endpoint":    protocol.personServerID + "/missions",
		"audit_endpoint":      protocol.personServerID + "/audit",
	})
}

// deferral defers a POST to original; polls must carry credential, signed by
// the Agent key.
func (protocol *testProtocol) deferral(
	t *testing.T,
	original string,
	credential string,
	terminal func(*http.Request) *http.Response,
) *deferralServer {
	origin := original[:strings.Index(original[len("https://"):], "/")+len("https://")]
	return &deferralServer{
		t: t, original: original, location: origin + "/pending/flow",
		verifyPoll: jwtPollProof(credential, protocol.agentKey.PublicJWK(), protocol.clock),
		terminal:   terminal, fallback: protocol.roundTrip,
	}
}

// personServerDeferral defers a POST to path at the Person Server, whose
// metadata names mission and audit endpoints; polls carry the Agent token.
func (protocol *testProtocol) personServerDeferral(
	t *testing.T,
	path string,
	terminal func(*http.Request) *http.Response,
) *deferralServer {
	server := protocol.deferral(t, protocol.personServerID+path, protocol.agentToken, terminal)
	server.fallback = func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json" {
			return protocol.personServerMetadata(request), nil
		}
		return protocol.roundTrip(request)
	}
	return server
}

// authorizedResourceToken mints the resource token the test Resource issues
// for personToken.
func (protocol *testProtocol) authorizedResourceToken(t *testing.T, personToken string) string {
	t.Helper()
	person, err := aauth.VerifyPersonToken(context.Background(), personToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	compact, err := aauth.MintResourceToken(protocol.resourceKey, aauth.ResourceTokenClaims{
		Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
		Audience: protocol.accessServerID, JTI: "deferred-resource-token", AgentJKT: thumbprint,
		IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(protocol.resourceTokenLifetime).Unix(),
		Scope: "records.read", PersonServer: protocol.personServerID,
		Subject: person.Subject, PresentedJTI: person.JTI,
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func testDeferredEventSubscription(t *testing.T, protected bool) {
	t.Helper()
	protocol := newTestProtocol(t)
	subscribeToken, err := events.MintSubscribeToken(protocol.agentProviderID, protocol.agentProviderKey, events.SubscribeTokenRequest{
		Agent: protocol.agentID, Resource: protocol.resourceID,
		ConfirmationKey: protocol.agentKey.PublicJWK(), EventID: "event-1", Lifetime: time.Hour,
	}, protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := protocol.resourceID + "/events/subscribe"
	if protected {
		endpoint = protocol.resourceID + "/events/tickets/ticket-1"
	}
	server := protocol.deferral(t, endpoint, subscribeToken, func(request *http.Request) *http.Response {
		return &http.Response{StatusCode: http.StatusOK, Request: request, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}
	})
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: protocol.agentID, SigningKey: protocol.agentKey,
		AgentToken: protocol.agentToken, KeyResolver: protocol.resolver,
		HTTPClient: &http.Client{Transport: server}, Clock: protocol.clock,
		Events: &agent.EventsConfig{Store: &agentEventStore{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	subscription := driveDeferred(t, server, protocol.advance, protocol.clock.Now, func() (agent.Result[agent.EventSubscription], error) {
		if protected {
			return client.BeginProtectedSubscription(context.Background(), agent.ProtectedSubscriptionInput{
				TicketURL: endpoint, SubscribeToken: subscribeToken, Context: []byte(`{"purpose":"waitlist"}`),
			})
		}
		return client.BeginPublicSubscription(context.Background(), agent.PublicSubscriptionInput{
			Endpoint: endpoint, SubscribeToken: subscribeToken, Context: []byte(`{"purpose":"waitlist"}`),
		})
	})
	if subscription.EventID != "event-1" || subscription.Resource != protocol.resourceID {
		t.Fatalf("subscription = %#v", subscription)
	}
}

type deferredBootstrapFixture struct {
	t           *testing.T
	now         time.Time
	clock       aauth.Clock
	providerKey jose.SigningKey
	durable     jose.SigningKey
	ephemeral   jose.SigningKey
	server      *deferralServer
	client      *agent.BootstrapClient
}

func newDeferredBootstrapFixture(t *testing.T) *deferredBootstrapFixture {
	t.Helper()
	fixture := &deferredBootstrapFixture{
		t: t, now: time.Date(2026, 8, 31, 5, 10, 0, 0, time.UTC),
		providerKey: testSigningKey(t, "deferred-ap-key", 0xd1),
		durable:     testSigningKey(t, "deferred-durable-key", 0xd2),
		ephemeral:   testSigningKey(t, "deferred-ephemeral-key", 0xd3),
	}
	fixture.clock = aauth.ClockFunc(func() time.Time { return fixture.now })
	fixture.server = &deferralServer{t: t, location: "https://ap.example/pending/flow"}
	client, err := agent.NewBootstrapClient(agent.BootstrapConfig{
		AgentProvider:      "https://ap.example",
		EnrollmentEndpoint: "https://ap.example/custom/enrollment",
		RefreshEndpoint:    "https://ap.example/custom/refresh",
		DurableKey:         fixture.durable,
		KeyResolver: signaturekey.StaticKeyResolver{
			{Issuer: "https://ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: fixture.providerKey.ID()}: fixture.providerKey.PublicJWK(),
		},
		HTTPClient: &http.Client{Transport: fixture.server}, Clock: fixture.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.client = client
	return fixture
}

func (fixture *deferredBootstrapFixture) advance(duration time.Duration) {
	fixture.now = fixture.now.Add(duration)
}

func (fixture *deferredBootstrapFixture) refreshedAgentToken(confirmation jose.JWK) func(*http.Request) *http.Response {
	return func(*http.Request) *http.Response {
		compact, err := aauth.MintAgentToken("https://ap.example", fixture.providerKey, aauth.AgentTokenRequest{
			Agent: "aauth:reference@ap.example", PersonServer: "https://ps.example",
			PublicKey: confirmation, Lifetime: 30 * time.Minute,
		}, fixture.now, "deferred-refreshed-token")
		if err != nil {
			fixture.t.Fatal(err)
		}
		return bootstrapJSONResponse(http.StatusOK, fmt.Sprintf(`{"agent_token":%q}`, compact))
	}
}

func jwtPollProof(credential string, key jose.JWK, clock aauth.Clock) func(*testing.T, *http.Request) {
	return func(t *testing.T, request *http.Request) {
		t.Helper()
		prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWT},
		})
		if err != nil {
			t.Fatal(err)
		}
		if compact, ok := prepared.Credential().JWT(); !ok || compact != credential {
			t.Fatal("poll is not signed with the original request's credential")
		}
		if _, err := prepared.Verify(key); err != nil {
			t.Fatal(err)
		}
	}
}

func hwkPollProof(key jose.JWK, clock aauth.Clock) func(*testing.T, *http.Request) {
	return func(t *testing.T, request *http.Request) {
		t.Helper()
		prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK},
		})
		if err != nil {
			t.Fatal(err)
		}
		if inline, ok := prepared.Credential().InlineJWK(); !ok || !inline.Equal(key) {
			t.Fatal("poll is not signed with the durable key")
		}
		if _, err := prepared.Verify(key); err != nil {
			t.Fatal(err)
		}
	}
}

func jktJWTPollProof(durable, ephemeral jose.JWK, clock aauth.Clock) func(*testing.T, *http.Request) {
	return func(t *testing.T, request *http.Request) {
		t.Helper()
		prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJKTJWT},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, delegation, err := prepared.VerifyJKTJWT()
		if err != nil {
			t.Fatal(err)
		}
		if !delegation.IdentityKey().Equal(durable) || !delegation.ConfirmationKey().Equal(ephemeral) {
			t.Fatal("poll is not signed under the refresh delegation")
		}
	}
}
