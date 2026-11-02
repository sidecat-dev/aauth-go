package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
	"gitlab.com/sidecat-dev/aauth-go/supervisionserver"
)

// keyedAgent is an Agent whose key and token a test keeps, to sign a request
// the client has no method for.
type keyedAgent struct {
	client *clientagent.Client
	id     string
	key    jose.SigningKey
	token  string
}

func (world *supervisionWorld) newKeyedAgent(local string) keyedAgent {
	world.t.Helper()
	agent := keyedAgent{id: "aauth:" + local + "@agents.example", key: newSigningKey(world.t, "agent-"+local)}
	var err error
	agent.token, err = world.provider.Issue(context.Background(), aauth.AgentTokenRequest{
		Agent: agent.id, PersonServer: supervisedPersonID, PublicKey: agent.key.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	agent.client, err = clientagent.New(world.ctx, clientagent.Config{
		Identifier: agent.id, SigningKey: agent.key, AgentToken: agent.token, KeyResolver: world.resolver,
		HTTPClient: world.httpClient, Clock: world.clock,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	return agent
}

// signedAs sends one request signed with the Agent's token and returns the
// status and the problem's error code.
func (world *supervisionWorld) signedAs(agent keyedAgent, method, target string, body []byte) (int, string) {
	world.t.Helper()
	if strings.HasPrefix(target, "/") {
		target = supervisedPersonID + target
	}
	var reader io.Reader
	options := signaturekey.SignOptions{}
	if body != nil {
		reader = bytes.NewReader(body)
		options.AdditionalComponents = []string{"content-type", "content-digest"}
	}
	request, err := http.NewRequestWithContext(world.ctx, method, target, reader)
	if err != nil {
		world.t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if err := signaturekey.SignJWTRequestWithOptions(request, agent.key, agent.token, world.clock, options); err != nil {
		world.t.Fatal(err)
	}
	response, err := world.httpClient.Do(request)
	if err != nil {
		world.t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		world.t.Fatal(err)
	}
	var answer struct {
		Error  string `json:"error"`
		Status string `json:"status"`
	}
	_ = json.Unmarshal(data, &answer)
	if answer.Error == "" {
		return response.StatusCode, answer.Status
	}
	return response.StatusCode, answer.Error
}

// TestSupervisedPendingURLAndDenialsAsTheAgentSeesThem checks what an Agent
// receives from a supervised request: a mission request's denial carries the
// supervisor's or the person's reason, another Agent's poll is wrong_poller,
// a reference the Person Server does not hold is gone, and a withdrawal
// answers status cancelled, after which the pending URL is gone.
func TestSupervisedPendingURLAndDenialsAsTheAgentSeesThem(t *testing.T) {
	t.Parallel()
	world := newSupervisionWorld(t, supervisionWorldOptions{})
	world.addSupervisor(homeSupervisorID, true, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		if request.Request.Kind == supervision.KindMissionProposal && strings.HasPrefix(request.Request.Description, "# Refused") {
			return decided(supervision.Decision{Verdict: supervision.VerdictDeny, Reason: "Not this quarter."})
		}
		return decided(supervision.Decision{Verdict: supervision.VerdictAsk, Summary: "Ask the person."})
	})
	assistant := world.newKeyedAgent("assistant")
	intruder := world.newKeyedAgent("intruder")
	world.route(assistant.id, personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"})
	ctx := world.ctx
	deniedWith := func(err error, status int, code, reason string) bool {
		problem := (*aauth.ProblemError)(nil)
		return errors.As(err, &problem) && problem.Status == status && string(problem.Code) == code && problem.Reason == reason
	}

	_, err := assistant.client.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: supervisedPersonID, Proposal: aauth.MissionProposal{Description: "# Refused trip"},
	})
	if !deniedWith(err, http.StatusForbidden, "mission_denied", "Not this quarter.") {
		t.Fatalf("immediate denial = %v, want 403 mission_denied with the supervisor's reason", err)
	}
	proposal, err := assistant.client.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: supervisedPersonID, Proposal: aauth.MissionProposal{Description: "# Reconcile records"},
	})
	if err != nil {
		t.Fatal(err)
	}
	waiting, ok := proposal.Pending()
	if !ok {
		t.Fatal("the supervisor's ask did not leave the proposal pending")
	}
	reviews, err := world.people.PendingSupervision(ctx, 10)
	if err != nil || len(reviews) != 1 {
		t.Fatalf("reviews = %#v, %v", reviews, err)
	}
	if err := world.people.ResolveSupervision(ctx, reviews[0].Reference, personserver.SupervisionAnswer{
		Answer: supervision.AnswerDeny, Reason: "Wait for the audit.",
	}); err != nil {
		t.Fatal(err)
	}
	world.advance(5 * time.Second)
	if _, err := assistant.client.PollMissionProposal(ctx, waiting); !deniedWith(err, http.StatusForbidden, "denied", "Wait for the audit.") {
		t.Fatalf("deferred denial = %v, want 403 denied with the person's reason", err)
	}

	permission, err := assistant.client.RequestPermission(ctx, clientagent.PermissionRequest{PersonServer: supervisedPersonID, Action: "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := permission.Pending()
	if !ok {
		t.Fatal("the supervisor's ask did not leave the permission pending")
	}
	location := pending.Location()
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		if status, code := world.signedAs(intruder, method, location, nil); status != http.StatusForbidden || code != "wrong_poller" {
			t.Fatalf("another Agent's %s = %d %s, want 403 wrong_poller", method, status, code)
		}
	}
	unknown := location[:strings.LastIndex(location, "/")+1] + "no-such-reference"
	if status, code := world.signedAs(assistant, http.MethodGet, unknown, nil); status != http.StatusGone || code != "invalid_code" {
		t.Fatalf("unknown reference = %d %s, want 410 invalid_code", status, code)
	}
	if status, answer := world.signedAs(assistant, http.MethodDelete, location, nil); status != http.StatusOK || answer != "cancelled" {
		t.Fatalf("withdrawal = %d %s, want 200 status cancelled", status, answer)
	}
	if status, code := world.signedAs(assistant, http.MethodGet, location, nil); status != http.StatusGone || code != "invalid_code" {
		t.Fatalf("poll after withdrawal = %d %s, want 410 invalid_code", status, code)
	}
}

// TestSupervisorDecidesOnTheAgentsUpdatedRequest has a supervisor ask the
// Agent to narrow an auth-token request. The Agent answers with an
// updated_request; the Person Server verifies the new pair, refusing one that
// does not match the request it replaces, relays it, and issues the auth
// token from the new resource token once the supervisor allows it.
func TestSupervisorDecidesOnTheAgentsUpdatedRequest(t *testing.T) {
	t.Parallel()
	world := newSupervisionWorld(t, supervisionWorldOptions{})
	home := world.addSupervisor(homeSupervisorID, true, func(request supervisionserver.DecisionRequest) supervisionserver.DecisionResult {
		if request.Request.Kind != supervision.KindAuthToken {
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
		}
		if len(request.Rounds) == 0 {
			return supervisionserver.DecisionResult{Clarify: &supervision.Clarification{Question: "Can you ask for read access only?"}}
		}
		if request.Rounds[len(request.Rounds)-1].Updated != nil {
			return decided(supervision.Decision{Verdict: supervision.VerdictAllow})
		}
		return decided(supervision.Decision{Verdict: supervision.VerdictDeny})
	})
	assistant := world.newKeyedAgent("assistant")
	world.route(assistant.id, personserver.Supervisor{Issuer: homeSupervisorID, Subject: "home-person-1"})
	ctx := world.ctx
	personToken := func(agent keyedAgent) string {
		t.Helper()
		person, err := agent.client.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: supervisedPersonID, Resource: supervisedResourceID})
		if err != nil {
			t.Fatal(err)
		}
		token, ok := person.Token()
		if !ok {
			t.Fatal("person token was not issued")
		}
		return token
	}
	resourceToken := func(agent keyedAgent, presented string, scopes ...string) string {
		t.Helper()
		token, err := agent.client.Authorize(ctx, clientagent.AuthorizeRequest{
			Resource: supervisedResourceID, PersonToken: presented, Scopes: scopes,
		})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	authAsks := func() []supervisionserver.DecisionRequest {
		var asks []supervisionserver.DecisionRequest
		for _, request := range home.asked() {
			if request.Request.Kind == supervision.KindAuthToken {
				asks = append(asks, request)
			}
		}
		return asks
	}
	presented := personToken(assistant)
	broad := resourceToken(assistant, presented, "records.read", "records.write")
	result, err := assistant.client.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: supervisedPersonID, ResourceToken: broad, PresentedToken: presented,
		Capabilities: []string{"clarification"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatal("the exchange did not wait")
	}
	if question, ok := pending.Clarification(); !ok || question.Question() != "Can you ask for read access only?" {
		t.Fatal("the supervisor's question did not reach the Agent")
	}
	update := func(resourceToken, presentedToken string) []byte {
		body, err := json.Marshal(map[string]string{
			"action": "updated_request", "resource_token": resourceToken, "presented_token": presentedToken,
			"justification": "Read access is enough.",
		})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}

	// Another Agent's resource token names another key: it is refused, and
	// the supervisor never sees it.
	other := world.newKeyedAgent("other")
	otherPresented := personToken(other)
	foreign := resourceToken(other, otherPresented, "records.read")
	if status, code := world.signedAs(assistant, http.MethodPost, pending.Location(), update(foreign, otherPresented)); status != http.StatusBadRequest || code != "invalid_resource_token" {
		t.Fatalf("a foreign resource token = %d %s, want 400 invalid_resource_token", status, code)
	}
	if asked := authAsks(); len(asked) != 1 {
		t.Fatalf("the supervisor was asked about %d auth-token requests, want only the first", len(asked))
	}

	narrow := resourceToken(assistant, presented, "records.read")
	if status, code := world.signedAs(assistant, http.MethodPost, pending.Location(), update(narrow, presented)); status != http.StatusNoContent {
		t.Fatalf("updated_request = %d %s, want 204", status, code)
	}
	asked := authAsks()
	last := asked[len(asked)-1]
	if len(asked) != 2 || last.Request.ResourceToken != narrow || last.Request.Justification != "Read access is enough." ||
		len(last.Rounds) != 1 || last.Rounds[0].Updated == nil {
		t.Fatalf("the supervisor saw %#v, want the updated request", last)
	}
	world.advance(time.Second)
	polled, err := assistant.client.PollExchange(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	token, ok := polled.Token()
	if !ok {
		t.Fatalf("the allow of the updated request issued no token: %v", polled.Failure())
	}
	claims, err := aauth.VerifyAuthToken(ctx, token, world.resolver, world.clock)
	if err != nil || claims.Scope != "records.read" {
		t.Fatalf("auth token %#v, %v; want the updated resource token's scope", claims, err)
	}
}
