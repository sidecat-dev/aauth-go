package agent_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
)

const interactionQuestionEndpoint = "https://ps.example/interaction"

func TestAskPersonQuestionSendsOneExactSignedRequestAndReturnsExactAnswer(t *testing.T) {
	fixture := newInteractionQuestionFixture(t)
	request := agent.InteractionQuestionRequest{
		PersonServer: fixture.protocol.personServerID,
		Description:  "A **route** decision is required.",
		Question:     "Which route should I take?",
	}
	wantRequest, err := aauth.EncodeInteractionQuestion(aauth.InteractionQuestion{
		Description: request.Description, Question: request.Question,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantAnswer := []byte("{\n  \"answer\": \"Take the northern route.\",\n  \"extension\": true\n}")
	responseBody := &trackingReadCloser{Reader: strings.NewReader(string(wantAnswer))}
	fixture.submit = func(httpRequest *http.Request) (*http.Response, error) {
		verified := verifyProofWithComponents(
			t, httpRequest, fixture.protocol.resolver, fixture.protocol.clock,
			aauth.AgentTokenType, []string{"content-type", "content-digest"},
		)
		if httpRequest.Method != http.MethodPost || httpRequest.URL.String() != interactionQuestionEndpoint ||
			string(verified.Proof.ExactBody()) != string(wantRequest.ExactJSON) {
			t.Fatalf("interaction request = %s %s %s", httpRequest.Method, httpRequest.URL, verified.Proof.ExactBody())
		}
		response := interactionQuestionResponse(httpRequest, http.StatusOK, nil)
		response.Body = responseBody
		response.ContentLength = int64(len(wantAnswer))
		return response, nil
	}

	result, err := fixture.client.AskPersonQuestion(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	answer, ok := result.Answer()
	if !ok {
		t.Fatalf("result = %#v, want answer", result)
	}
	if answer.Answer.Answer != "Take the northern route." || string(answer.ExactJSON) != string(wantAnswer) {
		t.Fatalf("answer = %#v, JSON=%s", answer.Answer, answer.ExactJSON)
	}
	if fixture.metadataCalls != 1 || fixture.submitCalls != 1 || fixture.otherCalls != 0 {
		t.Fatalf("calls = metadata %d, submit %d, other %d", fixture.metadataCalls, fixture.submitCalls, fixture.otherCalls)
	}
	if !responseBody.closed {
		t.Fatal("interaction answer response body was not closed")
	}
}

func TestAskPersonQuestionRejectsInvalidOrUnsupportedInputBeforeNetwork(t *testing.T) {
	valid := agent.InteractionQuestionRequest{
		PersonServer: "https://ps.example", Question: "Which route?",
	}
	for _, test := range []struct {
		name    string
		request agent.InteractionQuestionRequest
	}{
		{name: "missing Person Server", request: agent.InteractionQuestionRequest{Question: valid.Question}},
		{name: "wrong Person Server", request: agent.InteractionQuestionRequest{PersonServer: "https://other.example", Question: valid.Question}},
		{name: "missing question", request: agent.InteractionQuestionRequest{PersonServer: valid.PersonServer}},
		{name: "invalid question", request: agent.InteractionQuestionRequest{PersonServer: valid.PersonServer, Question: string([]byte{0xff})}},
		{name: "request too large", request: agent.InteractionQuestionRequest{PersonServer: valid.PersonServer, Question: strings.Repeat("q", 1<<20)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			calls := 0
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("unexpected network request")
			})})
			if _, err := client.AskPersonQuestion(context.Background(), test.request); err == nil {
				t.Fatal("AskPersonQuestion accepted invalid input")
			}
			if calls != 0 {
				t.Fatalf("network calls = %d, want 0", calls)
			}
		})
	}
}

func TestAskPersonQuestionRejectsSubagentBeforeNetwork(t *testing.T) {
	protocol := newTestProtocol(t)
	childID := "aauth:reader+question@ap.example"
	childKey := testSigningKey(t, "interaction-question-child-key", 132)
	compact, err := aauth.MintAgentToken(
		protocol.agentProviderID, protocol.agentProviderKey,
		aauth.AgentTokenRequest{
			Agent: childID, ParentAgent: protocol.agentID, PersonServer: protocol.personServerID,
			PublicKey: childKey.PublicJWK(), Lifetime: time.Hour,
		}, protocol.now, "interaction-question-child-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	client, err := agent.New(context.Background(), agent.Config{
		Identifier: childID, SigningKey: childKey, AgentToken: compact, KeyResolver: protocol.resolver,
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("subagent reached network")
		})}, Clock: protocol.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.AskPersonQuestion(context.Background(), agent.InteractionQuestionRequest{
		PersonServer: protocol.personServerID, Question: "Which route?",
	}); err == nil {
		t.Fatal("subagent submitted a top-level interaction question")
	}
	if calls != 0 {
		t.Fatalf("network calls = %d, want 0", calls)
	}
}

func TestAskPersonQuestionRequiresValidDiscoveredEndpoint(t *testing.T) {
	for _, test := range []struct {
		name           string
		metadataIssuer string
		endpoint       string
	}{
		{name: "missing endpoint", metadataIssuer: "https://ps.example"},
		{name: "invalid endpoint", metadataIssuer: "https://ps.example", endpoint: "http://ps.example/interaction"},
		{name: "wrong issuer", metadataIssuer: "https://other.example", endpoint: interactionQuestionEndpoint},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInteractionQuestionFixture(t)
			fixture.metadataIssuer = test.metadataIssuer
			fixture.endpoint = test.endpoint
			if _, err := fixture.client.AskPersonQuestion(context.Background(), agent.InteractionQuestionRequest{
				PersonServer: fixture.protocol.personServerID, Question: "Which route?",
			}); err == nil {
				t.Fatal("AskPersonQuestion accepted invalid metadata")
			}
			if fixture.metadataCalls != 1 || fixture.submitCalls != 0 {
				t.Fatalf("calls = metadata %d, submit %d", fixture.metadataCalls, fixture.submitCalls)
			}
		})
	}
}

func TestAskPersonQuestionPostHandoffInvalidResultIsUncertain(t *testing.T) {
	transportFailure := errors.New("connection reset after question handoff")
	for _, test := range []struct {
		name     string
		response func(*http.Request) (*http.Response, error)
	}{
		{name: "transport failure", response: func(*http.Request) (*http.Response, error) { return nil, transportFailure }},
		{name: "wrong success", response: func(request *http.Request) (*http.Response, error) {
			return interactionQuestionResponse(request, http.StatusCreated, nil), nil
		}},
		{name: "malformed answer", response: func(request *http.Request) (*http.Response, error) {
			return interactionQuestionResponse(request, http.StatusOK, []byte(`{"answer":null}`)), nil
		}},
		{name: "wrong content type", response: func(request *http.Request) (*http.Response, error) {
			response := interactionQuestionResponse(request, http.StatusOK, []byte(`{"answer":"yes"}`))
			response.Header.Set("Content-Type", "text/plain")
			return response, nil
		}},
		{name: "server failure", response: func(request *http.Request) (*http.Response, error) {
			return problemResponse(request, &aauth.ProblemError{Status: http.StatusInternalServerError, Code: "server_error"}), nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInteractionQuestionFixture(t)
			fixture.submit = test.response
			_, err := fixture.client.AskPersonQuestion(context.Background(), agent.InteractionQuestionRequest{
				PersonServer: fixture.protocol.personServerID, Question: "Which route?",
			})
			var uncertain *agent.InteractionQuestionUncertainError
			if !errors.As(err, &uncertain) {
				t.Fatalf("error = %T %v, want InteractionQuestionUncertainError", err, err)
			}
			if test.name == "transport failure" && !errors.Is(err, transportFailure) {
				t.Fatalf("transport error = %v", err)
			}
			if fixture.submitCalls != 1 || fixture.otherCalls != 0 {
				t.Fatalf("calls = submit %d, other %d", fixture.submitCalls, fixture.otherCalls)
			}
		})
	}
}

func TestAskPersonQuestionReturnsVerifiedPendingAndPollsOnce(t *testing.T) {
	fixture := newInteractionQuestionFixture(t)
	fixture.submit = func(request *http.Request) (*http.Response, error) {
		response := interactionQuestionResponse(request, http.StatusAccepted, []byte(`{"status":"pending"}`))
		response.Header.Set("Location", "/interaction/pending/question-1")
		response.Header.Set("Retry-After", "4")
		response.Header.Set("Cache-Control", "no-store")
		return response, nil
	}
	fixture.poll = func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.Body != nil && request.Body != http.NoBody {
			t.Fatalf("poll request = %s body=%T", request.Method, request.Body)
		}
		verifyProofWithComponents(t, request, fixture.protocol.resolver, fixture.protocol.clock, aauth.AgentTokenType, nil)
		return interactionQuestionResponse(request, http.StatusOK, []byte(`{"answer":"Take the northern route."}`)), nil
	}
	result, err := fixture.client.AskPersonQuestion(context.Background(), agent.InteractionQuestionRequest{
		PersonServer: fixture.protocol.personServerID, Question: "Which route?",
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok || pending.PersonServer() != fixture.protocol.personServerID ||
		pending.Location() != "https://ps.example/interaction/pending/question-1" || pending.RetryAfter() != 4*time.Second {
		t.Fatalf("pending = %#v, ok=%t", pending, ok)
	}
	result, err = fixture.client.PollPersonQuestion(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	answer, ok := result.Answer()
	if !ok || answer.Answer.Answer != "Take the northern route." {
		t.Fatalf("answer = %#v, ok=%t", answer, ok)
	}
	if fixture.submitCalls != 1 || fixture.pollCalls != 1 || fixture.otherCalls != 0 {
		t.Fatalf("calls = submit %d poll %d other %d", fixture.submitCalls, fixture.pollCalls, fixture.otherCalls)
	}
}

func TestAskPersonQuestionDefiniteClientFailureRemainsTyped(t *testing.T) {
	fixture := newInteractionQuestionFixture(t)
	fixture.submit = func(request *http.Request) (*http.Response, error) {
		return problemResponse(request, &aauth.ProblemError{
			Status: http.StatusForbidden, Code: "user_unreachable", Detail: "the person cannot be reached",
		}), nil
	}
	_, err := fixture.client.AskPersonQuestion(context.Background(), agent.InteractionQuestionRequest{
		PersonServer: fixture.protocol.personServerID, Question: "Which route?",
	})
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Code != "user_unreachable" || problem.Status != http.StatusForbidden {
		t.Fatalf("error = %T %v, want user_unreachable problem", err, err)
	}
	var uncertain *agent.InteractionQuestionUncertainError
	if errors.As(err, &uncertain) {
		t.Fatalf("definite failure became uncertain: %v", err)
	}
}

func TestInteractionQuestionUncertainErrorIsZeroSafe(t *testing.T) {
	t.Parallel()

	var failure *agent.InteractionQuestionUncertainError
	if failure.Error() == "" || failure.Unwrap() != nil {
		t.Fatalf("zero uncertain error = %q, unwrap %v", failure.Error(), failure.Unwrap())
	}
}

type interactionQuestionFixture struct {
	t              *testing.T
	protocol       *testProtocol
	client         *agent.Client
	metadataIssuer string
	endpoint       string
	metadataCalls  int
	submitCalls    int
	pollCalls      int
	otherCalls     int
	submit         func(*http.Request) (*http.Response, error)
	poll           func(*http.Request) (*http.Response, error)
}

func newInteractionQuestionFixture(t *testing.T) *interactionQuestionFixture {
	t.Helper()
	fixture := &interactionQuestionFixture{
		t: t, protocol: newTestProtocol(t), metadataIssuer: "https://ps.example", endpoint: interactionQuestionEndpoint,
	}
	fixture.client = fixture.protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(fixture.roundTrip)})
	return fixture
}

func (fixture *interactionQuestionFixture) roundTrip(request *http.Request) (*http.Response, error) {
	switch request.URL.String() {
	case fixture.protocol.personServerID + "/.well-known/aauth-person.json":
		fixture.metadataCalls++
		return jsonResponse(request, http.StatusOK, map[string]any{
			"issuer": fixture.metadataIssuer, "person_token_endpoint": fixture.protocol.personTokenEndpoint,
			"auth_token_endpoint": fixture.protocol.authTokenEndpoint, "interaction_endpoint": fixture.endpoint,
		}), nil
	case interactionQuestionEndpoint:
		fixture.submitCalls++
		if fixture.submit == nil {
			fixture.t.Fatal("unexpected interaction question submission")
		}
		return fixture.submit(request)
	case "https://ps.example/interaction/pending/question-1":
		fixture.pollCalls++
		if fixture.poll == nil {
			fixture.t.Fatal("unexpected interaction question poll")
		}
		return fixture.poll(request)
	default:
		fixture.otherCalls++
		fixture.t.Fatalf("unexpected request: %s %s", request.Method, request.URL)
		return nil, errors.New("unexpected request")
	}
}

func interactionQuestionResponse(request *http.Request, status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status), Request: request,
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(strings.NewReader(string(body))), ContentLength: int64(len(body)),
	}
}
