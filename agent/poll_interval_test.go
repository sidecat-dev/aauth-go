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

// pollIntervalSteps scripts the answers to successive polls of one pending
// URL. Core "Polling with GET": the agent respects Retry-After, polls every
// five seconds when it is absent, and increases its polling interval by five
// seconds on each 429. A 429 whose Retry-After cannot be read still backs off.
var pollIntervalSteps = []struct {
	status     int
	retryAfter string
	want       time.Duration
}{
	{status: http.StatusAccepted, want: 5 * time.Second},
	{status: http.StatusTooManyRequests, want: 10 * time.Second},
	{status: http.StatusTooManyRequests, want: 15 * time.Second},
	{status: http.StatusServiceUnavailable, retryAfter: "3", want: 3 * time.Second},
	{status: http.StatusTooManyRequests, want: 8 * time.Second},
	{status: http.StatusTooManyRequests, retryAfter: "30", want: 30 * time.Second},
	{status: http.StatusTooManyRequests, retryAfter: "soon", want: 35 * time.Second},
	{status: http.StatusAccepted, retryAfter: "2", want: 2 * time.Second},
}

type pollIntervalScript struct {
	t      *testing.T
	polls  int
	accept func(*http.Request) *http.Response
}

// respond answers the next scripted poll. A scripted 202 is the flow's own
// valid pending response without Retry-After unless the step names one.
func (script *pollIntervalScript) respond(request *http.Request) *http.Response {
	script.t.Helper()
	if script.polls >= len(pollIntervalSteps) {
		script.t.Fatalf("unexpected poll %d", script.polls+1)
	}
	step := pollIntervalSteps[script.polls]
	script.polls++
	if step.status == http.StatusAccepted {
		response := script.accept(request)
		response.Header.Del("Retry-After")
		if step.retryAfter != "" {
			response.Header.Set("Retry-After", step.retryAfter)
		}
		return response
	}
	header := http.Header{"Content-Type": []string{"text/plain"}}
	if step.retryAfter != "" {
		header.Set("Retry-After", step.retryAfter)
	}
	return &http.Response{
		StatusCode: step.status, Status: http.StatusText(step.status), Request: request,
		Header: header, Body: io.NopCloser(strings.NewReader("retry later")),
	}
}

func withoutRetryAfter(response *http.Response) *http.Response {
	response.Header.Del("Retry-After")
	return response
}

// assertPollIntervals polls through every scripted step and checks the
// interval each answer leaves on the continuation the caller polls next.
func assertPollIntervals[P interface{ RetryAfter() time.Duration }](
	t *testing.T,
	script *pollIntervalScript,
	pending P,
	poll func(P) (P, *http.Response, bool, error),
) {
	t.Helper()
	if pending.RetryAfter() != 5*time.Second {
		t.Fatalf("initial 202 without Retry-After: interval = %s, want 5s", pending.RetryAfter())
	}
	for index, step := range pollIntervalSteps {
		next, response, ok, err := poll(pending)
		if response != nil {
			response.Body.Close()
		}
		if err != nil {
			t.Fatalf("poll %d (%d): %v", index+1, step.status, err)
		}
		if !ok || next.RetryAfter() != step.want {
			t.Fatalf("poll %d (%d Retry-After %q): pending=%t interval %s, want %s",
				index+1, step.status, step.retryAfter, ok, next.RetryAfter(), step.want)
		}
		pending = next
	}
	if script.polls != len(pollIntervalSteps) {
		t.Fatalf("polls = %d, want %d", script.polls, len(pollIntervalSteps))
	}
}

func TestEveryAgentPollAppliesTheDefaultIntervalAndLinearBackoff(t *testing.T) {
	t.Run("person token", func(t *testing.T) {
		protocol := newTestProtocol(t)
		script := &pollIntervalScript{t: t, accept: func(request *http.Request) *http.Response {
			return validPersonTokenPendingResponse(request, "1", "pending")
		}}
		transport := &personTokenInteractionTransport{protocol: protocol}
		transport.initial = func(request *http.Request) (*http.Response, error) {
			return withoutRetryAfter(validPersonTokenPendingResponse(request, "1", "pending")), nil
		}
		for range pollIntervalSteps {
			transport.poll = append(transport.poll, func(request *http.Request) (*http.Response, error) {
				return script.respond(request), nil
			})
		}
		client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})
		pending := beginPersonTokenInteraction(t, client, protocol)
		assertPollIntervals(t, script, pending, func(pending agent.PendingPersonToken) (agent.PendingPersonToken, *http.Response, bool, error) {
			result, err := client.PollPersonToken(context.Background(), pending)
			next, ok := result.Pending()
			return next, nil, ok, err
		})
	})

	t.Run("resource session", func(t *testing.T) {
		protocol := newTestProtocol(t)
		script := &pollIntervalScript{t: t, accept: func(request *http.Request) *http.Response {
			return validResourceSessionPendingResponse(request, "1", "pending", true)
		}}
		client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			switch request.URL.String() {
			case protocol.resourceID + "/.well-known/aauth-resource.json":
				return resourceSessionMetadataResponseWithComponents(request, protocol.resourceID, nil), nil
			case protocol.resourceID + "/records":
				return withoutRetryAfter(validResourceSessionPendingResponse(request, "1", "pending", true)), nil
			case protocol.resourceID + resourceSessionLocation:
				return script.respond(request), nil
			default:
				return nil, errors.New("unexpected request: " + request.URL.String())
			}
		})})
		request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("AAuth-Capabilities", "interaction")
		started, err := client.BeginResourceSession(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		pending, ok := started.Pending()
		if !ok {
			t.Fatal("BeginResourceSession did not return pending")
		}
		assertPollIntervals(t, script, pending, func(pending agent.PendingResourceSession) (agent.PendingResourceSession, *http.Response, bool, error) {
			result, err := client.PollResourceSession(context.Background(), pending)
			response, _ := result.Response()
			next, ok := result.Pending()
			return next, response, ok, err
		})
	})

	t.Run("permission", func(t *testing.T) {
		fixture := newPermissionFixture(t)
		script := &pollIntervalScript{t: t, accept: func(request *http.Request) *http.Response {
			return permissionPendingResponse(request, "1", "pending")
		}}
		fixture.initial = func(request *http.Request) (*http.Response, error) {
			return withoutRetryAfter(permissionPendingResponse(request, "1", "pending")), nil
		}
		fixture.poll = func(request *http.Request) (*http.Response, error) {
			return script.respond(request), nil
		}
		pending := requestPendingPermission(t, fixture)
		assertPollIntervals(t, script, pending, func(pending agent.PendingPermission) (agent.PendingPermission, *http.Response, bool, error) {
			result, err := fixture.client.PollPermission(context.Background(), pending)
			response, _ := result.Response()
			next, ok := result.Pending()
			return next, response, ok, err
		})
	})

	t.Run("interaction relay", func(t *testing.T) {
		fixture := newInteractionRelayFixture(t)
		pendingRelay := func(request *http.Request) *http.Response {
			response := interactionQuestionResponse(request, http.StatusAccepted, []byte(`{"status":"pending"}`))
			response.Header.Set("Location", "/interaction/pending/relay-1")
			response.Header.Set("Cache-Control", "no-store")
			return response
		}
		script := &pollIntervalScript{t: t, accept: pendingRelay}
		fixture.submit = pendingRelay
		fixture.poll = script.respond
		result, err := fixture.client.RequestInteractionRelay(context.Background(), agent.InteractionRelayRequest{
			PersonServer: fixture.protocol.personServerID,
			Relay: aauth.InteractionRelay{
				Type: aauth.InteractionRelayInteraction, URL: "https://resource.example/confirm", Code: "ABCD-EFGH",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		pending, ok := result.Pending()
		if !ok {
			t.Fatal("RequestInteractionRelay did not return pending")
		}
		assertPollIntervals(t, script, pending, func(pending agent.PendingInteractionRelay) (agent.PendingInteractionRelay, *http.Response, bool, error) {
			result, err := fixture.client.PollInteractionRelay(context.Background(), pending)
			response, _ := result.Response()
			next, ok := result.Pending()
			return next, response, ok, err
		})
	})

	t.Run("person question", func(t *testing.T) {
		fixture := newInteractionQuestionFixture(t)
		pendingQuestion := func(request *http.Request) *http.Response {
			response := interactionQuestionResponse(request, http.StatusAccepted, []byte(`{"status":"pending"}`))
			response.Header.Set("Location", "/interaction/pending/question-1")
			response.Header.Set("Cache-Control", "no-store")
			return response
		}
		script := &pollIntervalScript{t: t, accept: pendingQuestion}
		fixture.submit = func(request *http.Request) (*http.Response, error) { return pendingQuestion(request), nil }
		fixture.poll = func(request *http.Request) (*http.Response, error) { return script.respond(request), nil }
		result, err := fixture.client.AskPersonQuestion(context.Background(), agent.InteractionQuestionRequest{
			PersonServer: fixture.protocol.personServerID, Question: "Which route?",
		})
		if err != nil {
			t.Fatal(err)
		}
		pending, ok := result.Pending()
		if !ok {
			t.Fatal("AskPersonQuestion did not return pending")
		}
		assertPollIntervals(t, script, pending, func(pending agent.PendingInteractionQuestion) (agent.PendingInteractionQuestion, *http.Response, bool, error) {
			result, err := fixture.client.PollPersonQuestion(context.Background(), pending)
			response, _ := result.Response()
			next, ok := result.Pending()
			return next, response, ok, err
		})
	})

	t.Run("auth-token call", func(t *testing.T) {
		protocol := newTestProtocol(t)
		personToken := mintBeginPersonToken(t, protocol, nil)
		person, err := aauth.VerifyPersonToken(context.Background(), personToken, protocol.resolver, protocol.clock)
		if err != nil {
			t.Fatal(err)
		}
		resourceClaims := beginResourceTokenClaims(t, protocol, person)
		requirement := mintAuthTokenRequirementHeader(t, protocol, resourceClaims)
		authToken := mintPendingAuthToken(t, protocol, resourceClaims, nil)
		heldInvocation := func(request *http.Request) *http.Response {
			return pendingResponse(request, requirement, "/pending/held", "1", pollBodyFor("pending"))
		}
		script := &pollIntervalScript{t: t, accept: heldInvocation}
		client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			switch request.URL.String() {
			case protocol.resourceID + "/.well-known/aauth-resource.json":
				return protocol.roundTrip(request)
			case protocol.resourceID + "/records":
				return withoutRetryAfter(heldInvocation(request)), nil
			case protocol.resourceID + "/pending/held":
				return script.respond(request), nil
			default:
				return nil, errors.New("unexpected request: " + request.URL.String())
			}
		})})
		request, err := http.NewRequest(http.MethodGet, protocol.resourceID+"/records", nil)
		if err != nil {
			t.Fatal(err)
		}
		started, err := client.Begin(context.Background(), agent.InitialCall{Request: request, PersonToken: personToken})
		if err != nil {
			t.Fatal(err)
		}
		pending, ok := started.PendingAuthToken()
		if !ok {
			t.Fatal("Begin did not return a pending call")
		}
		assertPollIntervals(t, script, pending, func(pending agent.PendingAuthTokenCall) (agent.PendingAuthTokenCall, *http.Response, bool, error) {
			result, err := client.PollAuthToken(context.Background(), agent.AuthTokenPoll{Pending: pending, AuthToken: authToken})
			response, _ := result.Response()
			next, ok := result.Pending()
			if ok && (next.Location() != pending.Location() || next.ResourceToken() != pending.ResourceToken()) {
				t.Fatalf("held invocation changed: %q %q", next.Location(), next.ResourceToken())
			}
			return next, response, ok, err
		})

		// The held application's own 202 names a new pending URL. It is the
		// retained result, so it is returned without a held continuation.
		script.accept = func(request *http.Request) *http.Response {
			return pendingResponse(request, requirement, "/application/pending-2", "1", pollBodyFor("pending"))
		}
		script.polls = 0
		result, err := client.PollAuthToken(context.Background(), agent.AuthTokenPoll{Pending: pending, AuthToken: authToken})
		if err != nil {
			t.Fatal(err)
		}
		response, ok := result.Response()
		if !ok || response.StatusCode != http.StatusAccepted {
			t.Fatalf("application 202 response = %#v, %t", response, ok)
		}
		response.Body.Close()
		if _, held := result.Pending(); held {
			t.Fatal("an application 202 with a new Location was treated as the held invocation")
		}
	})

	t.Run("R3 call", func(t *testing.T) {
		fixture := newAgentR3StepUpFixture(t)
		const body = `{"record":"alpha","enabled":true}`
		proposalToken, proposalReference, exactProposal := fixture.proposalResourceToken(t, "proposal-token-interval")
		completionToken := fixture.perCallAuthToken(t, "auth-token-interval", proposalReference, exactProposal)
		requirement := formatAgentR3Requirement(t, proposalToken)
		heldInvocation := func(request *http.Request) *http.Response {
			header := make(http.Header)
			header.Set("AAuth-Requirement", requirement)
			header.Set("Location", "/r3/pending/invocation-interval")
			header.Set("Cache-Control", "private, no-store")
			header.Set("Content-Type", "application/json")
			return &http.Response{
				StatusCode: http.StatusAccepted, Status: "202 Accepted", Request: request,
				Header: header, Body: io.NopCloser(strings.NewReader(`{"status":"pending"}`)),
			}
		}
		script := &pollIntervalScript{t: t, accept: heldInvocation}
		client := fixture.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodGet && request.URL.String() == fixture.protocol.resourceID+"/r3/pending/invocation-interval" {
				return script.respond(request), nil
			}
			return heldInvocation(request), nil
		})})
		started, err := client.BeginR3Call(context.Background(), agent.R3Call{
			Request: fixture.newRequest(t, body), ClassAuthToken: fixture.classAuthToken,
			Operation: fixture.operation, AdditionalSignatureComponents: fixture.components,
		})
		if err != nil {
			t.Fatal(err)
		}
		pending, ok := started.Pending()
		if !ok {
			t.Fatal("BeginR3Call did not return a pending call")
		}
		assertPollIntervals(t, script, pending, func(pending agent.PendingR3Call) (agent.PendingR3Call, *http.Response, bool, error) {
			result, err := client.PollR3Call(context.Background(), agent.R3Poll{Pending: pending, AuthToken: completionToken})
			response, _ := result.Response()
			next, ok := result.Pending()
			return next, response, ok, err
		})
	})
}
