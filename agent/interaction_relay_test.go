package agent_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
)

func TestRequestInteractionRelayReturnsFallbackOrVerifiedContinuation(t *testing.T) {
	for _, test := range []struct {
		name     string
		response func(*http.Request) *http.Response
		check    func(*testing.T, agent.InteractionRelayResult)
	}{
		{
			name: "unavailable",
			response: func(request *http.Request) *http.Response {
				return problemResponse(request, &aauth.ProblemError{
					Status: http.StatusFailedDependency,
					Code:   "interaction_unavailable",
					Detail: "the Person Server cannot relay this interaction",
				})
			},
			check: func(t *testing.T, result agent.InteractionRelayResult) {
				fallback, ok := result.Fallback()
				if !ok || fallback.Relay.URL != "https://resource.example/confirm" || fallback.Relay.Code != "ABCD-EFGH" {
					t.Fatalf("fallback = %#v, present=%t", fallback, ok)
				}
			},
		},
		{
			name: "pending",
			response: func(request *http.Request) *http.Response {
				response := interactionQuestionResponse(request, http.StatusAccepted, []byte(`{"status":"pending"}`))
				response.Header.Set("Location", "/interaction/pending/relay-1")
				response.Header.Set("Retry-After", "3")
				response.Header.Set("Cache-Control", "no-store")
				return response
			},
			check: func(t *testing.T, result agent.InteractionRelayResult) {
				pending, ok := result.Pending()
				if !ok || pending.Location() != "https://ps.example/interaction/pending/relay-1" ||
					pending.RetryAfter() != 3*time.Second || pending.Interacting() {
					t.Fatalf("pending = %#v, present=%t", pending, ok)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInteractionRelayFixture(t)
			fixture.submit = test.response
			input := agent.InteractionRelayRequest{
				PersonServer: fixture.protocol.personServerID,
				Relay: aauth.InteractionRelay{
					Type: aauth.InteractionRelayInteraction,
					URL:  "https://resource.example/confirm",
					Code: "ABCD-EFGH",
				},
			}
			want, err := aauth.EncodeInteractionRelay(input.Relay)
			if err != nil {
				t.Fatal(err)
			}
			fixture.wantRequest = want.ExactJSON
			result, err := fixture.client.RequestInteractionRelay(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			test.check(t, result)
			if fixture.metadataCalls != 1 || fixture.submitCalls != 1 || fixture.pollCalls != 0 {
				t.Fatalf("calls = metadata %d submit %d poll %d", fixture.metadataCalls, fixture.submitCalls, fixture.pollCalls)
			}
		})
	}
}

func TestRequestInteractionRelayCarriesMissionDigest(t *testing.T) {
	fixture := newInteractionRelayFixture(t)
	mission := aauth.MissionS256([]byte(`{"description":"complete payment"}`))
	input := agent.InteractionRelayRequest{
		PersonServer: fixture.protocol.personServerID,
		Relay: aauth.InteractionRelay{
			Type: aauth.InteractionRelayPayment, URL: "https://resource.example/pay",
			Code: "X7K2-M9P4", MissionS256: mission,
		},
	}
	want, err := aauth.EncodeInteractionRelay(input.Relay)
	if err != nil {
		t.Fatal(err)
	}
	fixture.wantRequest = want.ExactJSON
	fixture.submit = func(request *http.Request) *http.Response {
		response := interactionQuestionResponse(request, http.StatusAccepted, []byte(`{"status":"pending"}`))
		response.Header.Set("Location", "/interaction/pending/relay-mission")
		response.Header.Set("Retry-After", "1")
		response.Header.Set("Cache-Control", "no-store")
		return response
	}
	result, err := fixture.client.RequestInteractionRelay(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.Pending(); !ok {
		t.Fatal("mission relay did not return pending")
	}
}

func TestPollInteractionRelayPreservesInteractingAndReturnsTerminalState(t *testing.T) {
	fixture := newInteractionRelayFixture(t)
	fixture.submit = func(request *http.Request) *http.Response {
		response := interactionQuestionResponse(request, http.StatusAccepted, []byte(`{"status":"pending"}`))
		response.Header.Set("Location", "/interaction/pending/relay-1")
		response.Header.Set("Retry-After", "1")
		response.Header.Set("Cache-Control", "no-store")
		return response
	}
	polls := 0
	fixture.poll = func(request *http.Request) *http.Response {
		polls++
		if polls == 1 {
			response := interactionQuestionResponse(request, http.StatusAccepted, []byte(`{"status":"interacting"}`))
			response.Header.Set("Location", "/interaction/pending/relay-1")
			response.Header.Set("Retry-After", "2")
			response.Header.Set("Cache-Control", "no-store")
			return response
		}
		response := interactionQuestionResponse(request, http.StatusOK, []byte(`{"status":"interacting"}`))
		response.Header.Set("Cache-Control", "no-store")
		return response
	}

	result, err := fixture.client.RequestInteractionRelay(context.Background(), agent.InteractionRelayRequest{
		PersonServer: fixture.protocol.personServerID,
		Relay: aauth.InteractionRelay{
			Type: aauth.InteractionRelayPayment,
			URL:  "https://resource.example/pay",
			Code: "X7K2-M9P4",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, _ := result.Pending()
	result, err = fixture.client.PollInteractionRelay(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	interacting, ok := result.Pending()
	if !ok || !interacting.Interacting() {
		t.Fatalf("interacting result = %#v", result)
	}
	result, err = fixture.client.PollInteractionRelay(context.Background(), interacting)
	if err != nil {
		t.Fatal(err)
	}
	completion, ok := result.Completion()
	if !ok || completion.Completion.Status != aauth.InteractionRelayInteracting {
		t.Fatalf("completion = %#v, present=%t", completion, ok)
	}
	if fixture.pollCalls != 2 {
		t.Fatalf("poll calls = %d", fixture.pollCalls)
	}
}

func TestInteractionRelayRejectsPrematureOrRegressingCompletion(t *testing.T) {
	t.Run("premature initial completion", func(t *testing.T) {
		fixture := newInteractionRelayFixture(t)
		fixture.submit = func(request *http.Request) *http.Response {
			response := interactionQuestionResponse(request, http.StatusOK, []byte(`{"status":"pending"}`))
			response.Header.Set("Cache-Control", "no-store")
			return response
		}
		_, err := fixture.client.RequestInteractionRelay(context.Background(), agent.InteractionRelayRequest{
			PersonServer: fixture.protocol.personServerID,
			Relay: aauth.InteractionRelay{
				Type: aauth.InteractionRelayInteraction,
				URL:  "https://resource.example/confirm",
				Code: "ABCD-EFGH",
			},
		})
		var uncertain *agent.InteractionRelayUncertainError
		if !errors.As(err, &uncertain) {
			t.Fatalf("error = %T %v, want uncertain outcome", err, err)
		}
	})

	t.Run("terminal regression", func(t *testing.T) {
		fixture := newInteractionRelayFixture(t)
		fixture.submit = func(request *http.Request) *http.Response {
			response := interactionQuestionResponse(request, http.StatusAccepted, []byte(`{"status":"interacting"}`))
			response.Header.Set("Location", "/interaction/pending/relay-1")
			response.Header.Set("Retry-After", "1")
			response.Header.Set("Cache-Control", "no-store")
			return response
		}
		fixture.poll = func(request *http.Request) *http.Response {
			response := interactionQuestionResponse(request, http.StatusOK, []byte(`{"status":"pending"}`))
			response.Header.Set("Cache-Control", "no-store")
			return response
		}
		result, err := fixture.client.RequestInteractionRelay(context.Background(), agent.InteractionRelayRequest{
			PersonServer: fixture.protocol.personServerID,
			Relay: aauth.InteractionRelay{
				Type: aauth.InteractionRelayInteraction,
				URL:  "https://resource.example/confirm",
				Code: "ABCD-EFGH",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		pending, _ := result.Pending()
		if _, err := fixture.client.PollInteractionRelay(context.Background(), pending); err == nil {
			t.Fatal("terminal relay regressed from interacting to pending")
		}
	})
}

func TestRequestInteractionRelayRejectsInvalidInputBeforeNetwork(t *testing.T) {
	protocol := newTestProtocol(t)
	calls := 0
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected network call")
	})})
	for _, input := range []agent.InteractionRelayRequest{
		{},
		{PersonServer: protocol.personServerID},
		{PersonServer: protocol.personServerID, Relay: aauth.InteractionRelay{Type: aauth.InteractionRelayInteraction, URL: "http://resource.example/a", Code: "ABCD-EFGH"}},
		{PersonServer: protocol.personServerID, Relay: aauth.InteractionRelay{Type: aauth.InteractionRelayInteraction, URL: "https://resource.example/a", Code: "ABCD-EFGH", MissionS256: "not-a-digest"}},
	} {
		if _, err := client.RequestInteractionRelay(context.Background(), input); err == nil {
			t.Fatalf("invalid relay accepted: %#v", input)
		}
	}
	if calls != 0 {
		t.Fatalf("network calls = %d", calls)
	}
}

type interactionRelayFixture struct {
	t             *testing.T
	protocol      *testProtocol
	client        *agent.Client
	wantRequest   []byte
	metadataCalls int
	submitCalls   int
	pollCalls     int
	submit        func(*http.Request) *http.Response
	poll          func(*http.Request) *http.Response
}

func newInteractionRelayFixture(t *testing.T) *interactionRelayFixture {
	t.Helper()
	fixture := &interactionRelayFixture{t: t, protocol: newTestProtocol(t)}
	fixture.client = fixture.protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(fixture.roundTrip)})
	return fixture
}

func (fixture *interactionRelayFixture) roundTrip(request *http.Request) (*http.Response, error) {
	switch request.URL.String() {
	case fixture.protocol.personServerID + "/.well-known/aauth-person.json":
		fixture.metadataCalls++
		return jsonResponse(request, http.StatusOK, map[string]any{
			"issuer": fixture.protocol.personServerID, "jwks_uri": fixture.protocol.personServerID + "/.well-known/jwks.json",
			"person_token_endpoint": fixture.protocol.personTokenEndpoint,
			"auth_token_endpoint":   fixture.protocol.authTokenEndpoint,
			"interaction_endpoint":  interactionQuestionEndpoint,
		}), nil
	case interactionQuestionEndpoint:
		fixture.submitCalls++
		verified := verifyProofWithComponents(
			fixture.t, request, fixture.protocol.resolver, fixture.protocol.clock,
			aauth.AgentTokenType, []string{"content-type", "content-digest"},
		)
		if len(fixture.wantRequest) != 0 && string(verified.Proof.ExactBody()) != string(fixture.wantRequest) {
			fixture.t.Fatalf("relay body = %s, want %s", verified.Proof.ExactBody(), fixture.wantRequest)
		}
		return fixture.submit(request), nil
	case "https://ps.example/interaction/pending/relay-1":
		fixture.pollCalls++
		verifyProofWithComponents(fixture.t, request, fixture.protocol.resolver, fixture.protocol.clock, aauth.AgentTokenType, nil)
		return fixture.poll(request), nil
	default:
		fixture.t.Fatalf("unexpected request: %s %s", request.Method, request.URL)
		return nil, errors.New("unexpected request")
	}
}
