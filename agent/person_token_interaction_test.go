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

const (
	interactionLocation = "/person/pending/pending-1"
	interactionURL      = "https://ps.example/interaction"
	interactionCode     = "A1B2-C3D4"
)

func TestPersonTokenInteractionReturnsImmediateOrPendingResult(t *testing.T) {
	t.Run("immediate token", func(t *testing.T) {
		protocol := newTestProtocol(t)
		transport := &personTokenInteractionTransport{protocol: protocol}
		transport.initial = func(request *http.Request) (*http.Response, error) {
			return jsonResponse(request, http.StatusOK, map[string]any{
				"person_token": mintInteractionPersonToken(t, protocol, nil),
				"expires_in":   int64(protocol.personTokenLifetime / time.Second),
			}), nil
		}
		client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})

		result, err := client.PersonToken(context.Background(), agent.PersonTokenRequest{
			PersonServer: protocol.personServerID,
			Resource:     protocol.resourceID,
		})
		if err != nil {
			t.Fatal(err)
		}
		token, ok := result.Token()
		if !ok || token == "" {
			t.Fatalf("Token = %q, %v", token, ok)
		}
		if _, ok := result.Pending(); ok {
			t.Fatal("immediate result also reported a pending interaction")
		}
		if transport.initialCalls != 1 || transport.pollCalls != 0 {
			t.Fatalf("calls: initial=%d poll=%d", transport.initialCalls, transport.pollCalls)
		}
	})

	t.Run("interaction pending", func(t *testing.T) {
		protocol := newTestProtocol(t)
		transport := &personTokenInteractionTransport{protocol: protocol}
		transport.initial = func(request *http.Request) (*http.Response, error) {
			return validPersonTokenPendingResponse(request, "7", "pending"), nil
		}
		client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})

		result, err := client.PersonToken(context.Background(), agent.PersonTokenRequest{
			PersonServer: protocol.personServerID,
			Resource:     protocol.resourceID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := result.Token(); ok {
			t.Fatal("pending result also reported a token")
		}
		pending, ok := result.Pending()
		if !ok {
			t.Fatal("202 response did not produce a pending person-token handle")
		}
		if pending.PersonServer() != protocol.personServerID || pending.Resource() != protocol.resourceID ||
			pending.Location() != protocol.personServerID+interactionLocation ||
			pending.RetryAfter() != 7*time.Second || pending.InteractionURL() != interactionURL ||
			pending.InteractionCode() != interactionCode || pending.Interacting() {
			t.Fatalf("pending = PS %q resource %q location %q retry %s interaction %q code %q",
				pending.PersonServer(), pending.Resource(), pending.Location(), pending.RetryAfter(),
				pending.InteractionURL(), pending.InteractionCode())
		}
		if transport.initialCalls != 1 || transport.pollCalls != 0 {
			t.Fatalf("PersonToken followed the deferred response: initial=%d poll=%d", transport.initialCalls, transport.pollCalls)
		}
	})
}

func TestPersonTokenInteractionPollIsOneSignedBodylessGET(t *testing.T) {
	protocol := newTestProtocol(t)
	transport := &personTokenInteractionTransport{protocol: protocol}
	transport.initial = func(request *http.Request) (*http.Response, error) {
		return validPersonTokenPendingResponse(request, "5", "pending"), nil
	}
	transport.poll = []func(*http.Request) (*http.Response, error){
		func(request *http.Request) (*http.Response, error) {
			return validPersonTokenPendingResponse(request, "86400", "interacting"), nil
		},
	}
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})
	pending := beginPersonTokenInteraction(t, client, protocol)

	result, err := client.PollPersonToken(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	next, ok := result.Pending()
	if !ok {
		t.Fatal("pending poll did not return an updated pending handle")
	}
	if next.RetryAfter() != 24*time.Hour || next.Location() != pending.Location() ||
		next.InteractionURL() != pending.InteractionURL() || next.InteractionCode() != pending.InteractionCode() || !next.Interacting() {
		t.Fatalf("updated pending = location %q retry %s interaction %q code %q",
			next.Location(), next.RetryAfter(), next.InteractionURL(), next.InteractionCode())
	}
	if transport.pollCalls != 1 {
		t.Fatalf("PollPersonToken calls = %d, want exactly 1", transport.pollCalls)
	}
	if transport.lastPoll == nil || transport.lastPoll.Method != http.MethodGet ||
		transport.lastPoll.URL.String() != pending.Location() ||
		(transport.lastPoll.Body != nil && transport.lastPoll.Body != http.NoBody) ||
		transport.lastPoll.ContentLength != 0 || transport.lastPoll.GetBody != nil {
		t.Fatalf("poll request = %#v", transport.lastPoll)
	}
	for _, name := range []string{"Content-Type", "Content-Digest"} {
		if transport.lastPoll.Header.Get(name) != "" {
			t.Errorf("poll %s = %q", name, transport.lastPoll.Header.Get(name))
		}
	}
}

func TestPendingPersonTokenInteractingStateIsMonotonic(t *testing.T) {
	for _, laterStatus := range []string{"pending", "future-status"} {
		laterStatus := laterStatus
		t.Run(laterStatus, func(t *testing.T) {
			protocol := newTestProtocol(t)
			transport := &personTokenInteractionTransport{protocol: protocol}
			transport.initial = func(request *http.Request) (*http.Response, error) {
				return validPersonTokenPendingResponse(request, "0", "pending"), nil
			}
			transport.poll = []func(*http.Request) (*http.Response, error){
				func(request *http.Request) (*http.Response, error) {
					return validPersonTokenPendingResponse(request, "0", "interacting"), nil
				},
				func(request *http.Request) (*http.Response, error) {
					return validPersonTokenPendingResponse(request, "0", laterStatus), nil
				},
			}
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})
			pending := beginPersonTokenInteraction(t, client, protocol)
			result, err := client.PollPersonToken(context.Background(), pending)
			if err != nil {
				t.Fatal(err)
			}
			interacting, ok := result.Pending()
			if !ok || !interacting.Interacting() {
				t.Fatalf("interacting poll = %#v, pending = %t", interacting, ok)
			}
			result, err = client.PollPersonToken(context.Background(), interacting)
			if err != nil {
				t.Fatal(err)
			}
			next, ok := result.Pending()
			if !ok || !next.Interacting() {
				t.Fatalf("later %q poll regressed interacting state: %#v, pending = %t", laterStatus, next, ok)
			}
			if transport.pollCalls != 2 {
				t.Fatalf("PollPersonToken calls = %d, want exactly 2", transport.pollCalls)
			}
		})
	}
}

func TestPersonTokenInteractionPollCarriesForwardAnOmittedRequirement(t *testing.T) {
	protocol := newTestProtocol(t)
	transport := &personTokenInteractionTransport{protocol: protocol}
	transport.initial = func(request *http.Request) (*http.Response, error) {
		return validPersonTokenPendingResponse(request, "1", "pending"), nil
	}
	transport.poll = []func(*http.Request) (*http.Response, error){
		func(request *http.Request) (*http.Response, error) {
			response := validPersonTokenPendingResponse(request, "9", "interacting")
			response.Header.Del("AAuth-Requirement")
			return response, nil
		},
	}
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})
	pending := beginPersonTokenInteraction(t, client, protocol)
	result, err := client.PollPersonToken(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	next, ok := result.Pending()
	if !ok || next.InteractionURL() != pending.InteractionURL() || next.InteractionCode() != pending.InteractionCode() ||
		next.RetryAfter() != 9*time.Second || !next.Interacting() {
		t.Fatalf("updated pending = %#v", next)
	}
}

func TestPersonTokenResultAndPendingAccessorsAreZeroSafe(t *testing.T) {
	t.Parallel()

	var result agent.PersonTokenResult
	if token, ok := result.Token(); ok || token != "" {
		t.Fatalf("zero Token() = %q, %t", token, ok)
	}
	if pending, ok := result.Pending(); ok || pending != (agent.PendingPersonToken{}) {
		t.Fatalf("zero Pending() = %#v, %t", pending, ok)
	}
	var pending agent.PendingPersonToken
	if pending.PersonServer() != "" || pending.Resource() != "" || pending.Location() != "" ||
		pending.RetryAfter() != 0 || pending.InteractionURL() != "" || pending.InteractionCode() != "" || pending.Interacting() {
		t.Fatalf("zero pending accessors = %#v", pending)
	}
}

func TestPersonTokenInteractionPollVerifiesApprovedToken(t *testing.T) {
	protocol := newTestProtocol(t)
	transport := &personTokenInteractionTransport{protocol: protocol}
	transport.initial = func(request *http.Request) (*http.Response, error) {
		return validPersonTokenPendingResponse(request, "0", "pending"), nil
	}
	transport.poll = []func(*http.Request) (*http.Response, error){
		func(request *http.Request) (*http.Response, error) {
			return jsonResponse(request, http.StatusOK, map[string]any{
				"person_token": mintInteractionPersonToken(t, protocol, nil),
				"expires_in":   int64(protocol.personTokenLifetime / time.Second),
			}), nil
		},
	}
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})
	pending := beginPersonTokenInteraction(t, client, protocol)

	result, err := client.PollPersonToken(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	token, ok := result.Token()
	if !ok || token == "" {
		t.Fatalf("Token = %q, %v", token, ok)
	}
	if _, ok := result.Pending(); ok {
		t.Fatal("approved result also reported pending")
	}
	claims, err := aauth.VerifyPersonToken(context.Background(), token, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.ValidatePersonTokenContext(claims, protocol.resourceID, protocol.agentKey.PublicJWK()); err != nil {
		t.Fatal(err)
	}
	if transport.pollCalls != 1 {
		t.Fatalf("poll calls = %d, want 1", transport.pollCalls)
	}
}

func TestPersonTokenInteractionPollRejectsUnrelatedApprovedToken(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*testProtocol)
		change    func(*aauth.PersonTokenClaims)
	}{
		{name: "wrong issuer", change: func(claims *aauth.PersonTokenClaims) { claims.Issuer = "https://other-ps.example" }},
		{name: "wrong resource", change: func(claims *aauth.PersonTokenClaims) { claims.Audience = "https://other-resource.example" }},
		{name: "wrong key", change: func(claims *aauth.PersonTokenClaims) {
			claims.Confirmation.JWK = testSigningKey(t, "other-key", 91).PublicJWK()
		}},
		{
			name: "outlives agent token",
			configure: func(protocol *testProtocol) {
				var err error
				protocol.agentToken, err = aauth.MintAgentToken(
					protocol.agentProviderID, protocol.agentProviderKey,
					aauth.AgentTokenRequest{
						Agent: protocol.agentID, PersonServer: protocol.personServerID,
						PublicKey: protocol.agentKey.PublicJWK(), Lifetime: 5 * time.Minute,
					},
					protocol.now, "short-agent-token",
				)
				if err != nil {
					protocol.t.Fatal(err)
				}
			},
			change: func(claims *aauth.PersonTokenClaims) {
				claims.ExpiresAt = claims.IssuedAt + int64((10*time.Minute)/time.Second)
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			if test.configure != nil {
				test.configure(protocol)
			}
			transport := &personTokenInteractionTransport{protocol: protocol}
			transport.initial = func(request *http.Request) (*http.Response, error) {
				return validPersonTokenPendingResponse(request, "0", "pending"), nil
			}
			transport.poll = []func(*http.Request) (*http.Response, error){
				func(request *http.Request) (*http.Response, error) {
					return jsonResponse(request, http.StatusOK, map[string]any{
						"person_token": mintInteractionPersonToken(t, protocol, test.change),
						"expires_in":   60,
					}), nil
				},
			}
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})
			pending := beginPersonTokenInteraction(t, client, protocol)
			if _, err := client.PollPersonToken(context.Background(), pending); err == nil {
				t.Fatal("PollPersonToken accepted an unrelated person token")
			}
			if transport.pollCalls != 1 {
				t.Fatalf("poll calls = %d, want 1", transport.pollCalls)
			}
		})
	}
}

func TestPersonTokenInteractionPollPreservesTerminalProblems(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		code   aauth.ErrorCode
	}{
		{name: "denied", status: http.StatusForbidden, code: "denied"},
		{name: "expired", status: http.StatusRequestTimeout, code: "expired"},
		{name: "gone", status: http.StatusGone, code: "invalid_code"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			transport := &personTokenInteractionTransport{protocol: protocol}
			transport.initial = func(request *http.Request) (*http.Response, error) {
				return validPersonTokenPendingResponse(request, "0", "pending"), nil
			}
			transport.poll = []func(*http.Request) (*http.Response, error){
				func(request *http.Request) (*http.Response, error) {
					return problemResponse(request, &aauth.ProblemError{
						Status: test.status, Code: test.code, Detail: "terminal interaction outcome",
					}), nil
				},
			}
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})
			pending := beginPersonTokenInteraction(t, client, protocol)
			_, err := client.PollPersonToken(context.Background(), pending)
			var problem *aauth.ProblemError
			if !errors.As(err, &problem) || problem.Status != test.status || problem.Code != test.code {
				t.Fatalf("error = %v, problem = %#v", err, problem)
			}
			if transport.pollCalls != 1 {
				t.Fatalf("poll calls = %d, want 1", transport.pollCalls)
			}
		})
	}
}

func TestPersonTokenInteractionRejectsInvalidPendingResponses(t *testing.T) {
	tests := []struct {
		name   string
		change func(*http.Response)
	}{
		{name: "missing Location", change: func(response *http.Response) { response.Header.Del("Location") }},
		{name: "multiple Location", change: func(response *http.Response) {
			response.Header["Location"] = []string{"/person/pending/one", "/person/pending/two"}
		}},
		{name: "invalid Location", change: func(response *http.Response) { response.Header.Set("Location", "%") }},
		{name: "cross-origin Location", change: func(response *http.Response) { response.Header.Set("Location", "https://attacker.example/pending") }},
		{name: "HTTP Location", change: func(response *http.Response) { response.Header.Set("Location", "http://ps.example/pending") }},
		{name: "userinfo Location", change: func(response *http.Response) { response.Header.Set("Location", "https://user@ps.example/pending") }},
		{name: "fragment Location", change: func(response *http.Response) { response.Header.Set("Location", "/pending#fragment") }},
		{name: "multiple Retry-After", change: func(response *http.Response) {
			response.Header["Retry-After"] = []string{"1", "2"}
		}},
		{name: "negative Retry-After", change: func(response *http.Response) { response.Header.Set("Retry-After", "-1") }},
		{name: "fractional Retry-After", change: func(response *http.Response) { response.Header.Set("Retry-After", "1.5") }},
		{name: "date Retry-After", change: func(response *http.Response) {
			response.Header.Set("Retry-After", "Sun, 30 Aug 2026 18:00:00 GMT")
		}},
		{name: "overflow Retry-After", change: func(response *http.Response) { response.Header.Set("Retry-After", "9223372037") }},
		{name: "missing no-store", change: func(response *http.Response) { response.Header.Del("Cache-Control") }},
		{name: "wrong cache control", change: func(response *http.Response) { response.Header.Set("Cache-Control", "private") }},
		{name: "missing status", change: func(response *http.Response) { replaceInteractionBody(response, `{}`) }},
		{name: "empty status", change: func(response *http.Response) { replaceInteractionBody(response, `{"status":""}`) }},
		{name: "non-string status", change: func(response *http.Response) { replaceInteractionBody(response, `{"status":1}`) }},
		{name: "duplicate status", change: func(response *http.Response) {
			replaceInteractionBody(response, `{"status":"pending","status":"interacting"}`)
		}},
		{name: "malformed status body", change: func(response *http.Response) { replaceInteractionBody(response, `{"status":`) }},
		{name: "missing requirement", change: func(response *http.Response) { response.Header.Del("AAuth-Requirement") }},
		// An approval or clarification wait is a pending request the Agent
		// polls; claims is not a requirement a Person Server sends an Agent.
		{name: "wrong requirement", change: func(response *http.Response) {
			response.Header.Set("AAuth-Requirement", `requirement=claims`)
		}},
		{name: "missing interaction URL", change: func(response *http.Response) {
			response.Header.Set("AAuth-Requirement", `requirement=interaction;code="A1B2-C3D4"`)
		}},
		{name: "missing interaction code", change: func(response *http.Response) {
			response.Header.Set("AAuth-Requirement", `requirement=interaction;url="https://ps.example/interaction"`)
		}},
		{name: "HTTP interaction URL", change: func(response *http.Response) {
			response.Header.Set("AAuth-Requirement", interactionRequirement("http://ps.example/interaction", interactionCode))
		}},
		{name: "interaction URL query", change: func(response *http.Response) {
			response.Header.Set("AAuth-Requirement", interactionRequirement("https://ps.example/interaction?code=embedded", interactionCode))
		}},
		{name: "interaction URL fragment", change: func(response *http.Response) {
			response.Header.Set("AAuth-Requirement", interactionRequirement("https://ps.example/interaction#fragment", interactionCode))
		}},
		{name: "interaction URL userinfo", change: func(response *http.Response) {
			response.Header.Set("AAuth-Requirement", interactionRequirement("https://user@ps.example/interaction", interactionCode))
		}},
		{name: "undersized interaction code", change: func(response *http.Response) {
			response.Header.Set("AAuth-Requirement", interactionRequirement(interactionURL, "ABCD"))
		}},
		{name: "invalid interaction code alphabet", change: func(response *http.Response) {
			response.Header.Set("AAuth-Requirement", interactionRequirement(interactionURL, "A1BI-C3D4"))
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			protocol := newTestProtocol(t)
			transport := &personTokenInteractionTransport{protocol: protocol}
			transport.initial = func(request *http.Request) (*http.Response, error) {
				response := validPersonTokenPendingResponse(request, "5", "pending")
				test.change(response)
				return response, nil
			}
			client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})
			result, err := client.PersonToken(context.Background(), agent.PersonTokenRequest{
				PersonServer: protocol.personServerID,
				Resource:     protocol.resourceID,
			})
			if err == nil {
				if _, ok := result.Pending(); ok {
					t.Fatal("invalid 202 response produced a pending handle")
				}
				t.Fatal("invalid 202 response was accepted")
			}
			if transport.initialCalls != 1 || transport.pollCalls != 0 {
				t.Fatalf("calls: initial=%d poll=%d", transport.initialCalls, transport.pollCalls)
			}
		})
	}
}

func TestPersonTokenInteractionTreatsUnknownStatusAsPending(t *testing.T) {
	protocol := newTestProtocol(t)
	transport := &personTokenInteractionTransport{protocol: protocol}
	transport.initial = func(request *http.Request) (*http.Response, error) {
		return validPersonTokenPendingResponse(request, "5", "future-status"), nil
	}
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})
	result, err := client.PersonToken(context.Background(), agent.PersonTokenRequest{
		PersonServer: protocol.personServerID,
		Resource:     protocol.resourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.Pending(); !ok {
		t.Fatal("unknown status was not treated as pending")
	}
	pending, _ := result.Pending()
	if pending.Interacting() {
		t.Fatal("unknown status was treated as interacting")
	}
}

func TestPersonTokenInteractionUsesDefaultRetryAndSplitRequirementFields(t *testing.T) {
	protocol := newTestProtocol(t)
	transport := &personTokenInteractionTransport{protocol: protocol}
	transport.initial = func(request *http.Request) (*http.Response, error) {
		response := validPersonTokenPendingResponse(request, "5", "pending")
		response.Header.Del("Retry-After")
		response.Header["Aauth-Requirement"] = []string{
			`future=extension`,
			validInteractionRequirement() + `;future-param=?1`,
		}
		return response, nil
	}
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})
	result, err := client.PersonToken(context.Background(), agent.PersonTokenRequest{
		PersonServer: protocol.personServerID, Resource: protocol.resourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok || pending.RetryAfter() != 5*time.Second || pending.InteractionURL() != interactionURL ||
		pending.InteractionCode() != interactionCode {
		t.Fatalf("pending = %#v", pending)
	}
}

func TestPersonTokenInteractionRejectsZeroAndCrossClientHandlesBeforeNetwork(t *testing.T) {
	protocol := newTestProtocol(t)
	transport := &personTokenInteractionTransport{protocol: protocol}
	transport.initial = func(request *http.Request) (*http.Response, error) {
		return validPersonTokenPendingResponse(request, "0", "pending"), nil
	}
	client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})
	pending := beginPersonTokenInteraction(t, client, protocol)

	before := transport.networkCalls
	if _, err := client.PollPersonToken(context.Background(), agent.PendingPersonToken{}); err == nil {
		t.Fatal("zero pending handle was accepted")
	}
	if transport.networkCalls != before {
		t.Fatalf("zero handle used network: calls=%d, want %d", transport.networkCalls, before)
	}

	sameKeyOther := newTestProtocol(t)
	sameKeyOther.agentID = "aauth:other-same-key@ap.example"
	sameKeyOther.agentKey = protocol.agentKey
	var err error
	sameKeyOther.agentToken, err = aauth.MintAgentToken(
		sameKeyOther.agentProviderID,
		sameKeyOther.agentProviderKey,
		aauth.AgentTokenRequest{
			Agent: sameKeyOther.agentID, PersonServer: sameKeyOther.personServerID,
			PublicKey: sameKeyOther.agentKey.PublicJWK(), Lifetime: time.Hour,
		},
		sameKeyOther.now,
		"same-key-other-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	sameKeyTransport := &personTokenInteractionTransport{protocol: sameKeyOther}
	sameKeyClient := sameKeyOther.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(sameKeyTransport.roundTrip)})
	if _, err := sameKeyClient.PollPersonToken(context.Background(), pending); err == nil {
		t.Fatal("pending handle was accepted by another Agent using the same key")
	}
	if sameKeyTransport.networkCalls != 0 {
		t.Fatalf("same-key cross-Agent handle used network: calls=%d", sameKeyTransport.networkCalls)
	}

	other := newTestProtocol(t)
	other.agentID = "aauth:other@ap.example"
	other.agentKey = testSigningKey(t, "other-agent-key", 92)
	other.agentToken, err = aauth.MintAgentToken(
		other.agentProviderID,
		other.agentProviderKey,
		aauth.AgentTokenRequest{
			Agent:        other.agentID,
			PersonServer: other.personServerID,
			PublicKey:    other.agentKey.PublicJWK(),
			Lifetime:     time.Hour,
		},
		other.now,
		"other-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	otherTransport := &personTokenInteractionTransport{protocol: other}
	otherClient := other.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(otherTransport.roundTrip)})
	if _, err := otherClient.PollPersonToken(context.Background(), pending); err == nil {
		t.Fatal("pending handle was accepted by another client")
	}
	if otherTransport.networkCalls != 0 {
		t.Fatalf("cross-client handle used network: calls=%d", otherTransport.networkCalls)
	}
}

func TestPersonTokenInteractionPollHonorsCancellationWithoutRetry(t *testing.T) {
	t.Run("already canceled", func(t *testing.T) {
		protocol := newTestProtocol(t)
		transport := &personTokenInteractionTransport{protocol: protocol}
		transport.initial = func(request *http.Request) (*http.Response, error) {
			return validPersonTokenPendingResponse(request, "0", "pending"), nil
		}
		client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})
		pending := beginPersonTokenInteraction(t, client, protocol)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := client.PollPersonToken(ctx, pending); !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context canceled", err)
		}
		if transport.pollCalls != 0 {
			t.Fatalf("canceled poll calls = %d", transport.pollCalls)
		}
	})

	t.Run("transport cancellation", func(t *testing.T) {
		protocol := newTestProtocol(t)
		transport := &personTokenInteractionTransport{protocol: protocol}
		transport.initial = func(request *http.Request) (*http.Response, error) {
			return validPersonTokenPendingResponse(request, "0", "pending"), nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		transport.poll = []func(*http.Request) (*http.Response, error){
			func(request *http.Request) (*http.Response, error) {
				cancel()
				return nil, request.Context().Err()
			},
		}
		client := protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(transport.roundTrip)})
		pending := beginPersonTokenInteraction(t, client, protocol)
		if _, err := client.PollPersonToken(ctx, pending); !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context canceled", err)
		}
		if transport.pollCalls != 1 {
			t.Fatalf("poll calls = %d, want 1", transport.pollCalls)
		}
	})
}

type personTokenInteractionTransport struct {
	protocol     *testProtocol
	initial      func(*http.Request) (*http.Response, error)
	poll         []func(*http.Request) (*http.Response, error)
	networkCalls int
	initialCalls int
	pollCalls    int
	lastPoll     *http.Request
}

func (transport *personTokenInteractionTransport) roundTrip(request *http.Request) (*http.Response, error) {
	transport.networkCalls++
	protocol := transport.protocol
	if request.Method == http.MethodGet && request.URL.String() == protocol.personServerID+"/.well-known/aauth-person.json" {
		return jsonResponse(request, http.StatusOK, map[string]any{
			"issuer":                protocol.personServerID,
			"person_token_endpoint": protocol.personTokenEndpoint,
			"auth_token_endpoint":   protocol.authTokenEndpoint,
		}), nil
	}
	if request.Method == http.MethodPost && request.URL.String() == protocol.personTokenEndpoint {
		transport.initialCalls++
		verified := verifyProof(tFromProtocol(protocol), request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
		agentClaims, err := verified.AgentClaims()
		if err != nil {
			return nil, err
		}
		var input struct {
			Resource string `json:"resource"`
		}
		decodeRequest(tFromProtocol(protocol), request, &input)
		if agentClaims.Subject != protocol.agentID || input.Resource != protocol.resourceID {
			return nil, errors.New("person-token request context mismatch")
		}
		if transport.initial == nil {
			return nil, errors.New("unexpected initial person-token request")
		}
		return transport.initial(request)
	}
	if request.Method == http.MethodGet && request.URL.String() == protocol.personServerID+interactionLocation {
		transport.pollCalls++
		transport.lastPoll = request
		verified := verifyProof(tFromProtocol(protocol), request, protocol.resolver, protocol.clock, aauth.AgentTokenType)
		agentClaims, err := verified.AgentClaims()
		if err != nil {
			return nil, err
		}
		if agentClaims.Subject != protocol.agentID {
			return nil, errors.New("poll agent mismatch")
		}
		index := transport.pollCalls - 1
		if index >= len(transport.poll) {
			return nil, errors.New("unexpected additional person-token poll")
		}
		return transport.poll[index](request)
	}
	return nil, errors.New("unexpected request: " + request.Method + " " + request.URL.String())
}

func beginPersonTokenInteraction(t *testing.T, client *agent.Client, protocol *testProtocol) agent.PendingPersonToken {
	t.Helper()
	result, err := client.PersonToken(context.Background(), agent.PersonTokenRequest{
		PersonServer: protocol.personServerID,
		Resource:     protocol.resourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatal("PersonToken did not return pending")
	}
	return pending
}

func mintInteractionPersonToken(
	t *testing.T,
	protocol *testProtocol,
	change func(*aauth.PersonTokenClaims),
) string {
	t.Helper()
	claims := aauth.PersonTokenClaims{
		Issuer: protocol.personServerID, DWK: aauth.PersonDiscoveryDocument,
		Audience: protocol.resourceID, Subject: "person-123",
		Confirmation: aauth.Confirmation{JWK: protocol.agentKey.PublicJWK()},
		JTI:          "person-token-interaction", IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(protocol.personTokenLifetime).Unix(),
	}
	if change != nil {
		change(&claims)
	}
	compact, err := aauth.MintPersonToken(protocol.personServerKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func validPersonTokenPendingResponse(request *http.Request, retryAfter, status string) *http.Response {
	header := make(http.Header)
	header.Set("Location", interactionLocation)
	header.Set("Retry-After", retryAfter)
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Type", "application/json")
	header.Set("AAuth-Requirement", validInteractionRequirement()+`;future="ignored"`)
	return &http.Response{
		StatusCode: http.StatusAccepted,
		Status:     "202 Accepted",
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(`{"status":"` + status + `"}`)),
		Request:    request,
	}
}

func validInteractionRequirement() string {
	return interactionRequirement(interactionURL, interactionCode)
}

func interactionRequirement(url, code string) string {
	return `requirement=interaction;url="` + url + `";code="` + code + `"`
}

func replaceInteractionBody(response *http.Response, body string) {
	response.Body = io.NopCloser(strings.NewReader(body))
}

func tFromProtocol(protocol *testProtocol) *testing.T {
	return protocol.t
}
