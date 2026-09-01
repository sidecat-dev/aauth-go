package agent_test

import (
	"bytes"
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
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestExchangeInteractionImmediateResultMatchesExchange(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return harness.authTokenResponse(request, nil), nil
	}
	client := harness.client(t)

	want, err := client.Exchange(context.Background(), agent.ExchangeRequest{
		PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.BeginExchange(context.Background(), agent.ExchangeRequest{
		PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := result.Token()
	if !ok || got != want {
		t.Fatalf("BeginExchange token = %q, %t; want %q", got, ok, want)
	}
	if _, ok := result.Pending(); ok {
		t.Fatal("immediate result also reported pending")
	}
	if _, ok := result.Response(); ok {
		t.Fatal("immediate result exposed a raw response")
	}
	if harness.metadataCalls != 2 || harness.initialCalls != 2 || harness.pollCalls != 0 {
		t.Fatalf("calls: metadata=%d initial=%d poll=%d", harness.metadataCalls, harness.initialCalls, harness.pollCalls)
	}
	if harness.capabilitiesPresent {
		t.Fatal("empty capabilities were encoded")
	}
}

func TestExchangeInteractionPreservesExplicitEmptyCapabilities(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return problemResponse(request, &aauth.ProblemError{
			Status: http.StatusForbidden, Code: "user_unreachable", Detail: "no declared interaction capability",
		}), nil
	}
	client := harness.client(t)
	_, err := client.BeginExchange(context.Background(), agent.ExchangeRequest{
		PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
		Capabilities: []string{},
	})
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Code != "user_unreachable" {
		t.Fatalf("explicit empty capabilities = %T %v", err, err)
	}
	if !harness.capabilitiesPresent || len(harness.capabilities) != 0 {
		t.Fatalf("encoded capabilities = %#v, present=%t", harness.capabilities, harness.capabilitiesPresent)
	}
}

func TestExchangeInteractionInitialPendingIsVerifiedAndDoesNotPoll(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangePendingResponse(request, "/pending/exchange-1", "7", "pending"), nil
	}
	client := harness.client(t)
	result, err := client.BeginExchange(context.Background(), agent.ExchangeRequest{
		PersonServer:  harness.protocol.personServerID,
		ResourceToken: harness.resourceToken,
		Capabilities:  []string{"interaction", "future-capability"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatal("BeginExchange did not return pending")
	}
	if pending.PersonServer() != harness.protocol.personServerID ||
		pending.Location() != harness.protocol.personServerID+"/pending/exchange-1" ||
		pending.RetryAfter() != 7*time.Second ||
		pending.InteractionURL() != exchangeInteractionURL ||
		pending.InteractionCode() != exchangeInteractionCode || pending.Interacting() {
		t.Fatalf("pending = %#v", pending)
	}
	if got := strings.Join(harness.capabilities, ","); got != "interaction,future-capability" || !harness.capabilitiesPresent {
		t.Fatalf("capabilities = %v, present=%t", harness.capabilities, harness.capabilitiesPresent)
	}
	if harness.metadataCalls != 1 || harness.initialCalls != 1 || harness.pollCalls != 0 {
		t.Fatalf("calls: metadata=%d initial=%d poll=%d", harness.metadataCalls, harness.initialCalls, harness.pollCalls)
	}
}

func TestExchangeInteractionGenericPendingRequirementsAndFallbacks(t *testing.T) {
	for _, test := range []struct {
		name         string
		requirement  string
		capabilities []string
		want         aauth.Requirement
		wantFailure  bool
	}{
		{name: "none"},
		{name: "approval", requirement: "requirement=approval", want: aauth.RequirementApproval},
		{name: "clarification", requirement: `requirement=clarification`, capabilities: []string{"clarification"}, want: aauth.RequirementClarification},
		{name: "claims", requirement: `requirement=claims`, want: aauth.RequirementClaims, wantFailure: true},
		{name: "unknown", requirement: "requirement=future-consent", want: aauth.Requirement("future-consent"), wantFailure: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			harness := newExchangeInteractionHarness(t)
			harness.initial = func(request *http.Request) (*http.Response, error) {
				response := validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending")
				response.Header.Del("Retry-After")
				if test.requirement == "" {
					response.Header.Del("AAuth-Requirement")
				} else {
					response.Header.Set("AAuth-Requirement", test.requirement)
				}
				if test.want == aauth.RequirementClarification {
					response.Body = io.NopCloser(strings.NewReader(`{"status":"pending","clarification":"which","timeout":30,"options":["a","b"]}`))
				}
				if test.want == aauth.RequirementClaims {
					response.Body = io.NopCloser(strings.NewReader(`{"status":"pending","required_claims":["email"]}`))
				}
				return response, nil
			}
			harness.poll = []func(*http.Request) (*http.Response, error){func(request *http.Request) (*http.Response, error) {
				return harness.authTokenResponse(request, nil), nil
			}}
			client := harness.client(t)
			result, err := client.BeginExchange(context.Background(), agent.ExchangeRequest{
				PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
				Capabilities: test.capabilities,
			})
			if err != nil {
				t.Fatal(err)
			}
			pending, ok := result.Pending()
			if !ok || pending.Requirement() != test.want || pending.RetryAfter() != 5*time.Second {
				t.Fatalf("pending = %#v, ok=%t, requirement=%q, retry=%s", pending, ok, pending.Requirement(), pending.RetryAfter())
			}
			var unsupported *agent.UnsupportedRequirementError
			if test.wantFailure != errors.As(result.Failure(), &unsupported) {
				t.Fatalf("Failure = %v", result.Failure())
			}
			completed, err := client.PollExchange(context.Background(), pending)
			if err != nil {
				t.Fatalf("generic pending could not poll: %v", err)
			}
			if token, ok := completed.Token(); !ok || token == "" {
				t.Fatalf("poll token = %q, %t", token, ok)
			}
		})
	}
}

func TestExchangeInteractionValidatesOnlyTheActiveRequirementBody(t *testing.T) {
	for _, test := range []struct {
		name, requirement, body string
	}{
		{
			name:        "clarification requires text",
			requirement: "requirement=clarification",
			body:        `{"status":"pending","clarification":null}`,
		},
		{
			name:        "clarification timeout cannot be null",
			requirement: "requirement=clarification",
			body:        `{"status":"pending","clarification":"which","timeout":null}`,
		},
		{
			name:        "clarification options cannot be null",
			requirement: "requirement=clarification",
			body:        `{"status":"pending","clarification":"which","options":null}`,
		},
		{
			name:        "claims cannot be null",
			requirement: "requirement=claims",
			body:        `{"status":"pending","required_claims":null}`,
		},
		{
			name:        "claims cannot contain an empty name",
			requirement: "requirement=claims",
			body:        `{"status":"pending","required_claims":["email",""]}`,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			harness := newExchangeInteractionHarness(t)
			harness.initial = func(request *http.Request) (*http.Response, error) {
				response := validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending")
				response.Header.Set("AAuth-Requirement", test.requirement)
				response.Body = io.NopCloser(strings.NewReader(test.body))
				return response, nil
			}
			if _, err := harness.client(t).BeginExchange(context.Background(), agent.ExchangeRequest{
				PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
			}); err == nil {
				t.Fatal("BeginExchange accepted an invalid requirement body")
			}
		})
	}

	t.Run("unknown extension body remains opaque", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		harness.initial = func(request *http.Request) (*http.Response, error) {
			response := validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending")
			response.Header.Set("AAuth-Requirement", "requirement=future-consent")
			response.Body = io.NopCloser(strings.NewReader(
				`{"status":"pending","timeout":"vendor-defined","options":{"mode":"later"},"required_claims":"extension-owned"}`,
			))
			return response, nil
		}
		result, err := harness.client(t).BeginExchange(context.Background(), agent.ExchangeRequest{
			PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
		})
		if err != nil {
			t.Fatal(err)
		}
		pending, ok := result.Pending()
		if !ok || pending.Requirement() != aauth.Requirement("future-consent") {
			t.Fatalf("pending = %#v, ok = %t", pending, ok)
		}
		var unsupported *agent.UnsupportedRequirementError
		if !errors.As(result.Failure(), &unsupported) || unsupported.Requirement != aauth.Requirement("future-consent") {
			t.Fatalf("Failure = %v", result.Failure())
		}
	})
}

func TestExchangeClarificationRetainsTypedQuestionAndCopiesOptions(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangeClarificationResponse(
			request,
			`{"status":"pending","clarification":"Why do you need write access?","timeout":30,"options":["create event","cancel"]}`,
		), nil
	}
	result, err := harness.client(t).BeginExchange(context.Background(), agent.ExchangeRequest{
		PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
		Capabilities: []string{"clarification"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Failure() != nil {
		t.Fatalf("Failure = %v", result.Failure())
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatal("BeginExchange did not return pending clarification")
	}
	question, ok := pending.Clarification()
	if !ok || question.Question() != "Why do you need write access?" {
		t.Fatalf("Clarification = %#v, %t", question, ok)
	}
	if timeout, ok := question.Timeout(); !ok || timeout != 30*time.Second {
		t.Fatalf("Timeout = %s, %t", timeout, ok)
	}
	options := question.Options()
	if len(options) != 2 || options[0] != "create event" || options[1] != "cancel" {
		t.Fatalf("Options = %#v", options)
	}
	options[0] = "mutated"
	if got := question.Options(); got[0] != "create event" {
		t.Fatalf("Options alias internal storage: %#v", got)
	}
	if next, _ := pending.Clarification(); next.Options()[0] != "create event" {
		t.Fatal("PendingExchange returned aliased clarification options")
	}

	harness = newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangeClarificationResponse(
			request,
			`{"status":"pending","clarification":"Anything else?"}`,
		), nil
	}
	result, err = harness.client(t).BeginExchange(context.Background(), agent.ExchangeRequest{
		PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
		Capabilities: []string{"clarification"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, _ = result.Pending()
	question, _ = pending.Clarification()
	if timeout, ok := question.Timeout(); ok || timeout != 0 {
		t.Fatalf("absent Timeout = %s, %t", timeout, ok)
	}
	if options := question.Options(); options != nil {
		t.Fatalf("absent Options = %#v", options)
	}
}

func TestPendingExchangeSnapshotRestoresExactClarificationWithANewClient(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangeClarificationResponse(
			request,
			`{"status":"pending","clarification":"Why?","timeout":30,"options":["explain","cancel"]}`,
		), nil
	}
	client := harness.client(t)
	pending := beginExchangeClarification(t, client, harness)
	snapshot, err := pending.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"resource_token"`)) {
		t.Fatalf("snapshot omitted its Resource-token credential: %s", encoded)
	}
	var stored agent.PendingExchangeSnapshot
	if err := json.Unmarshal(encoded, &stored); err != nil {
		t.Fatal(err)
	}

	client = nil
	pending = agent.PendingExchange{}
	beforeMetadata := harness.metadataCalls
	beforeInitial := harness.initialCalls
	beforePoll := harness.pollCalls
	beforeAction := harness.actionCalls
	resolver := &recordingKeyResolver{delegate: harness.protocol.resolver}
	restoredClient, err := agent.New(context.Background(), agent.Config{
		Identifier: harness.protocol.agentID, SigningKey: harness.protocol.agentKey,
		AgentToken: harness.protocol.agentToken, KeyResolver: resolver,
		HTTPClient: &http.Client{Transport: roundTripperFunc(harness.roundTrip)}, Clock: harness.protocol.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver.references = nil
	restored, err := restoredClient.RestorePendingExchange(context.Background(), stored)
	if err != nil {
		t.Fatal(err)
	}
	if harness.metadataCalls != beforeMetadata+1 || harness.initialCalls != beforeInitial ||
		harness.pollCalls != beforePoll || harness.actionCalls != beforeAction {
		t.Fatalf("restore calls: metadata=%d initial=%d poll=%d action=%d",
			harness.metadataCalls, harness.initialCalls, harness.pollCalls, harness.actionCalls)
	}
	if len(resolver.references) != 2 ||
		resolver.references[0].DiscoveryDocument != aauth.AgentDiscoveryDocument ||
		resolver.references[1].DiscoveryDocument != aauth.ResourceDiscoveryDocument {
		t.Fatalf("restore key resolutions = %#v", resolver.references)
	}
	if restored.PersonServer() != harness.protocol.personServerID ||
		restored.Location() != harness.protocol.personServerID+"/pending/exchange-1" ||
		restored.Requirement() != aauth.RequirementClarification {
		t.Fatalf("restored pending = %#v", restored)
	}
	question, ok := restored.Clarification()
	if !ok || question.Question() != "Why?" {
		t.Fatalf("restored clarification = %#v, %t", question, ok)
	}
	if timeout, ok := question.Timeout(); !ok || timeout != 30*time.Second {
		t.Fatalf("restored timeout = %s, %t", timeout, ok)
	}
	if answerBefore, ok := question.AnswerBefore(); !ok || !answerBefore.Equal(harness.protocol.now.Add(30*time.Second)) {
		t.Fatalf("restored answer-before = %s, %t", answerBefore, ok)
	}
	if got := question.Options(); len(got) != 2 || got[0] != "explain" || got[1] != "cancel" {
		t.Fatalf("restored options = %#v", got)
	}
}

func TestRestorePendingExchangeRestoresMissionBoundResourceContext(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	missionS256 := aauth.MissionS256([]byte("approved pending exchange mission"))
	harness.resourceClaims.MissionS256 = missionS256
	harness.resourceClaims.Tenant = "tenant-7"
	var err error
	harness.resourceToken, err = aauth.MintResourceToken(harness.protocol.resourceKey, harness.resourceClaims)
	if err != nil {
		t.Fatal(err)
	}
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangePendingResponse(request, "/pending/mission-exchange", "0", "pending"), nil
	}
	harness.poll = []func(*http.Request) (*http.Response, error){func(request *http.Request) (*http.Response, error) {
		return harness.authTokenResponse(request, func(claims *aauth.AuthTokenClaims) {
			claims.MissionS256 = missionS256
			claims.Tenant = harness.resourceClaims.Tenant
		}), nil
	}}
	client := harness.client(t)
	pending := beginExchangeInteraction(t, client, harness)
	snapshot, err := pending.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var stored agent.PendingExchangeSnapshot
	if err := json.Unmarshal(encoded, &stored); err != nil {
		t.Fatal(err)
	}
	restored, err := client.RestorePendingExchange(context.Background(), stored)
	if err != nil {
		t.Fatal(err)
	}
	restoredSnapshot, err := restored.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if stored.ResourceToken != harness.resourceToken || restoredSnapshot.ResourceToken != harness.resourceToken {
		t.Fatal("mission restore did not preserve the exact Resource token")
	}
	completed, err := client.PollExchange(context.Background(), restored)
	if err != nil {
		t.Fatal(err)
	}
	authToken, ok := completed.Token()
	if !ok {
		t.Fatal("restored mission exchange did not return an Auth token")
	}
	authClaims, err := aauth.VerifyAuthToken(context.Background(), authToken, harness.protocol.resolver, harness.protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.MissionS256 != missionS256 || authClaims.Tenant != harness.resourceClaims.Tenant {
		t.Fatalf("restored mission claims = %#v", authClaims)
	}
}

func TestRestorePendingExchangeStillRejectsUnrelatedResourceProfiles(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
	}
	client := harness.client(t)
	pending := beginExchangeInteraction(t, client, harness)
	snapshot, err := pending.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		change func(*aauth.ResourceTokenClaims)
	}{
		{name: "interaction", change: func(claims *aauth.ResourceTokenClaims) {
			claims.Interaction = &aauth.ResourceInteraction{URL: exchangeInteractionURL, Code: exchangeInteractionCode}
		}},
		{name: "account", change: func(claims *aauth.ResourceTokenClaims) {
			account := "account-123"
			claims.Account = &account
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			claims := harness.resourceClaims
			test.change(&claims)
			resourceToken, err := aauth.MintResourceToken(harness.protocol.resourceKey, claims)
			if err != nil {
				t.Fatal(err)
			}
			changed := snapshot
			changed.ResourceToken = resourceToken
			if _, err := client.RestorePendingExchange(context.Background(), changed); err == nil ||
				!strings.Contains(err.Error(), "outside the direct pending-exchange profile") {
				t.Fatalf("RestorePendingExchange error = %v", err)
			}
		})
	}
}

func TestRestorePendingExchangeReverifiesTokenIdentityOriginShapeAndCapabilities(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangeClarificationResponse(request, `{"status":"pending","clarification":"Why?","timeout":30}`), nil
	}
	pending := beginExchangeClarification(t, harness.client(t), harness)
	snapshot, err := pending.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	client := harness.client(t)
	beforeInitial := harness.initialCalls
	beforePoll := harness.pollCalls
	beforeAction := harness.actionCalls

	for _, test := range []struct {
		name   string
		change func(*agent.PendingExchangeSnapshot)
	}{
		{name: "resource token", change: func(s *agent.PendingExchangeSnapshot) { s.ResourceToken += "x" }},
		{name: "agent provider", change: func(s *agent.PendingExchangeSnapshot) { s.AgentProvider = "https://other-ap.example" }},
		{name: "agent", change: func(s *agent.PendingExchangeSnapshot) { s.Agent = "aauth:other@ap.example" }},
		{name: "person server", change: func(s *agent.PendingExchangeSnapshot) { s.PersonServer = "https://other-ps.example" }},
		{name: "off-origin location", change: func(s *agent.PendingExchangeSnapshot) { s.Location = "https://other.example/pending/1" }},
		{name: "missing capability", change: func(s *agent.PendingExchangeSnapshot) { s.Capabilities = nil }},
		{name: "contradictory action shape", change: func(s *agent.PendingExchangeSnapshot) { s.Requirement = aauth.RequirementApproval }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			changed := snapshot
			changed.Capabilities = append([]string(nil), snapshot.Capabilities...)
			changed.ClarificationOptions = append([]string(nil), snapshot.ClarificationOptions...)
			test.change(&changed)
			if _, err := client.RestorePendingExchange(context.Background(), changed); err == nil {
				t.Fatal("RestorePendingExchange accepted a modified snapshot")
			}
		})
	}
	if harness.initialCalls != beforeInitial || harness.pollCalls != beforePoll || harness.actionCalls != beforeAction {
		t.Fatalf("invalid restores used consequence endpoints: initial=%d poll=%d action=%d",
			harness.initialCalls, harness.pollCalls, harness.actionCalls)
	}

	harness.protocol.now = harness.protocol.now.Add(21 * time.Minute)
	currentClient := harness.client(t)
	if _, err := currentClient.RestorePendingExchange(context.Background(), snapshot); err == nil {
		t.Fatal("RestorePendingExchange accepted an expired Resource token")
	}
	if harness.initialCalls != beforeInitial || harness.pollCalls != beforePoll || harness.actionCalls != beforeAction {
		t.Fatalf("expired restore used consequence endpoints: initial=%d poll=%d action=%d",
			harness.initialCalls, harness.pollCalls, harness.actionCalls)
	}
}

func TestRestorePendingExchangeRequiresCurrentAgentKey(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangeClarificationResponse(request, `{"status":"pending","clarification":"Why?"}`), nil
	}
	pending := beginExchangeClarification(t, harness.client(t), harness)
	snapshot, err := pending.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	other := newTestProtocol(t)
	other.agentKey = testSigningKey(t, "restore-other-agent-key", 96)
	other.agentToken, err = aauth.MintAgentToken(
		other.agentProviderID,
		other.agentProviderKey,
		aauth.AgentTokenRequest{
			Agent: other.agentID, PersonServer: other.personServerID,
			PublicKey: other.agentKey.PublicJWK(), Lifetime: time.Hour,
		},
		other.now,
		"restore-other-agent-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	otherClient := other.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected HTTP")
	})})
	if _, err := otherClient.RestorePendingExchange(context.Background(), snapshot); err == nil {
		t.Fatal("RestorePendingExchange accepted a different current Agent key")
	}
	if calls != 0 {
		t.Fatalf("restore used HTTP: %d calls", calls)
	}
}

func TestAnswerClarificationRejectsAtObservedTimeoutBeforeNetwork(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	observedAt := harness.protocol.now
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangeClarificationResponse(request, `{"status":"pending","clarification":"Why?","timeout":5}`), nil
	}
	harness.action = func(request *http.Request) (*http.Response, error) {
		return emptyResponse(request, http.StatusOK), nil
	}
	client := harness.client(t)
	pending := beginExchangeClarification(t, client, harness)
	question, _ := pending.Clarification()
	answerBefore, ok := question.AnswerBefore()
	if !ok || !answerBefore.Equal(observedAt.Add(5*time.Second)) {
		t.Fatalf("AnswerBefore = %s, %t", answerBefore, ok)
	}
	harness.protocol.now = observedAt.Add(4 * time.Second)
	if err := client.AnswerClarification(context.Background(), pending, "before"); err != nil {
		t.Fatal(err)
	}
	harness.protocol.now = answerBefore
	if err := client.AnswerClarification(context.Background(), pending, "at deadline"); err == nil ||
		!strings.Contains(err.Error(), "answer deadline") {
		t.Fatalf("deadline error = %v", err)
	}
	if err := client.CancelClarification(context.Background(), pending); err == nil ||
		!strings.Contains(err.Error(), "response deadline") {
		t.Fatalf("late cancellation error = %v", err)
	}
	if harness.actionCalls != 1 {
		t.Fatalf("deadline answer used network: %d action calls", harness.actionCalls)
	}
}

func TestExchangeClarificationRequiresDeclaredCapabilityOnBeginAndPoll(t *testing.T) {
	t.Run("begin", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		harness.initial = func(request *http.Request) (*http.Response, error) {
			return validExchangeClarificationResponse(request, `{"status":"pending","clarification":"Why?"}`), nil
		}
		if _, err := harness.client(t).BeginExchange(context.Background(), agent.ExchangeRequest{
			PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
		}); err == nil || !strings.Contains(err.Error(), "declared clarification capability") {
			t.Fatalf("BeginExchange error = %v", err)
		}
		if harness.networkCalls != 2 {
			t.Fatalf("network calls = %d, want metadata plus initial request", harness.networkCalls)
		}
	})

	t.Run("poll", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		harness.initial = func(request *http.Request) (*http.Response, error) {
			response := validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending")
			response.Header.Del("AAuth-Requirement")
			return response, nil
		}
		harness.poll = []func(*http.Request) (*http.Response, error){func(request *http.Request) (*http.Response, error) {
			return validExchangeClarificationResponse(request, `{"status":"pending","clarification":"Why?"}`), nil
		}}
		client := harness.client(t)
		result, err := client.BeginExchange(context.Background(), agent.ExchangeRequest{
			PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
		})
		if err != nil {
			t.Fatal(err)
		}
		pending, _ := result.Pending()
		if _, err := client.PollExchange(context.Background(), pending); err == nil ||
			!strings.Contains(err.Error(), "declared clarification capability") {
			t.Fatalf("PollExchange error = %v", err)
		}
		if harness.pollCalls != 1 {
			t.Fatalf("poll calls = %d", harness.pollCalls)
		}
	})
}

func TestExchangeClarificationPollClearsOmittedRequirementAndPreservesContinuationIdentity(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangeClarificationResponse(request, `{"status":"pending","clarification":"First?"}`), nil
	}
	harness.poll = []func(*http.Request) (*http.Response, error){
		func(request *http.Request) (*http.Response, error) {
			response := validExchangePendingResponse(request, "/pending/exchange-1", "9", "interacting")
			response.Header.Del("AAuth-Requirement")
			return response, nil
		},
		func(request *http.Request) (*http.Response, error) {
			return validExchangeClarificationResponseAt(
				request,
				"/pending/substituted",
				`{"status":"pending","clarification":"Second?"}`,
			), nil
		},
	}
	client := harness.client(t)
	pending := beginExchangeClarification(t, client, harness)
	first, err := client.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	next, ok := first.Pending()
	if !ok || next.Location() != pending.Location() {
		t.Fatalf("pending location = %q, want %q", next.Location(), pending.Location())
	}
	if next.Requirement() != "" || !next.Interacting() {
		t.Fatalf("fresh pending requirement = %q, interacting = %t", next.Requirement(), next.Interacting())
	}
	if question, ok := next.Clarification(); ok || question != (agent.ClarificationQuestion{}) {
		t.Fatalf("stale clarification = %#v, %t", question, ok)
	}
	if _, err := client.PollExchange(context.Background(), next); err == nil ||
		!strings.Contains(err.Error(), "pending exchange Location changed") {
		t.Fatalf("changed Location error = %v", err)
	}
}

func TestAnswerClarificationPostsOneSignedExactResponse(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangeClarificationResponse(request, `{"status":"pending","clarification":"Why?"}`), nil
	}
	harness.action = func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.String() != harness.protocol.personServerID+"/pending/exchange-1" {
			t.Fatalf("action = %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Content-Digest") == "" {
			t.Fatalf("action headers = %#v", request.Header)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(body), `{"action":"clarification_response","clarification_response":"Because the calendar owner asked me to."}`; got != want {
			t.Fatalf("body = %s, want %s", got, want)
		}
		return emptyResponse(request, http.StatusNoContent), nil
	}
	client := harness.client(t)
	pending := beginExchangeClarification(t, client, harness)
	if err := client.AnswerClarification(context.Background(), pending, "Because the calendar owner asked me to."); err != nil {
		t.Fatal(err)
	}
	if harness.actionCalls != 1 || harness.pollCalls != 0 {
		t.Fatalf("calls: action=%d poll=%d", harness.actionCalls, harness.pollCalls)
	}
}

func TestCancelClarificationDeletesOnceWithoutABody(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangeClarificationResponse(request, `{"status":"pending","clarification":"Why?"}`), nil
	}
	harness.action = func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodDelete || request.URL.String() != harness.protocol.personServerID+"/pending/exchange-1" {
			t.Fatalf("action = %s %s", request.Method, request.URL)
		}
		if request.Body != nil && request.Body != http.NoBody {
			t.Fatal("DELETE carried a body")
		}
		if request.ContentLength != 0 || request.GetBody != nil || request.Header.Get("Content-Type") != "" ||
			request.Header.Get("Content-Digest") != "" {
			t.Fatalf("DELETE body metadata = length %d hasGetBody %t headers %#v", request.ContentLength, request.GetBody != nil, request.Header)
		}
		return emptyResponse(request, http.StatusNoContent), nil
	}
	client := harness.client(t)
	pending := beginExchangeClarification(t, client, harness)
	if err := client.CancelClarification(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	if harness.actionCalls != 1 || harness.pollCalls != 0 {
		t.Fatalf("calls: action=%d poll=%d", harness.actionCalls, harness.pollCalls)
	}
}

func TestClarificationActionsAcceptAny2xxResponse(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusNoContent, 299} {
		status := status
		for _, operation := range []string{"answer", "cancel"} {
			operation := operation
			t.Run(fmt.Sprintf("%s/%d", operation, status), func(t *testing.T) {
				harness := newExchangeInteractionHarness(t)
				harness.initial = func(request *http.Request) (*http.Response, error) {
					return validExchangeClarificationResponse(request, `{"status":"pending","clarification":"Why?"}`), nil
				}
				harness.action = func(request *http.Request) (*http.Response, error) {
					return emptyResponse(request, status), nil
				}
				client := harness.client(t)
				pending := beginExchangeClarification(t, client, harness)
				var err error
				if operation == "answer" {
					err = client.AnswerClarification(context.Background(), pending, "answer")
				} else {
					err = client.CancelClarification(context.Background(), pending)
				}
				if err != nil {
					t.Fatal(err)
				}
				if harness.actionCalls != 1 || harness.pollCalls != 0 {
					t.Fatalf("calls: action=%d poll=%d", harness.actionCalls, harness.pollCalls)
				}
			})
		}
	}
}

func TestCancelClarificationRequiresAnActiveClarificationBeforeNetwork(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		response := validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending")
		response.Header.Del("AAuth-Requirement")
		return response, nil
	}
	client := harness.client(t)
	result, err := client.BeginExchange(context.Background(), agent.ExchangeRequest{
		PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
		Capabilities: []string{"clarification"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, _ := result.Pending()
	before := harness.networkCalls
	if err := client.CancelClarification(context.Background(), pending); err == nil ||
		!strings.Contains(err.Error(), "pending clarification is required") {
		t.Fatalf("CancelClarification error = %v", err)
	}
	if harness.networkCalls != before {
		t.Fatalf("inactive cancellation used network: calls=%d, want %d", harness.networkCalls, before)
	}
}

func TestExchangeClarificationActionsRejectInvalidInputsBeforeNetwork(t *testing.T) {
	t.Run("answer text", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		client := harness.client(t)
		for _, answer := range []string{"", " \n\t", strings.Repeat("x", (64<<10)+1)} {
			if err := client.AnswerClarification(context.Background(), agent.PendingExchange{}, answer); err == nil {
				t.Fatalf("AnswerClarification accepted answer length %d", len(answer))
			}
		}
		if harness.networkCalls != 0 {
			t.Fatalf("invalid answers used network: %d calls", harness.networkCalls)
		}
	})

	t.Run("zero pending", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		client := harness.client(t)
		if err := client.AnswerClarification(context.Background(), agent.PendingExchange{}, "answer"); err == nil {
			t.Fatal("AnswerClarification accepted zero pending")
		}
		if err := client.CancelClarification(context.Background(), agent.PendingExchange{}); err == nil {
			t.Fatal("CancelClarification accepted zero pending")
		}
		if harness.networkCalls != 0 {
			t.Fatalf("zero pending used network: %d calls", harness.networkCalls)
		}
	})
}

func TestExchangeClarificationActionsBindClientIdentityAndKey(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangeClarificationResponse(request, `{"status":"pending","clarification":"Why?"}`), nil
	}
	pending := beginExchangeClarification(t, harness.client(t), harness)

	for _, differentKey := range []bool{false, true} {
		differentKey := differentKey
		t.Run(map[bool]string{false: "identity", true: "key"}[differentKey], func(t *testing.T) {
			other := newTestProtocol(t)
			if differentKey {
				other.agentKey = testSigningKey(t, "clarification-other-agent-key", 97)
			} else {
				other.agentID = "aauth:clarification-other@ap.example"
			}
			var err error
			other.agentToken, err = aauth.MintAgentToken(
				other.agentProviderID,
				other.agentProviderKey,
				aauth.AgentTokenRequest{
					Agent: other.agentID, PersonServer: other.personServerID,
					PublicKey: other.agentKey.PublicJWK(), Lifetime: time.Hour,
				},
				other.now,
				"clarification-other-agent-token",
			)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			otherClient := other.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("unexpected network")
			})})
			if err := otherClient.AnswerClarification(context.Background(), pending, "answer"); err == nil {
				t.Fatal("AnswerClarification accepted a different client")
			}
			if err := otherClient.CancelClarification(context.Background(), pending); err == nil {
				t.Fatal("CancelClarification accepted a different client")
			}
			if calls != 0 {
				t.Fatalf("different client used network: %d calls", calls)
			}
		})
	}
}

func TestExchangeClarificationActionsPreserveTypedServerProblemsWithoutRetry(t *testing.T) {
	for _, operation := range []string{"answer", "cancel"} {
		operation := operation
		t.Run(operation, func(t *testing.T) {
			harness := newExchangeInteractionHarness(t)
			harness.initial = func(request *http.Request) (*http.Response, error) {
				return validExchangeClarificationResponse(request, `{"status":"pending","clarification":"Why?"}`), nil
			}
			harness.action = func(request *http.Request) (*http.Response, error) {
				return problemResponse(request, &aauth.ProblemError{
					Status: http.StatusConflict, Code: "clarification_conflict", Detail: "question changed",
				}), nil
			}
			client := harness.client(t)
			pending := beginExchangeClarification(t, client, harness)
			var err error
			if operation == "answer" {
				err = client.AnswerClarification(context.Background(), pending, "answer")
			} else {
				err = client.CancelClarification(context.Background(), pending)
			}
			var problem *aauth.ProblemError
			if !errors.As(err, &problem) || problem.Status != http.StatusConflict || problem.Code != "clarification_conflict" {
				t.Fatalf("error = %v, problem = %#v", err, problem)
			}
			if harness.actionCalls != 1 {
				t.Fatalf("action calls = %d, want one", harness.actionCalls)
			}
		})
	}
}

func TestExchangeClarificationActionsDoNotFollowRedirects(t *testing.T) {
	for _, operation := range []string{"answer", "cancel"} {
		operation := operation
		t.Run(operation, func(t *testing.T) {
			harness := newExchangeInteractionHarness(t)
			harness.initial = func(request *http.Request) (*http.Response, error) {
				return validExchangeClarificationResponse(request, `{"status":"pending","clarification":"Why?"}`), nil
			}
			harness.action = func(request *http.Request) (*http.Response, error) {
				response := emptyResponse(request, http.StatusTemporaryRedirect)
				response.Header.Set("Location", "/pending/redirected")
				return response, nil
			}
			client := harness.client(t)
			pending := beginExchangeClarification(t, client, harness)
			var err error
			if operation == "answer" {
				err = client.AnswerClarification(context.Background(), pending, "answer")
			} else {
				err = client.CancelClarification(context.Background(), pending)
			}
			if err == nil {
				t.Fatalf("error = %v", err)
			}
			if harness.actionCalls != 1 {
				t.Fatalf("action calls = %d, want one", harness.actionCalls)
			}
		})
	}
}

func TestExchangeInteractionResolvesPendingAgainstTokenEndpointOrigin(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.protocol.authTokenEndpoint = "https://token.ps-edge.example/v2/token"
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangePendingResponse(request, "pending/exchange-1", "0", "pending"), nil
	}
	client := harness.client(t)
	result, err := client.BeginExchange(context.Background(), agent.ExchangeRequest{
		PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
		Capabilities: []string{"interaction"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, _ := result.Pending()
	if pending.Location() != "https://token.ps-edge.example/v2/pending/exchange-1" {
		t.Fatalf("Location = %q", pending.Location())
	}
}

func TestExchangeInteractionPollsExactlyOncePerInvocation(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
	}
	harness.poll = []func(*http.Request) (*http.Response, error){
		func(request *http.Request) (*http.Response, error) {
			return validExchangePendingResponse(request, "/pending/exchange-1", "9", "interacting"), nil
		},
		func(request *http.Request) (*http.Response, error) {
			return harness.authTokenResponse(request, nil), nil
		},
	}
	client := harness.client(t)
	pending := beginExchangeInteraction(t, client, harness)

	result, err := client.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	interacting, ok := result.Pending()
	if !ok || !interacting.Interacting() || interacting.RetryAfter() != 9*time.Second {
		t.Fatalf("first poll = %#v, pending=%t", interacting, ok)
	}
	if harness.pollCalls != 1 {
		t.Fatalf("first invocation made %d polls", harness.pollCalls)
	}
	result, err = client.PollExchange(context.Background(), interacting)
	if err != nil {
		t.Fatal(err)
	}
	token, ok := result.Token()
	if !ok || token == "" {
		t.Fatalf("terminal result token = %q, %t", token, ok)
	}
	if harness.pollCalls != 2 || harness.metadataCalls != 1 {
		t.Fatalf("calls: metadata=%d poll=%d", harness.metadataCalls, harness.pollCalls)
	}
}

func TestExchangeInteractionRequiresDeclaredValidCapability(t *testing.T) {
	t.Run("undeclared interaction", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		harness.initial = func(request *http.Request) (*http.Response, error) {
			return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
		}
		client := harness.client(t)
		if _, err := client.BeginExchange(context.Background(), agent.ExchangeRequest{
			PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
		}); err == nil {
			t.Fatal("BeginExchange accepted interaction without capability")
		}
		if harness.initialCalls != 1 || harness.pollCalls != 0 {
			t.Fatalf("calls: initial=%d poll=%d", harness.initialCalls, harness.pollCalls)
		}
	})

	t.Run("immediate-only Exchange does not follow pending", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		harness.initial = func(request *http.Request) (*http.Response, error) {
			return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
		}
		client := harness.client(t)
		if _, err := client.Exchange(context.Background(), agent.ExchangeRequest{
			PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
			Capabilities: []string{"interaction"},
		}); err == nil {
			t.Fatal("Exchange accepted a pending response")
		}
		if harness.initialCalls != 1 || harness.pollCalls != 0 {
			t.Fatalf("calls: initial=%d poll=%d", harness.initialCalls, harness.pollCalls)
		}
	})

	for _, capabilities := range [][]string{{""}, {"interaction", "interaction"}, {"not a token"}} {
		capabilities := capabilities
		t.Run(strings.Join(capabilities, "+"), func(t *testing.T) {
			harness := newExchangeInteractionHarness(t)
			client := harness.client(t)
			if _, err := client.BeginExchange(context.Background(), agent.ExchangeRequest{
				PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
				Capabilities: capabilities,
			}); err == nil {
				t.Fatal("BeginExchange accepted malformed capabilities")
			}
			if harness.networkCalls != 0 {
				t.Fatalf("malformed capability used network: %d calls", harness.networkCalls)
			}
		})
	}
}

func TestExchangeInteractionBindsPendingToStableClientIdentity(t *testing.T) {
	harness := newExchangeInteractionHarness(t)
	harness.initial = func(request *http.Request) (*http.Response, error) {
		return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
	}
	client := harness.client(t)
	pending := beginExchangeInteraction(t, client, harness)
	before := harness.networkCalls
	if _, err := client.PollExchange(context.Background(), agent.PendingExchange{}); err == nil {
		t.Fatal("zero pending was accepted")
	}
	if harness.networkCalls != before {
		t.Fatal("zero pending used network")
	}
	harness.poll = []func(*http.Request) (*http.Response, error){func(request *http.Request) (*http.Response, error) {
		return harness.authTokenResponse(request, nil), nil
	}}
	recomposed := harness.client(t)
	result, err := recomposed.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatalf("equivalent recomposed Client could not poll: %v", err)
	}
	if token, ok := result.Token(); !ok || token == "" {
		t.Fatalf("recomposed Client result token = %q, %t", token, ok)
	}

	for _, differentKey := range []bool{false, true} {
		differentKey := differentKey
		t.Run(map[bool]string{false: "different identity", true: "different key"}[differentKey], func(t *testing.T) {
			other := newTestProtocol(t)
			if differentKey {
				other.agentKey = testSigningKey(t, "other-agent-key", 99)
			} else {
				other.agentID = "aauth:other@ap.example"
			}
			var err error
			other.agentToken, err = aauth.MintAgentToken(
				other.agentProviderID, other.agentProviderKey,
				aauth.AgentTokenRequest{
					Agent: other.agentID, PersonServer: other.personServerID,
					PublicKey: other.agentKey.PublicJWK(), Lifetime: time.Hour,
				},
				other.now,
				"other-agent-token",
			)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			otherClient := other.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("unexpected network")
			})})
			if _, err := otherClient.PollExchange(context.Background(), pending); err == nil {
				t.Fatal("pending was accepted by a different stable identity")
			}
			if calls != 0 {
				t.Fatalf("different client used network: %d calls", calls)
			}
		})
	}
}

func TestExchangeInteractionRejectsMalformedPendingResponses(t *testing.T) {
	tests := []struct {
		name   string
		change func(*http.Response)
	}{
		{name: "missing Location", change: func(r *http.Response) { r.Header.Del("Location") }},
		{name: "off-origin Location", change: func(r *http.Response) { r.Header.Set("Location", "https://other.example/pending/1") }},
		{name: "multiple Retry-After", change: func(r *http.Response) { r.Header["Retry-After"] = []string{"0", "1"} }},
		{name: "fractional Retry-After", change: func(r *http.Response) { r.Header.Set("Retry-After", "0.5") }},
		{name: "missing no-store", change: func(r *http.Response) { r.Header.Del("Cache-Control") }},
		{name: "wrong content type", change: func(r *http.Response) { r.Header.Set("Content-Type", "text/plain") }},
		{name: "blank status", change: func(r *http.Response) { r.Body = io.NopCloser(strings.NewReader(`{"status":""}`)) }},
		{name: "malformed body", change: func(r *http.Response) { r.Body = io.NopCloser(strings.NewReader(`{"status":`)) }},
		{name: "oversized body", change: func(r *http.Response) {
			r.Body = io.NopCloser(strings.NewReader(`{"status":"` + strings.Repeat("x", (1<<20)+1) + `"}`))
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			harness := newExchangeInteractionHarness(t)
			harness.initial = func(request *http.Request) (*http.Response, error) {
				response := validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending")
				test.change(response)
				return response, nil
			}
			client := harness.client(t)
			if _, err := client.BeginExchange(context.Background(), agent.ExchangeRequest{
				PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
				Capabilities: []string{"interaction"},
			}); err == nil {
				t.Fatal("BeginExchange accepted malformed pending response")
			}
			if harness.pollCalls != 0 {
				t.Fatalf("malformed pending response triggered %d polls", harness.pollCalls)
			}
		})
	}
}

func TestExchangeInteractionPreservesInteractionAndMonotonicState(t *testing.T) {
	t.Run("monotonic and omitted requirement", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		harness.initial = func(request *http.Request) (*http.Response, error) {
			return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
		}
		harness.poll = []func(*http.Request) (*http.Response, error){
			func(request *http.Request) (*http.Response, error) {
				return validExchangePendingResponse(request, "/pending/exchange-1", "0", "interacting"), nil
			},
			func(request *http.Request) (*http.Response, error) {
				response := validExchangePendingResponse(request, "/pending/exchange-1", "2", "future-status")
				response.Header.Del("AAuth-Requirement")
				return response, nil
			},
		}
		client := harness.client(t)
		pending := beginExchangeInteraction(t, client, harness)
		first, err := client.PollExchange(context.Background(), pending)
		if err != nil {
			t.Fatal(err)
		}
		interacting, _ := first.Pending()
		second, err := client.PollExchange(context.Background(), interacting)
		if err != nil {
			t.Fatal(err)
		}
		next, ok := second.Pending()
		if !ok || !next.Interacting() || next.Requirement() != "" ||
			next.InteractionURL() != "" || next.InteractionCode() != "" {
			t.Fatalf("next pending = %#v, ok=%t", next, ok)
		}
	})

	t.Run("fresh interaction replaces prior interaction", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		harness.initial = func(request *http.Request) (*http.Response, error) {
			return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
		}
		harness.poll = []func(*http.Request) (*http.Response, error){func(request *http.Request) (*http.Response, error) {
			response := validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending")
			value, _ := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{
				URL: "https://ps.example/other-interaction", Code: "ABCDEFGH",
			})
			response.Header.Set("AAuth-Requirement", value)
			return response, nil
		}}
		client := harness.client(t)
		pending := beginExchangeInteraction(t, client, harness)
		result, err := client.PollExchange(context.Background(), pending)
		if err != nil {
			t.Fatal(err)
		}
		next, ok := result.Pending()
		if !ok || next.InteractionURL() != "https://ps.example/other-interaction" ||
			next.InteractionCode() != "ABCDEFGH" {
			t.Fatalf("replacement interaction = %#v, %t", next, ok)
		}
		if harness.pollCalls != 1 {
			t.Fatalf("poll calls = %d", harness.pollCalls)
		}
	})

	t.Run("fresh interaction owns its code representation", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		harness.initial = func(request *http.Request) (*http.Response, error) {
			return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
		}
		harness.poll = []func(*http.Request) (*http.Response, error){func(request *http.Request) (*http.Response, error) {
			response := validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending")
			value, _ := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{
				URL: exchangeInteractionURL, Code: "A1B2C3D4",
			})
			response.Header.Set("AAuth-Requirement", value)
			return response, nil
		}}
		client := harness.client(t)
		pending := beginExchangeInteraction(t, client, harness)
		result, err := client.PollExchange(context.Background(), pending)
		if err != nil {
			t.Fatal(err)
		}
		next, _ := result.Pending()
		if next.InteractionCode() != "A1B2C3D4" {
			t.Fatalf("display code = %q", next.InteractionCode())
		}
	})
}

func TestExchangeInteractionRetryResponsesContinuePendingState(t *testing.T) {
	for _, test := range []struct {
		status     int
		retryAfter string
		want       time.Duration
	}{
		{status: http.StatusTooManyRequests, retryAfter: "99", want: 12 * time.Second},
		{status: http.StatusServiceUnavailable, retryAfter: "", want: 5 * time.Second},
		{status: http.StatusServiceUnavailable, retryAfter: "11", want: 11 * time.Second},
	} {
		harness := newExchangeInteractionHarness(t)
		harness.initial = func(request *http.Request) (*http.Response, error) {
			return validExchangePendingResponse(request, "/pending/exchange-1", "7", "pending"), nil
		}
		harness.poll = []func(*http.Request) (*http.Response, error){func(request *http.Request) (*http.Response, error) {
			response := &http.Response{StatusCode: test.status, Request: request, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("retry"))}
			if test.retryAfter != "" {
				response.Header.Set("Retry-After", test.retryAfter)
			}
			return response, nil
		}}
		client := harness.client(t)
		pending := beginExchangeInteraction(t, client, harness)
		result, err := client.PollExchange(context.Background(), pending)
		if err != nil {
			t.Fatal(err)
		}
		response, responseOK := result.Response()
		next, pendingOK := result.Pending()
		if !responseOK || !pendingOK || next.RetryAfter() != test.want {
			t.Fatalf("response=%t pending=%t retry=%s want=%s", responseOK, pendingOK, next.RetryAfter(), test.want)
		}
		response.Body.Close()
	}
}

func TestExchangeInteractionReturnsCallerOwnedRetryableResponses(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			harness := newExchangeInteractionHarness(t)
			harness.initial = func(request *http.Request) (*http.Response, error) {
				return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
			}
			harness.poll = []func(*http.Request) (*http.Response, error){func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status, Status: http.StatusText(status), Request: request,
					Header: http.Header{"Retry-After": []string{"13"}, "Content-Type": []string{"text/plain"}},
					Body:   io.NopCloser(strings.NewReader("retry body")),
				}, nil
			}}
			client := harness.client(t)
			pending := beginExchangeInteraction(t, client, harness)
			result, err := client.PollExchange(context.Background(), pending)
			if err != nil {
				t.Fatal(err)
			}
			response, ok := result.Response()
			if !ok || response.StatusCode != status || response.Header.Get("Retry-After") != "13" {
				t.Fatalf("response = %#v, ok=%t", response, ok)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if string(body) != "retry body" {
				t.Fatalf("body = %q", body)
			}
		})
	}
}

func TestExchangeInteractionPreservesTypedTerminalProblems(t *testing.T) {
	for _, test := range []struct {
		status int
		code   aauth.ErrorCode
	}{{http.StatusForbidden, "denied"}, {http.StatusRequestTimeout, "expired"}, {http.StatusGone, "invalid_code"}} {
		test := test
		t.Run(string(test.code), func(t *testing.T) {
			harness := newExchangeInteractionHarness(t)
			harness.initial = func(request *http.Request) (*http.Response, error) {
				return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
			}
			harness.poll = []func(*http.Request) (*http.Response, error){func(request *http.Request) (*http.Response, error) {
				return problemResponse(request, &aauth.ProblemError{Status: test.status, Code: test.code, Detail: "terminal"}), nil
			}}
			client := harness.client(t)
			pending := beginExchangeInteraction(t, client, harness)
			_, err := client.PollExchange(context.Background(), pending)
			var problem *aauth.ProblemError
			if !errors.As(err, &problem) || problem.Status != test.status || problem.Code != test.code {
				t.Fatalf("error = %v, problem = %#v", err, problem)
			}
			if harness.pollCalls != 1 {
				t.Fatalf("poll calls = %d", harness.pollCalls)
			}
		})
	}
}

func TestExchangeInteractionRejectsSubstitutedAuthTokens(t *testing.T) {
	otherKey := testSigningKey(t, "other-agent-key", 98)
	tests := []struct {
		name   string
		change func(*aauth.AuthTokenClaims)
	}{
		{name: "resource", change: func(c *aauth.AuthTokenClaims) { c.Audience = "https://other-resource.example" }},
		{name: "person", change: func(c *aauth.AuthTokenClaims) { c.Subject = "other-person" }},
		{name: "person server", change: func(c *aauth.AuthTokenClaims) { c.PersonServer = "https://other-ps.example" }},
		{name: "request key", change: func(c *aauth.AuthTokenClaims) { c.Confirmation.JWK = otherKey.PublicJWK() }},
		{name: "scope", change: func(c *aauth.AuthTokenClaims) { c.Scope = "admin" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			harness := newExchangeInteractionHarness(t)
			harness.initial = func(request *http.Request) (*http.Response, error) {
				return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
			}
			harness.poll = []func(*http.Request) (*http.Response, error){func(request *http.Request) (*http.Response, error) {
				return harness.authTokenResponse(request, test.change), nil
			}}
			client := harness.client(t)
			pending := beginExchangeInteraction(t, client, harness)
			if _, err := client.PollExchange(context.Background(), pending); err == nil {
				t.Fatal("PollExchange accepted substituted auth token")
			}
			if harness.pollCalls != 1 {
				t.Fatalf("poll calls = %d", harness.pollCalls)
			}
		})
	}

	t.Run("lifetime exceeds original agent token", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		shortAgentToken, err := aauth.MintAgentToken(
			harness.protocol.agentProviderID,
			harness.protocol.agentProviderKey,
			aauth.AgentTokenRequest{
				Agent: harness.protocol.agentID, PersonServer: harness.protocol.personServerID,
				PublicKey: harness.protocol.agentKey.PublicJWK(), Lifetime: 5 * time.Minute,
			},
			harness.protocol.now,
			"short-agent-token",
		)
		if err != nil {
			t.Fatal(err)
		}
		harness.protocol.agentToken = shortAgentToken
		harness.initial = func(request *http.Request) (*http.Response, error) {
			return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
		}
		harness.poll = []func(*http.Request) (*http.Response, error){func(request *http.Request) (*http.Response, error) {
			return harness.authTokenResponse(request, nil), nil
		}}
		client := harness.client(t)
		pending := beginExchangeInteraction(t, client, harness)
		if _, err := client.PollExchange(context.Background(), pending); err == nil ||
			!strings.Contains(err.Error(), "lifetime exceeds the agent token") {
			t.Fatalf("PollExchange error = %v", err)
		}
	})
}

func TestExchangeInteractionCancellationMakesNoUnintendedRequest(t *testing.T) {
	t.Run("begin canceled", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		client := harness.client(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := client.BeginExchange(ctx, agent.ExchangeRequest{
			PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
			Capabilities: []string{"interaction"},
		}); !errors.Is(err, context.Canceled) {
			t.Fatalf("BeginExchange error = %v", err)
		}
		if harness.networkCalls != 0 {
			t.Fatalf("canceled begin used network: %d calls", harness.networkCalls)
		}
	})

	t.Run("poll canceled", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		harness.initial = func(request *http.Request) (*http.Response, error) {
			return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
		}
		client := harness.client(t)
		pending := beginExchangeInteraction(t, client, harness)
		before := harness.networkCalls
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := client.PollExchange(ctx, pending); !errors.Is(err, context.Canceled) {
			t.Fatalf("PollExchange error = %v", err)
		}
		if harness.networkCalls != before {
			t.Fatalf("canceled poll used network: calls=%d, want %d", harness.networkCalls, before)
		}
	})

	t.Run("transport failure is not retried", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		harness.initial = func(*http.Request) (*http.Response, error) {
			return nil, errors.New("transport failed")
		}
		client := harness.client(t)
		if _, err := client.BeginExchange(context.Background(), agent.ExchangeRequest{
			PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
			Capabilities: []string{"interaction"},
		}); err == nil || !strings.Contains(err.Error(), "transport failed") {
			t.Fatalf("BeginExchange error = %v", err)
		}
		if harness.metadataCalls != 1 || harness.initialCalls != 1 || harness.pollCalls != 0 {
			t.Fatalf("calls: metadata=%d initial=%d poll=%d", harness.metadataCalls, harness.initialCalls, harness.pollCalls)
		}
	})

	t.Run("poll transport failure is not retried", func(t *testing.T) {
		harness := newExchangeInteractionHarness(t)
		harness.initial = func(request *http.Request) (*http.Response, error) {
			return validExchangePendingResponse(request, "/pending/exchange-1", "0", "pending"), nil
		}
		harness.poll = []func(*http.Request) (*http.Response, error){func(*http.Request) (*http.Response, error) {
			return nil, errors.New("poll transport failed")
		}}
		client := harness.client(t)
		pending := beginExchangeInteraction(t, client, harness)
		if _, err := client.PollExchange(context.Background(), pending); err == nil ||
			!strings.Contains(err.Error(), "poll transport failed") {
			t.Fatalf("PollExchange error = %v", err)
		}
		if harness.metadataCalls != 1 || harness.initialCalls != 1 || harness.pollCalls != 1 {
			t.Fatalf("calls: metadata=%d initial=%d poll=%d", harness.metadataCalls, harness.initialCalls, harness.pollCalls)
		}
	})
}

func TestExchangeInteractionZeroAccessorsAreSafe(t *testing.T) {
	var result agent.ExchangeResult
	if token, ok := result.Token(); ok || token != "" {
		t.Fatalf("Token = %q, %t", token, ok)
	}
	if pending, ok := result.Pending(); ok || pending != (agent.PendingExchange{}) {
		t.Fatalf("Pending = %#v, %t", pending, ok)
	}
	if response, ok := result.Response(); ok || response != nil {
		t.Fatalf("Response = %#v, %t", response, ok)
	}
	var pending agent.PendingExchange
	if pending.PersonServer() != "" || pending.Location() != "" || pending.RetryAfter() != 0 ||
		pending.InteractionURL() != "" || pending.InteractionCode() != "" || pending.Interacting() {
		t.Fatalf("zero pending accessors = %#v", pending)
	}
}

const (
	exchangeInteractionURL  = "https://ps.example/interaction"
	exchangeInteractionCode = "A1B2-C3D4"
)

type exchangeInteractionHarness struct {
	t                   *testing.T
	protocol            *testProtocol
	resourceToken       string
	resourceClaims      aauth.ResourceTokenClaims
	initial             func(*http.Request) (*http.Response, error)
	poll                []func(*http.Request) (*http.Response, error)
	action              func(*http.Request) (*http.Response, error)
	networkCalls        int
	metadataCalls       int
	initialCalls        int
	pollCalls           int
	actionCalls         int
	capabilities        []string
	capabilitiesPresent bool
}

func newExchangeInteractionHarness(t *testing.T) *exchangeInteractionHarness {
	t.Helper()
	protocol := newTestProtocol(t)
	thumbprint, err := protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	claims := aauth.ResourceTokenClaims{
		Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
		Audience: protocol.accessServerID, JTI: "resource-token-exchange-1",
		PersonServer: protocol.personServerID, Subject: "person-123", PresentedJTI: "person-token-1",
		AgentJKT: thumbprint, Scope: "records.read", IssuedAt: protocol.now.Unix(),
		ExpiresAt: protocol.now.Add(20 * time.Minute).Unix(),
	}
	compact, err := aauth.MintResourceToken(protocol.resourceKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	return &exchangeInteractionHarness{t: t, protocol: protocol, resourceToken: compact, resourceClaims: claims}
}

func (harness *exchangeInteractionHarness) client(t *testing.T) *agent.Client {
	t.Helper()
	return harness.protocol.newClientWithHTTPClient(t, &http.Client{Transport: roundTripperFunc(harness.roundTrip)})
}

func (harness *exchangeInteractionHarness) roundTrip(request *http.Request) (*http.Response, error) {
	harness.networkCalls++
	if request.Method == http.MethodGet && request.URL.String() == harness.protocol.personServerID+"/.well-known/aauth-person.json" {
		harness.metadataCalls++
		return jsonResponse(request, http.StatusOK, map[string]any{
			"issuer":                harness.protocol.personServerID,
			"person_token_endpoint": harness.protocol.personTokenEndpoint,
			"auth_token_endpoint":   harness.protocol.authTokenEndpoint,
		}), nil
	}
	if request.Method == http.MethodPost && request.URL.String() == harness.protocol.authTokenEndpoint {
		harness.initialCalls++
		if request.Header.Get("Prefer") != "wait=0" {
			harness.t.Fatalf("exchange Prefer = %q, want wait=0", request.Header.Get("Prefer"))
		}
		verified := verifyProof(harness.t, request, harness.protocol.resolver, harness.protocol.clock, aauth.AgentTokenType)
		if _, err := verified.AgentClaims(); err != nil {
			harness.t.Fatal(err)
		}
		var body struct {
			ResourceToken string    `json:"resource_token"`
			Capabilities  *[]string `json:"capabilities"`
		}
		decodeRequest(harness.t, request, &body)
		if body.ResourceToken != harness.resourceToken {
			harness.t.Fatal("exchange changed the resource token bytes")
		}
		harness.capabilitiesPresent = body.Capabilities != nil
		if body.Capabilities != nil {
			harness.capabilities = append([]string(nil), (*body.Capabilities)...)
		}
		if harness.initial == nil {
			return nil, errors.New("unexpected initial exchange")
		}
		return harness.initial(request)
	}
	if request.Method == http.MethodGet && strings.HasPrefix(request.URL.String(), harness.protocol.personServerID+"/pending/") {
		harness.pollCalls++
		if request.Body != nil && request.Body != http.NoBody {
			harness.t.Fatal("poll carried a body")
		}
		verified := verifyProof(harness.t, request, harness.protocol.resolver, harness.protocol.clock, aauth.AgentTokenType)
		if _, err := verified.AgentClaims(); err != nil {
			harness.t.Fatal(err)
		}
		index := harness.pollCalls - 1
		if index >= len(harness.poll) {
			return nil, errors.New("unexpected poll")
		}
		return harness.poll[index](request)
	}
	if (request.Method == http.MethodPost || request.Method == http.MethodDelete) &&
		strings.HasPrefix(request.URL.String(), harness.protocol.personServerID+"/pending/") {
		harness.actionCalls++
		verified := verifyProof(harness.t, request, harness.protocol.resolver, harness.protocol.clock, aauth.AgentTokenType)
		if _, err := verified.AgentClaims(); err != nil {
			harness.t.Fatal(err)
		}
		if harness.action == nil {
			return nil, errors.New("unexpected pending action")
		}
		return harness.action(request)
	}
	return nil, errors.New("unexpected request: " + request.URL.String())
}

func (harness *exchangeInteractionHarness) authTokenResponse(
	request *http.Request,
	change func(*aauth.AuthTokenClaims),
) *http.Response {
	claims := aauth.AuthTokenClaims{
		Issuer: harness.protocol.accessServerID, DWK: aauth.AccessDiscoveryDocument,
		Audience: harness.resourceClaims.Issuer, JTI: "auth-token-exchange-1",
		PersonServer: harness.resourceClaims.PersonServer, Subject: harness.resourceClaims.Subject,
		Confirmation: aauth.Confirmation{JWK: harness.protocol.agentKey.PublicJWK()},
		Scope:        harness.resourceClaims.Scope, IssuedAt: harness.protocol.now.Unix(),
		ExpiresAt: harness.protocol.now.Add(10 * time.Minute).Unix(),
	}
	if change != nil {
		change(&claims)
	}
	compact, err := aauth.MintAuthToken(harness.protocol.accessServerKey, claims)
	if err != nil {
		harness.t.Fatal(err)
	}
	return jsonResponse(request, http.StatusOK, map[string]any{
		"auth_token": compact, "expires_in": int64(600),
	})
}

func beginExchangeInteraction(t *testing.T, client *agent.Client, harness *exchangeInteractionHarness) agent.PendingExchange {
	t.Helper()
	result, err := client.BeginExchange(context.Background(), agent.ExchangeRequest{
		PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
		Capabilities: []string{"interaction"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatal("BeginExchange did not return pending")
	}
	return pending
}

func beginExchangeClarification(t *testing.T, client *agent.Client, harness *exchangeInteractionHarness) agent.PendingExchange {
	t.Helper()
	result, err := client.BeginExchange(context.Background(), agent.ExchangeRequest{
		PersonServer: harness.protocol.personServerID, ResourceToken: harness.resourceToken,
		Capabilities: []string{"clarification"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := result.Pending()
	if !ok {
		t.Fatal("BeginExchange did not return pending clarification")
	}
	return pending
}

func validExchangePendingResponse(request *http.Request, location, retryAfter, status string) *http.Response {
	requirement, _ := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{
		URL: exchangeInteractionURL, Code: exchangeInteractionCode,
	})
	body := []byte(`{"status":"` + status + `"}`)
	header := make(http.Header)
	header.Set("Location", location)
	header.Set("Retry-After", retryAfter)
	header.Set("Cache-Control", "private, no-store")
	header.Set("Content-Type", "application/json")
	header.Set("AAuth-Requirement", requirement)
	return &http.Response{
		StatusCode: http.StatusAccepted, Status: http.StatusText(http.StatusAccepted), Request: request,
		Header: header, Body: io.NopCloser(bytes.NewReader(body)),
	}
}

func validExchangeClarificationResponse(request *http.Request, body string) *http.Response {
	return validExchangeClarificationResponseAt(request, "/pending/exchange-1", body)
}

func validExchangeClarificationResponseAt(request *http.Request, location, body string) *http.Response {
	response := validExchangePendingResponse(request, location, "0", "pending")
	response.Header.Set("AAuth-Requirement", "requirement=clarification")
	response.Body = io.NopCloser(strings.NewReader(body))
	return response
}

type recordingKeyResolver struct {
	delegate   signaturekey.KeyResolver
	references []signaturekey.StaticKeyReference
}

func (resolver *recordingKeyResolver) ResolveKey(
	ctx context.Context,
	issuer string,
	document string,
	keyID string,
) (jose.JWK, error) {
	resolver.references = append(resolver.references, signaturekey.StaticKeyReference{
		Issuer: issuer, DiscoveryDocument: document, KeyID: keyID,
	})
	return resolver.delegate.ResolveKey(ctx, issuer, document, keyID)
}

func emptyResponse(request *http.Request, status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Request:    request,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
	}
}
