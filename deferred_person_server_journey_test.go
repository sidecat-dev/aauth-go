package aauth_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestCurrentPersonServerDeferredAuthorizationJourney(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 14, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs(
		"agent-token",
		"other-agent-token",
		"wrong-key-agent-token",
		"person-token",
		"resource-token",
		"auth-token",
		"resource-token-denied",
		"resource-token-expired",
		"resource-token-invalid-code",
	)
	apKey := testSigningKey(t, "ap-key")
	_, psPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	psSigner := &failOnceEd25519Signer{privateKey: psPrivateKey}
	psKey, err := jose.NewSigningKey("ps-key", psSigner)
	if err != nil {
		t.Fatal(err)
	}
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
	wrongKeyToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent: "aauth:planner@ap.example", PersonServer: "https://ps.example",
		PublicKey: otherKey.PublicJWK(), Lifetime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
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

	var personPolicyCalls, policyCalls int
	personTokenStore, missionIssuanceStore := testCurrentPersonServerCustody(t)
	personAuthorizationDirectory := t.TempDir() + "/person-authorization"
	personAuthorizationStore := openTestFileAuthorizationStateStore(t, personAuthorizationDirectory)
	personConfig := reference.PersonServerConfig{
		AuthorizationStore:   personAuthorizationStore,
		Identifier:           "https://ps.example",
		SigningKey:           psKey,
		KeyResolver:          resolver,
		Clock:                clock,
		NewID:                ids,
		PersonTokenStore:     personTokenStore,
		MissionIssuanceStore: missionIssuanceStore,
		PersonTokenPolicy: func(_ context.Context, _ aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			personPolicyCalls++
			return aauth.PersonTokenDecision{Subject: "pairwise-user-for-resource", Lifetime: time.Hour}, nil
		},
		PersonTokenInteractionRequired: func(_ context.Context, request aauth.PersonTokenRequest) (bool, error) {
			return request.Agent == "aauth:planner@ap.example", nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: evaluation.Proposal.Description}, nil
		},
		InteractionRequired: func(_ context.Context, request aauth.AuthorizationRequest) (bool, error) {
			return request.Agent == "aauth:planner@ap.example", nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			policyCalls++
			return aauth.AuthorizationDecision{
				Subject: request.Subject,
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
			bytes.Repeat([]byte{4}, 16),
			{20, 21, 22, 23, 24},
			bytes.Repeat([]byte{5}, 16),
			{25, 26, 27, 28, 29},
			bytes.Repeat([]byte{6}, 16),
			{30, 31, 32, 33, 34},
			bytes.Repeat([]byte{7}, 16),
			{35, 36, 37, 38, 39},
		}, nil)),
		PendingLifetime: time.Minute,
	}
	ps, err := reference.NewPersonServer(personConfig)
	if err != nil {
		t.Fatal(err)
	}

	var executionCount int
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier:                   "https://resource.example",
		AccessMode:                   aauth.AccessModeAuthToken,
		PersonServer:                 "https://ps.example",
		SigningKey:                   resourceKey,
		KeyResolver:                  resolver,
		Clock:                        clock,
		NewID:                        ids,
		Scopes:                       []string{"documents.read"},
		ScopeDescriptions:            map[string]string{"documents.read": "Read documents"},
		RequiredScopesForRequest:     testRequiredResourceScopes("documents.read"),
		ReplayStore:                  testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error { return nil },
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

	agentAuthorizationDirectory := t.TempDir() + "/agent-authorization"
	agentAuthorizationStore := openTestFileAuthorizationStateStore(t, agentAuthorizationDirectory)
	agentConfig := reference.AgentConfig{
		AuthorizationStore: agentAuthorizationStore,
		Identifier:         "aauth:planner@ap.example",
		SigningKey:         agentKey,
		AgentToken:         agentToken,
		KeyResolver:        resolver,
		HTTPClient:         client,
		Clock:              clock,
	}
	agent, err := reference.NewAgent(agentConfig)
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
	wrongKeyAgent, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t), Identifier: "aauth:planner@ap.example",
		SigningKey: otherKey, AgentToken: wrongKeyToken, KeyResolver: resolver,
		HTTPClient: client, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	personAuthorization, err := agent.RequestPersonTokenAuthorization(
		context.Background(), "https://ps.example/person", "https://resource.example", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if personAuthorization.Grant != nil || personAuthorization.Pending == nil {
		t.Fatalf("initial person-token authorization = %#v", personAuthorization)
	}
	personPending := personAuthorization.Pending
	if personPending.PersonServer != "https://ps.example" ||
		personPending.Location != "https://ps.example/pending/"+personPending.ID ||
		personPending.Requirement == nil || personPending.Requirement.Type != aauth.RequirementInteraction {
		t.Fatalf("pending person-token authorization = %#v", personPending)
	}
	if personPolicyCalls != 0 {
		t.Fatalf("person-token policy ran before trusted approval; calls = %d", personPolicyCalls)
	}
	otherPersonPending := *personPending
	if _, err := other.PollPersonTokenAuthorization(context.Background(), &otherPersonPending); err == nil {
		t.Fatal("another agent polled the person-token authorization")
	}
	wrongKeyPending := *personPending
	if _, err := wrongKeyAgent.PollPersonTokenAuthorization(context.Background(), &wrongKeyPending); err == nil {
		t.Fatal("the same agent identifier polled the person-token authorization with another key")
	}
	if err := personAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	personAuthorizationStore = openTestFileAuthorizationStateStore(t, personAuthorizationDirectory)
	personConfig.AuthorizationStore = personAuthorizationStore
	ps, err = reference.NewPersonServer(personConfig)
	if err != nil {
		t.Fatal(err)
	}
	psHandler = ps.Handler()
	if err := agentAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	agentAuthorizationStore = openTestFileAuthorizationStateStore(t, agentAuthorizationDirectory)
	agentConfig.AuthorizationStore = agentAuthorizationStore
	agent, err = reference.NewAgent(agentConfig)
	if err != nil {
		t.Fatal(err)
	}
	personPending = &reference.PendingPersonTokenAuthorization{ID: personPending.ID}
	waitingPerson, err := agent.PollPersonTokenAuthorization(context.Background(), personPending)
	if err != nil {
		t.Fatal(err)
	}
	if waitingPerson.Pending == nil || waitingPerson.Pending.Status != "pending" || waitingPerson.Pending.Requirement == nil {
		t.Fatalf("waiting person-token poll = %#v", waitingPerson)
	}
	personPending = waitingPerson.Pending
	personInteraction, err := client.Get(
		personPending.Requirement.InteractionURL + "?code=" + personPending.Requirement.InteractionCode,
	)
	if err != nil {
		t.Fatal(err)
	}
	personInteraction.Body.Close()
	if personInteraction.StatusCode != http.StatusOK {
		t.Fatalf("person-token interaction status = %d", personInteraction.StatusCode)
	}
	if err := ps.ApprovePersonToken(context.Background(), personPending.ID); err != nil {
		t.Fatal(err)
	}
	if personPolicyCalls != 1 {
		t.Fatalf("person-token policy calls after approval = %d", personPolicyCalls)
	}
	if err := personAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	personAuthorizationStore = openTestFileAuthorizationStateStore(t, personAuthorizationDirectory)
	personConfig.AuthorizationStore = personAuthorizationStore
	ps, err = reference.NewPersonServer(personConfig)
	if err != nil {
		t.Fatal(err)
	}
	psHandler = ps.Handler()
	personAuthorization, err = agent.PollPersonTokenAuthorization(context.Background(), personPending)
	if err != nil {
		t.Fatal(err)
	}
	if personAuthorization.Grant == nil || personAuthorization.Pending != nil {
		t.Fatalf("approved person-token authorization = %#v", personAuthorization)
	}
	person := *personAuthorization.Grant
	if err := personAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	personAuthorizationStore = openTestFileAuthorizationStateStore(t, personAuthorizationDirectory)
	personConfig.AuthorizationStore = personAuthorizationStore
	ps, err = reference.NewPersonServer(personConfig)
	if err != nil {
		t.Fatal(err)
	}
	psHandler = ps.Handler()
	if err := agentAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	agentAuthorizationStore = openTestFileAuthorizationStateStore(t, agentAuthorizationDirectory)
	agentConfig.AuthorizationStore = agentAuthorizationStore
	agent, err = reference.NewAgent(agentConfig)
	if err != nil {
		t.Fatal(err)
	}
	replayedPerson, err := agent.PollPersonTokenAuthorization(context.Background(), personPending)
	if err != nil {
		t.Fatal(err)
	}
	if replayedPerson.Grant == nil || replayedPerson.Grant.PersonToken != person.PersonToken || personPolicyCalls != 1 {
		t.Fatalf("replayed person-token authorization = %#v, policy calls %d", replayedPerson, personPolicyCalls)
	}
	resourceGrant, err := agent.RequestResourceTokenWithPersonToken(
		context.Background(),
		"https://resource.example/authorize",
		[]string{"documents.read"},
		person.PersonToken,
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
	otherPending := *pending
	if _, err := other.PollTokenAuthorization(context.Background(), &otherPending); err == nil {
		t.Fatal("another agent polled the person-server authorization")
	}
	if err := personAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	personAuthorizationStore = openTestFileAuthorizationStateStore(t, personAuthorizationDirectory)
	personConfig.AuthorizationStore = personAuthorizationStore
	ps, err = reference.NewPersonServer(personConfig)
	if err != nil {
		t.Fatal(err)
	}
	psHandler = ps.Handler()
	if err := agentAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	agentAuthorizationStore = openTestFileAuthorizationStateStore(t, agentAuthorizationDirectory)
	agentConfig.AuthorizationStore = agentAuthorizationStore
	agent, err = reference.NewAgent(agentConfig)
	if err != nil {
		t.Fatal(err)
	}
	pending = &reference.PendingTokenAuthorization{ID: pending.ID}

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
	psSigner.failNext.Store(true)
	if _, err := agent.PollTokenAuthorization(context.Background(), pending); err == nil {
		t.Fatal("transient auth-token mint failure was hidden")
	} else {
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) || problem.Status != http.StatusInternalServerError || problem.Code != "server_error" {
			t.Fatalf("transient mint error = %v", err)
		}
	}
	if err := personAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	personAuthorizationStore = openTestFileAuthorizationStateStore(t, personAuthorizationDirectory)
	personConfig.AuthorizationStore = personAuthorizationStore
	ps, err = reference.NewPersonServer(personConfig)
	if err != nil {
		t.Fatal(err)
	}
	psHandler = ps.Handler()

	approved, err := agent.PollTokenAuthorization(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Pending != nil || approved.Grant == nil {
		t.Fatalf("approved poll = %#v", approved)
	}
	if approved.Grant.Claims.Subject != "pairwise-user-for-resource" ||
		approved.Grant.Claims.PersonServer != "https://ps.example" ||
		approved.Grant.Claims.Agent != "" {
		t.Fatalf("approved grant = %#v", approved.Grant)
	}
	if err := personAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	personAuthorizationStore = openTestFileAuthorizationStateStore(t, personAuthorizationDirectory)
	personConfig.AuthorizationStore = personAuthorizationStore
	ps, err = reference.NewPersonServer(personConfig)
	if err != nil {
		t.Fatal(err)
	}
	psHandler = ps.Handler()
	lostResponsePoll, err := http.NewRequest(http.MethodGet, pending.Location, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignJWTRequestWithOptions(lostResponsePoll, agentKey, agentToken, clock, signaturekey.SignOptions{Nonce: "lost-terminal-person-response"}); err != nil {
		t.Fatal(err)
	}
	lostResponse, err := client.Do(lostResponsePoll)
	if err != nil {
		t.Fatal(err)
	}
	defer lostResponse.Body.Close()
	var lostResult struct {
		AuthToken string `json:"auth_token"`
	}
	if lostResponse.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(lostResponse.Body)
		t.Fatalf("restarted terminal poll = %d body=%s", lostResponse.StatusCode, body)
	}
	if err := json.NewDecoder(lostResponse.Body).Decode(&lostResult); err != nil {
		t.Fatal(err)
	}
	if lostResult.AuthToken != approved.Grant.AuthToken {
		t.Fatalf("restarted terminal auth token changed")
	}
	recovered, err := agent.PollTokenAuthorization(context.Background(), &reference.PendingTokenAuthorization{ID: pending.ID})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Grant == nil || recovered.Grant.AuthToken != approved.Grant.AuthToken {
		t.Fatalf("lost terminal response recovery = %#v", recovered)
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
		nextResourceGrant, err := agent.RequestResourceTokenWithPersonToken(
			context.Background(),
			"https://resource.example/authorize",
			[]string{"documents.read"},
			person.PersonToken,
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

	deniedPerson, err := agent.RequestPersonTokenAuthorization(
		context.Background(), "https://ps.example/person", "https://resource.example", nil,
	)
	if err != nil || deniedPerson.Pending == nil {
		t.Fatalf("denied person-token start = %#v, %v", deniedPerson, err)
	}
	response, err := client.Get(
		deniedPerson.Pending.Requirement.InteractionURL + "?code=" + deniedPerson.Pending.Requirement.InteractionCode,
	)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("denied person-token interaction status = %d", response.StatusCode)
	}
	if err := ps.RejectPersonToken(context.Background(), deniedPerson.Pending.ID, aauth.PollingDenied); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.PollPersonTokenAuthorization(context.Background(), deniedPerson.Pending); err == nil {
		t.Fatal("denied person-token authorization returned a grant")
	} else {
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Code != aauth.PollingDenied {
			t.Fatalf("denied person-token polling error = %#v", err)
		}
	}

	expiredPerson, err := agent.RequestPersonTokenAuthorization(
		context.Background(), "https://ps.example/person", "https://resource.example", nil,
	)
	if err != nil || expiredPerson.Pending == nil {
		t.Fatalf("expired person-token start = %#v, %v", expiredPerson, err)
	}
	now = now.Add(time.Minute)
	if _, err := agent.PollPersonTokenAuthorization(context.Background(), expiredPerson.Pending); err == nil {
		t.Fatal("expired person-token authorization remained pending")
	} else {
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) || problem.Status != http.StatusRequestTimeout || problem.Code != aauth.PollingExpired {
			t.Fatalf("expired person-token polling error = %#v", err)
		}
	}
	if personPolicyCalls != 1 {
		t.Fatalf("person-token policy ran for denied or expired interaction; calls = %d", personPolicyCalls)
	}
	if _, err := agent.RequestPersonToken(
		context.Background(), "https://ps.example/person", "https://resource.example", nil,
	); err == nil || !strings.Contains(err.Error(), "use RequestPersonTokenAuthorization") {
		t.Fatalf("immediate-only deferred person-token error = %v", err)
	}
}

type failOnceEd25519Signer struct {
	privateKey ed25519.PrivateKey
	failNext   atomic.Bool
}

func (signer *failOnceEd25519Signer) Public() crypto.PublicKey {
	return signer.privateKey.Public()
}

func (signer *failOnceEd25519Signer) Sign(
	_ io.Reader,
	message []byte,
	_ crypto.SignerOpts,
) ([]byte, error) {
	if signer.failNext.CompareAndSwap(true, false) {
		return nil, errors.New("injected transient signing failure")
	}
	return ed25519.Sign(signer.privateKey, message), nil
}
