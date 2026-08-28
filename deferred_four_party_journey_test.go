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

func TestCurrentFourPartyDeferredAuthorizationJourney(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 16, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs(
		"agent-token",
		"person-token",
		"resource-token",
		"auth-token",
		"resource-token-denied",
		"resource-token-expired",
		"resource-token-invalid-code",
	)
	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	asKey := testSigningKey(t, "as-key")
	resourceKey := testSigningKey(t, "resource-key")
	agentKey := testSigningKey(t, "agent-key")

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

	client := &http.Client{}
	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: client,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			for _, allowed := range []string{
				"https://ap.example/",
				"https://ps.example/",
				"https://as.example/",
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

	var accessPolicyCalls int
	accessAuthorizationDirectory := t.TempDir() + "/access-authorization"
	accessAuthorizationStore := openTestFileAuthorizationStateStore(t, accessAuthorizationDirectory)
	accessConfig := reference.AccessServerConfig{
		AuthorizationStore: accessAuthorizationStore,
		Identifier:         "https://as.example",
		SigningKey:         asKey,
		KeyResolver:        resolver,
		Clock:              clock,
		NewID:              ids,
		TrustedPersonServer: func(_ context.Context, identifier string) error {
			if identifier != "https://ps.example" {
				return fmt.Errorf("untrusted person server %s", identifier)
			}
			return nil
		},
		InteractionRequired: func(_ context.Context, request aauth.AuthorizationRequest) (bool, error) {
			return request.Agent == "aauth:planner@ap.example", nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			accessPolicyCalls++
			return aauth.AuthorizationDecision{
				Subject: "federated-pairwise-user",
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
	}
	accessServer, err := reference.NewAccessServer(accessConfig)
	if err != nil {
		t.Fatal(err)
	}

	var personPolicyCalls int
	personTokenStore, missionIssuanceStore := testCurrentPersonServerCustody(t)
	personAuthorizationDirectory := t.TempDir() + "/person-authorization"
	personAuthorizationStore := openTestFileAuthorizationStateStore(t, personAuthorizationDirectory)
	personConfig := reference.PersonServerConfig{
		AuthorizationStore: personAuthorizationStore,
		Identifier:         "https://ps.example",
		SigningKey:         psKey,
		KeyResolver:        resolver,
		Clock:              clock,
		NewID:              ids,
		Random: bytes.NewReader(bytes.Join([][]byte{
			bytes.Repeat([]byte{7}, 16),
			bytes.Repeat([]byte{8}, 16),
			bytes.Repeat([]byte{9}, 16),
			bytes.Repeat([]byte{10}, 16),
		}, nil)),
		PendingLifetime:  time.Minute,
		FederationClient: client,
		AccessServerEndpoint: func(_ context.Context, identifier string) (string, error) {
			if identifier != "https://as.example" {
				return "", fmt.Errorf("unknown access server %s", identifier)
			}
			return identifier + "/token", nil
		},
		PersonTokenStore:     personTokenStore,
		MissionIssuanceStore: missionIssuanceStore,
		PersonTokenPolicy: func(_ context.Context, _ aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			return aauth.PersonTokenDecision{Subject: "federated-pairwise-user", Lifetime: time.Hour}, nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: evaluation.Proposal.Description}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			personPolicyCalls++
			return aauth.AuthorizationDecision{
				Subject: request.Subject,
				Scope:   request.Scope,
			}, nil
		},
	}
	personServer, err := reference.NewPersonServer(personConfig)
	if err != nil {
		t.Fatal(err)
	}

	var operationCalls int
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier:                   "https://resource.example",
		AccessMode:                   aauth.AccessModeAuthToken,
		AccessServer:                 "https://as.example",
		SigningKey:                   resourceKey,
		KeyResolver:                  resolver,
		Clock:                        clock,
		NewID:                        ids,
		Scopes:                       []string{"records.read"},
		ScopeDescriptions:            map[string]string{"records.read": "Read records"},
		RequiredScopesForRequest:     testRequiredResourceScopes("records.read"),
		ReplayStore:                  testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error { return nil },
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			operationCalls++
			return map[string]string{
				"agent":   request.Agent,
				"subject": request.Subject,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	accessHandler := accessServer.Handler()
	personHandler := personServer.Handler()
	var accessServerPolls int
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			personHandler.ServeHTTP(response, request)
		}),
		"as.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodGet &&
				strings.HasPrefix(request.URL.Path, "/pending/") &&
				request.Header.Get("Signature-Key") != "" {
				accessServerPolls++
				if accessServerPolls == 1 {
					response.Header().Set("Content-Type", "application/problem+json")
					response.WriteHeader(http.StatusTooManyRequests)
					_, _ = io.WriteString(response, `{"status":429,"error":"slow_down"}`)
					return
				}
			}
			accessHandler.ServeHTTP(response, request)
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
	person, err := agent.RequestPersonToken(context.Background(), "https://ps.example/person", "https://resource.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	resourceGrant, err := agent.RequestResourceTokenWithPersonToken(
		context.Background(),
		"https://resource.example/authorize",
		[]string{"records.read"},
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
		!strings.HasPrefix(pending.Location, "https://ps.example/pending/") ||
		pending.Requirement == nil ||
		pending.Requirement.Type != aauth.RequirementInteraction ||
		!strings.HasPrefix(pending.Requirement.InteractionURL, "https://as.example/interaction/") {
		t.Fatalf("proxied pending authorization = %#v", pending)
	}
	if personPolicyCalls != 1 || accessPolicyCalls != 0 {
		t.Fatalf("policy calls after initial exchange: PS=%d AS=%d", personPolicyCalls, accessPolicyCalls)
	}
	if err := personServer.ApproveAuthorization(context.Background(), pending.ID); err == nil {
		t.Fatal("person server approved an access-server-owned interaction")
	}
	wrongInteractionOwner, err := client.Get(
		"https://ps.example/interaction/" + pending.ID +
			"?code=" + pending.Requirement.InteractionCode,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongInteractionOwner.Body.Close()
	if wrongInteractionOwner.StatusCode != http.StatusGone {
		body, _ := io.ReadAll(wrongInteractionOwner.Body)
		t.Fatalf("PS-hosted AS interaction status = %d, body = %s", wrongInteractionOwner.StatusCode, body)
	}

	asPendingID := strings.TrimPrefix(
		pending.Requirement.InteractionURL,
		"https://as.example/interaction/",
	)
	interactionURL := pending.Requirement.InteractionURL
	interactionCode := pending.Requirement.InteractionCode
	unsignedASPoll, err := client.Get("https://as.example/pending/" + asPendingID)
	if err != nil {
		t.Fatal(err)
	}
	defer unsignedASPoll.Body.Close()
	if unsignedASPoll.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(unsignedASPoll.Body)
		t.Fatalf("unsigned AS poll status = %d, body = %s", unsignedASPoll.StatusCode, body)
	}

	waiting, err := agent.PollTokenAuthorization(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if waiting.Pending == nil || waiting.Pending.Status != "pending" {
		t.Fatalf("waiting poll = %#v", waiting)
	}
	if pending.RetryAfter != 5*time.Second ||
		!pending.NotBefore.Equal(now.Add(5*time.Second)) {
		t.Fatalf("proxied slowdown state = %#v", pending)
	}
	if _, err := agent.PollTokenAuthorization(context.Background(), pending); err == nil {
		t.Fatal("agent ignored the proxied slowdown interval")
	}
	if accessServerPolls != 1 {
		t.Fatalf("AS polls before slowdown elapsed = %d", accessServerPolls)
	}
	now = now.Add(5 * time.Second)
	if err := accessAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	accessAuthorizationStore = openTestFileAuthorizationStateStore(t, accessAuthorizationDirectory)
	accessConfig.AuthorizationStore = accessAuthorizationStore
	accessServer, err = reference.NewAccessServer(accessConfig)
	if err != nil {
		t.Fatal(err)
	}
	accessHandler = accessServer.Handler()
	if err := personAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	personAuthorizationStore = openTestFileAuthorizationStateStore(t, personAuthorizationDirectory)
	personConfig.AuthorizationStore = personAuthorizationStore
	personServer, err = reference.NewPersonServer(personConfig)
	if err != nil {
		t.Fatal(err)
	}
	personHandler = personServer.Handler()
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

	interaction, err := client.Get(
		interactionURL + "?code=" + interactionCode,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer interaction.Body.Close()
	if interaction.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(interaction.Body)
		t.Fatalf("interaction status = %d, body = %s", interaction.StatusCode, body)
	}
	if accessPolicyCalls != 0 {
		t.Fatalf("interaction code conferred AS policy authority; calls = %d", accessPolicyCalls)
	}

	interacting, err := agent.PollTokenAuthorization(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if interacting.Pending == nil || interacting.Pending.Status != "interacting" {
		t.Fatalf("interacting poll = %#v", interacting)
	}

	if err := accessServer.ApproveAuthorization(context.Background(), pending.Requirement.InteractionCode); err == nil {
		t.Fatal("access server accepted an interaction code where a pending identifier was required")
	}
	if err := accessServer.ApproveAuthorization(context.Background(), asPendingID); err != nil {
		t.Fatal(err)
	}
	if accessPolicyCalls != 1 {
		t.Fatalf("AS policy calls after approval = %d", accessPolicyCalls)
	}

	approved, err := agent.PollTokenAuthorization(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Pending != nil || approved.Grant == nil {
		t.Fatalf("approved poll = %#v", approved)
	}
	if approved.Grant.Claims.Issuer != "https://as.example" ||
		approved.Grant.Claims.Subject != "federated-pairwise-user" {
		t.Fatalf("approved federated grant = %#v", approved.Grant)
	}

	protected, err := agent.DoAuthorized(
		context.Background(),
		http.MethodGet,
		"https://resource.example/records",
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
	if operationCalls != 1 {
		t.Fatalf("protected operation calls = %d", operationCalls)
	}

	newPending := func() *reference.PendingTokenAuthorization {
		t.Helper()
		now = now.Add(time.Second)
		nextResourceGrant, err := agent.RequestResourceTokenWithPersonToken(
			context.Background(),
			"https://resource.example/authorize",
			[]string{"records.read"},
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
			t.Fatalf("next federated authorization = %#v", next)
		}
		return next.Pending
	}
	asPendingIdentifier := func(pending *reference.PendingTokenAuthorization) string {
		t.Helper()
		if pending.Requirement == nil {
			t.Fatal("federated pending authorization has no requirement")
		}
		return strings.TrimPrefix(
			pending.Requirement.InteractionURL,
			"https://as.example/interaction/",
		)
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
	if err := accessServer.RejectAuthorization(
		asPendingIdentifier(denied),
		aauth.PollingDenied,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.PollTokenAuthorization(context.Background(), denied); err == nil {
		t.Fatal("denied AS authorization returned a grant")
	} else {
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) ||
			problem.Status != http.StatusForbidden ||
			problem.Code != aauth.PollingDenied {
			t.Fatalf("proxied denial error = %#v", err)
		}
	}
	if _, err := agent.PollTokenAuthorization(context.Background(), denied); err == nil {
		t.Fatal("PS proxy returned a second denial response")
	}

	expired := newPending()
	now = now.Add(time.Minute)
	if _, err := agent.PollTokenAuthorization(context.Background(), expired); err == nil {
		t.Fatal("expired federated authorization remained pending")
	} else {
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) ||
			problem.Status != http.StatusRequestTimeout ||
			problem.Code != aauth.PollingExpired {
			t.Fatalf("proxied expiry error = %#v", err)
		}
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
				"invalid AS code attempt %d status = %d, want %d; body = %s",
				attempt,
				response.StatusCode,
				expectedStatus,
				body,
			)
		}
	}
	if _, err := agent.PollTokenAuthorization(context.Background(), invalidCode); err == nil {
		t.Fatal("invalid-code AS authorization remained pending")
	} else {
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) ||
			problem.Status != http.StatusGone ||
			problem.Code != aauth.PollingInvalidCode {
			t.Fatalf("proxied invalid-code error = %#v", err)
		}
	}
}
