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

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestCurrentResourceManagedDeferredAccessStartsAtProtectedEndpoint(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs("agent-token", "other-agent-token", "opaque-access-token")
	apKey := testSigningKey(t, "ap-key")
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
		Agent:     "aauth:reader@ap.example",
		PublicKey: agentKey.PublicJWK(),
		Lifetime:  2 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:     "aauth:other@ap.example",
		PublicKey: otherKey.PublicJWK(),
		Lifetime:  2 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasPrefix(endpoint, "https://ap.example/") {
				return nil
			}
			return fmt.Errorf("endpoint outside trust boundary: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var policyCalls int
	var executionCount int
	exactBody := []byte(`{"query":"deferred current payload"}`)
	resourceAuthorizationDirectory := t.TempDir() + "/resource-authorization"
	resourceAuthorizationStore := openTestFileAuthorizationStateStore(t, resourceAuthorizationDirectory)
	resourceConfig := reference.ResourceConfig{
		Identifier:               "https://resource.example",
		AccessMode:               aauth.AccessModeSessionToken,
		KeyResolver:              resolver,
		Clock:                    clock,
		NewID:                    ids,
		Scopes:                   []string{"documents.read"},
		RequiredScopesForRequest: testRequiredResourceScopes("documents.read"),
		ReplayStore:              testResourceReplayStore(t, clock),
		AuthorizationStore:       resourceAuthorizationStore,
		InteractionRequired: func(_ context.Context, request aauth.AuthorizationRequest) (bool, error) {
			return request.Agent == "aauth:reader@ap.example", nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			policyCalls++
			return aauth.AuthorizationDecision{
				Subject: "person-123",
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
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			executionCount++
			if request.Method != http.MethodPost || request.Path != "/documents" ||
				!bytes.Equal(request.Body, exactBody) || request.ContentType != "application/json" {
				t.Fatalf("authorized body context = %#v", request)
			}
			return map[string]any{
				"agent":   request.Agent,
				"subject": request.Subject,
			}, nil
		},
	}
	resource, err := reference.NewResource(resourceConfig)
	if err != nil {
		t.Fatal(err)
	}

	resourceHandler := resource.Handler()
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"resource.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodGet && request.URL.Path == "/documents" &&
				request.Header.Get("Authorization") == "" &&
				request.Header.Get("Prefer") != "wait=0" {
				http.Error(response, "missing Prefer wait", http.StatusBadRequest)
				return
			}
			resourceHandler.ServeHTTP(response, request)
		}),
	})
	defer gateway.Close()
	client.Transport = gateway.Client().Transport

	agentAuthorizationDirectory := t.TempDir() + "/agent-authorization"
	agentAuthorizationStore := openTestFileAuthorizationStateStore(t, agentAuthorizationDirectory)
	agentConfig := reference.AgentConfig{
		AuthorizationStore: agentAuthorizationStore,
		Identifier:         "aauth:reader@ap.example",
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

	authorization, err := agent.RequestResourceManagedAccess(
		context.Background(),
		reference.AuthorizedCall{
			Method: http.MethodPost, Endpoint: "https://resource.example/documents",
			Body: exactBody, ContentType: "application/json",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Grant != nil || authorization.Pending == nil {
		t.Fatalf("initial authorization = %#v", authorization)
	}
	pending := authorization.Pending
	if pending.Resource != "https://resource.example" ||
		pending.Location != "https://resource.example/pending/"+pending.ID ||
		pending.Requirement == nil ||
		pending.Requirement.Type != aauth.RequirementInteraction ||
		pending.Requirement.InteractionURL != "https://resource.example/interaction/"+pending.ID {
		t.Fatalf("pending authorization = %#v", pending)
	}
	if policyCalls != 0 {
		t.Fatalf("authorization policy ran before user approval; calls = %d", policyCalls)
	}

	otherPending := *pending
	if _, err := other.PollResourceManagedAccess(context.Background(), &otherPending); err == nil {
		t.Fatal("another agent polled the pending authorization")
	}

	if err := resourceAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	resourceAuthorizationStore = openTestFileAuthorizationStateStore(t, resourceAuthorizationDirectory)
	resourceConfig.AuthorizationStore = resourceAuthorizationStore
	if err := agentAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	agentAuthorizationStore = openTestFileAuthorizationStateStore(t, agentAuthorizationDirectory)
	agentConfig.AuthorizationStore = agentAuthorizationStore

	resource, err = reference.NewResource(resourceConfig)
	if err != nil {
		t.Fatal(err)
	}
	resourceHandler = resource.Handler()
	agent, err = reference.NewAgent(agentConfig)
	if err != nil {
		t.Fatal(err)
	}
	pending = &reference.PendingAccessAuthorization{ID: pending.ID}

	beforeInteraction, err := agent.PollResourceManagedAccess(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if beforeInteraction.Pending == nil || beforeInteraction.Pending.Status != "pending" {
		t.Fatalf("pre-interaction poll = %#v", beforeInteraction)
	}

	humanCode := strings.ToLower(strings.ReplaceAll(
		pending.Requirement.InteractionCode,
		"0",
		"o",
	))
	interaction, err := client.Get(pending.Requirement.InteractionURL + "?code=" + humanCode)
	if err != nil {
		t.Fatal(err)
	}
	defer interaction.Body.Close()
	if interaction.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(interaction.Body)
		t.Fatalf("interaction status = %d, body = %s", interaction.StatusCode, body)
	}

	reusedCode, err := client.Get(pending.Requirement.InteractionURL + "?code=" + humanCode)
	if err != nil {
		t.Fatal(err)
	}
	defer reusedCode.Body.Close()
	if reusedCode.StatusCode != http.StatusGone {
		body, _ := io.ReadAll(reusedCode.Body)
		t.Fatalf("reused interaction code status = %d, body = %s", reusedCode.StatusCode, body)
	}

	interacting, err := agent.PollResourceManagedAccess(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if interacting.Pending == nil || interacting.Pending.Status != "interacting" {
		t.Fatalf("interacting poll = %#v", interacting)
	}
	if policyCalls != 0 || executionCount != 0 {
		t.Fatalf("interaction code conferred authority: policy=%d operation=%d", policyCalls, executionCount)
	}

	if err := resource.ApproveAuthorization(context.Background(), pending.ID); err != nil {
		t.Fatal(err)
	}
	if policyCalls != 1 {
		t.Fatalf("authorization policy calls after approval = %d", policyCalls)
	}

	approved, err := agent.PollResourceManagedAccess(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Pending != nil || approved.Grant == nil {
		t.Fatalf("approved poll = %#v", approved)
	}
	if approved.Grant.Token != "opaque-access-token" ||
		strings.Join(approved.Grant.Scope, " ") != "documents.read" {
		t.Fatalf("approved grant = %#v", approved.Grant)
	}
	if err := resourceAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	resourceAuthorizationStore = openTestFileAuthorizationStateStore(t, resourceAuthorizationDirectory)
	resourceConfig.AuthorizationStore = resourceAuthorizationStore
	resource, err = reference.NewResource(resourceConfig)
	if err != nil {
		t.Fatal(err)
	}
	resourceHandler = resource.Handler()
	lostResponsePoll, err := http.NewRequest(http.MethodGet, pending.Location, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignJWTRequestWithOptions(lostResponsePoll, agentKey, agentToken, clock, signaturekey.SignOptions{Nonce: "lost-terminal-resource-response"}); err != nil {
		t.Fatal(err)
	}
	lostResponse, err := client.Do(lostResponsePoll)
	if err != nil {
		t.Fatal(err)
	}
	defer lostResponse.Body.Close()
	if lostResponse.StatusCode != http.StatusOK || lostResponse.Header.Get("AAuth-Access") != approved.Grant.Token {
		body, _ := io.ReadAll(lostResponse.Body)
		t.Fatalf("restarted terminal poll = %d access=%q body=%s", lostResponse.StatusCode, lostResponse.Header.Get("AAuth-Access"), body)
	}

	recovered, err := agent.PollResourceManagedAccess(context.Background(), &reference.PendingAccessAuthorization{ID: pending.ID})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Grant == nil || recovered.Grant.Token != approved.Grant.Token {
		t.Fatalf("lost terminal response recovery = %#v", recovered)
	}

	protected, err := agent.DoWithAccess(
		context.Background(),
		reference.AuthorizedCall{
			Method: http.MethodPost, Endpoint: "https://resource.example/documents",
			Body: exactBody, ContentType: "application/json",
		},
		approved.Grant,
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

	tampered, err := http.NewRequest(
		http.MethodPost,
		"https://resource.example/documents",
		bytes.NewReader(exactBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Header.Set("Content-Type", "application/json")
	accessAuthorization, err := aauth.AccessAuthorization(approved.Grant.Token)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Header.Set("Authorization", accessAuthorization)
	if err := signaturekey.SignJWTRequestWithOptions(
		tampered,
		agentKey,
		agentToken,
		clock,
		signaturekey.SignOptions{Nonce: "captured-deferred-body"},
	); err != nil {
		t.Fatal(err)
	}
	tampered.Body = io.NopCloser(strings.NewReader(`{"query":"tampered"}`))
	tampered.ContentLength = int64(len(`{"query":"tampered"}`))
	tamperedResponse, err := client.Do(tampered)
	if err != nil {
		t.Fatal(err)
	}
	defer tamperedResponse.Body.Close()
	if tamperedResponse.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(tamperedResponse.Body)
		t.Fatalf("tampered body status = %d, body = %s", tamperedResponse.StatusCode, body)
	}
	if executionCount != 1 {
		t.Fatalf("tampered protected body reached operation; executions = %d", executionCount)
	}

	now = now.Add(time.Second)
	expiring, err := agent.RequestResourceManagedAccess(
		context.Background(),
		reference.AuthorizedCall{Method: http.MethodGet, Endpoint: "https://resource.example/documents"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if expiring.Pending == nil || expiring.Grant != nil {
		t.Fatalf("expiring authorization = %#v", expiring)
	}
	now = now.Add(time.Minute + time.Second)
	if _, err := agent.PollResourceManagedAccess(context.Background(), expiring.Pending); err == nil {
		t.Fatal("expired pending authorization returned a grant")
	}
	if _, err := agent.PollResourceManagedAccess(context.Background(), expiring.Pending); err == nil {
		t.Fatal("expired pending authorization remained reusable")
	}
	if policyCalls != 1 || executionCount != 1 {
		t.Fatalf("expired pending authorization conferred authority: policy=%d operation=%d", policyCalls, executionCount)
	}

	now = now.Add(time.Second)
	attacked, err := agent.RequestResourceManagedAccess(
		context.Background(),
		reference.AuthorizedCall{Method: http.MethodGet, Endpoint: "https://resource.example/documents"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if attacked.Pending == nil {
		t.Fatalf("attacked authorization = %#v", attacked)
	}
	for attempt, expected := range []int{
		http.StatusBadRequest,
		http.StatusBadRequest,
		http.StatusGone,
	} {
		invalid, err := client.Get(attacked.Pending.Requirement.InteractionURL + "?code=ZZZZ-ZZZZ")
		if err != nil {
			t.Fatal(err)
		}
		invalid.Body.Close()
		if invalid.StatusCode != expected {
			t.Fatalf("invalid code attempt %d status = %d", attempt+1, invalid.StatusCode)
		}
	}
	if _, err := agent.PollResourceManagedAccess(context.Background(), attacked.Pending); err == nil {
		t.Fatal("attempt-limited pending authorization returned a grant")
	}
	if policyCalls != 1 || executionCount != 1 {
		t.Fatalf("invalid interaction code conferred authority: policy=%d operation=%d", policyCalls, executionCount)
	}

	now = now.Add(time.Second)
	denied, err := agent.RequestResourceManagedAccess(
		context.Background(),
		reference.AuthorizedCall{Method: http.MethodGet, Endpoint: "https://resource.example/documents"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if denied.Pending == nil {
		t.Fatalf("denied authorization = %#v", denied)
	}
	denialInteraction, err := client.Get(
		denied.Pending.Requirement.InteractionURL +
			"?code=" + denied.Pending.Requirement.InteractionCode,
	)
	if err != nil {
		t.Fatal(err)
	}
	denialInteraction.Body.Close()
	if denialInteraction.StatusCode != http.StatusOK {
		t.Fatalf("denial interaction status = %d", denialInteraction.StatusCode)
	}
	if err := resource.RejectAuthorization(denied.Pending.ID, aauth.PollingDenied); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.PollResourceManagedAccess(context.Background(), denied.Pending); err == nil {
		t.Fatal("denied poll succeeded")
	} else {
		var problem *aauth.ProblemError
		if !errors.As(err, &problem) ||
			problem.Status != http.StatusForbidden ||
			problem.Code != aauth.PollingDenied {
			t.Fatalf("denied poll error = %#v", err)
		}
	}
	if policyCalls != 1 || executionCount != 1 {
		t.Fatalf("denied interaction conferred authority: policy=%d operation=%d", policyCalls, executionCount)
	}
}
