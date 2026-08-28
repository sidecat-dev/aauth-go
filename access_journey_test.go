package aauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

type bodyAwareAccessAgent interface {
	DoWithAccess(context.Context, reference.AuthorizedCall, *reference.AccessGrant) (*http.Response, error)
}

func TestCurrentResourceManagedAccessStartsAtProtectedEndpoint(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)
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
	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
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

	var policyRequest aauth.AuthorizationRequest
	var operationRequest aauth.AuthorizedRequest
	var executionCount int
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier:               "https://resource.example",
		AccessMode:               aauth.AccessModeSessionToken,
		KeyResolver:              resolver,
		Clock:                    clock,
		NewID:                    ids,
		Scopes:                   []string{"documents.read"},
		RequiredScopesForRequest: testRequiredResourceScopes("documents.read"),
		ReplayStore:              testResourceReplayStore(t, clock),
		AuthorizationStore:       testAuthorizationStateStore(t),
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			policyRequest = request
			return aauth.AuthorizationDecision{
				Subject: "person-123",
				Scope:   request.Scope,
			}, nil
		},
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			executionCount++
			operationRequest = request
			return map[string]any{"agent": request.Agent}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example":       ap.Handler(),
		"resource.example": resource.Handler(),
	})
	defer gateway.Close()
	client.Transport = gateway.Client().Transport

	metadataResponse, err := client.Get("https://resource.example/.well-known/aauth-resource.json")
	if err != nil {
		t.Fatal(err)
	}
	defer metadataResponse.Body.Close()
	var metadata map[string]any
	if err := json.NewDecoder(metadataResponse.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["access_mode"] != string(aauth.AccessModeSessionToken) {
		t.Fatalf("resource access_mode = %#v", metadata["access_mode"])
	}
	if _, exists := metadata["jwks_uri"]; exists {
		t.Fatal("resource-managed metadata advertised a JWKS despite having no signing key")
	}

	agent, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:reader@ap.example",
		SigningKey:         agentKey,
		AgentToken:         agentToken,
		KeyResolver:        resolver,
		HTTPClient:         client,
		Clock:              clock,
	})
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

	agentAuthorize, err := http.NewRequest(http.MethodPost, "https://resource.example/authorize", strings.NewReader(`{"scope":"documents.read"}`))
	if err != nil {
		t.Fatal(err)
	}
	agentAuthorize.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(agentAuthorize, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	agentAuthorizeResponse, err := client.Do(agentAuthorize)
	if err != nil {
		t.Fatal(err)
	}
	defer agentAuthorizeResponse.Body.Close()
	if agentAuthorizeResponse.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(agentAuthorizeResponse.Body)
		t.Fatalf("agent-token /authorize response = %d %q requirement=%q", agentAuthorizeResponse.StatusCode, body, agentAuthorizeResponse.Header.Get("AAuth-Requirement"))
	}
	agentAuthorizeRequirement, err := aauth.ParseRequirementHeader(agentAuthorizeResponse.Header.Get("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	if agentAuthorizeResponse.StatusCode != http.StatusUnauthorized || agentAuthorizeRequirement.Type != aauth.RequirementPersonToken {
		t.Fatalf("agent-token /authorize response = %d %#v", agentAuthorizeResponse.StatusCode, agentAuthorizeRequirement)
	}

	protectedBody := []byte(`{"query":"current payload"}`)
	protectedCall := reference.AuthorizedCall{
		Method:      http.MethodPost,
		Endpoint:    "https://resource.example/documents",
		Body:        protectedBody,
		ContentType: "application/json",
	}
	authorization, err := agent.RequestResourceManagedAccess(
		context.Background(),
		protectedCall,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Grant == nil || authorization.Pending != nil {
		t.Fatalf("immediate authorization = %#v", authorization)
	}
	grant := *authorization.Grant
	if grant.Token != "opaque-access-token" {
		t.Fatalf("access token = %q", grant.Token)
	}
	if strings.Join(grant.Scope, " ") != "documents.read" {
		t.Fatalf("access scope = %q", grant.Scope)
	}
	if policyRequest.Agent != "aauth:reader@ap.example" ||
		policyRequest.PersonServer != "" || policyRequest.Subject != "" ||
		policyRequest.Resource != "https://resource.example" ||
		strings.Join(policyRequest.Scope, " ") != "documents.read" {
		t.Fatalf("local policy request = %#v", policyRequest)
	}
	bodyAware, ok := any(agent).(bodyAwareAccessAgent)
	if !ok {
		t.Fatal("Agent.DoWithAccess does not accept one body-aware AuthorizedCall")
	}
	response, err := bodyAware.DoWithAccess(context.Background(), protectedCall, &grant)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("AAuth-Access operation status = %d, body = %s", response.StatusCode, body)
	}
	if executionCount != 1 {
		t.Fatalf("protected operation execution count = %d", executionCount)
	}
	if operationRequest.Agent != "aauth:reader@ap.example" ||
		operationRequest.Subject != "person-123" ||
		strings.Join(operationRequest.Scope, " ") != "documents.read" ||
		!bytes.Equal(operationRequest.Body, protectedBody) ||
		operationRequest.ContentType != "application/json" {
		t.Fatalf("authorized operation request = %#v", operationRequest)
	}

	tamperedBodyRequest, err := http.NewRequest(
		http.MethodPost,
		"https://resource.example/documents",
		bytes.NewReader(protectedBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	tamperedBodyRequest.Header.Set("Content-Type", "application/json")
	authorizationHeader, err := aauth.AccessAuthorization(grant.Token)
	if err != nil {
		t.Fatal(err)
	}
	tamperedBodyRequest.Header.Set("Authorization", authorizationHeader)
	if err := aauth.SignRequestWithOptions(
		tamperedBodyRequest,
		agentKey,
		agentToken,
		clock,
		aauth.SignRequestOptions{Nonce: "captured-immediate-body"},
	); err != nil {
		t.Fatal(err)
	}
	tamperedBodyRequest.Body = io.NopCloser(strings.NewReader(`{"query":"tampered"}`))
	tamperedBodyRequest.ContentLength = int64(len(`{"query":"tampered"}`))
	tamperedResponse, err := client.Do(tamperedBodyRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer tamperedResponse.Body.Close()
	if tamperedResponse.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(tamperedResponse.Body)
		t.Fatalf("tampered body status = %d, body = %s", tamperedResponse.StatusCode, body)
	}
	if executionCount != 1 {
		t.Fatalf("tampered immediate body reached operation; execution count = %d", executionCount)
	}

	unsignedRequest, err := http.NewRequest(
		http.MethodGet,
		"https://resource.example/documents",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	unsignedRequest.Header.Set("Authorization", "AAuth "+grant.Token)
	unsigned, err := client.Do(unsignedRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer unsigned.Body.Close()
	if unsigned.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(unsigned.Body)
		t.Fatalf("unsigned access status = %d, body = %s", unsigned.StatusCode, body)
	}
	if executionCount != 1 {
		t.Fatalf("unsigned access invoked operation; execution count = %d", executionCount)
	}

	lowercaseRequest, err := http.NewRequest(
		http.MethodGet,
		"https://resource.example/documents",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	lowercaseRequest.Header.Set("Authorization", "aauth "+grant.Token)
	if err := aauth.SignRequest(lowercaseRequest, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	lowercase, err := client.Do(lowercaseRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer lowercase.Body.Close()
	if lowercase.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(lowercase.Body)
		t.Fatalf("lowercase AAuth access status = %d, body = %s", lowercase.StatusCode, body)
	}
	if executionCount != 2 {
		t.Fatalf("lowercase AAuth access execution count = %d", executionCount)
	}

	malformedRequest, err := http.NewRequest(
		http.MethodGet,
		"https://resource.example/documents",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	malformedRequest.Header.Set("Authorization", "AAuth one two")
	if err := aauth.SignRequest(malformedRequest, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	malformed, err := client.Do(malformedRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer malformed.Body.Close()
	if malformed.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(malformed.Body)
		t.Fatalf("malformed AAuth access status = %d, body = %s", malformed.StatusCode, body)
	}
	if got := malformed.Header.Get("Signature-Error"); got != "" {
		t.Fatalf("malformed authenticated access Signature-Error = %q", got)
	}
	if executionCount != 2 {
		t.Fatalf("malformed access invoked operation; execution count = %d", executionCount)
	}

	replayed, err := client.Do(lowercaseRequest.Clone(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Body.Close()
	if replayed.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(replayed.Body)
		t.Fatalf("replayed access status = %d, body = %s", replayed.StatusCode, body)
	}
	if executionCount != 2 {
		t.Fatalf("replayed access invoked operation; execution count = %d", executionCount)
	}

	tamperedRequest, err := http.NewRequest(
		http.MethodGet,
		"https://resource.example/documents",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	tamperedRequest.Header.Set("Authorization", "AAuth "+grant.Token)
	if err := aauth.SignRequest(tamperedRequest, agentKey, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	tamperedRequest.Header.Set("Authorization", "AAuth substituted-token")
	tampered, err := client.Do(tamperedRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer tampered.Body.Close()
	if tampered.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(tampered.Body)
		t.Fatalf("tampered access status = %d, body = %s", tampered.StatusCode, body)
	}
	if executionCount != 2 {
		t.Fatalf("tampered access invoked operation; execution count = %d", executionCount)
	}

	stolenGrant := grant
	stolen, err := other.DoWithAccess(
		context.Background(),
		reference.AuthorizedCall{Method: http.MethodGet, Endpoint: "https://resource.example/documents"},
		&stolenGrant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer stolen.Body.Close()
	if stolen.StatusCode != http.StatusForbidden && stolen.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(stolen.Body)
		t.Fatalf("stolen access status = %d, body = %s", stolen.StatusCode, body)
	}
	if executionCount != 2 {
		t.Fatalf("stolen access invoked operation; execution count = %d", executionCount)
	}

	now = now.Add(time.Hour + time.Minute)
	expired, err := agent.DoWithAccess(
		context.Background(),
		reference.AuthorizedCall{Method: http.MethodGet, Endpoint: "https://resource.example/documents"},
		&grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer expired.Body.Close()
	if expired.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(expired.Body)
		t.Fatalf("expired access status = %d, body = %s", expired.StatusCode, body)
	}
	if executionCount != 2 {
		t.Fatalf("expired access invoked operation; execution count = %d", executionCount)
	}
}
