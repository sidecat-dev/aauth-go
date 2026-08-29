package aauth_test

import (
	"bytes"
	"context"
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

func TestCurrentParentMediatedSubagentAuthorization(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 7, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs(
		"parent-agent-token",
		"subagent-token",
		"subagent-person-token",
		"subagent-resource-token",
		"subagent-auth-token",
		"deferred-subagent-resource-token",
		"deferred-subagent-auth-token",
	)
	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	resourceKey := testSigningKey(t, "resource-key")
	parentKey := testSigningKey(t, "parent-key")
	subagentKey := testSigningKey(t, "subagent-key")

	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: apKey,
		Clock:      clock,
		NewID:      ids,
	})
	if err != nil {
		t.Fatal(err)
	}
	parentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:planner@ap.example",
		PersonServer: "https://ps.example",
		PublicKey:    parentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	subagentToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:planner+search1@ap.example",
		PersonServer: "https://ps.example",
		ParentAgent:  "aauth:planner@ap.example",
		PublicKey:    subagentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	discoveryClient := &http.Client{}
	keyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: discoveryClient,
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
			return fmt.Errorf("discovery endpoint is outside the test trust boundary: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var policyRequest aauth.AuthorizationRequest
	var personPolicyRequest aauth.PersonTokenRequest
	var policyCalls int
	var deferSubagent bool
	personTokenStore, missionIssuanceStore := testCurrentPersonServerCustody(t)
	ps, err := reference.NewPersonServer(reference.PersonServerConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "https://ps.example",
		SigningKey:         psKey,
		KeyResolver:        keyResolver,
		Clock:              clock,
		NewID:              ids,
		InteractionRequired: func(_ context.Context, request aauth.AuthorizationRequest) (bool, error) {
			return deferSubagent && request.ParentAgent == "aauth:planner@ap.example", nil
		},
		PersonTokenStore:     personTokenStore,
		MissionIssuanceStore: missionIssuanceStore,
		PersonTokenPolicy: func(_ context.Context, request aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			personPolicyRequest = request
			return aauth.PersonTokenDecision{Subject: "pairwise-user-for-resource", Lifetime: time.Hour}, nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: evaluation.Proposal.Description}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			policyCalls++
			policyRequest = request
			return aauth.AuthorizationDecision{
				Subject: request.Subject,
				Scope:   request.Scope,
			}, nil
		},
		Random: bytes.NewReader(bytes.Join([][]byte{
			bytes.Repeat([]byte{4}, 16),
			{0, 1, 2, 3, 4},
		}, nil)),
		PendingLifetime: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	var operationRequest aauth.AuthorizedRequest
	resource, err := reference.NewResource(reference.ResourceConfig{
		Identifier:                   "https://resource.example",
		AccessMode:                   aauth.AccessModeAuthToken,
		PersonServer:                 "https://ps.example",
		SigningKey:                   resourceKey,
		KeyResolver:                  keyResolver,
		Clock:                        clock,
		NewID:                        ids,
		Scopes:                       []string{"search.read"},
		ScopeDescriptions:            map[string]string{"search.read": "Search"},
		RequiredScopesForRequest:     testRequiredResourceScopes("search.read"),
		ReplayStore:                  testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error { return nil },
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			operationRequest = request
			return map[string]any{"results": []string{"match"}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example":       ap.Handler(),
		"ps.example":       ps.Handler(),
		"resource.example": resource.Handler(),
	})
	defer gateway.Close()
	discoveryClient.Transport = gateway.Client().Transport

	parent, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:planner@ap.example",
		SigningKey:         parentKey,
		AgentToken:         parentToken,
		KeyResolver:        keyResolver,
		HTTPClient:         gateway.Client(),
		Clock:              clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	subagent, err := reference.NewAgent(reference.AgentConfig{
		AuthorizationStore: testAuthorizationStateStore(t),
		Identifier:         "aauth:planner+search1@ap.example",
		SigningKey:         subagentKey,
		AgentToken:         subagentToken,
		KeyResolver:        keyResolver,
		HTTPClient:         gateway.Client(),
		Clock:              clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	person, err := parent.RequestPersonTokenForSubagent(
		context.Background(),
		"https://ps.example/person",
		"https://resource.example",
		subagentToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	if personPolicyRequest.Agent != "aauth:planner+search1@ap.example" ||
		personPolicyRequest.ParentAgent != "aauth:planner@ap.example" ||
		!personPolicyRequest.Confirmation.Equal(subagentKey.PublicJWK()) {
		t.Fatalf("person-token policy context = %#v", personPolicyRequest)
	}
	resourceGrant, err := subagent.RequestResourceTokenWithPersonToken(
		context.Background(),
		"https://resource.example/authorize",
		[]string{"search.read"},
		person.PersonToken,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := subagent.ExchangeResourceToken(
		context.Background(),
		"https://ps.example/token",
		resourceGrant,
	); err == nil || !strings.Contains(err.Error(), "sub-agent cannot request authorization directly") {
		t.Fatalf("direct sub-agent exchange error = %v", err)
	}

	grant, err := parent.AuthorizeSubagent(
		context.Background(),
		"https://ps.example/token",
		resourceGrant,
		subagentToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Claims.Agent != "" || grant.Claims.Actor != nil ||
		grant.Claims.PersonServer != "https://ps.example" ||
		grant.Claims.Subject != "pairwise-user-for-resource" ||
		!grant.Claims.Confirmation.JWK.Equal(subagentKey.PublicJWK()) {
		t.Fatalf("sub-agent grant claims = %#v", grant.Claims)
	}
	if policyRequest.Agent != "aauth:planner+search1@ap.example" ||
		policyRequest.ParentAgent != "aauth:planner@ap.example" {
		t.Fatalf("policy context = %#v", policyRequest)
	}

	response, err := subagent.DoAuthorized(
		context.Background(),
		http.MethodGet,
		"https://resource.example/search",
		grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("sub-agent protected operation status = %d, body = %s", response.StatusCode, body)
	}
	if operationRequest.Agent != "" || operationRequest.PersonServer != "https://ps.example" ||
		operationRequest.Subject != "pairwise-user-for-resource" {
		t.Fatalf("protected operation person context = %#v", operationRequest)
	}

	deferSubagent = true
	now = now.Add(time.Second)
	deferredResourceGrant, err := subagent.RequestResourceTokenWithPersonToken(
		context.Background(),
		"https://resource.example/authorize",
		[]string{"search.read"},
		person.PersonToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := parent.RequestSubagentTokenAuthorization(
		context.Background(),
		"https://ps.example/token",
		deferredResourceGrant,
		subagentToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Grant != nil || authorization.Pending == nil {
		t.Fatalf("deferred sub-agent authorization = %#v", authorization)
	}
	pending := authorization.Pending
	if policyCalls != 1 {
		t.Fatalf("sub-agent policy ran before deferred approval; calls = %d", policyCalls)
	}

	interaction, err := gateway.Client().Get(
		pending.Requirement.InteractionURL +
			"?code=" + pending.Requirement.InteractionCode,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer interaction.Body.Close()
	if interaction.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(interaction.Body)
		t.Fatalf("deferred sub-agent interaction status = %d, body = %s", interaction.StatusCode, body)
	}
	if err := ps.ApproveAuthorization(context.Background(), pending.ID); err != nil {
		t.Fatal(err)
	}
	if policyCalls != 2 {
		t.Fatalf("sub-agent policy calls after deferred approval = %d", policyCalls)
	}

	deferred, err := parent.PollTokenAuthorization(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	if deferred.Grant == nil ||
		deferred.Grant.Claims.Agent != "" || deferred.Grant.Claims.Actor != nil ||
		deferred.Grant.Claims.PersonServer != "https://ps.example" ||
		deferred.Grant.Claims.Subject != "pairwise-user-for-resource" ||
		!deferred.Grant.Claims.Confirmation.JWK.Equal(subagentKey.PublicJWK()) {
		t.Fatalf("deferred sub-agent grant = %#v", deferred.Grant)
	}
	deferredResponse, err := subagent.DoAuthorized(
		context.Background(),
		http.MethodGet,
		"https://resource.example/search",
		*deferred.Grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer deferredResponse.Body.Close()
	if deferredResponse.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(deferredResponse.Body)
		t.Fatalf("deferred sub-agent protected status = %d, body = %s", deferredResponse.StatusCode, body)
	}
}
