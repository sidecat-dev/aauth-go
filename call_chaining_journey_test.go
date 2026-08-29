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

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestCurrentCallChainThroughPersonServer(t *testing.T) {
	testCurrentCallChain(t, false, false, false)
}

func TestCurrentCallChainThroughAccessServer(t *testing.T) {
	testCurrentCallChain(t, true, false, false)
}

func TestCurrentCallChainThroughPersonServerRejectsSubstitutedUpstreamKey(t *testing.T) {
	testCurrentCallChain(t, false, true, false)
}

func TestCurrentCallChainThroughAccessServerRejectsSubstitutedUpstreamKey(t *testing.T) {
	testCurrentCallChain(t, true, true, false)
}

func TestCurrentCallChainRoutesSubagentByUpstreamPSThroughPersonServer(t *testing.T) {
	testCurrentCallChain(t, false, false, true)
}

func TestCurrentCallChainRoutesSubagentByUpstreamPSThroughAccessServer(t *testing.T) {
	testCurrentCallChain(t, true, false, true)
}

func testCurrentCallChain(t *testing.T, federated bool, substituteUpstreamKey bool, chainedSubagent bool) {
	t.Helper()
	t.Parallel()

	now := time.Date(2026, 8, 28, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	psKey := testSigningKey(t, "ps-key")
	asKey := testSigningKey(t, "as-key")
	resourceKey := testSigningKey(t, "downstream-resource-key")
	intermediaryKey := testSigningKey(t, "intermediary-key")
	subagentKey := testSigningKey(t, "subagent-key")
	substitutedKey := testSigningKey(t, "substituted-upstream-key")

	intermediaryProvider, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://first.example",
		SigningKey: intermediaryKey,
		Clock:      clock,
		NewID:      sequentialIDs("intermediary-agent-token", "subagent-agent-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	intermediaryToken, err := intermediaryProvider.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:booking@first.example",
		PersonServer: "https://intermediary-ps.example",
		PublicKey:    intermediaryKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	var subagentToken string
	if chainedSubagent {
		subagentToken, err = intermediaryProvider.IssueAgentToken(aauth.AgentTokenRequest{
			Agent:        "aauth:booking+worker1@first.example",
			PersonServer: "https://subagent-ps.example",
			ParentAgent:  "aauth:booking@first.example",
			PublicKey:    subagentKey.PublicJWK(),
			Lifetime:     time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	client := &http.Client{}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			for _, prefix := range []string{
				"https://first.example/",
				"https://ps.example/",
				"https://as.example/",
				"https://downstream.example/",
			} {
				if strings.HasPrefix(endpoint, prefix) {
					return nil
				}
			}
			return fmt.Errorf("endpoint outside trust boundary: %s", endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var accessServer *reference.AccessServer
	if federated {
		accessServer, err = reference.NewAccessServer(reference.AccessServerConfig{
			AuthorizationStore: testAuthorizationStateStore(t),
			Identifier:         "https://as.example",
			SigningKey:         asKey,
			KeyResolver:        resolver,
			Clock:              clock,
			NewID:              sequentialIDs("downstream-auth-token"),
			TrustedPersonServer: func(_ context.Context, identifier string) error {
				if identifier != "https://ps.example" {
					return fmt.Errorf("untrusted person server %s", identifier)
				}
				return nil
			},
			TrustedUpstreamIssuer: func(_ context.Context, identifier string) error {
				if identifier != "https://ps.example" {
					return fmt.Errorf("untrusted upstream issuer %s", identifier)
				}
				return nil
			},
			AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
				if request.Upstream == nil || request.Upstream.Subject != "upstream-directed-person" {
					return aauth.AuthorizationDecision{}, fmt.Errorf("missing upstream authorization")
				}
				return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	personTokenStore, missionIssuanceStore := testCurrentPersonServerCustody(t)
	var personPolicyRequest aauth.PersonTokenRequest
	personPolicyCalls := 0
	var authorizationRequest aauth.AuthorizationRequest
	personIDs := []string{"downstream-person-token"}
	if !federated {
		personIDs = append(personIDs, "downstream-auth-token")
	}
	personAuthorizationDirectory := t.TempDir() + "/person-authorization"
	personAuthorizationStore := openTestFileAuthorizationStateStore(t, personAuthorizationDirectory)
	personConfig := reference.PersonServerConfig{
		AuthorizationStore:   personAuthorizationStore,
		Identifier:           "https://ps.example",
		SigningKey:           psKey,
		KeyResolver:          resolver,
		Clock:                clock,
		NewID:                sequentialIDs(personIDs...),
		PersonTokenStore:     personTokenStore,
		MissionIssuanceStore: missionIssuanceStore,
		PersonTokenPolicy: func(_ context.Context, request aauth.PersonTokenRequest) (aauth.PersonTokenDecision, error) {
			personPolicyCalls++
			personPolicyRequest = request
			if request.Upstream == nil || request.Upstream.Subject != "upstream-directed-person" {
				return aauth.PersonTokenDecision{}, fmt.Errorf("upstream authorization is required")
			}
			return aauth.PersonTokenDecision{Subject: "downstream-directed-person", Lifetime: time.Hour}, nil
		},
		PersonTokenInteractionRequired: func(_ context.Context, request aauth.PersonTokenRequest) (bool, error) {
			return request.Upstream != nil, nil
		},
		CurrentMissionPolicy: func(_ context.Context, evaluation aauth.MissionEvaluation) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: evaluation.Proposal.Description}, nil
		},
		TrustedUpstreamIssuer: func(_ context.Context, identifier string) error {
			if identifier != "https://ps.example" {
				return fmt.Errorf("untrusted upstream issuer %s", identifier)
			}
			return nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			authorizationRequest = request
			if request.Upstream == nil || request.Upstream.Subject != "upstream-directed-person" {
				return aauth.AuthorizationDecision{}, fmt.Errorf("upstream authorization is required")
			}
			return aauth.AuthorizationDecision{Subject: request.Subject, Scope: request.Scope}, nil
		},
		FederationClient: func() *http.Client {
			if federated {
				return client
			}
			return nil
		}(),
		AccessServerEndpoint: func() func(context.Context, string) (string, error) {
			if !federated {
				return nil
			}
			return func(_ context.Context, identifier string) (string, error) {
				if identifier != "https://as.example" {
					return "", fmt.Errorf("unknown access server %s", identifier)
				}
				return identifier + "/token", nil
			}
		}(),
		Random: bytes.NewReader(bytes.Join([][]byte{
			bytes.Repeat([]byte{8}, 16), {0, 1, 2, 3, 4},
		}, nil)),
		PendingLifetime: time.Minute,
	}
	personServer, err := reference.NewPersonServer(personConfig)
	if err != nil {
		t.Fatal(err)
	}

	var protected aauth.AuthorizedRequest
	resourceConfig := reference.ResourceConfig{
		Identifier:   "https://downstream.example",
		AccessMode:   aauth.AccessModeAuthToken,
		PersonServer: "https://ps.example",
		SigningKey:   resourceKey,
		KeyResolver:  resolver,
		Clock:        clock,
		NewID:        sequentialIDs("downstream-resource-token"),
		Scopes:       []string{"payments.charge"},
		ScopeDescriptions: map[string]string{
			"payments.charge": "Charge an approved payment",
		},
		RequiredScopesForRequest: testRequiredResourceScopes("payments.charge"),
		ReplayStore:              testResourceReplayStore(t, clock),
		ProtectedAuthorizationPolicy: func(context.Context, aauth.AuthorizedRequest) error {
			return nil
		},
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			protected = request
			return map[string]bool{"charged": true}, nil
		},
	}
	if federated {
		resourceConfig.PersonServer = ""
		resourceConfig.AccessServer = "https://as.example"
	}
	downstream, err := reference.NewResource(resourceConfig)
	if err != nil {
		t.Fatal(err)
	}

	personHandler := personServer.Handler()
	handlers := map[string]http.Handler{
		"first.example": intermediaryProvider.Handler(),
		"ps.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			personHandler.ServeHTTP(response, request)
		}),
		"downstream.example": downstream.Handler(),
	}
	if federated {
		handlers["as.example"] = accessServer.Handler()
	}
	gateway := newLogicalGateway(t, handlers)
	defer gateway.Close()
	client.Transport = gateway.Client().Transport

	intermediaryAuthorizationDirectory := t.TempDir() + "/intermediary-authorization"
	intermediaryAuthorizationStore := openTestFileAuthorizationStateStore(t, intermediaryAuthorizationDirectory)
	intermediaryConfig := reference.AgentConfig{
		AuthorizationStore: intermediaryAuthorizationStore,
		Identifier:         "aauth:booking@first.example",
		SigningKey:         intermediaryKey,
		AgentToken:         intermediaryToken,
		KeyResolver:        resolver,
		HTTPClient:         client,
		Clock:              clock,
	}
	intermediary, err := reference.NewAgent(intermediaryConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := intermediary.RequestPersonTokenForUpstreamAuthorization(
		context.Background(), "https://ps.example/person", "https://downstream.example", "",
	); err == nil || err.Error() != "reference: upstream auth token is required" {
		t.Fatalf("empty typed upstream token error = %v", err)
	}
	if _, err := intermediary.RequestPersonTokenForChainedSubagentAuthorization(
		context.Background(), "https://ps.example/person", "https://downstream.example", "", "upstream",
	); err == nil || err.Error() != "reference: sub-agent token is required" {
		t.Fatalf("empty typed chained sub-agent token error = %v", err)
	}
	if _, err := intermediary.RequestPersonTokenForChainedSubagentAuthorization(
		context.Background(), "https://ps.example/person", "https://downstream.example", "subagent", "",
	); err == nil || err.Error() != "reference: upstream auth token is required" {
		t.Fatalf("empty typed chained upstream token error = %v", err)
	}
	resourceCaller := intermediary
	expectedTargetAgent := "aauth:booking@first.example"
	expectedParentAgent := ""
	expectedTargetKey := intermediaryKey.PublicJWK()
	if chainedSubagent {
		resourceCaller, err = reference.NewAgent(reference.AgentConfig{
			AuthorizationStore: testAuthorizationStateStore(t),
			Identifier:         "aauth:booking+worker1@first.example",
			SigningKey:         subagentKey,
			AgentToken:         subagentToken,
			KeyResolver:        resolver,
			HTTPClient:         client,
			Clock:              clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		expectedTargetAgent = "aauth:booking+worker1@first.example"
		expectedParentAgent = "aauth:booking@first.example"
		expectedTargetKey = subagentKey.PublicJWK()
	}
	upstreamToken, err := aauth.MintAuthToken(psKey, aauth.AuthTokenClaims{
		Issuer:       "https://ps.example",
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     "https://first.example",
		JTI:          "upstream-auth-token",
		PersonServer: "https://ps.example",
		Subject:      "upstream-directed-person",
		Confirmation: aauth.Confirmation{JWK: intermediaryKey.PublicJWK()},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(time.Hour).Unix(),
		Scope:        "flights.book",
	})
	if err != nil {
		t.Fatal(err)
	}

	var personAuthorization reference.PersonTokenAuthorization
	if chainedSubagent {
		personAuthorization, err = intermediary.RequestPersonTokenForChainedSubagentAuthorization(
			context.Background(),
			"https://ps.example/person",
			"https://downstream.example",
			subagentToken,
			upstreamToken,
		)
	} else {
		personAuthorization, err = intermediary.RequestPersonTokenForUpstreamAuthorization(
			context.Background(),
			"https://ps.example/person",
			"https://downstream.example",
			upstreamToken,
		)
	}
	if err != nil {
		t.Fatal(err)
	}
	if personAuthorization.Grant != nil || personAuthorization.Pending == nil {
		t.Fatalf("deferred call-chain person-token authorization = %#v", personAuthorization)
	}
	if chainedSubagent {
		if _, err := resourceCaller.PollPersonTokenAuthorization(context.Background(), personAuthorization.Pending); err == nil {
			t.Fatal("target chained sub-agent polled the intermediary-owned person-token continuation")
		}
	}
	pendingID := personAuthorization.Pending.ID
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
	if err := intermediaryAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	intermediaryAuthorizationStore = openTestFileAuthorizationStateStore(t, intermediaryAuthorizationDirectory)
	intermediaryConfig.AuthorizationStore = intermediaryAuthorizationStore
	intermediary, err = reference.NewAgent(intermediaryConfig)
	if err != nil {
		t.Fatal(err)
	}
	personAuthorization.Pending = &reference.PendingPersonTokenAuthorization{ID: pendingID}
	personAuthorization, err = intermediary.PollPersonTokenAuthorization(context.Background(), personAuthorization.Pending)
	if err != nil {
		t.Fatal(err)
	}
	if personAuthorization.Pending == nil || personAuthorization.Pending.Requirement == nil {
		t.Fatalf("recovered call-chain person-token continuation = %#v", personAuthorization)
	}
	interaction, err := gateway.Client().Get(
		personAuthorization.Pending.Requirement.InteractionURL + "?code=" + personAuthorization.Pending.Requirement.InteractionCode,
	)
	if err != nil {
		t.Fatal(err)
	}
	interaction.Body.Close()
	if interaction.StatusCode != http.StatusOK {
		t.Fatalf("call-chain person-token interaction status = %d", interaction.StatusCode)
	}
	if err := personServer.ApprovePersonToken(context.Background(), personAuthorization.Pending.ID); err != nil {
		t.Fatal(err)
	}
	personAuthorization, err = intermediary.PollPersonTokenAuthorization(context.Background(), personAuthorization.Pending)
	if err != nil {
		t.Fatal(err)
	}
	if personAuthorization.Grant == nil || personAuthorization.Pending != nil {
		t.Fatalf("approved call-chain person-token authorization = %#v", personAuthorization)
	}
	person := *personAuthorization.Grant
	if personPolicyCalls != 1 {
		t.Fatalf("call-chain person-token policy calls = %d, want 1", personPolicyCalls)
	}
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
	if err := intermediaryAuthorizationStore.Close(); err != nil {
		t.Fatal(err)
	}
	intermediaryAuthorizationStore = openTestFileAuthorizationStateStore(t, intermediaryAuthorizationDirectory)
	intermediaryConfig.AuthorizationStore = intermediaryAuthorizationStore
	intermediary, err = reference.NewAgent(intermediaryConfig)
	if err != nil {
		t.Fatal(err)
	}
	replayedPerson, err := intermediary.PollPersonTokenAuthorization(
		context.Background(), &reference.PendingPersonTokenAuthorization{ID: pendingID},
	)
	if err != nil {
		t.Fatal(err)
	}
	if replayedPerson.Grant == nil || replayedPerson.Grant.PersonToken != person.PersonToken || personPolicyCalls != 1 {
		t.Fatalf("replayed call-chain person token = %#v, policy calls %d", replayedPerson, personPolicyCalls)
	}
	if person.Claims.Subject != "downstream-directed-person" ||
		person.Claims.Subject == "upstream-directed-person" ||
		personPolicyRequest.Upstream == nil ||
		personPolicyRequest.Agent != expectedTargetAgent ||
		personPolicyRequest.ParentAgent != expectedParentAgent ||
		!person.Claims.Confirmation.JWK.Equal(expectedTargetKey) {
		t.Fatalf("downstream person-token context = %#v / policy %#v", person.Claims, personPolicyRequest)
	}
	resourceGrant, err := resourceCaller.RequestResourceTokenWithPersonToken(
		context.Background(),
		"https://downstream.example/authorize",
		[]string{"payments.charge"},
		person.PersonToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	if substituteUpstreamKey {
		substitutedUpstreamToken, err := aauth.MintAuthToken(psKey, aauth.AuthTokenClaims{
			Issuer:       "https://ps.example",
			DWK:          aauth.PersonDiscoveryDocument,
			Audience:     "https://first.example",
			JTI:          "substituted-upstream-auth-token",
			PersonServer: "https://ps.example",
			Subject:      "upstream-directed-person",
			Confirmation: aauth.Confirmation{JWK: substitutedKey.PublicJWK()},
			IssuedAt:     now.Unix(),
			ExpiresAt:    now.Add(time.Hour).Unix(),
			Scope:        "flights.book",
		})
		if err != nil {
			t.Fatal(err)
		}
		var boundaryEndpoint string
		var boundaryBody []byte
		if federated {
			boundaryEndpoint = "https://as.example/token"
			boundaryBody, err = json.Marshal(map[string]string{
				"resource_token": resourceGrant.ResourceToken,
				"agent_token":    intermediaryToken,
				"upstream_token": substitutedUpstreamToken,
			})
		} else {
			boundaryEndpoint = "https://ps.example/token"
			boundaryBody, err = json.Marshal(map[string]string{
				"resource_token": resourceGrant.ResourceToken,
				"upstream_token": substitutedUpstreamToken,
			})
		}
		if err != nil {
			t.Fatal(err)
		}
		boundaryRequest, err := http.NewRequest(
			http.MethodPost,
			boundaryEndpoint,
			bytes.NewReader(boundaryBody),
		)
		if err != nil {
			t.Fatal(err)
		}
		boundaryRequest.Header.Set("Content-Type", "application/json")
		if federated {
			err = signaturekey.SignJWKSURIRequestWithOptions(
				boundaryRequest,
				psKey,
				"https://ps.example",
				aauth.PersonDiscoveryDocument,
				clock,
				signaturekey.SignOptions{Nonce: "direct-ps-to-as-substitution"},
			)
		} else {
			err = signaturekey.SignJWTRequestWithOptions(
				boundaryRequest,
				intermediaryKey,
				intermediaryToken,
				clock,
				signaturekey.SignOptions{Nonce: "direct-ps-substitution"},
			)
		}
		if err != nil {
			t.Fatal(err)
		}
		boundaryResponse, err := client.Do(boundaryRequest)
		if err != nil {
			t.Fatal(err)
		}
		defer boundaryResponse.Body.Close()
		problem, err := aauth.DecodeProblemResponse(boundaryResponse)
		if err != nil {
			t.Fatal(err)
		}
		if boundaryResponse.StatusCode != http.StatusForbidden || problem.Code != "invalid_upstream_token" ||
			!strings.Contains(problem.Detail, "confirmation key") {
			t.Fatalf("substituted upstream-token boundary response = %d %#v", boundaryResponse.StatusCode, problem)
		}
		return
	}
	var grant reference.Grant
	if chainedSubagent {
		grant, err = intermediary.AuthorizeChainedSubagent(
			context.Background(),
			"https://ps.example/token",
			resourceGrant,
			subagentToken,
			upstreamToken,
		)
	} else {
		grant, err = intermediary.ExchangeChainedResourceToken(
			context.Background(),
			"https://ps.example/token",
			resourceGrant,
			upstreamToken,
		)
	}
	if err != nil {
		t.Fatal(err)
	}
	expectedIssuer := "https://ps.example"
	expectedDWK := aauth.PersonDiscoveryDocument
	if federated {
		expectedIssuer = "https://as.example"
		expectedDWK = aauth.AccessDiscoveryDocument
	}
	if grant.Claims.Issuer != expectedIssuer || grant.Claims.DWK != expectedDWK ||
		grant.Claims.PersonServer != "https://ps.example" ||
		grant.Claims.Subject != "downstream-directed-person" ||
		grant.Claims.Agent != "" || grant.Claims.Actor != nil ||
		!grant.Claims.Confirmation.JWK.Equal(expectedTargetKey) {
		t.Fatalf("downstream auth-token claims = %#v", grant.Claims)
	}
	if authorizationRequest.Upstream == nil ||
		authorizationRequest.Upstream.Subject != "upstream-directed-person" ||
		authorizationRequest.Subject != "downstream-directed-person" ||
		authorizationRequest.Agent != expectedTargetAgent ||
		authorizationRequest.ParentAgent != expectedParentAgent {
		t.Fatalf("downstream authorization policy = %#v", authorizationRequest)
	}

	response, err := resourceCaller.DoAuthorized(
		context.Background(),
		http.MethodPost,
		"https://downstream.example/charge",
		grant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("downstream protected status = %d, body = %s", response.StatusCode, body)
	}
	if protected.Agent != "" || protected.PersonServer != "https://ps.example" ||
		protected.Subject != "downstream-directed-person" {
		t.Fatalf("downstream protected context = %#v", protected)
	}
}
