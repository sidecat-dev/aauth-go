package aauth_test

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
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestResourceExtendsAuthorizationToDownstreamResource(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 27, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs(
		"original-agent-token",
		"intermediary-agent-token",
		"first-resource-token",
		"upstream-auth-token",
		"second-resource-token",
		"downstream-auth-token",
	)
	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	firstKey := testSigningKey(t, "first-key")
	secondKey := testSigningKey(t, "second-key")
	originalKey := testSigningKey(t, "original-key")
	intermediaryKey := testSigningKey(t, "intermediary-key")

	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: apKey,
		Clock:      clock,
		NewID:      ids,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstProvider, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://first.example",
		SigningKey: firstKey,
		Clock:      clock,
		NewID:      ids,
	})
	if err != nil {
		t.Fatal(err)
	}
	originalToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:planner@ap.example",
		PersonServer: "https://ps.example",
		PublicKey:    originalKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	intermediaryToken, err := firstProvider.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:flights@first.example",
		PersonServer: "https://ps.example",
		PublicKey:    intermediaryKey.PublicJWK(),
		Lifetime:     time.Hour,
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
				"https://first.example/",
				"https://second.example/",
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

	var chainedPolicyRequest aauth.AuthorizationRequest
	ps, err := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier:  "https://ps.example",
		SigningKey:  psKey,
		KeyResolver: resolver,
		Clock:       clock,
		NewID:       ids,
		TrustedUpstreamIssuer: func(_ context.Context, identifier string) error {
			if identifier != "https://ps.example" {
				return fmt.Errorf("untrusted upstream issuer %s", identifier)
			}
			return nil
		},
		MissionPolicy: func(_ context.Context, proposal aauth.MissionProposal) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: proposal.Description}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			if request.Upstream != nil {
				chainedPolicyRequest = request
			}
			return aauth.AuthorizationDecision{
				Subject: "pairwise-user",
				Scope:   request.Scope,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var downstreamOperation aauth.AuthorizedRequest
	second, err := reference.NewResource(reference.ResourceConfig{
		Identifier:   "https://second.example",
		PersonServer: "https://ps.example",
		SigningKey:   secondKey,
		KeyResolver:  resolver,
		Clock:        clock,
		NewID:        ids,
		Scopes:       []string{"payments.charge"},
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			downstreamOperation = request
			return map[string]any{"charged": true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var intermediary *reference.Agent
	var misdirectedUpstreamRefused bool
	first, err := reference.NewResource(reference.ResourceConfig{
		Identifier:   "https://first.example",
		PersonServer: "https://ps.example",
		SigningKey:   firstKey,
		KeyResolver:  resolver,
		Clock:        clock,
		NewID:        ids,
		Scopes:       []string{"flights.book"},
		Operation: func(ctx context.Context, request aauth.AuthorizedRequest) (any, error) {
			if request.Mission == nil || request.AuthToken == "" {
				return nil, fmt.Errorf("upstream request did not retain authorization context")
			}
			resourceGrant, err := intermediary.RequestResourceTokenForReference(
				ctx,
				"https://second.example/authorize",
				[]string{"payments.charge"},
				*request.Mission,
			)
			if err != nil {
				return nil, err
			}
			misdirectedClaims, err := aauth.VerifyAuthToken(ctx, request.AuthToken, resolver, clock)
			if err != nil {
				return nil, err
			}
			misdirectedClaims.Audience = "https://other.example"
			misdirectedClaims.JTI = "misdirected-upstream"
			misdirected, err := aauth.MintAuthToken(psKey, misdirectedClaims)
			if err != nil {
				return nil, err
			}
			if _, err := intermediary.ExchangeChainedResourceToken(
				ctx,
				"https://ps.example/token",
				resourceGrant,
				misdirected,
			); err != nil && strings.Contains(err.Error(), "audience") {
				misdirectedUpstreamRefused = true
			} else {
				return nil, fmt.Errorf("misdirected upstream refusal = %v", err)
			}
			grant, err := intermediary.ExchangeChainedResourceToken(
				ctx,
				"https://ps.example/token",
				resourceGrant,
				request.AuthToken,
			)
			if err != nil {
				return nil, err
			}
			response, err := intermediary.DoAuthorized(
				ctx,
				http.MethodPost,
				"https://second.example/charge",
				grant,
			)
			if err != nil {
				return nil, err
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(response.Body)
				return nil, fmt.Errorf("downstream status %d: %s", response.StatusCode, body)
			}
			var result map[string]any
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				return nil, err
			}
			return result, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	firstProviderHandler := firstProvider.Handler()
	firstResourceHandler := first.Handler()
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": ps.Handler(),
		"first.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/.well-known/aauth-agent.json" {
				firstProviderHandler.ServeHTTP(response, request)
				return
			}
			firstResourceHandler.ServeHTTP(response, request)
		}),
		"second.example": second.Handler(),
	})
	defer gateway.Close()
	client.Transport = gateway.Client().Transport

	original, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:planner@ap.example",
		SigningKey:  originalKey,
		AgentToken:  originalToken,
		KeyResolver: resolver,
		HTTPClient:  client,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	intermediary, err = reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:flights@first.example",
		SigningKey:  intermediaryKey,
		AgentToken:  intermediaryToken,
		KeyResolver: resolver,
		HTTPClient:  client,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	mission, err := original.CreateMission(context.Background(), "https://ps.example/mission", aauth.MissionProposal{
		Description: "Book a flight and charge the approved payment method.",
	})
	if err != nil {
		t.Fatal(err)
	}
	upstreamGrant, err := original.Authorize(
		context.Background(),
		"https://first.example/authorize",
		"https://ps.example/token",
		[]string{"flights.book"},
		mission,
	)
	if err != nil {
		t.Fatal(err)
	}
	response, err := original.DoAuthorized(
		context.Background(),
		http.MethodPost,
		"https://first.example/book",
		upstreamGrant,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("call-chain status = %d, body = %s", response.StatusCode, body)
	}
	if downstreamOperation.Agent != "aauth:flights@first.example" ||
		downstreamOperation.Actor == nil ||
		downstreamOperation.Actor.Agent != "aauth:planner@ap.example" {
		t.Fatalf("downstream authorization context = %#v", downstreamOperation)
	}
	if chainedPolicyRequest.Upstream == nil ||
		chainedPolicyRequest.Upstream.Audience != "https://first.example" ||
		chainedPolicyRequest.Agent != "aauth:flights@first.example" {
		t.Fatalf("PS chained policy context = %#v", chainedPolicyRequest)
	}
	if !misdirectedUpstreamRefused {
		t.Fatal("misdirected upstream token was not refused")
	}
}

func TestResourceExtendsAuthorizationThroughDownstreamAccessServer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	ids := sequentialIDs(
		"original-agent-token",
		"second-intermediary-agent-token",
		"intermediary-agent-token",
		"intermediary-subagent-token",
		"mission",
		"upstream-resource-token",
		"upstream-auth-token",
		"downstream-resource-token",
		"downstream-auth-token",
		"third-resource-token",
		"third-auth-token",
		"downstream-resource-token-deferred",
		"downstream-auth-token-deferred",
		"third-resource-token-deferred",
		"third-auth-token-deferred",
	)
	apKey := testSigningKey(t, "ap-key")
	psKey := testSigningKey(t, "ps-key")
	firstKey := testSigningKey(t, "first-key")
	secondKey := testSigningKey(t, "second-key")
	thirdKey := testSigningKey(t, "third-key")
	accessKey := testSigningKey(t, "access-key")
	untrustedKey := testSigningKey(t, "untrusted-key")
	originalKey := testSigningKey(t, "original-key")
	intermediaryKey := testSigningKey(t, "intermediary-key")
	intermediarySubagentKey := testSigningKey(t, "intermediary-subagent-key")
	secondIntermediaryKey := testSigningKey(t, "second-intermediary-key")

	ap, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example",
		SigningKey: apKey,
		Clock:      clock,
		NewID:      ids,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondProvider, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://second.example",
		SigningKey: secondKey,
		Clock:      clock,
		NewID:      ids,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstProvider, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://first.example",
		SigningKey: firstKey,
		Clock:      clock,
		NewID:      ids,
	})
	if err != nil {
		t.Fatal(err)
	}
	originalToken, err := ap.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:planner@ap.example",
		PersonServer: "https://ps.example",
		PublicKey:    originalKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondIntermediaryToken, err := secondProvider.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:payments@second.example",
		PersonServer: "https://ps.example",
		PublicKey:    secondIntermediaryKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	intermediaryToken, err := firstProvider.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:flights@first.example",
		PersonServer: "https://ps.example",
		PublicKey:    intermediaryKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	intermediarySubagentToken, err := firstProvider.IssueAgentToken(aauth.AgentTokenRequest{
		Agent:        "aauth:flights+fare1@first.example",
		PersonServer: "https://ps.example",
		ParentAgent:  "aauth:flights@first.example",
		PublicKey:    intermediarySubagentKey.PublicJWK(),
		Lifetime:     time.Hour,
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
				"https://first.example/",
				"https://second.example/",
				"https://third.example/",
				"https://as.example/",
				"https://untrusted.example/",
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

	var accessPolicyRequest aauth.AuthorizationRequest
	var accessPolicyCalls int
	var deferAccessAuthorization bool
	accessServer, err := reference.NewAccessServer(reference.AccessServerConfig{
		Identifier:  "https://as.example",
		SigningKey:  accessKey,
		KeyResolver: resolver,
		Clock:       clock,
		NewID:       ids,
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
			accessPolicyCalls++
			accessPolicyRequest = request
			if request.Upstream != nil {
				request.Upstream.Agent = "aauth:mutated-by-as-policy@ap.example"
			}
			return aauth.AuthorizationDecision{
				Subject: "federated-pairwise-user",
				Scope:   request.Scope,
			}, nil
		},
		InteractionRequired: func(_ context.Context, _ aauth.AuthorizationRequest) (bool, error) {
			return deferAccessAuthorization, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	untrustedServer, err := reference.NewAccessServer(reference.AccessServerConfig{
		Identifier:  "https://untrusted.example",
		SigningKey:  untrustedKey,
		KeyResolver: resolver,
		Clock:       clock,
		NewID:       func() string { return "unused-untrusted-id" },
		TrustedPersonServer: func(_ context.Context, _ string) error {
			return nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			return aauth.AuthorizationDecision{Scope: request.Scope}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var personPolicySawFirstResource bool
	var personPolicySawSecondResource bool
	personServer, err := reference.NewPersonServer(reference.PersonServerConfig{
		Identifier:       "https://ps.example",
		SigningKey:       psKey,
		KeyResolver:      resolver,
		Clock:            clock,
		NewID:            ids,
		FederationClient: client,
		AccessServerEndpoint: func(_ context.Context, identifier string) (string, error) {
			if identifier != "https://as.example" {
				return "", fmt.Errorf("unknown access server %s", identifier)
			}
			return identifier + "/token", nil
		},
		TrustedUpstreamIssuer: func(_ context.Context, identifier string) error {
			if identifier != "https://ps.example" &&
				identifier != "https://as.example" &&
				identifier != "https://untrusted.example" {
				return fmt.Errorf("untrusted upstream issuer %s", identifier)
			}
			return nil
		},
		MissionPolicy: func(_ context.Context, proposal aauth.MissionProposal) (aauth.MissionDecision, error) {
			return aauth.MissionDecision{Description: proposal.Description}, nil
		},
		AuthorizationPolicy: func(_ context.Context, request aauth.AuthorizationRequest) (aauth.AuthorizationDecision, error) {
			if request.Upstream != nil {
				switch request.Upstream.Audience {
				case "https://first.example":
					personPolicySawFirstResource = true
				case "https://second.example":
					personPolicySawSecondResource = true
				}
				request.Upstream.Agent = "aauth:mutated-by-ps-policy@ap.example"
			}
			return aauth.AuthorizationDecision{
				Subject: "person-server-user",
				Scope:   request.Scope,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var thirdOperation aauth.AuthorizedRequest
	var thirdOperationCalls int
	third, err := reference.NewResource(reference.ResourceConfig{
		Identifier:   "https://third.example",
		PersonServer: "https://ps.example",
		SigningKey:   thirdKey,
		KeyResolver:  resolver,
		Clock:        clock,
		NewID:        ids,
		Scopes:       []string{"ledger.write"},
		Operation: func(_ context.Context, request aauth.AuthorizedRequest) (any, error) {
			thirdOperationCalls++
			thirdOperation = request
			return map[string]any{"recorded": true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var secondIntermediary *reference.Agent
	var downstreamOperation aauth.AuthorizedRequest
	var downstreamOperationCalls int
	second, err := reference.NewResource(reference.ResourceConfig{
		Identifier:   "https://second.example",
		AccessServer: "https://as.example",
		SigningKey:   secondKey,
		KeyResolver:  resolver,
		Clock:        clock,
		NewID:        ids,
		Scopes:       []string{"payments.charge"},
		Operation: func(ctx context.Context, request aauth.AuthorizedRequest) (any, error) {
			downstreamOperationCalls++
			downstreamOperation = request
			if request.Mission == nil || request.AuthToken == "" {
				return nil, errors.New("downstream request did not retain authorization context")
			}
			resourceGrant, err := secondIntermediary.RequestResourceTokenForReference(
				ctx,
				"https://third.example/authorize",
				[]string{"ledger.write"},
				*request.Mission,
			)
			if err != nil {
				return nil, err
			}
			grant, err := secondIntermediary.ExchangeChainedResourceToken(
				ctx,
				"https://ps.example/token",
				resourceGrant,
				request.AuthToken,
			)
			if err != nil {
				return nil, err
			}
			response, err := secondIntermediary.DoAuthorized(
				ctx,
				http.MethodPost,
				"https://third.example/record",
				grant,
			)
			if err != nil {
				return nil, err
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(response.Body)
				return nil, fmt.Errorf("third-resource status %d: %s", response.StatusCode, body)
			}
			return map[string]any{"charged": true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var intermediary *reference.Agent
	var intermediarySubagent *reference.Agent
	var untrustedUpstreamToken string
	first, err := reference.NewResource(reference.ResourceConfig{
		Identifier:   "https://first.example",
		PersonServer: "https://ps.example",
		SigningKey:   firstKey,
		KeyResolver:  resolver,
		Clock:        clock,
		NewID:        ids,
		Scopes:       []string{"flights.book"},
		Operation: func(ctx context.Context, request aauth.AuthorizedRequest) (any, error) {
			if request.Mission == nil || request.AuthToken == "" {
				return nil, errors.New("upstream request did not retain authorization context")
			}
			resourceGrant, err := intermediary.RequestResourceTokenForReference(
				ctx,
				"https://second.example/authorize",
				[]string{"payments.charge"},
				*request.Mission,
			)
			if err != nil {
				return nil, err
			}
			if request.Path == "/book" {
				upstream, err := aauth.VerifyAuthToken(ctx, request.AuthToken, resolver, clock)
				if err != nil {
					return nil, err
				}

				wrongAudience := upstream
				wrongAudience.JTI = "wrong-audience-upstream"
				wrongAudience.Audience = "https://other.example"
				wrongAudienceToken, err := aauth.MintAuthToken(psKey, wrongAudience)
				if err != nil {
					return nil, err
				}
				if _, err := intermediary.ExchangeChainedResourceToken(
					ctx,
					"https://ps.example/token",
					resourceGrant,
					wrongAudienceToken,
				); err == nil {
					return nil, errors.New("wrong upstream audience was accepted")
				}

				changedMission := upstream
				changedMission.JTI = "changed-mission-upstream"
				changedMission.Mission = &aauth.MissionReference{
					Approver: "https://ps.example",
					S256:     strings.Repeat("A", 43),
				}
				changedMissionToken, err := aauth.MintAuthToken(psKey, changedMission)
				if err != nil {
					return nil, err
				}
				if _, err := intermediary.ExchangeChainedResourceToken(
					ctx,
					"https://ps.example/token",
					resourceGrant,
					changedMissionToken,
				); err == nil {
					return nil, errors.New("changed upstream mission was accepted")
				}

				untrusted := upstream
				untrusted.Issuer = "https://untrusted.example"
				untrusted.DWK = aauth.AccessDiscoveryDocument
				untrusted.JTI = "untrusted-upstream"
				untrustedToken, err := aauth.MintAuthToken(untrustedKey, untrusted)
				if err != nil {
					return nil, err
				}
				untrustedUpstreamToken = untrustedToken
				if _, err := intermediary.ExchangeChainedResourceToken(
					ctx,
					"https://ps.example/token",
					resourceGrant,
					untrustedToken,
				); err == nil {
					return nil, errors.New("untrusted upstream issuer was accepted")
				}
				if accessPolicyCalls != 0 || downstreamOperationCalls != 0 {
					return nil, fmt.Errorf(
						"refused chains reached policy or effect: policy=%d operation=%d",
						accessPolicyCalls,
						downstreamOperationCalls,
					)
				}
			}

			authorizedAgent := intermediary
			var authorization reference.TokenAuthorization
			if request.Path == "/book" {
				subagentResourceGrant, err := intermediarySubagent.RequestResourceTokenForReference(
					ctx,
					"https://second.example/authorize",
					[]string{"payments.charge"},
					*request.Mission,
				)
				if err != nil {
					return nil, err
				}
				authorization, err = intermediary.RequestChainedSubagentTokenAuthorization(
					ctx,
					"https://ps.example/token",
					subagentResourceGrant,
					intermediarySubagentToken,
					request.AuthToken,
				)
				authorizedAgent = intermediarySubagent
			} else {
				authorization, err = intermediary.RequestChainedTokenAuthorization(
					ctx,
					"https://ps.example/token",
					resourceGrant,
					request.AuthToken,
				)
			}
			if err != nil {
				return nil, err
			}
			if request.Path == "/book-deferred" {
				if authorization.Pending == nil ||
					authorization.Pending.Requirement == nil ||
					!strings.HasPrefix(
						authorization.Pending.Requirement.InteractionURL,
						"https://as.example/interaction/",
					) {
					return nil, fmt.Errorf("deferred chained authorization = %#v", authorization)
				}
				interaction, err := client.Get(
					authorization.Pending.Requirement.InteractionURL +
						"?code=" + authorization.Pending.Requirement.InteractionCode,
				)
				if err != nil {
					return nil, err
				}
				interaction.Body.Close()
				if interaction.StatusCode != http.StatusOK {
					return nil, fmt.Errorf("downstream interaction status = %d", interaction.StatusCode)
				}
				accessPendingID := strings.TrimPrefix(
					authorization.Pending.Requirement.InteractionURL,
					"https://as.example/interaction/",
				)
				if err := accessServer.ApproveAuthorization(ctx, accessPendingID); err != nil {
					return nil, err
				}
				authorization, err = intermediary.PollTokenAuthorization(ctx, authorization.Pending)
				if err != nil {
					return nil, err
				}
			}
			if authorization.Grant == nil {
				return nil, fmt.Errorf("chained authorization did not complete: %#v", authorization)
			}
			response, err := authorizedAgent.DoAuthorized(
				ctx,
				http.MethodPost,
				"https://second.example/charge",
				*authorization.Grant,
			)
			if err != nil {
				return nil, err
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(response.Body)
				return nil, fmt.Errorf("downstream status %d: %s", response.StatusCode, body)
			}
			return map[string]any{"booked": true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	firstProviderHandler := firstProvider.Handler()
	firstResourceHandler := first.Handler()
	secondProviderHandler := secondProvider.Handler()
	secondResourceHandler := second.Handler()
	accessServerHandler := accessServer.Handler()
	var forwardedUpstreamTokens []string
	var forwardedSubagentTokens []string
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"ap.example": ap.Handler(),
		"ps.example": personServer.Handler(),
		"as.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodPost && request.URL.Path == "/token" {
				body, err := io.ReadAll(request.Body)
				if err != nil {
					http.Error(response, err.Error(), http.StatusBadRequest)
					return
				}
				request.Body = io.NopCloser(bytes.NewReader(body))
				var input struct {
					UpstreamToken string `json:"upstream_token"`
					SubagentToken string `json:"subagent_token"`
				}
				if err := json.Unmarshal(body, &input); err != nil {
					http.Error(response, err.Error(), http.StatusBadRequest)
					return
				}
				forwardedUpstreamTokens = append(forwardedUpstreamTokens, input.UpstreamToken)
				forwardedSubagentTokens = append(forwardedSubagentTokens, input.SubagentToken)
			}
			accessServerHandler.ServeHTTP(response, request)
		}),
		"untrusted.example": untrustedServer.Handler(),
		"first.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/.well-known/aauth-agent.json" {
				firstProviderHandler.ServeHTTP(response, request)
				return
			}
			firstResourceHandler.ServeHTTP(response, request)
		}),
		"second.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/.well-known/aauth-agent.json" {
				secondProviderHandler.ServeHTTP(response, request)
				return
			}
			secondResourceHandler.ServeHTTP(response, request)
		}),
		"third.example": third.Handler(),
	})
	defer gateway.Close()
	client.Transport = gateway.Client().Transport

	original, err := reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:planner@ap.example",
		SigningKey:  originalKey,
		AgentToken:  originalToken,
		KeyResolver: resolver,
		HTTPClient:  client,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	intermediarySubagent, err = reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:flights+fare1@first.example",
		SigningKey:  intermediarySubagentKey,
		AgentToken:  intermediarySubagentToken,
		KeyResolver: resolver,
		HTTPClient:  client,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	intermediary, err = reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:flights@first.example",
		SigningKey:  intermediaryKey,
		AgentToken:  intermediaryToken,
		KeyResolver: resolver,
		HTTPClient:  client,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondIntermediary, err = reference.NewAgent(reference.AgentConfig{
		Identifier:  "aauth:payments@second.example",
		SigningKey:  secondIntermediaryKey,
		AgentToken:  secondIntermediaryToken,
		KeyResolver: resolver,
		HTTPClient:  client,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	mission, err := original.CreateMission(context.Background(), "https://ps.example/mission", aauth.MissionProposal{
		Description: "Book a flight and charge the approved payment method.",
	})
	if err != nil {
		t.Fatal(err)
	}
	upstreamGrant, err := original.Authorize(
		context.Background(),
		"https://first.example/authorize",
		"https://ps.example/token",
		[]string{"flights.book"},
		mission,
	)
	if err != nil {
		t.Fatal(err)
	}
	response, err := original.DoAuthorized(
		context.Background(),
		http.MethodPost,
		"https://first.example/book",
		upstreamGrant,
	)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("four-party call-chain status = %d, body = %s", response.StatusCode, body)
	}
	response.Body.Close()
	if !personPolicySawFirstResource || !personPolicySawSecondResource {
		t.Fatalf(
			"person-server policy did not see both chained resources: first=%t second=%t",
			personPolicySawFirstResource,
			personPolicySawSecondResource,
		)
	}
	if accessPolicyRequest.Agent != "aauth:flights+fare1@first.example" ||
		accessPolicyRequest.ParentAgent != "aauth:flights@first.example" ||
		accessPolicyRequest.Upstream == nil ||
		accessPolicyRequest.Upstream.Audience != "https://first.example" {
		t.Fatalf("access-server policy context = %#v", accessPolicyRequest)
	}
	if downstreamOperation.Agent != "aauth:flights+fare1@first.example" ||
		downstreamOperation.Actor == nil ||
		downstreamOperation.Actor.Agent != "aauth:flights@first.example" ||
		downstreamOperation.Actor.Actor == nil ||
		downstreamOperation.Actor.Actor.Agent != "aauth:planner@ap.example" ||
		downstreamOperation.Actor.Actor.Actor != nil {
		t.Fatalf("downstream authorization context = %#v", downstreamOperation)
	}
	if thirdOperation.Agent != "aauth:payments@second.example" ||
		thirdOperation.Actor == nil ||
		thirdOperation.Actor.Agent != "aauth:flights+fare1@first.example" ||
		thirdOperation.Actor.Actor == nil ||
		thirdOperation.Actor.Actor.Agent != "aauth:flights@first.example" ||
		thirdOperation.Actor.Actor.Actor == nil ||
		thirdOperation.Actor.Actor.Actor.Agent != "aauth:planner@ap.example" ||
		thirdOperation.Actor.Actor.Actor.Actor != nil {
		t.Fatalf("third-resource authorization context = %#v", thirdOperation)
	}

	now = now.Add(time.Second)
	deferAccessAuthorization = true
	response, err = original.DoAuthorized(
		context.Background(),
		http.MethodPost,
		"https://first.example/book-deferred",
		upstreamGrant,
	)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("deferred four-party call-chain status = %d, body = %s", response.StatusCode, body)
	}
	response.Body.Close()
	if accessPolicyCalls != 2 ||
		downstreamOperationCalls != 2 ||
		thirdOperationCalls != 2 {
		t.Fatalf(
			"completed call-chain counts: AS policy=%d downstream operation=%d third operation=%d",
			accessPolicyCalls,
			downstreamOperationCalls,
			thirdOperationCalls,
		)
	}
	if downstreamOperation.Agent != "aauth:flights@first.example" ||
		downstreamOperation.Actor == nil ||
		downstreamOperation.Actor.Agent != "aauth:planner@ap.example" ||
		downstreamOperation.Actor.Actor != nil {
		t.Fatalf("deferred downstream authorization context = %#v", downstreamOperation)
	}
	if thirdOperation.Agent != "aauth:payments@second.example" ||
		thirdOperation.Actor == nil ||
		thirdOperation.Actor.Agent != "aauth:flights@first.example" ||
		thirdOperation.Actor.Actor == nil ||
		thirdOperation.Actor.Actor.Agent != "aauth:planner@ap.example" ||
		thirdOperation.Actor.Actor.Actor != nil {
		t.Fatalf("deferred third-resource authorization context = %#v", thirdOperation)
	}
	expectedForwardedUpstreamTokens := []string{
		untrustedUpstreamToken,
		upstreamGrant.AuthToken,
		upstreamGrant.AuthToken,
	}
	if len(forwardedUpstreamTokens) != len(expectedForwardedUpstreamTokens) {
		t.Fatalf(
			"PS-to-AS upstream-token forwards = %d, want %d",
			len(forwardedUpstreamTokens),
			len(expectedForwardedUpstreamTokens),
		)
	}
	for index, forwarded := range forwardedUpstreamTokens {
		if forwarded != expectedForwardedUpstreamTokens[index] {
			t.Fatalf("PS-to-AS upstream token %d was not forwarded byte-for-byte", index)
		}
	}
	expectedForwardedSubagentTokens := []string{"", intermediarySubagentToken, ""}
	if len(forwardedSubagentTokens) != len(expectedForwardedSubagentTokens) {
		t.Fatalf(
			"PS-to-AS subagent-token forwards = %d, want %d",
			len(forwardedSubagentTokens),
			len(expectedForwardedSubagentTokens),
		)
	}
	for index, forwarded := range forwardedSubagentTokens {
		if forwarded != expectedForwardedSubagentTokens[index] {
			t.Fatalf("PS-to-AS subagent token %d was not forwarded byte-for-byte", index)
		}
	}
}
