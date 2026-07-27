package aauth_test

import (
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
		downstreamOperation.Actor.Agent != "aauth:flights@first.example" {
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
