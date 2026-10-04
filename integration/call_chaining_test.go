package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// TestCurrentCoreImmediateTwoResourceCallChain executes the immediate
// PS-authorized form of Core call chaining through every participating role.
// Resource 1 receives an auth token from the original Agent, then uses that
// exact token as upstream_token while acting as its own Agent toward Resource
// 2. Resource 1's Agent token deliberately names another Person Server so the
// journey can succeed only by routing and binding from the verified upstream
// token.
func TestCurrentCoreImmediateTwoResourceCallChain(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 30, 22, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		originalAgentProviderID = "https://agents.example"
		originalAgentID         = "aauth:reader@agents.example"
		personServerID          = "https://person.example"
		resourceOneID           = "https://resource-one.example"
		resourceOneAgentID      = "aauth:relay@resource-one.example"
		resourceOneOwnPS        = "https://relay-person.example"
		resourceTwoID           = "https://resource-two.example"
		upstreamSubject         = "person-at-resource-one"
		downstreamSubject       = "person-at-resource-two"
	)
	upstreamScope := []string{"orders.fulfill"}
	downstreamScope := []string{"inventory.reserve"}

	originalProviderKey := newSigningKey(t, "call-chain-original-provider")
	originalAgentKey := newSigningKey(t, "call-chain-original-agent")
	personServerKey := newSigningKey(t, "call-chain-person-server")
	resourceOneProviderKey := newSigningKey(t, "call-chain-resource-one-provider")
	resourceOneResourceKey := newSigningKey(t, "call-chain-resource-one-resource")
	resourceOneAgentKey := newSigningKey(t, "call-chain-resource-one-agent")
	resourceTwoKey := newSigningKey(t, "call-chain-resource-two")

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	keyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasSuffix(endpoint, ".example/.well-known/aauth-agent.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-person.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-resource.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/jwks.json") {
				return nil
			}
			return errors.New("unexpected discovery endpoint: " + endpoint)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	originalProvider, err := agentprovider.New(agentprovider.Config{
		Issuer: originalAgentProviderID, SigningKey: originalProviderKey, Clock: clock,
		NewID: func() string { return "call-chain-original-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	originalAgentToken, err := originalProvider.Issue(aauth.AgentTokenRequest{
		Agent: originalAgentID, PersonServer: personServerID,
		PublicKey: originalAgentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Resource 1 is also an Agent Provider at the same origin. Their issuer keys
	// remain distinct and the collocated JWKS publishes both; Resource 1's Agent
	// proof key is a third, separate key.
	resourceOneProvider, err := agentprovider.New(agentprovider.Config{
		Issuer: resourceOneID, SigningKey: resourceOneProviderKey, Clock: clock,
		NewID: func() string { return "call-chain-resource-one-agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceOneAgentToken, err := resourceOneProvider.Issue(aauth.AgentTokenRequest{
		Agent: resourceOneAgentID, PersonServer: resourceOneOwnPS,
		PublicKey: resourceOneAgentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	personTokens := newMemoryPersonTokenStore()
	directBindCalls := 0
	directAuthorizeCalls := 0
	chainBindCalls := 0
	chainAuthorizeCalls := 0
	personServerRecompositions := 0
	issuedTokenSequence := 0

	requireUpstream := func(upstream *aauth.AuthTokenClaims) error {
		if upstream == nil {
			return errors.New("call-chaining policy received no upstream token")
		}
		if upstream.Issuer != personServerID || upstream.DWK != aauth.PersonDiscoveryDocument ||
			upstream.Audience != resourceOneID || upstream.PersonServer != personServerID ||
			upstream.Subject != upstreamSubject || !slices.Equal(strings.Fields(upstream.Scope), upstreamScope) {
			return fmt.Errorf("unexpected upstream claims: %#v", upstream)
		}
		if !upstream.Confirmation.JWK.Equal(originalAgentKey.PublicJWK()) {
			return errors.New("upstream token is not bound to the original Agent key")
		}
		if upstream.Confirmation.JWK.Equal(resourceOneAgentKey.PublicJWK()) {
			return errors.New("upstream token was incorrectly rebound to Resource 1's Agent key")
		}
		return nil
	}

	personServerConfig := personserver.PSAuthorizationConfig{
		Issuer: personServerID, SigningKey: personServerKey, KeyResolver: keyResolver,
		Clock: clock, Tokens: personTokens, IssuedTokens: newMemoryIssuedAuthTokenStore(),
		NewID: func() string {
			issuedTokenSequence++
			return fmt.Sprintf("call-chain-person-server-token-%d", issuedTokenSequence)
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			directBindCalls++
			if request.Upstream != nil {
				return personserver.Person{}, errors.New("ordinary person-binding policy received an upstream token")
			}
			if request.Agent != originalAgentID || request.Subagent != "" || request.Resource != resourceOneID {
				return personserver.Person{}, fmt.Errorf("unexpected direct person-binding context: %#v", request)
			}
			return personserver.Person{
				Subject: upstreamSubject, Tenant: "tenant-1", Lifetime: 30 * time.Minute,
			}, nil
		},
		Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			directAuthorizeCalls++
			if request.Upstream != nil {
				return personserver.AuthorizationDecision{}, errors.New("ordinary authorization policy received an upstream token")
			}
			if request.Agent != originalAgentID || request.Subagent != "" || request.Resource != resourceOneID ||
				request.Subject != upstreamSubject || request.Tenant != "tenant-1" ||
				!slices.Equal(request.Scopes, upstreamScope) {
				return personserver.AuthorizationDecision{}, fmt.Errorf("unexpected direct authorization context: %#v", request)
			}
			return personserver.AuthorizationDecision{
				Scopes: append([]string(nil), request.Scopes...), Lifetime: 20 * time.Minute,
			}, nil
		},
		CallChaining: &personserver.CallChainingConfig{
			BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
				chainBindCalls++
				if request.Agent != resourceOneAgentID || request.Subagent != "" || request.Resource != resourceTwoID {
					return personserver.Person{}, fmt.Errorf("unexpected chained person-binding context: %#v", request)
				}
				if err := requireUpstream(request.Upstream); err != nil {
					return personserver.Person{}, err
				}
				// A policy callback receives its own claims value. Mutating it must
				// not alter the server's retained or later policy context.
				request.Upstream.Subject = "mutated-by-person-policy"
				request.Upstream.Scope = "mutated.by.person.policy"
				return personserver.Person{
					Subject: downstreamSubject, Tenant: "tenant-1", Lifetime: 25 * time.Minute,
				}, nil
			},
			Authorize: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				chainAuthorizeCalls++
				if request.Agent != resourceOneAgentID || request.Subagent != "" || request.Resource != resourceTwoID ||
					request.Subject != downstreamSubject || request.Tenant != "tenant-1" ||
					!slices.Equal(request.Scopes, downstreamScope) {
					return personserver.AuthorizationDecision{}, fmt.Errorf("unexpected chained authorization context: %#v", request)
				}
				if err := requireUpstream(request.Upstream); err != nil {
					return personserver.AuthorizationDecision{}, err
				}
				request.Upstream.Subject = "mutated-by-authorization-policy"
				request.Upstream.Scope = "mutated.by.authorization.policy"
				return personserver.AuthorizationDecision{
					Scopes: append([]string(nil), request.Scopes...), Lifetime: 15 * time.Minute,
				}, nil
			},
		},
	}
	newPersonServer := func() (*personserver.Server, error) {
		return personserver.NewPSAuthorization(personServerConfig)
	}
	people, err := newPersonServer()
	if err != nil {
		t.Fatal(err)
	}

	var upstreamAuthToken string
	var downstreamAuthToken string
	resourceTwoCalls := 0
	resourceTwoServer, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceTwoID, SigningKey: resourceTwoKey, KeyResolver: keyResolver, Clock: clock,
		NewID:             func() string { return "call-chain-resource-two-token" },
		ScopeDescriptions: map[string]string{"inventory.reserve": "Reserve inventory"},
		RequiredScopes:    func(*http.Request) []string { return append([]string(nil), downstreamScope...) },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: downstreamSubject}) ||
				personContext.Tenant != "tenant-1" {
				return fmt.Errorf("unexpected Resource 2 person: %#v %#v", identity, personContext)
			}
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			resourceTwoCalls++
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok || principal.PersonServer != personServerID || principal.Subject != downstreamSubject ||
				principal.Tenant != "tenant-1" || !slices.Equal(principal.Scope, downstreamScope) ||
				!principal.Confirmation.Equal(resourceOneAgentKey.PublicJWK()) {
				t.Errorf("Resource 2 principal = %#v, present=%t", principal, ok)
			}
			compact, ok := resource.AuthTokenFromContext(request.Context())
			if !ok || compact != downstreamAuthToken || compact == upstreamAuthToken {
				t.Errorf("Resource 2 auth token = %q, present=%t", compact, ok)
			}
			_, _ = io.WriteString(response, "inventory reserved")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	var relay *clientagent.Client
	resourceOneCalls := 0
	resourceOneServer, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceOneID, SigningKey: resourceOneResourceKey, KeyResolver: keyResolver, Clock: clock,
		NewID:             func() string { return "call-chain-resource-one-token" },
		ScopeDescriptions: map[string]string{"orders.fulfill": "Fulfill orders"},
		RequiredScopes:    func(*http.Request) []string { return append([]string(nil), upstreamScope...) },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: upstreamSubject}) ||
				personContext.Tenant != "tenant-1" {
				return fmt.Errorf("unexpected Resource 1 person: %#v %#v", identity, personContext)
			}
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			resourceOneCalls++
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok || principal.PersonServer != personServerID || principal.Subject != upstreamSubject ||
				principal.Tenant != "tenant-1" || !slices.Equal(principal.Scope, upstreamScope) ||
				!principal.Confirmation.Equal(originalAgentKey.PublicJWK()) {
				t.Errorf("Resource 1 principal = %#v, present=%t", principal, ok)
				http.Error(response, "invalid Resource 1 principal", http.StatusInternalServerError)
				return
			}
			compact, ok := resource.AuthTokenFromContext(request.Context())
			if !ok || compact == "" || compact != upstreamAuthToken {
				t.Errorf("Resource 1 auth token = %q, present=%t, want exact upstream token", compact, ok)
				http.Error(response, "missing upstream token", http.StatusInternalServerError)
				return
			}
			verifiedUpstream, err := aauth.VerifyAuthToken(request.Context(), compact, keyResolver, clock)
			if err != nil {
				t.Errorf("verify upstream auth token: %v", err)
				http.Error(response, "invalid upstream token", http.StatusInternalServerError)
				return
			}
			if err := requireUpstream(&verifiedUpstream); err != nil {
				t.Error(err)
				http.Error(response, "unexpected upstream token", http.StatusInternalServerError)
				return
			}
			if relay == nil {
				t.Error("Resource 1 Agent was not composed")
				http.Error(response, "missing Resource 1 Agent", http.StatusInternalServerError)
				return
			}

			downstreamPersonResult, err := relay.PersonToken(request.Context(), clientagent.PersonTokenRequest{
				Resource: resourceTwoID, UpstreamToken: compact,
			})
			if err != nil {
				t.Errorf("Resource 1 obtain downstream person token: %v", err)
				http.Error(response, "downstream person token failed", http.StatusBadGateway)
				return
			}
			downstreamPersonToken, ok := downstreamPersonResult.Token()
			if !ok {
				t.Errorf("downstream person-token result = %#v", downstreamPersonResult)
				http.Error(response, "downstream person token unavailable", http.StatusBadGateway)
				return
			}
			downstreamPerson, err := aauth.VerifyPersonToken(request.Context(), downstreamPersonToken, keyResolver, clock)
			if err != nil {
				t.Errorf("verify downstream person token: %v", err)
				http.Error(response, "invalid downstream person token", http.StatusBadGateway)
				return
			}
			if downstreamPerson.Issuer != personServerID || downstreamPerson.Audience != resourceTwoID ||
				downstreamPerson.Subject != downstreamSubject || downstreamPerson.Subject == upstreamSubject ||
				!downstreamPerson.Confirmation.JWK.Equal(resourceOneAgentKey.PublicJWK()) {
				t.Errorf("downstream person token = %#v", downstreamPerson)
				http.Error(response, "unexpected downstream person token", http.StatusBadGateway)
				return
			}

			// Recompose the Person Server after it has retained the downstream
			// person token but before the matching auth-token request. The exchange
			// must recover lineage from TokenStore rather than Server-local state.
			recomposedPeople, err := newPersonServer()
			if err != nil {
				t.Errorf("recompose Person Server: %v", err)
				http.Error(response, "Person Server recomposition failed", http.StatusBadGateway)
				return
			}
			personServerRecompositions++
			network.Handle(personServerID, recomposedPeople.Handler())

			downstreamResourceToken, err := relay.Authorize(request.Context(), clientagent.AuthorizeRequest{
				Resource: resourceTwoID, PersonToken: downstreamPersonToken,
				Scopes: downstreamScope, UpstreamToken: compact,
			})
			if err != nil {
				t.Errorf("Resource 1 obtain downstream resource token: %v", err)
				http.Error(response, "downstream resource token failed", http.StatusBadGateway)
				return
			}
			downstreamResource, err := aauth.VerifyResourceToken(request.Context(), downstreamResourceToken, keyResolver, clock)
			if err != nil {
				t.Errorf("verify downstream resource token: %v", err)
				http.Error(response, "invalid downstream resource token", http.StatusBadGateway)
				return
			}
			resourceOneJKT, err := resourceOneAgentKey.PublicJWK().Thumbprint()
			if err != nil {
				t.Errorf("Resource 1 Agent key thumbprint: %v", err)
				http.Error(response, "invalid Resource 1 Agent key", http.StatusInternalServerError)
				return
			}
			if downstreamResource.Issuer != resourceTwoID || downstreamResource.Audience != personServerID ||
				downstreamResource.PersonServer != personServerID || downstreamResource.Subject != downstreamSubject ||
				downstreamResource.AgentJKT != resourceOneJKT ||
				!slices.Equal(strings.Fields(downstreamResource.Scope), downstreamScope) {
				t.Errorf("downstream resource token = %#v", downstreamResource)
				http.Error(response, "unexpected downstream resource token", http.StatusBadGateway)
				return
			}

			downstreamAuthToken, err = relay.Exchange(request.Context(), clientagent.ExchangeRequest{
				ResourceToken: downstreamResourceToken, PresentedToken: downstreamPersonToken, UpstreamToken: compact,
			})
			if err != nil {
				t.Errorf("Resource 1 obtain downstream auth token: %v", err)
				http.Error(response, "downstream auth token failed", http.StatusBadGateway)
				return
			}
			downstreamAuth, err := aauth.VerifyAuthToken(request.Context(), downstreamAuthToken, keyResolver, clock)
			if err != nil {
				t.Errorf("verify downstream auth token: %v", err)
				http.Error(response, "invalid downstream auth token", http.StatusBadGateway)
				return
			}
			if downstreamAuth.Issuer != personServerID || downstreamAuth.DWK != aauth.PersonDiscoveryDocument ||
				downstreamAuth.Audience != resourceTwoID || downstreamAuth.PersonServer != personServerID ||
				downstreamAuth.Subject != downstreamSubject || downstreamAuth.Subject == upstreamSubject ||
				!downstreamAuth.Confirmation.JWK.Equal(resourceOneAgentKey.PublicJWK()) ||
				!slices.Equal(strings.Fields(downstreamAuth.Scope), downstreamScope) ||
				slices.Equal(strings.Fields(downstreamAuth.Scope), upstreamScope) {
				t.Errorf("downstream auth token = %#v", downstreamAuth)
				http.Error(response, "unexpected downstream auth token", http.StatusBadGateway)
				return
			}

			downstreamRequest, err := http.NewRequestWithContext(
				request.Context(), http.MethodPost, resourceTwoID+"/inventory/42/reservations", nil,
			)
			if err != nil {
				t.Errorf("construct downstream request: %v", err)
				http.Error(response, "downstream request failed", http.StatusInternalServerError)
				return
			}
			downstreamResponse, err := relay.Do(request.Context(), clientagent.Call{
				Request: downstreamRequest, AuthToken: downstreamAuthToken, UpstreamToken: compact,
			})
			if err != nil {
				t.Errorf("Resource 1 call Resource 2: %v", err)
				http.Error(response, "downstream call failed", http.StatusBadGateway)
				return
			}
			downstreamBody, readErr := io.ReadAll(downstreamResponse.Body)
			downstreamResponse.Body.Close()
			if readErr != nil {
				t.Errorf("read Resource 2 response: %v", readErr)
				http.Error(response, "downstream response failed", http.StatusBadGateway)
				return
			}
			if downstreamResponse.StatusCode != http.StatusOK || string(downstreamBody) != "inventory reserved" {
				t.Errorf("Resource 2 response = %d %q", downstreamResponse.StatusCode, downstreamBody)
				http.Error(response, "downstream response refused", http.StatusBadGateway)
				return
			}
			_, _ = io.WriteString(response, "order fulfilled: "+string(downstreamBody))
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	originalProviderHandler := originalProvider.Handler()
	resourceOneProviderHandler := resourceOneProvider.Handler()
	resourceOneResourceHandler := resourceOneServer.Handler()
	network.Handle(originalAgentProviderID, originalProviderHandler)
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceTwoID, resourceTwoServer.Handler())
	network.Handle(resourceOneID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			switch request.URL.Path {
			case "/.well-known/aauth-agent.json":
				resourceOneProviderHandler.ServeHTTP(response, request)
				return
			case "/.well-known/jwks.json":
				response.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(response).Encode(map[string]any{
					"keys": []jose.JWK{resourceOneProviderKey.PublicJWK(), resourceOneResourceKey.PublicJWK()},
				}); err != nil {
					t.Errorf("encode collocated JWKS: %v", err)
				}
				return
			}
		}
		resourceOneResourceHandler.ServeHTTP(response, request)
	}))

	reader, err := clientagent.New(ctx, clientagent.Config{
		Identifier: originalAgentID, SigningKey: originalAgentKey, AgentToken: originalAgentToken,
		KeyResolver: keyResolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	relay, err = clientagent.New(ctx, clientagent.Config{
		Identifier: resourceOneAgentID, SigningKey: resourceOneAgentKey, AgentToken: resourceOneAgentToken,
		KeyResolver: keyResolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	relayClaims, err := aauth.VerifyAgentToken(ctx, resourceOneAgentToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if relayClaims.Issuer != resourceOneID || relayClaims.Subject != resourceOneAgentID ||
		relayClaims.PersonServer != resourceOneOwnPS || relayClaims.PersonServer == personServerID ||
		!relayClaims.Confirmation.JWK.Equal(resourceOneAgentKey.PublicJWK()) {
		t.Fatalf("Resource 1 Agent token = %#v", relayClaims)
	}

	upstreamPersonResult, err := reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceOneID,
	})
	if err != nil {
		t.Fatal(err)
	}
	upstreamPersonToken, ok := upstreamPersonResult.Token()
	if !ok {
		t.Fatalf("upstream person-token result = %#v", upstreamPersonResult)
	}
	upstreamResourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceOneID, PersonToken: upstreamPersonToken, Scopes: upstreamScope,
	})
	if err != nil {
		t.Fatal(err)
	}
	upstreamAuthToken, err = reader.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: upstreamResourceToken, PresentedToken: upstreamPersonToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifiedUpstream, err := aauth.VerifyAuthToken(ctx, upstreamAuthToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireUpstream(&verifiedUpstream); err != nil {
		t.Fatal(err)
	}

	upstreamRequest, err := http.NewRequestWithContext(
		ctx, http.MethodPost, resourceOneID+"/orders/42/fulfill", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	upstreamResponse, err := reader.Do(ctx, clientagent.Call{
		Request: upstreamRequest, AuthToken: upstreamAuthToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	upstreamBody, readErr := io.ReadAll(upstreamResponse.Body)
	upstreamResponse.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if upstreamResponse.StatusCode != http.StatusOK ||
		string(upstreamBody) != "order fulfilled: inventory reserved" {
		t.Fatalf("Resource 1 response = %d %q", upstreamResponse.StatusCode, upstreamBody)
	}

	if resourceOneCalls != 1 || resourceTwoCalls != 1 {
		t.Fatalf("protected calls = Resource 1 %d, Resource 2 %d; want 1/1", resourceOneCalls, resourceTwoCalls)
	}
	if directBindCalls != 1 || directAuthorizeCalls != 1 || chainBindCalls != 1 || chainAuthorizeCalls != 1 {
		t.Fatalf(
			"policy calls = direct bind %d authorize %d, chain bind %d authorize %d; want 1/1/1/1",
			directBindCalls, directAuthorizeCalls, chainBindCalls, chainAuthorizeCalls,
		)
	}
	if personServerRecompositions != 1 {
		t.Fatalf("Person Server recompositions = %d, want 1", personServerRecompositions)
	}
	lastRecord, commits, loads := personTokens.observation()
	if commits != 2 || loads < 2 {
		t.Fatalf("person-token store transitions = commits %d loads %d, want 2 and at least 2", commits, loads)
	}
	if lastRecord.PersonServer != personServerID || lastRecord.Resource != resourceTwoID ||
		lastRecord.Subject != downstreamSubject || lastRecord.AgentProvider != resourceOneID ||
		lastRecord.Agent != resourceOneAgentID || lastRecord.ParentAgent != "" ||
		!lastRecord.Confirmation.Equal(resourceOneAgentKey.PublicJWK()) ||
		lastRecord.UpstreamTokenReference != (aauth.TokenReference{Issuer: verifiedUpstream.Issuer, JTI: verifiedUpstream.JTI}) ||
		lastRecord.UpstreamTokenSHA256 != sha256.Sum256([]byte(upstreamAuthToken)) {
		t.Fatalf("retained downstream person-token record = %#v", lastRecord)
	}
}
