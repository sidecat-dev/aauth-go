package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentCoreParentMediatedSubagentImmediatePSAuthorization(t *testing.T) {
	t.Parallel()

	runCurrentCoreParentMediatedSubagentAuthorization(t, false, false)
}

func TestCurrentCoreParentMediatedSubagentImmediateASAuthorization(t *testing.T) {
	t.Parallel()

	runCurrentCoreParentMediatedSubagentAuthorization(t, true, false)
}

func TestCurrentCoreParentMediatedSubagentDeferredPSAuthorization(t *testing.T) {
	t.Parallel()

	runCurrentCoreParentMediatedSubagentAuthorization(t, false, true)
}

func runCurrentCoreParentMediatedSubagentAuthorization(t *testing.T, federated, deferred bool) {
	t.Helper()

	ctx := context.Background()
	now := time.Date(2026, 8, 30, 21, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		parentAgentID   = "aauth:planner@ap.example"
		childAgentID    = "aauth:planner+search@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
		accessServerID  = "https://as.example"
	)
	scope := []string{"records.read"}
	parentAdditionalClaims := map[string]json.RawMessage{
		"platform": json.RawMessage(`"orchestrator"`),
	}
	childAdditionalClaims := map[string]json.RawMessage{
		"workload": json.RawMessage(`"search-worker"`),
	}

	agentProviderKey := newSigningKey(t, "subagent-ap")
	parentKey := newSigningKey(t, "subagent-parent")
	childKey := newSigningKey(t, "subagent-child")
	personServerKey := newSigningKey(t, "subagent-ps")
	resourceKey := newSigningKey(t, "subagent-resource")
	accessServerKey := newSigningKey(t, "subagent-as")
	childJKT, err := childKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	keyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient,
		Clock:  clock,
		Admit: func(_ context.Context, endpoint string) error {
			if strings.HasSuffix(endpoint, ".example/.well-known/aauth-agent.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-person.json") ||
				strings.HasSuffix(endpoint, ".example/.well-known/aauth-access.json") ||
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

	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: agentProviderKey, Clock: clock,
		NewID: func() string { return "subagent-parent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	parentToken, err := provider.Issue(aauth.AgentTokenRequest{
		Agent: parentAgentID, PersonServer: personServerID,
		PublicKey: parentKey.PublicJWK(), Lifetime: time.Hour,
		AdditionalClaims: parentAdditionalClaims,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Agent Provider enrollment is outside this slice. MintAgentToken gives the
	// integration journey the exact child credential the current Core text
	// requires, including its authoritative parent_agent relationship.
	childToken, err := aauth.MintAgentToken(agentProviderID, agentProviderKey, aauth.AgentTokenRequest{
		Agent: childAgentID, ParentAgent: parentAgentID,
		PublicKey: childKey.PublicJWK(), Lifetime: 10 * time.Minute,
		AdditionalClaims: childAdditionalClaims,
	}, now, "subagent-child-token")
	if err != nil {
		t.Fatal(err)
	}

	personTokens := newMemoryPersonTokenStore()
	personBindingCalls := 0
	authorizationPolicyCalls := 0
	requirePersonPolicy := func(request personserver.PersonTokenRequest) error {
		if request.Agent != parentAgentID || request.Subagent != childAgentID || request.Resource != resourceID {
			return fmt.Errorf("person-token policy identities = parent %q child %q resource %q", request.Agent, request.Subagent, request.Resource)
		}
		if !reflect.DeepEqual(request.AgentAdditionalClaims, parentAdditionalClaims) ||
			!reflect.DeepEqual(request.SubagentAdditionalClaims, childAdditionalClaims) {
			return fmt.Errorf("person-token policy claims = parent %#v child %#v", request.AgentAdditionalClaims, request.SubagentAdditionalClaims)
		}
		return nil
	}
	requireAuthorizationPolicy := func(request personserver.AuthorizationRequest) error {
		if request.Agent != parentAgentID || request.Subagent != childAgentID || request.Resource != resourceID ||
			request.Subject != "person-123" || request.Tenant != "tenant-1" || !slices.Equal(request.Scopes, scope) {
			return fmt.Errorf("authorization policy context = %#v", request)
		}
		if !reflect.DeepEqual(request.AgentAdditionalClaims, parentAdditionalClaims) ||
			!reflect.DeepEqual(request.SubagentAdditionalClaims, childAdditionalClaims) {
			return fmt.Errorf("authorization policy claims = parent %#v child %#v", request.AgentAdditionalClaims, request.SubagentAdditionalClaims)
		}
		return nil
	}

	var newPeople func() (*personserver.Server, error)
	var deferredAuthorizations *integrationDeferredAuthorizationStore
	if federated {
		config := personserver.FederatedAuthorizationConfig{
			Issuer: personServerID, SigningKey: personServerKey, KeyResolver: keyResolver,
			Clock: clock, Tokens: personTokens, HTTPClient: httpClient,
			NewID: func() string { return "subagent-person-token" },
			AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
				if issuer != accessServerID {
					return "", errors.New("unexpected access server")
				}
				return accessServerID + "/token", nil
			},
			BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
				personBindingCalls++
				if err := requirePersonPolicy(request); err != nil {
					return personserver.Person{}, err
				}
				return personserver.Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: 20 * time.Minute}, nil
			},
			Consent: func(_ context.Context, request personserver.AuthorizationRequest) error {
				authorizationPolicyCalls++
				return requireAuthorizationPolicy(request)
			},
		}
		newPeople = func() (*personserver.Server, error) {
			return personserver.NewFederatedAuthorization(config)
		}
	} else {
		ids := []string{"subagent-person-token", "subagent-auth-token"}
		config := personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: personServerKey, KeyResolver: keyResolver,
			Clock: clock, Tokens: personTokens,
			NewID: func() string {
				id := ids[0]
				ids = ids[1:]
				return id
			},
			BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
				personBindingCalls++
				if err := requirePersonPolicy(request); err != nil {
					return personserver.Person{}, err
				}
				return personserver.Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: 20 * time.Minute}, nil
			},
		}
		if deferred {
			deferredAuthorizations = newIntegrationDeferredAuthorizationStore()
			config.AuthorizationInteractions = deferredAuthorizations
			config.RequireAuthorizationInteraction = func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationInteractionPolicy, bool, error) {
				authorizationPolicyCalls++
				if err := requireAuthorizationPolicy(request); err != nil {
					return personserver.AuthorizationInteractionPolicy{}, false, err
				}
				return personserver.AuthorizationInteractionPolicy{
					URL: personServerID + "/consent", Lifetime: 5 * time.Minute,
				}, true, nil
			}
		} else {
			config.Authorize = func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				authorizationPolicyCalls++
				if err := requireAuthorizationPolicy(request); err != nil {
					return personserver.AuthorizationDecision{}, err
				}
				return personserver.AuthorizationDecision{Scopes: append([]string(nil), scope...), Lifetime: 15 * time.Minute}, nil
			}
		}
		newPeople = func() (*personserver.Server, error) {
			return personserver.NewPSAuthorization(config)
		}
	}
	people, err := newPeople()
	if err != nil {
		t.Fatal(err)
	}

	accessPolicyCalls := 0
	var access http.Handler
	if federated {
		accessServer, err := accessserver.New(accessserver.Config{
			Issuer: accessServerID, SigningKey: accessServerKey, KeyResolver: keyResolver,
			Clock: clock, NewID: func() string { return "subagent-as-auth-token" },
			TrustPersonServer: func(_ context.Context, issuer string) error {
				if issuer != personServerID {
					return errors.New("unexpected person server")
				}
				return nil
			},
			Authorize: func(_ context.Context, request accessserver.AuthorizationRequest) (accessserver.Decision, error) {
				accessPolicyCalls++
				if request.PersonServer != personServerID || request.Resource != resourceID ||
					request.Subject != "person-123" || request.Tenant != "tenant-1" || !slices.Equal(request.Scopes, scope) ||
					request.Agent.Identifier != parentAgentID || !request.Agent.Confirmation.Equal(parentKey.PublicJWK()) ||
					!reflect.DeepEqual(request.Agent.AdditionalClaims, parentAdditionalClaims) {
					return accessserver.Decision{}, fmt.Errorf("access policy parent context = %#v", request)
				}
				if request.Subagent == nil || request.Subagent.Identifier != childAgentID ||
					!request.Subagent.Confirmation.Equal(childKey.PublicJWK()) ||
					!reflect.DeepEqual(request.Subagent.AdditionalClaims, childAdditionalClaims) {
					return accessserver.Decision{}, fmt.Errorf("access policy child context = %#v", request.Subagent)
				}
				return accessserver.Decision{Scopes: append([]string(nil), scope...), Lifetime: 15 * time.Minute}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		access = accessServer.Handler()
	}

	protectedCalls := 0
	protected := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		protectedCalls++
		principal, ok := resource.AuthPrincipalFromContext(request.Context())
		if !ok || principal.PersonServer != personServerID || principal.Subject != "person-123" ||
			principal.Tenant != "tenant-1" || !slices.Equal(principal.Scope, scope) ||
			!principal.Confirmation.Equal(childKey.PublicJWK()) {
			t.Errorf("sub-agent protected principal = %#v, present=%t", principal, ok)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"accepted":"subagent"}`)
	})
	var protectedResource *resource.Server
	if federated {
		protectedResource, err = resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
			Issuer: resourceID, AccessServer: accessServerID,
			SigningKey: resourceKey, KeyResolver: keyResolver, Clock: clock,
			NewID:             func() string { return "subagent-resource-token" },
			ScopeDescriptions: map[string]string{"records.read": "Read records"},
			RequiredScopes:    func(*http.Request) []string { return append([]string(nil), scope...) },
			ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
				if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) || personContext.Tenant != "tenant-1" {
					return errors.New("unexpected Resource person")
				}
				return nil
			},
			Protected: protected,
		})
	} else {
		protectedResource, err = resource.NewPSAuthorization(resource.PSAuthorizationConfig{
			Issuer: resourceID, SigningKey: resourceKey, KeyResolver: keyResolver, Clock: clock,
			NewID:             func() string { return "subagent-resource-token" },
			ScopeDescriptions: map[string]string{"records.read": "Read records"},
			RequiredScopes:    func(*http.Request) []string { return append([]string(nil), scope...) },
			ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
				if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) || personContext.Tenant != "tenant-1" {
					return errors.New("unexpected Resource person")
				}
				return nil
			},
			Protected: protected,
		})
	}
	if err != nil {
		t.Fatal(err)
	}

	network.Handle(agentProviderID, provider.Handler())
	network.Handle(personServerID, people.Handler())
	network.Handle(resourceID, protectedResource.Handler())
	if access != nil {
		network.Handle(accessServerID, access)
	}
	childClaims, err := aauth.VerifyAgentToken(ctx, childToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if childClaims.PersonServer != "" {
		t.Fatalf("child Agent token ps = %q, want omitted", childClaims.PersonServer)
	}

	parent, err := clientagent.New(ctx, clientagent.Config{
		Identifier: parentAgentID, SigningKey: parentKey, AgentToken: parentToken,
		KeyResolver: keyResolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	child, err := clientagent.New(ctx, clientagent.Config{
		Identifier: childAgentID, SigningKey: childKey, AgentToken: childToken,
		KeyResolver: keyResolver, HTTPClient: httpClient, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}

	personResult, err := parent.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID, SubagentToken: childToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatalf("sub-agent person-token result = %#v", personResult)
	}
	personClaims, err := aauth.VerifyPersonToken(ctx, personToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if !personClaims.Confirmation.JWK.Equal(childKey.PublicJWK()) {
		t.Fatalf("person token cnf = %#v, want child key %#v", personClaims.Confirmation.JWK, childKey.PublicJWK())
	}
	if _, err := parent.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: scope,
	}); err == nil {
		t.Fatal("parent used a person token bound to the child key")
	}
	record, commits, _ := personTokens.observation()
	if commits != 1 || record.AgentProvider != agentProviderID || record.Agent != childAgentID ||
		record.ParentAgent != parentAgentID || !record.Confirmation.Equal(childKey.PublicJWK()) {
		t.Fatalf("retained sub-agent relationship = %#v; commits=%d", record, commits)
	}
	people, err = newPeople()
	if err != nil {
		t.Fatal(err)
	}
	network.Handle(personServerID, people.Handler())

	resourceToken, err := child.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: scope,
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceClaims, err := aauth.VerifyResourceToken(ctx, resourceToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if resourceClaims.AgentJKT != childJKT {
		t.Fatalf("resource token agent_jkt = %q, want child key %q", resourceClaims.AgentJKT, childJKT)
	}

	var authToken string
	if deferred {
		result, err := parent.BeginExchange(ctx, clientagent.ExchangeRequest{
			PersonServer: personServerID, ResourceToken: resourceToken, PresentedToken: personToken, SubagentToken: childToken,
			Capabilities: []string{"interaction"},
		})
		if err != nil {
			t.Fatal(err)
		}
		pending, ok := result.Pending()
		if !ok || pending.InteractionCode() == "" || !strings.HasPrefix(pending.InteractionURL(), personServerID+"/consent/") {
			t.Fatalf("sub-agent pending authorization = %#v, present=%t", result, ok)
		}
		snapshot, err := pending.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		var restoredSnapshot clientagent.PendingExchangeSnapshot
		if err := json.Unmarshal(encoded, &restoredSnapshot); err != nil {
			t.Fatal(err)
		}
		pending, err = parent.RestorePendingExchange(ctx, restoredSnapshot)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := child.PollExchange(ctx, pending); err == nil {
			t.Fatal("child polled a parent-mediated authorization interaction")
		}
		reference := strings.TrimPrefix(pending.InteractionURL(), personServerID+"/consent/")
		interaction, err := people.ConsumeAuthorizationInteractionCode(ctx, reference, pending.InteractionCode())
		if err != nil {
			t.Fatal(err)
		}
		if interaction.Agent() != parentAgentID || !reflect.DeepEqual(interaction.AgentAdditionalClaims(), parentAdditionalClaims) {
			t.Fatalf("authorization interaction parent = %q %#v", interaction.Agent(), interaction.AgentAdditionalClaims())
		}
		if subagent, ok := interaction.Subagent(); !ok || subagent != childAgentID ||
			!reflect.DeepEqual(interaction.SubagentAdditionalClaims(), childAdditionalClaims) {
			t.Fatalf("authorization interaction child = %q %t %#v", subagent, ok, interaction.SubagentAdditionalClaims())
		}
		people, err = newPeople()
		if err != nil {
			t.Fatal(err)
		}
		network.Handle(personServerID, people.Handler())
		resumed, err := people.ResumeAuthorizationInteraction(ctx, reference)
		if err != nil {
			t.Fatal(err)
		}
		if err := people.ApproveAuthorizationInteraction(ctx, resumed, personserver.AuthorizationDecision{
			Scopes: append([]string(nil), scope...), Lifetime: 15 * time.Minute,
		}); err != nil {
			t.Fatal(err)
		}
		result, err = parent.PollExchange(ctx, pending)
		if err != nil {
			t.Fatal(err)
		}
		authToken, ok = result.Token()
		if !ok || authToken == "" {
			t.Fatalf("sub-agent approved authorization = %#v, present=%t", result, ok)
		}
		creates, approvals, terminalConsumes := deferredAuthorizations.counts()
		if creates != 1 || approvals != 1 || terminalConsumes != 1 {
			t.Fatalf("deferred sub-agent effects: creates=%d approvals=%d consumes=%d", creates, approvals, terminalConsumes)
		}
	} else {
		authToken, err = parent.Exchange(ctx, clientagent.ExchangeRequest{
			PersonServer: personServerID, ResourceToken: resourceToken, PresentedToken: personToken, SubagentToken: childToken,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	authClaims, err := aauth.VerifyAuthToken(ctx, authToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if !authClaims.Confirmation.JWK.Equal(childKey.PublicJWK()) {
		t.Fatalf("auth token cnf = %#v, want child key %#v", authClaims.Confirmation.JWK, childKey.PublicJWK())
	}
	expectedAuthExpiry := now.Add(10 * time.Minute)
	if authClaims.ExpiresAt != expectedAuthExpiry.Unix() {
		t.Fatalf("auth token expiry = %s, want bounded ceiling %s",
			time.Unix(authClaims.ExpiresAt, 0), expectedAuthExpiry)
	}
	if _, exposed := tokenClaims(t, authToken)["parent_agent"]; exposed {
		t.Fatal("auth token exposed the retained parent/sub-agent relationship to the Resource")
	}
	record, commits, loads := personTokens.observation()
	if commits != 1 || loads == 0 || record.Agent != childAgentID || record.ParentAgent != parentAgentID {
		t.Fatalf("retained relationship after exchange = %#v; commits=%d loads=%d", record, commits, loads)
	}
	if personBindingCalls != 1 || authorizationPolicyCalls != 1 {
		t.Fatalf("PS policy calls = binding %d authorization %d, want 1/1", personBindingCalls, authorizationPolicyCalls)
	}
	if federated && accessPolicyCalls != 1 {
		t.Fatalf("AS policy calls = %d, want 1", accessPolicyCalls)
	}
	if !federated && accessPolicyCalls != 0 {
		t.Fatalf("three-party authorization reached AS policy %d times", accessPolicyCalls)
	}

	parentRequest, _ := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	if response, err := parent.Do(ctx, clientagent.Call{Request: parentRequest, AuthToken: authToken}); err == nil {
		if response != nil {
			response.Body.Close()
		}
		t.Fatal("parent used an auth token bound to the child key")
	}
	if protectedCalls != 0 {
		t.Fatalf("parent use reached protected consequence; calls=%d", protectedCalls)
	}

	childRequest, _ := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	response, err := child.Do(ctx, clientagent.Call{Request: childRequest, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != `{"accepted":"subagent"}` || protectedCalls != 1 {
		t.Fatalf("child protected consequence = %d %q; calls=%d", response.StatusCode, body, protectedCalls)
	}
}
