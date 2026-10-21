package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// assertBindingRevokedProblem checks a refusal caused by a revoked binding.
// Its public detail names the binding, so a caller can tell it from a denial.
func assertBindingRevokedProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var problem struct {
		Code   string `json:"error"`
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if response.Code != status || problem.Code != code || problem.Detail != agentBindingRevokedDetail {
		t.Fatalf("binding refusal = %d %#v", response.Code, problem)
	}
}

// assertRevokedPendingProblem checks the polling error revoked and the public
// detail naming which Agent token was revoked.
func assertRevokedPendingProblem(t *testing.T, response *httptest.ResponseRecorder, detail string) {
	t.Helper()
	var problem struct {
		Code   string `json:"error"`
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusForbidden || problem.Code != "revoked" || problem.Detail != detail {
		t.Fatalf("revoked pending request = %d %#v", response.Code, problem)
	}
}

// Protocol 28e8258, Agent-Person Binding and Pending URL Security: revoking
// the binding ends a PS-hosted consent wait in every live state. The refusal
// is a terminal answer, so the pending URL is gone afterwards.
func TestRevokedAgentBindingEndsPSHostedConsentInEveryState(t *testing.T) {
	t.Parallel()

	for _, state := range []string{"waiting", "interacting", "clarifying", "approved"} {
		t.Run(state, func(t *testing.T) {
			t.Parallel()
			protocol := newAuthorizationInteractionProtocol(t)
			config := protocol.config(newMemoryDeferredAuthorizationStore())
			config.AgentBindingRevocations = newMemoryAgentBindingRevocations()
			server, err := NewPSAuthorization(config)
			if err != nil {
				t.Fatal(err)
			}
			response := protocol.exchange(t, server, []string{"interaction", "clarification"})
			if response.Code != http.StatusAccepted {
				t.Fatalf("consent request = %d %s", response.Code, response.Body.String())
			}
			location := response.Header().Get("Location")
			requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
			if err != nil {
				t.Fatal(err)
			}
			decision := AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}
			var value AuthorizationInteraction
			if state != "waiting" {
				value, err = server.ConsumeAuthorizationInteractionCode(context.Background(), strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/"), requirement.Code)
				if err != nil {
					t.Fatal(err)
				}
			}
			switch state {
			case "clarifying":
				if err := server.RequestAuthorizationClarification(context.Background(), value, AuthorizationClarificationRequest{
					Question: "Which records?", Lifetime: time.Minute,
				}); err != nil {
					t.Fatal(err)
				}
			case "approved":
				if err := server.ApproveAuthorizationInteraction(context.Background(), value, decision); err != nil {
					t.Fatal(err)
				}
			}
			if err := server.RevokeAgentBinding(context.Background(), AgentBinding{AgentProvider: protocol.providerID, Agent: protocol.agentID}); err != nil {
				t.Fatal(err)
			}
			minted := protocol.tokenIDCalls()
			if state == "interacting" {
				if err := server.ApproveAuthorizationInteraction(context.Background(), value, decision); !errors.Is(err, ErrAgentBindingRevoked) {
					t.Fatalf("approval under a revoked binding = %v", err)
				}
			}
			assertBindingRevokedProblem(t, protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken), http.StatusBadRequest, "revoked_presented_token")
			assertAuthorizationInteractionProblem(t, protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken), http.StatusGone, "invalid_code")
			if state == "interacting" {
				if err := server.ApproveAuthorizationInteraction(context.Background(), value, decision); err == nil {
					t.Fatal("an ended request was approved")
				}
			}
			if protocol.tokenIDCalls() != minted {
				t.Fatal("a revoked binding minted an Auth token")
			}
		})
	}
}

// The same holds for a PS-hosted Person-token interaction.
func TestRevokedAgentBindingEndsPersonTokenInteractionsInEveryState(t *testing.T) {
	t.Parallel()

	for _, state := range []string{"waiting", "interacting", "approved"} {
		t.Run(state, func(t *testing.T) {
			t.Parallel()
			protocol := newPersonInteractionProtocol(t)
			protocol.bindings = newMemoryAgentBindingRevocations()
			store := newMemoryDeferredTokenStore()
			server := protocol.newServer(t, store, true)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, protocol.personTokenRequest(t))
			if response.Code != http.StatusAccepted {
				t.Fatalf("person-token interaction = %d %s", response.Code, response.Body.String())
			}
			location := response.Header().Get("Location")
			requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
			if err != nil {
				t.Fatal(err)
			}
			person := Person{Subject: "person-123", Lifetime: 10 * time.Minute}
			var interaction PersonTokenInteraction
			if state != "waiting" {
				interaction, err = server.ConsumePersonTokenInteractionCode(context.Background(), personInteractionReference(t, requirement.URL), requirement.Code)
				if err != nil {
					t.Fatal(err)
				}
			}
			if state == "approved" {
				if err := server.ApprovePersonTokenInteraction(context.Background(), interaction, person); err != nil {
					t.Fatal(err)
				}
			}
			if err := server.RevokeAgentBinding(context.Background(), AgentBinding{AgentProvider: "https://provider.example", Agent: protocol.agentID}); err != nil {
				t.Fatal(err)
			}
			commits := store.tokenCommitCount()
			if state == "interacting" {
				if err := server.ApprovePersonTokenInteraction(context.Background(), interaction, person); !errors.Is(err, ErrAgentBindingRevoked) {
					t.Fatalf("approval under a revoked binding = %v", err)
				}
			}
			poll := httptest.NewRecorder()
			server.Handler().ServeHTTP(poll, protocol.pollRequest(t, location, protocol.agentKey, protocol.agentToken))
			assertBindingRevokedProblem(t, poll, http.StatusForbidden, "person_token_denied")
			again := httptest.NewRecorder()
			server.Handler().ServeHTTP(again, protocol.pollRequest(t, location, protocol.agentKey, protocol.agentToken))
			assertPersonInteractionProblem(t, again, http.StatusGone, "invalid_code")
			if store.tokenCommitCount() != commits {
				t.Fatal("a revoked binding retained a Person token")
			}
		})
	}
}

// Protocol 28e8258, Presenting a Revoked Token and Polling Error Codes: a
// pending request whose Agent token is revoked while it waits ends with
// revoked, detail saying which. For a parent-mediated request that includes
// the sub-agent token: the child never authenticates to the PS, so the PS is
// the only party that can refuse to bind a credential to its key.
func TestRevokedAgentTokenEndsPSHostedWaits(t *testing.T) {
	t.Parallel()

	const childRevoked = "The sub-agent token of this request was revoked."
	const starterRevoked = "The Agent token that started this request was revoked."
	interactionPolicy := func(context.Context, AuthorizationRequest) (AuthorizationInteractionPolicy, bool, error) {
		return AuthorizationInteractionPolicy{URL: "https://ps.example/interact", Lifetime: time.Minute, RetryAfter: time.Second}, true, nil
	}
	consent := func(t *testing.T, p *subagentPersonServerProtocol, revocations *referenceAgentTokenRevocationStore, child bool) (*Server, string, AuthorizationInteraction) {
		t.Helper()
		agent, key := "aauth:planner@ap.example", p.parentKey.PublicJWK()
		if child {
			agent, key = "aauth:planner+search@ap.example", p.childKey.PublicJWK()
		}
		parent := ""
		if child {
			parent = "aauth:planner@ap.example"
		}
		if err := p.store.Commit(context.Background(), PersonTokenRecord{
			JTI: "person-token", PersonServer: "https://ps.example", Resource: "https://resource.example",
			Subject: "person-123", Tenant: "tenant-1", ExpiresAt: p.now.Add(10 * time.Minute),
			RetainUntil: p.now.Add(15 * time.Minute), AgentProvider: "https://ap.example",
			Agent: agent, ParentAgent: parent, Confirmation: key,
		}); err != nil {
			t.Fatal(err)
		}
		server, err := NewPSAuthorization(PSAuthorizationConfig{
			Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
			Clock: p.clock, NewID: func() string { return "auth-token" }, Tokens: p.store,
			BindPerson: p.policyPerson, Authorize: p.policyAuthorization,
			AuthorizationInteractions:       newMemoryDeferredAuthorizationStore(),
			RequireAuthorizationInteraction: interactionPolicy,
			AgentTokenRevocations:           revocations,
		})
		if err != nil {
			t.Fatal(err)
		}
		childToken := ""
		if child {
			childToken = p.childToken
		}
		resourceToken := p.resourceToken(t, "https://ps.example", "person-token", key)
		started := p.tokenRequestWithCapabilities(t, server, p.parentKey, p.parentToken, childToken, resourceToken, []string{"interaction"})
		if started.Code != http.StatusAccepted {
			t.Fatalf("consent = %d %s", started.Code, started.Body.String())
		}
		requirement, err := aauth.ParseInteractionRequirement(started.Header().Values("AAuth-Requirement"))
		if err != nil {
			t.Fatal(err)
		}
		value, err := server.ConsumeAuthorizationInteractionCode(context.Background(), strings.TrimPrefix(requirement.URL, "https://ps.example/interact/"), requirement.Code)
		if err != nil {
			t.Fatal(err)
		}
		return server, started.Header().Get("Location"), value
	}
	poll := func(t *testing.T, p *subagentPersonServerProtocol, server *Server, location, token string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "https://ps.example"+location, nil)
		if err := signaturekey.SignJWTRequest(request, p.parentKey, token, p.clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}

	t.Run("consent for a revoked sub-agent token", func(t *testing.T) {
		t.Parallel()
		p := newSubagentPersonServerProtocol(t)
		revocations := newReferenceAgentTokenRevocationStore()
		server, location, value := consent(t, p, revocations, true)
		revocations.revoked[aauth.TokenReference{Issuer: "https://ap.example", JTI: "child-token"}] = true
		decision := AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}
		if err := server.ApproveAuthorizationInteraction(context.Background(), value, decision); !errors.Is(err, ErrAgentTokenRevoked) {
			t.Fatalf("approval for a revoked sub-agent token = %v", err)
		}
		assertRevokedPendingProblem(t, poll(t, p, server, location, p.parentToken), childRevoked)
		assertAuthorizationInteractionProblem(t, poll(t, p, server, location, p.parentToken), http.StatusGone, "invalid_code")
	})

	t.Run("approved consent for a sub-agent token revoked afterwards", func(t *testing.T) {
		t.Parallel()
		p := newSubagentPersonServerProtocol(t)
		revocations := newReferenceAgentTokenRevocationStore()
		server, location, value := consent(t, p, revocations, true)
		if err := server.ApproveAuthorizationInteraction(context.Background(), value, AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}); err != nil {
			t.Fatal(err)
		}
		revocations.revoked[aauth.TokenReference{Issuer: "https://ap.example", JTI: "child-token"}] = true
		assertRevokedPendingProblem(t, poll(t, p, server, location, p.parentToken), childRevoked)
		assertAuthorizationInteractionProblem(t, poll(t, p, server, location, p.parentToken), http.StatusGone, "invalid_code")
	})

	t.Run("consent whose starting Agent token was revoked", func(t *testing.T) {
		t.Parallel()
		p := newSubagentPersonServerProtocol(t)
		revocations := newReferenceAgentTokenRevocationStore()
		server, location, _ := consent(t, p, revocations, false)
		revocations.revoked[aauth.TokenReference{Issuer: "https://ap.example", JTI: "parent-token"}] = true
		// The Agent polls with a later token for the same key.
		later := p.mintAgentToken(t, "aauth:planner@ap.example", "", p.parentKey.PublicJWK(), 40*time.Minute, "parent-token-2", p.parentAdditionalClaims)
		assertRevokedPendingProblem(t, poll(t, p, server, location, later), starterRevoked)
		assertAuthorizationInteractionProblem(t, poll(t, p, server, location, later), http.StatusGone, "invalid_code")
	})

	t.Run("Person-token interaction for a revoked sub-agent token", func(t *testing.T) {
		t.Parallel()
		p := newSubagentPersonServerProtocol(t)
		store := newMemoryDeferredTokenStore()
		revocations := newReferenceAgentTokenRevocationStore()
		server, err := NewPSAuthorization(PSAuthorizationConfig{
			Issuer: "https://ps.example", SigningKey: p.personKey, KeyResolver: p.resolver,
			Clock: p.clock, NewID: func() string { return "person-token-1" }, Tokens: store,
			BindPerson: p.policyPerson, Authorize: p.policyAuthorization,
			RequirePersonTokenInteraction: func(context.Context, PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error) {
				return PersonTokenInteractionPolicy{URL: "https://ps.example/interact", Lifetime: time.Minute, RetryAfter: time.Second}, true, nil
			},
			AgentTokenRevocations: revocations,
		})
		if err != nil {
			t.Fatal(err)
		}
		started := p.personRequest(t, server, p.childToken)
		if started.Code != http.StatusAccepted {
			t.Fatalf("delegated person interaction = %d %s", started.Code, started.Body.String())
		}
		location := started.Header().Get("Location")
		requirement, err := aauth.ParseInteractionRequirement(started.Header().Values("AAuth-Requirement"))
		if err != nil {
			t.Fatal(err)
		}
		interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), strings.TrimPrefix(requirement.URL, "https://ps.example/interact/"), requirement.Code)
		if err != nil {
			t.Fatal(err)
		}
		revocations.revoked[aauth.TokenReference{Issuer: "https://ap.example", JTI: "child-token"}] = true
		if err := server.ApprovePersonTokenInteraction(context.Background(), interaction, Person{Subject: "person-123", Lifetime: 10 * time.Minute}); !errors.Is(err, ErrAgentTokenRevoked) {
			t.Fatalf("approval for a revoked sub-agent token = %v", err)
		}
		assertRevokedPendingProblem(t, poll(t, p, server, location, p.parentToken), childRevoked)
		response := poll(t, p, server, location, p.parentToken)
		assertPersonInteractionProblem(t, response, http.StatusGone, "invalid_code")
		if store.tokenCommitCount() != 0 {
			t.Fatal("a revoked sub-agent token received a Person token")
		}
	})
}

// Protocol 28e8258, Agent-Person Binding: an agent whose association changes
// has its binding revoked and a new one established. The replacement admits
// requests made after it, while every pending request and presented
// credential from before it stays refused, so the host need not wait for the
// old binding's credentials to expire before re-binding the Agent.
func TestReestablishedAgentBindingAdmitsOnlyLaterRequests(t *testing.T) {
	t.Parallel()

	t.Run("Person-token interaction outliving an hour", func(t *testing.T) {
		t.Parallel()
		protocol := newPersonInteractionProtocol(t)
		var err error
		protocol.agentToken, err = aauth.MintAgentToken("https://provider.example", protocol.providerKey, aauth.AgentTokenRequest{
			Agent: protocol.agentID, PersonServer: protocol.personServerID,
			PublicKey: protocol.agentKey.PublicJWK(), Lifetime: 24 * time.Hour,
		}, protocol.now, "agent-token-24h")
		if err != nil {
			t.Fatal(err)
		}
		protocol.bindings = newMemoryAgentBindingRevocations()
		store := newMemoryDeferredTokenStore()
		server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
			Issuer: protocol.personServerID, SigningKey: protocol.personServerKey,
			KeyResolver: protocol.resolver, Clock: protocol.clock,
			NewID: func() string { return "person-token-1" }, HTTPClient: http.DefaultClient,
			AccessServerEndpoint: func(context.Context, string) (string, error) { return "https://access.example/token", nil },
			Tokens:               store,
			BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
				return Person{Subject: "new-person", Lifetime: time.Minute}, nil
			},
			Consent: func(context.Context, AuthorizationRequest) error { return nil },
			RequirePersonTokenInteraction: func(context.Context, PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error) {
				return PersonTokenInteractionPolicy{URL: "https://person.example/interaction", Lifetime: 3 * time.Hour}, true, nil
			},
			AgentBindingRevocations: protocol.bindings,
		})
		if err != nil {
			t.Fatal(err)
		}
		started := httptest.NewRecorder()
		server.Handler().ServeHTTP(started, protocol.personTokenRequest(t))
		if started.Code != http.StatusAccepted {
			t.Fatalf("interaction = %d %s", started.Code, started.Body.String())
		}
		location := started.Header().Get("Location")
		requirement, err := aauth.ParseInteractionRequirement(started.Header().Values("AAuth-Requirement"))
		if err != nil {
			t.Fatal(err)
		}
		binding := AgentBinding{AgentProvider: "https://provider.example", Agent: protocol.agentID}
		protocol.now = protocol.now.Add(time.Minute)
		if err := server.RevokeAgentBinding(context.Background(), binding); err != nil {
			t.Fatal(err)
		}
		protocol.now = protocol.now.Add(time.Hour + 5*time.Minute)
		if err := server.ReestablishAgentBinding(context.Background(), binding); err != nil {
			t.Fatal(err)
		}
		protocol.now = protocol.now.Add(time.Second)
		interaction, err := server.ConsumePersonTokenInteractionCode(context.Background(), personInteractionReference(t, requirement.URL), requirement.Code)
		if err != nil {
			t.Fatal(err)
		}
		if err := server.ApprovePersonTokenInteraction(context.Background(), interaction, Person{Subject: "previous-person", Lifetime: 10 * time.Minute}); !errors.Is(err, ErrAgentBindingRevoked) {
			t.Fatalf("approval of a wait from the revoked binding = %v", err)
		}
		poll := httptest.NewRecorder()
		server.Handler().ServeHTTP(poll, protocol.pollRequest(t, location, protocol.agentKey, protocol.agentToken))
		assertBindingRevokedProblem(t, poll, http.StatusForbidden, "person_token_denied")
		again := httptest.NewRecorder()
		server.Handler().ServeHTTP(again, protocol.pollRequest(t, location, protocol.agentKey, protocol.agentToken))
		assertPersonInteractionProblem(t, again, http.StatusGone, "invalid_code")
		if store.tokenCommitCount() != 0 {
			t.Fatal("the revoked binding's wait retained a Person token")
		}
		// A request made under the new binding is admitted.
		fresh := httptest.NewRecorder()
		server.Handler().ServeHTTP(fresh, protocol.personTokenRequest(t))
		if fresh.Code != http.StatusAccepted {
			t.Fatalf("request under the new binding = %d %s", fresh.Code, fresh.Body.String())
		}
	})

	t.Run("PS-hosted consent and presented Person tokens", func(t *testing.T) {
		t.Parallel()
		protocol := newAuthorizationInteractionProtocol(t)
		bindings := newMemoryAgentBindingRevocations()
		config := protocol.config(newMemoryDeferredAuthorizationStore())
		config.AgentBindingRevocations = bindings
		server, err := NewPSAuthorization(config)
		if err != nil {
			t.Fatal(err)
		}
		// The same Person token, issued before the revocation, is presented twice.
		body, err := json.Marshal(map[string]any{
			"resource_token": protocol.resourceToken, "presented_token": protocol.presentedToken(t),
			"capabilities": []string{"interaction"},
		})
		if err != nil {
			t.Fatal(err)
		}
		response := protocol.exchangeBody(t, server, string(body))
		if response.Code != http.StatusAccepted {
			t.Fatalf("consent request = %d %s", response.Code, response.Body.String())
		}
		location := response.Header().Get("Location")
		requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
		if err != nil {
			t.Fatal(err)
		}
		binding := AgentBinding{AgentProvider: protocol.providerID, Agent: protocol.agentID}
		protocol.now = protocol.now.Add(time.Second)
		if err := server.RevokeAgentBinding(context.Background(), binding); err != nil {
			t.Fatal(err)
		}
		protocol.now = protocol.now.Add(time.Second)
		if err := server.ReestablishAgentBinding(context.Background(), binding); err != nil {
			t.Fatal(err)
		}
		protocol.now = protocol.now.Add(time.Second)
		value, err := server.ConsumeAuthorizationInteractionCode(context.Background(), strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/"), requirement.Code)
		if err != nil {
			t.Fatal(err)
		}
		minted := protocol.tokenIDCalls()
		if err := server.ApproveAuthorizationInteraction(context.Background(), value, AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}); !errors.Is(err, ErrAgentBindingRevoked) {
			t.Fatalf("approval of a wait from the revoked binding = %v", err)
		}
		assertBindingRevokedProblem(t, protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken), http.StatusBadRequest, "revoked_presented_token")
		assertAuthorizationInteractionProblem(t, protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken), http.StatusGone, "invalid_code")
		// The Person token issued before the replacement stays refused.
		assertBindingRevokedProblem(t, protocol.exchangeBody(t, server, string(body)), http.StatusBadRequest, "revoked_presented_token")
		if protocol.tokenIDCalls() != minted || protocol.policyCalls != 1 {
			t.Fatalf("the revoked binding reached policy or issuance: minted %d policy %d", protocol.tokenIDCalls()-minted, protocol.policyCalls)
		}
	})

	t.Run("a Person token issued under the new binding", func(t *testing.T) {
		t.Parallel()
		p := newSubagentPersonServerProtocol(t)
		bindings := newMemoryAgentBindingRevocations()
		server := p.directServer(t, PSAuthorizationConfig{AgentBindingRevocations: bindings})
		binding := AgentBinding{AgentProvider: "https://ap.example", Agent: "aauth:planner@ap.example"}
		if err := server.RevokeAgentBinding(context.Background(), binding); err != nil {
			t.Fatal(err)
		}
		assertBindingRevokedProblem(t, p.personRequest(t, server, p.childToken), http.StatusForbidden, "person_token_denied")
		p.now = p.now.Add(time.Second)
		if err := server.ReestablishAgentBinding(context.Background(), binding); err != nil {
			t.Fatal(err)
		}
		// A request at the instant of the replacement is not after it.
		assertBindingRevokedProblem(t, p.personRequest(t, server, p.childToken), http.StatusForbidden, "person_token_denied")
		p.now = p.now.Add(time.Second)
		if response := p.personRequest(t, server, p.childToken); response.Code != http.StatusOK {
			t.Fatalf("Person token under the new binding = %d %s", response.Code, response.Body.String())
		}
	})
}

// Replacing a binding is a host-authenticated administrative action on a
// revoked top-level binding; a store in an impossible state fails closed.
func TestReestablishAgentBindingRequiresARevocation(t *testing.T) {
	t.Parallel()

	p := newSubagentPersonServerProtocol(t)
	binding := AgentBinding{AgentProvider: "https://ap.example", Agent: "aauth:planner@ap.example"}
	if err := p.directServer(t, PSAuthorizationConfig{}).ReestablishAgentBinding(context.Background(), binding); err == nil {
		t.Fatal("replacement without a store was accepted")
	}
	bindings := newMemoryAgentBindingRevocations()
	server := p.directServer(t, PSAuthorizationConfig{AgentBindingRevocations: bindings})
	if err := server.ReestablishAgentBinding(context.Background(), binding); !errors.Is(err, ErrAgentBindingNotRevoked) {
		t.Fatalf("replacement of an unrevoked binding = %v", err)
	}
	if err := server.ReestablishAgentBinding(context.Background(), AgentBinding{
		AgentProvider: "https://ap.example", Agent: "aauth:planner+search@ap.example",
	}); err == nil {
		t.Fatal("replacement of a sub-agent binding was accepted")
	}
	bindings.set(binding, AgentBindingRevocation{ReestablishedAt: p.now})
	response := p.parentPersonRequest(t, server)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("inconsistent binding state = %d %s", response.Code, response.Body.String())
	}
}

// Protocol 28e8258, Agent-Person Binding: mission approval issues Person tokens
// for the Agent's person, so a revoked binding refuses it on the immediate
// path, at a deferred host decision, and at delivery of an approval retained
// before the revocation.
func TestRevokedAgentBindingRefusesMissionApproval(t *testing.T) {
	t.Parallel()

	proposal := []byte(`{"description":"# Report","tools":[{"name":"Publish","description":"Publish"}],"resources":["https://resource.example"]}`)
	propose := func(t *testing.T, protocol *missionProtocol, server *Server) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/mission", bytes.NewReader(proposal))
		request.Header.Set("Content-Type", "application/json")
		if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	poll := func(t *testing.T, protocol *missionProtocol, server *Server, location string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, protocol.personServerID+location, nil)
		if err := signaturekey.SignJWTRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	newServer := func(t *testing.T, protocol *missionProtocol, deferProposal bool) (*Server, *missionProposalCaptureStore, *int) {
		t.Helper()
		store := &missionProposalCaptureStore{memoryMissionStore: protocol.store, proposals: make(map[string]MissionProposalSnapshot)}
		policyCalls := 0
		missions := &MissionConfig{
			Approve: func(_ context.Context, request MissionApprovalRequest) (MissionDecision, error) {
				policyCalls++
				return MissionDecision{Description: "ok", ApprovedTools: request.Proposal.Tools, ApprovedResources: request.Proposal.Resources}, nil
			},
			AcceptUpdate:                    func(context.Context, MissionUpdatePolicyRequest) error { return nil },
			ConfirmPersonAcceptedCompletion: func(context.Context, MissionCompletionPolicyRequest) error { return nil },
		}
		if deferProposal {
			missions.DeferProposal = func(context.Context, MissionApprovalRequest) (MissionProposalPendingPolicy, bool, error) {
				policyCalls++
				return MissionProposalPendingPolicy{Lifetime: 10 * time.Minute, RetryAfter: time.Second}, true, nil
			}
		}
		server, err := NewPSAuthorization(PSAuthorizationConfig{
			Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
			Clock: protocol.clock, Tokens: store, NewID: func() string { return "mission-person-token" },
			BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
				return Person{Subject: "person-123", Lifetime: time.Hour}, nil
			},
			Authorize: func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
				return AuthorizationDecision{Scopes: request.Scopes, Lifetime: time.Hour}, nil
			},
			Missions:                missions,
			AgentBindingRevocations: newMemoryAgentBindingRevocations(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return server, store, &policyCalls
	}
	committed := func(store *missionProposalCaptureStore) (int, int) {
		store.memoryMissionStore.mu.Lock()
		defer store.memoryMissionStore.mu.Unlock()
		return len(store.memoryMissionStore.missions), len(store.memoryMissionStore.records)
	}
	revoke := func(t *testing.T, protocol *missionProtocol, server *Server) {
		t.Helper()
		if err := server.RevokeAgentBinding(context.Background(), AgentBinding{AgentProvider: protocol.agentProviderID, Agent: protocol.agentID}); err != nil {
			t.Fatal(err)
		}
	}

	for _, deferProposal := range []bool{false, true} {
		t.Run(map[bool]string{false: "new immediate proposal", true: "new deferred proposal"}[deferProposal], func(t *testing.T) {
			t.Parallel()
			protocol := newMissionProtocol(t)
			server, store, policyCalls := newServer(t, protocol, deferProposal)
			revoke(t, protocol, server)
			assertBindingRevokedProblem(t, propose(t, protocol, server), http.StatusForbidden, "person_token_denied")
			missions, tokens := committed(store)
			if *policyCalls != 0 || missions != 0 || tokens != 0 || len(store.proposals) != 0 {
				t.Fatalf("revoked binding reached policy or retention: policy %d missions %d tokens %d proposals %d", *policyCalls, missions, tokens, len(store.proposals))
			}
		})
	}

	t.Run("proposal pending at revocation", func(t *testing.T) {
		t.Parallel()
		protocol := newMissionProtocol(t)
		server, store, _ := newServer(t, protocol, true)
		started := propose(t, protocol, server)
		if started.Code != http.StatusAccepted {
			t.Fatalf("deferred proposal = %d %s", started.Code, started.Body.String())
		}
		location := started.Header().Get("Location")
		review, err := server.ResumeMissionProposal(context.Background(), strings.TrimPrefix(location, "/mission/pending/"))
		if err != nil {
			t.Fatal(err)
		}
		revoke(t, protocol, server)
		decision := MissionDecision{Description: "ok", ApprovedTools: review.Proposal().Tools, ApprovedResources: review.Proposal().Resources}
		if err := server.ApproveMissionProposal(context.Background(), review, decision); !errors.Is(err, ErrAgentBindingRevoked) {
			t.Fatalf("host approval under a revoked binding = %v", err)
		}
		assertBindingRevokedProblem(t, poll(t, protocol, server, location), http.StatusForbidden, "person_token_denied")
		assertAuthorizationInteractionProblem(t, poll(t, protocol, server, location), http.StatusGone, "invalid_code")
		if missions, tokens := committed(store); missions != 0 || tokens != 0 {
			t.Fatalf("revoked binding committed missions %d tokens %d", missions, tokens)
		}
	})

	t.Run("approval retained before revocation", func(t *testing.T) {
		t.Parallel()
		protocol := newMissionProtocol(t)
		server, _, _ := newServer(t, protocol, true)
		started := propose(t, protocol, server)
		if started.Code != http.StatusAccepted {
			t.Fatalf("deferred proposal = %d %s", started.Code, started.Body.String())
		}
		location := started.Header().Get("Location")
		review, err := server.ResumeMissionProposal(context.Background(), strings.TrimPrefix(location, "/mission/pending/"))
		if err != nil {
			t.Fatal(err)
		}
		if err := server.ApproveMissionProposal(context.Background(), review, MissionDecision{
			Description: "ok", ApprovedTools: review.Proposal().Tools, ApprovedResources: review.Proposal().Resources,
		}); err != nil {
			t.Fatal(err)
		}
		revoke(t, protocol, server)
		assertBindingRevokedProblem(t, poll(t, protocol, server, location), http.StatusForbidden, "person_token_denied")
		assertAuthorizationInteractionProblem(t, poll(t, protocol, server, location), http.StatusGone, "invalid_code")
	})
}
