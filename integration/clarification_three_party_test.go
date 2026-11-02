package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestCurrentCoreThreePartyClarificationAcrossRecomposition(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 8, 31, 19, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	const (
		agentProviderID = "https://ap.example"
		agentID         = "aauth:reader@ap.example"
		wrongAgentID    = "aauth:other@ap.example"
		personServerID  = "https://ps.example"
		resourceID      = "https://resource.example"
		accessServerID  = "https://as.example"
	)
	scope := []string{"records.read"}
	agentProviderKey := newSigningKey(t, "clarification-journey-ap")
	agentKey := newSigningKey(t, "clarification-journey-agent")
	wrongAgentKey := newSigningKey(t, "clarification-journey-wrong-agent")
	personServerKey := newSigningKey(t, "clarification-journey-ps")
	resourceKey := newSigningKey(t, "clarification-journey-resource")

	network := newLogicalTransport()
	httpClient := &http.Client{Transport: network}
	keyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient, TransportEnforcesEgress: true,
		Clock: clock,
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

	agentTokenIDs := []string{"clarification-agent-token", "clarification-wrong-agent-token"}
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: agentProviderID, SigningKey: agentProviderKey, Clock: clock,
		NewID: func() string {
			id := agentTokenIDs[0]
			agentTokenIDs = agentTokenIDs[1:]
			return id
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := provider.Issue(ctx, aauth.AgentTokenRequest{
		Agent: agentID, PersonServer: personServerID,
		PublicKey: agentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongAgentToken, err := provider.Issue(ctx, aauth.AgentTokenRequest{
		Agent: wrongAgentID, PersonServer: personServerID,
		PublicKey: wrongAgentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	personTokens := newMemoryPersonTokenStore()
	authorizations := newIntegrationDeferredAuthorizationStore()
	ids := []string{"clarification-person-token", "clarification-auth-token"}
	newIDCalls := 0
	policyCalls := 0
	newPeople := func() *personserver.Server {
		people, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
			Issuer: personServerID, SigningKey: personServerKey, KeyResolver: keyResolver,
			Clock: clock, Tokens: personTokens,
			NewID: func() string {
				if len(ids) == 0 {
					t.Fatal("Person Server minted an unexpected third token")
				}
				id := ids[0]
				ids = ids[1:]
				newIDCalls++
				return id
			},
			BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
				if request.Agent != agentID || request.Resource != resourceID {
					return personserver.Person{}, errors.New("unexpected person-token request")
				}
				return personserver.Person{Subject: "person-123", Tenant: "tenant-1", Lifetime: 20 * time.Minute}, nil
			},
			RequireAuthorizationInteraction: func(_ context.Context, request personserver.AuthorizationRequest) (personserver.AuthorizationInteractionPolicy, bool, error) {
				policyCalls++
				if request.Agent != agentID || request.Resource != resourceID || request.Subject != "person-123" ||
					request.Tenant != "tenant-1" || !slices.Equal(request.Scopes, scope) ||
					!slices.Equal(request.Capabilities, []string{"interaction", "clarification"}) {
					return personserver.AuthorizationInteractionPolicy{}, false, errors.New("unexpected clarification authorization request")
				}
				return personserver.AuthorizationInteractionPolicy{
					URL: personServerID + "/consent", Lifetime: 5 * time.Minute,
				}, true, nil
			},
			AuthorizationInteractions: authorizations,
		})
		if err != nil {
			t.Fatal(err)
		}
		return people
	}

	protectedCalls := 0
	protectedResource, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: resourceID, SigningKey: resourceKey, KeyResolver: keyResolver, Clock: clock,
		NewID:             func() string { return "clarification-resource-token" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return append([]string(nil), scope...) },
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
			if identity != (resource.PersonIdentity{Issuer: personServerID, Subject: "person-123"}) ||
				personContext.Tenant != "tenant-1" {
				return errors.New("unexpected Resource person")
			}
			return nil
		},
		Protected: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			protectedCalls++
			principal, ok := resource.AuthPrincipalFromContext(request.Context())
			if !ok || principal.PersonServer != personServerID || principal.Subject != "person-123" ||
				principal.Tenant != "tenant-1" || !slices.Equal(principal.Scope, scope) ||
				!principal.Confirmation.Equal(agentKey.PublicJWK()) {
				t.Errorf("clarification principal = %#v, present=%t", principal, ok)
			}
			_, _ = io.WriteString(response, "clarification accepted")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	personTokenRequests := 0
	authorizationRequests := 0
	pollRequests := 0
	answerRequests := 0
	people := newPeople()
	servePeople := func(server *personserver.Server) {
		network.Handle(personServerID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch {
			case request.Method == http.MethodPost && request.URL.Path == "/person":
				personTokenRequests++
			case request.Method == http.MethodPost && request.URL.Path == "/token":
				authorizationRequests++
				if request.Header.Get("Prefer") != "wait=0" {
					t.Errorf("auth-token Prefer = %q, want wait=0", request.Header.Get("Prefer"))
				}
			case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/token/pending/"):
				pollRequests++
			case request.Method == http.MethodPost && strings.HasPrefix(request.URL.Path, "/token/pending/"):
				answerRequests++
			}
			server.Handler().ServeHTTP(response, request)
		}))
	}
	resourceTokenRequests := 0
	accessCalls := 0
	network.Handle(agentProviderID, provider.Handler())
	servePeople(people)
	network.Handle(resourceID, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && request.URL.Path == "/authorize" {
			resourceTokenRequests++
		}
		protectedResource.Handler().ServeHTTP(response, request)
	}))
	network.Handle(accessServerID, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { accessCalls++ }))

	newReader := func() *clientagent.Client {
		reader, err := clientagent.New(ctx, clientagent.Config{
			Identifier: agentID, SigningKey: agentKey, AgentToken: agentToken,
			KeyResolver: keyResolver, HTTPClient: httpClient, Clock: clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		return reader
	}
	reader := newReader()
	personResult, err := reader.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: personServerID, Resource: resourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	personToken, ok := personResult.Token()
	if !ok {
		t.Fatalf("person-token result = %#v", personResult)
	}
	resourceToken, err := reader.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: resourceID, PersonToken: personToken, Scopes: scope,
	})
	if err != nil {
		t.Fatal(err)
	}
	begin, err := reader.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: personServerID, ResourceToken: resourceToken, PresentedToken: personToken,
		Capabilities: []string{"interaction", "clarification"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := begin.Pending()
	if !ok || pending.Requirement() != aauth.RequirementInteraction || pending.Interacting() ||
		!strings.HasPrefix(pending.Location(), personServerID+"/token/pending/") ||
		!strings.HasPrefix(pending.InteractionURL(), personServerID+"/consent/") || pending.InteractionCode() == "" {
		t.Fatalf("initial pending = %#v, present=%t", pending, ok)
	}
	if personTokenRequests != 1 || resourceTokenRequests != 1 || authorizationRequests != 1 ||
		pollRequests != 0 || answerRequests != 0 || protectedCalls != 0 || accessCalls != 0 ||
		policyCalls != 1 || newIDCalls != 1 {
		t.Fatalf("initial effects: person=%d resource=%d auth=%d poll=%d answer=%d protected=%d AS=%d policy=%d ids=%d",
			personTokenRequests, resourceTokenRequests, authorizationRequests, pollRequests, answerRequests,
			protectedCalls, accessCalls, policyCalls, newIDCalls)
	}

	reference := strings.TrimPrefix(pending.InteractionURL(), personServerID+"/consent/")
	interaction, err := people.ConsumeAuthorizationInteractionCode(ctx, reference, pending.InteractionCode())
	if err != nil {
		t.Fatal(err)
	}
	question := personserver.AuthorizationClarificationRequest{
		Question: "Which record set should be read?",
		Options:  []string{"current", "archive"},
		Lifetime: 2 * time.Minute,
	}
	if err := people.RequestAuthorizationClarification(ctx, interaction, question); err != nil {
		t.Fatal(err)
	}

	clarificationResult, err := reader.PollExchange(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	clarifying, ok := clarificationResult.Pending()
	clarification, hasClarification := clarifying.Clarification()
	timeout, hasTimeout := clarification.Timeout()
	if !ok || !hasClarification || clarifying.Requirement() != aauth.RequirementClarification ||
		clarification.Question() != question.Question || !hasTimeout || timeout != question.Lifetime ||
		!slices.Equal(clarification.Options(), question.Options) {
		t.Fatalf("clarification result=%#v pending=%#v question=%#v present=%t timeout=%s/%t",
			clarificationResult, clarifying, clarification, hasClarification, timeout, hasTimeout)
	}
	mutatedOptions := clarification.Options()
	mutatedOptions[0] = "mutated"
	if got := clarification.Options(); !slices.Equal(got, question.Options) {
		t.Fatalf("Agent clarification options were not copy isolated: %#v", got)
	}
	if pollRequests != 1 || answerRequests != 0 || authorizationRequests != 1 {
		t.Fatalf("clarification delivery requests: auth=%d poll=%d answer=%d", authorizationRequests, pollRequests, answerRequests)
	}

	// Persist only the exported continuation, discard the in-memory handle,
	// and restore it under a newly composed Agent before answering.
	snapshot, err := clarifying.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	encodedSnapshot, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot = clientagent.PendingExchangeSnapshot{}
	if err := json.Unmarshal(encodedSnapshot, &snapshot); err != nil {
		t.Fatal(err)
	}
	clarifying = clientagent.PendingExchange{}
	recomposedReader := newReader()
	restored, err := recomposedReader.RestorePendingExchange(ctx, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	restoredQuestion, ok := restored.Clarification()
	answerBefore, hasAnswerBefore := restoredQuestion.AnswerBefore()
	if !ok || restoredQuestion.Question() != question.Question ||
		!hasAnswerBefore || !answerBefore.Equal(now.Add(question.Lifetime)) ||
		!slices.Equal(restoredQuestion.Options(), question.Options) {
		t.Fatalf("restored clarification = %#v, present=%t", restoredQuestion, ok)
	}

	answer := "current"
	wrongBody, err := json.Marshal(map[string]string{
		"action": "clarification_response", "clarification_response": answer,
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, restored.Location(), bytes.NewReader(wrongBody))
	if err != nil {
		t.Fatal(err)
	}
	wrongRequest.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWTRequestWithOptions(
		wrongRequest, wrongAgentKey, wrongAgentToken, clock,
		signaturekey.SignOptions{AdditionalComponents: []string{"content-type", "content-digest"}},
	); err != nil {
		t.Fatal(err)
	}
	wrongResponse, err := httpClient.Do(wrongRequest)
	if err != nil {
		t.Fatal(err)
	}
	wrongProblem, err := aauth.DecodeProblemResponse(wrongResponse)
	wrongResponse.Body.Close()
	if err != nil || wrongProblem.Status != http.StatusGone || wrongProblem.Code != "invalid_code" {
		t.Fatalf("wrong-Agent clarification answer = %#v, %v", wrongProblem, err)
	}
	if answerRequests != 1 || pollRequests != 1 {
		t.Fatalf("wrong-Agent answer requests=%d polls=%d", answerRequests, pollRequests)
	}

	if err := recomposedReader.AnswerClarification(ctx, restored, answer); err != nil {
		t.Fatal(err)
	}
	if answerRequests != 2 || pollRequests != 1 {
		t.Fatalf("accepted answer requests=%d polls=%d", answerRequests, pollRequests)
	}

	// Recompose the Person Server over the same stores after the signed answer.
	people = newPeople()
	servePeople(people)
	resumed, err := people.ResumeAuthorizationInteraction(ctx, reference)
	if err != nil {
		t.Fatal(err)
	}
	dialogue := resumed.Clarifications()
	if len(dialogue) != 1 || dialogue[0].Question != question.Question ||
		!dialogue[0].RequestedAt.Equal(now) || !dialogue[0].ExpiresAt.Equal(now.Add(question.Lifetime)) ||
		dialogue[0].Response != answer || !dialogue[0].RespondedAt.Equal(now) ||
		!slices.Equal(dialogue[0].Options, question.Options) {
		t.Fatalf("retained clarification dialogue = %#v", dialogue)
	}
	dialogue[0].Options[0] = "mutated host copy"
	if got := resumed.Clarifications()[0].Options; !slices.Equal(got, question.Options) {
		t.Fatalf("host clarification options were not copy isolated: %#v", got)
	}
	if err := people.ApproveAuthorizationInteraction(ctx, resumed, personserver.AuthorizationDecision{
		Scopes: append([]string(nil), scope...), Lifetime: 10 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}

	// Poll once with the continuation restored before Person Server recomposition.
	approvedResult, err := recomposedReader.PollExchange(ctx, restored)
	if err != nil {
		t.Fatal(err)
	}
	authToken, ok := approvedResult.Token()
	if !ok || authToken == "" || pollRequests != 2 || answerRequests != 2 {
		t.Fatalf("approved result=%#v present=%t polls=%d answers=%d", approvedResult, ok, pollRequests, answerRequests)
	}
	authClaims, err := aauth.VerifyAuthToken(ctx, authToken, keyResolver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if authClaims.Issuer != personServerID || authClaims.Audience != resourceID ||
		authClaims.PersonServer != personServerID || authClaims.Subject != "person-123" ||
		authClaims.Tenant != "tenant-1" || !authClaims.Confirmation.JWK.Equal(agentKey.PublicJWK()) ||
		!slices.Equal(strings.Fields(authClaims.Scope), scope) {
		t.Fatalf("clarification auth token = %#v", authClaims)
	}

	protectedRequest, _ := http.NewRequest(http.MethodGet, resourceID+"/records", nil)
	protectedResponse, err := recomposedReader.Do(ctx, clientagent.Call{Request: protectedRequest, AuthToken: authToken})
	if err != nil {
		t.Fatal(err)
	}
	protectedBody, _ := io.ReadAll(protectedResponse.Body)
	protectedResponse.Body.Close()
	if protectedResponse.StatusCode != http.StatusOK || string(protectedBody) != "clarification accepted" ||
		protectedCalls != 1 || accessCalls != 0 {
		t.Fatalf("protected response=%d %q protected=%d AS=%d",
			protectedResponse.StatusCode, protectedBody, protectedCalls, accessCalls)
	}

	_, err = recomposedReader.PollExchange(ctx, restored)
	var gone *aauth.ProblemError
	if !errors.As(err, &gone) || gone.Status != http.StatusGone || gone.Code != "invalid_code" ||
		pollRequests != 3 || answerRequests != 2 {
		t.Fatalf("terminal replay = %v, problem=%#v, polls=%d answers=%d", err, gone, pollRequests, answerRequests)
	}
	creates, approvals, terminalConsumes := authorizations.counts()
	if creates != 1 || approvals != 1 || terminalConsumes != 1 || policyCalls != 1 ||
		newIDCalls != 2 || personTokenRequests != 1 || resourceTokenRequests != 1 ||
		authorizationRequests != 1 || accessCalls != 0 || protectedCalls != 1 {
		t.Fatalf("final effects: creates=%d approvals=%d consumes=%d policy=%d ids=%d person=%d resource=%d auth=%d AS=%d protected=%d",
			creates, approvals, terminalConsumes, policyCalls, newIDCalls, personTokenRequests,
			resourceTokenRequests, authorizationRequests, accessCalls, protectedCalls)
	}
}
