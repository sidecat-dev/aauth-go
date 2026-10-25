package personserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestAuthorizationClarificationLifecycleAcrossRecomposition(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)

	pendingResponse := protocol.exchange(t, server, []string{"interaction", "clarification"})
	interactionRequirement, err := aauth.ParseInteractionRequirement(pendingResponse.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(interactionRequirement.URL, protocol.interactionURL+"/")
	interaction, err := server.ConsumeAuthorizationInteractionCode(
		context.Background(), reference, interactionRequirement.Code,
	)
	if err != nil {
		t.Fatal(err)
	}
	question := AuthorizationClarificationRequest{
		Question: "Why do you need write access?",
		Options:  []string{"Create the meeting", "Cancel the request"},
		Lifetime: time.Minute,
	}
	if err := server.RequestAuthorizationClarification(context.Background(), interaction, question); err != nil {
		t.Fatal(err)
	}

	location := pendingResponse.Header().Get("Location")
	clarification := protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken)
	if clarification.Code != http.StatusAccepted ||
		clarification.Header().Get("AAuth-Requirement") != "requirement=clarification" ||
		clarification.Header().Get("Location") != location {
		t.Fatalf("clarification poll = %d headers=%#v body=%s", clarification.Code, clarification.Header(), clarification.Body.String())
	}
	var body struct {
		Status        string   `json:"status"`
		Clarification string   `json:"clarification"`
		Timeout       int64    `json:"timeout"`
		Options       []string `json:"options"`
	}
	if err := json.NewDecoder(clarification.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "pending" || body.Clarification != question.Question || body.Timeout != 60 ||
		!reflect.DeepEqual(body.Options, question.Options) {
		t.Fatalf("clarification body = %#v", body)
	}

	answer := "I need to create the meeting the person requested."
	answered := protocol.answerClarification(t, server, location, protocol.agentKey, protocol.agentToken, answer)
	if answered.Code != http.StatusNoContent || answered.Body.Len() != 0 {
		t.Fatalf("clarification answer = %d %s", answered.Code, answered.Body.String())
	}
	if exactReplay := protocol.answerClarification(t, server, location, protocol.agentKey, protocol.agentToken, answer); exactReplay.Code != http.StatusNoContent {
		t.Fatalf("exact clarification replay = %d %s", exactReplay.Code, exactReplay.Body.String())
	}
	changed := protocol.answerClarification(t, server, location, protocol.agentKey, protocol.agentToken, "A different answer")
	assertAuthorizationInteractionProblem(t, changed, http.StatusConflict, "conflict")

	recomposed := protocol.newServer(t, store)
	resumed, err := recomposed.ResumeAuthorizationInteraction(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	rounds := resumed.Clarifications()
	if len(rounds) != 1 || rounds[0].Question != question.Question || rounds[0].Response != answer ||
		!reflect.DeepEqual(rounds[0].Options, question.Options) || rounds[0].RequestedAt != protocol.now ||
		!rounds[0].ExpiresAt.Equal(protocol.now.Add(time.Minute)) || rounds[0].RespondedAt != protocol.now {
		t.Fatalf("retained clarification = %#v", rounds)
	}
	rounds[0].Options[0] = "mutated"
	if got := resumed.Clarifications()[0].Options[0]; got != question.Options[0] {
		t.Fatalf("clarification options were not copy isolated: %q", got)
	}

	if err := recomposed.ApproveAuthorizationInteraction(context.Background(), resumed, AuthorizationDecision{
		Scopes: []string{"records.read"}, Lifetime: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	approved := protocol.poll(t, recomposed, location, protocol.agentKey, protocol.agentToken)
	if approved.Code != http.StatusOK {
		t.Fatalf("approved clarification poll = %d %s", approved.Code, approved.Body.String())
	}
}

func TestAuthorizationClarificationCancellationIsTerminal(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	pendingResponse := protocol.exchange(t, server, []string{"interaction", "clarification"})
	requirement, err := aauth.ParseInteractionRequirement(pendingResponse.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	interaction, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.RequestAuthorizationClarification(context.Background(), interaction, AuthorizationClarificationRequest{
		Question: "Continue?", Lifetime: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	location := pendingResponse.Header().Get("Location")
	cancelled := protocol.cancelClarification(t, server, location, protocol.agentKey, protocol.agentToken)
	if cancelled.Code != http.StatusOK || cancelled.Header().Get("Cache-Control") != "no-store" ||
		strings.TrimSpace(cancelled.Body.String()) != `{"status":"cancelled"}` {
		t.Fatalf("cancel = %d %s", cancelled.Code, cancelled.Body.String())
	}
	if replay := protocol.cancelClarification(t, server, location, protocol.agentKey, protocol.agentToken); replay.Code != http.StatusGone {
		t.Fatalf("request after cancellation = %d %s", replay.Code, replay.Body.String())
	}
	poll := protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken)
	assertAuthorizationInteractionProblem(t, poll, http.StatusGone, "invalid_code")
	resumed, err := server.ResumeAuthorizationInteraction(context.Background(), reference)
	if err != nil {
		t.Fatalf("resume cancelled authorization: %v", err)
	}
	if cancelledAt, ok := resumed.CancelledAt(); !ok || !cancelledAt.Equal(protocol.now) {
		t.Fatalf("cancelled observation = %s, %t", cancelledAt, ok)
	}
}

func TestAuthorizationClarificationRejectsMalformedStoreResults(t *testing.T) {
	t.Run("changed canonical question deadline", func(t *testing.T) {
		protocol := newAuthorizationInteractionProtocol(t)
		base := newMemoryDeferredAuthorizationStore()
		store := &alteredClarificationStore{
			memoryDeferredAuthorizationStore: base,
			alter: func(round *AuthorizationClarificationRound) {
				round.ExpiresAt = round.ExpiresAt.Add(time.Second)
			},
		}
		server := protocol.newServer(t, store)
		pendingResponse := protocol.exchange(t, server, []string{"interaction", "clarification"})
		requirement, err := aauth.ParseInteractionRequirement(pendingResponse.Header().Values("AAuth-Requirement"))
		if err != nil {
			t.Fatal(err)
		}
		reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
		interaction, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
		if err != nil {
			t.Fatal(err)
		}
		err = server.RequestAuthorizationClarification(context.Background(), interaction, AuthorizationClarificationRequest{
			Question: "Continue?", Lifetime: time.Minute,
		})
		if !errors.Is(err, ErrPendingAuthorizationConflict) {
			t.Fatalf("changed canonical deadline = %v", err)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*memoryPendingAuthorization)
	}{
		{name: "missing dialogue", mutate: func(pending *memoryPendingAuthorization) {
			pending.clarifications = nil
		}},
		{name: "answered final round", mutate: func(pending *memoryPendingAuthorization) {
			last := &pending.clarifications[len(pending.clarifications)-1]
			last.Response = "stale answer"
			last.RespondedAt = last.RequestedAt.Add(time.Second)
		}},
		{name: "cancellation before question", mutate: func(pending *memoryPendingAuthorization) {
			last := pending.clarifications[len(pending.clarifications)-1]
			pending.cancelledAt = last.RequestedAt.Add(-time.Second)
		}},
		{name: "cancellation at question expiry", mutate: func(pending *memoryPendingAuthorization) {
			last := pending.clarifications[len(pending.clarifications)-1]
			pending.cancelledAt = last.ExpiresAt
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			protocol := newAuthorizationInteractionProtocol(t)
			store := newMemoryDeferredAuthorizationStore()
			server := protocol.newServer(t, store)
			pendingResponse := protocol.exchange(t, server, []string{"interaction", "clarification"})
			requirement, err := aauth.ParseInteractionRequirement(pendingResponse.Header().Values("AAuth-Requirement"))
			if err != nil {
				t.Fatal(err)
			}
			reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
			interaction, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.RequestAuthorizationClarification(context.Background(), interaction, AuthorizationClarificationRequest{
				Question: "Continue?", Lifetime: time.Minute,
			}); err != nil {
				t.Fatal(err)
			}
			location := pendingResponse.Header().Get("Location")
			if cancelled := protocol.cancelClarification(t, server, location, protocol.agentKey, protocol.agentToken); cancelled.Code != http.StatusOK {
				t.Fatalf("cancel = %d %s", cancelled.Code, cancelled.Body.String())
			}
			store.mu.Lock()
			test.mutate(store.pending[reference])
			store.mu.Unlock()
			if _, err := server.ResumeAuthorizationInteraction(context.Background(), reference); !errors.Is(err, ErrPendingAuthorizationConflict) {
				t.Fatalf("malformed cancelled snapshot = %v", err)
			}
		})
	}
}

type alteredClarificationStore struct {
	*memoryDeferredAuthorizationStore
	alter func(*AuthorizationClarificationRound)
}

func (store *alteredClarificationStore) RequestPendingAuthorizationClarification(
	ctx context.Context,
	reference string,
	request AuthorizationClarificationRequest,
	now time.Time,
) (AuthorizationClarificationRound, error) {
	round, err := store.memoryDeferredAuthorizationStore.RequestPendingAuthorizationClarification(ctx, reference, request, now)
	if err == nil && store.alter != nil {
		store.alter(&round)
	}
	return round, err
}

func TestAuthorizationClarificationExactQuestionReplayRecoversCanonicalDeadline(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	pendingResponse := protocol.exchange(t, server, []string{"interaction", "clarification"})
	requirement, err := aauth.ParseInteractionRequirement(pendingResponse.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	interaction, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	request := AuthorizationClarificationRequest{Question: "Why?", Lifetime: 4 * time.Minute}
	if err := server.RequestAuthorizationClarification(context.Background(), interaction, request); err != nil {
		t.Fatal(err)
	}
	protocol.now = protocol.now.Add(time.Second)
	if err := server.RequestAuthorizationClarification(context.Background(), interaction, request); err != nil {
		t.Fatalf("exact question replay after time advanced: %v", err)
	}
	snapshot, err := store.LoadPendingAuthorization(context.Background(), reference, protocol.now)
	if err != nil || len(snapshot.Clarifications) != 1 ||
		!snapshot.Clarifications[0].RequestedAt.Equal(protocol.now.Add(-time.Second)) ||
		!snapshot.Clarifications[0].ExpiresAt.Equal(protocol.now.Add(4*time.Minute-time.Second)) {
		t.Fatalf("canonical clarification = %#v, %v", snapshot.Clarifications, err)
	}
}

func TestAuthorizationClarificationHistoryCannotEscapePendingBoundary(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	response := protocol.exchange(t, server, []string{"interaction", "clarification"})
	requirement, err := aauth.ParseInteractionRequirement(response.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	if _, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code); err != nil {
		t.Fatal(err)
	}
	base, err := store.LoadPendingAuthorization(context.Background(), reference, protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		round AuthorizationClarificationRound
	}{
		{
			name: "before creation",
			round: AuthorizationClarificationRound{
				Question: "forged", RequestedAt: base.Record.CreatedAt.Add(-time.Second),
				ExpiresAt: base.Record.CreatedAt.Add(time.Minute),
			},
		},
		{
			name: "after pending expiry",
			round: AuthorizationClarificationRound{
				Question: "forged", RequestedAt: base.Record.CreatedAt,
				ExpiresAt: base.Record.ExpiresAt.Add(time.Second),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			forged := base
			forged.State = AuthorizationPollClarifying
			forged.Clarifications = []AuthorizationClarificationRound{test.round}
			if err := server.validatePendingAuthorizationSnapshot(context.Background(), forged); !errors.Is(err, ErrPendingAuthorizationConflict) {
				t.Fatalf("forged clarification history = %v", err)
			}
		})
	}
}

func TestAuthorizationClarificationRequiresDeclaredCapabilityAndBoundedQuestion(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	pendingResponse := protocol.exchange(t, server, []string{"interaction"})
	requirement, err := aauth.ParseInteractionRequirement(pendingResponse.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	interaction, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.RequestAuthorizationClarification(context.Background(), interaction, AuthorizationClarificationRequest{
		Question: "Why?", Lifetime: time.Minute,
	}); !errors.Is(err, ErrAuthorizationClarificationUnsupported) {
		t.Fatalf("undeclared clarification = %v", err)
	}
	for _, request := range []AuthorizationClarificationRequest{
		{Question: "", Lifetime: time.Minute},
		{Question: strings.Repeat("x", MaximumAuthorizationClarificationBytes+1), Lifetime: time.Minute},
		{Question: "Why?", Lifetime: 0},
		{Question: "Why?", Lifetime: 10 * time.Minute},
	} {
		if err := validateAuthorizationClarificationRequest(request, protocol.now, protocol.now.Add(4*time.Minute)); err == nil {
			t.Fatalf("invalid clarification request accepted: %#v", request)
		}
	}
}

func TestAuthorizationClarificationEnforcesDeadlineAndRoundBound(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		protocol := newAuthorizationInteractionProtocol(t)
		store := newMemoryDeferredAuthorizationStore()
		server := protocol.newServer(t, store)
		pendingResponse := protocol.exchange(t, server, []string{"interaction", "clarification"})
		requirement, err := aauth.ParseInteractionRequirement(pendingResponse.Header().Values("AAuth-Requirement"))
		if err != nil {
			t.Fatal(err)
		}
		reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
		interaction, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
		if err != nil {
			t.Fatal(err)
		}
		if err := server.RequestAuthorizationClarification(context.Background(), interaction, AuthorizationClarificationRequest{
			Question: "Answer quickly", Lifetime: time.Minute,
		}); err != nil {
			t.Fatal(err)
		}
		protocol.now = protocol.now.Add(time.Minute)
		response := protocol.answerClarification(t, server, pendingResponse.Header().Get("Location"), protocol.agentKey, protocol.agentToken, "too late")
		assertAuthorizationInteractionProblem(t, response, http.StatusRequestTimeout, "expired")
	})

	t.Run("rounds", func(t *testing.T) {
		protocol := newAuthorizationInteractionProtocol(t)
		store := newMemoryDeferredAuthorizationStore()
		server := protocol.newServer(t, store)
		pendingResponse := protocol.exchange(t, server, []string{"interaction", "clarification"})
		requirement, err := aauth.ParseInteractionRequirement(pendingResponse.Header().Values("AAuth-Requirement"))
		if err != nil {
			t.Fatal(err)
		}
		reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
		interaction, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
		if err != nil {
			t.Fatal(err)
		}
		location := pendingResponse.Header().Get("Location")
		for round := 0; round < MaximumAuthorizationClarificationRounds; round++ {
			question := AuthorizationClarificationRequest{
				Question: fmt.Sprintf("Question %d", round+1), Lifetime: time.Minute,
			}
			if err := server.RequestAuthorizationClarification(context.Background(), interaction, question); err != nil {
				t.Fatalf("round %d question: %v", round+1, err)
			}
			response := protocol.answerClarification(
				t, server, location, protocol.agentKey, protocol.agentToken, fmt.Sprintf("Answer %d", round+1),
			)
			if response.Code != http.StatusNoContent {
				t.Fatalf("round %d answer = %d %s", round+1, response.Code, response.Body.String())
			}
		}
		if err := server.RequestAuthorizationClarification(context.Background(), interaction, AuthorizationClarificationRequest{
			Question: "One too many", Lifetime: time.Minute,
		}); !errors.Is(err, ErrPendingAuthorizationConflict) {
			t.Fatalf("sixth clarification = %v", err)
		}
		resumed, err := server.ResumeAuthorizationInteraction(context.Background(), reference)
		if err != nil || len(resumed.Clarifications()) != MaximumAuthorizationClarificationRounds {
			t.Fatalf("retained rounds = %d, err=%v", len(resumed.Clarifications()), err)
		}
	})
}

func TestAuthorizationClarificationActionRejectsInvalidActionAndWrongIdentity(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	pendingResponse := protocol.exchange(t, server, []string{"interaction", "clarification"})
	requirement, err := aauth.ParseInteractionRequirement(pendingResponse.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	interaction, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.RequestAuthorizationClarification(context.Background(), interaction, AuthorizationClarificationRequest{
		Question: "Why?", Lifetime: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	location := pendingResponse.Header().Get("Location")
	invalid := protocol.clarificationAction(
		t, server, location, protocol.agentKey, protocol.agentToken,
		`{"action":"updated_request","resource_token":"not-implemented"}`,
	)
	assertAuthorizationInteractionProblem(t, invalid, http.StatusBadRequest, "invalid_request")

	otherKey := personServerTestKey(t, "clarification-other-agent")
	otherToken := protocol.agentTokenWith(
		t, "aauth:other@provider.example", otherKey, protocol.now.Add(30*time.Minute), "clarification-other-token",
	)
	wrongIdentity := protocol.answerClarification(t, server, location, otherKey, otherToken, "answer")
	assertAuthorizationInteractionProblem(t, wrongIdentity, http.StatusGone, "invalid_code")

	if accepted := protocol.answerClarification(t, server, location, protocol.agentKey, protocol.agentToken, "answer"); accepted.Code != http.StatusNoContent {
		t.Fatalf("valid answer after refusals = %d %s", accepted.Code, accepted.Body.String())
	}
}

func TestUpdatedRequestReplacesThePendingAskWhenIdentityMatches(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	pendingResponse := protocol.exchange(t, server, []string{"interaction", "clarification"})
	requirement, err := aauth.ParseInteractionRequirement(pendingResponse.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	interaction, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.RequestAuthorizationClarification(context.Background(), interaction, AuthorizationClarificationRequest{
		Question: "Why write?", Lifetime: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	location := pendingResponse.Header().Get("Location")
	thumbprint, err := protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	narrowPerson := protocol.personTokenForUpdate(t, "authorization-person-token-2", protocol.subject)
	narrowResource, err := aauth.MintResourceToken(protocol.resourceKey, aauth.ResourceTokenClaims{
		Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument, Audience: protocol.personServerID,
		JTI: "authorization-resource-token-2", PersonServer: protocol.personServerID, Subject: protocol.subject,
		PresentedJTI: "authorization-person-token-2", AgentJKT: thumbprint,
		IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read", Tenant: protocol.tenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	accepted := protocol.clarificationAction(t, server, location, protocol.agentKey, protocol.agentToken, updatedRequestBody(t, narrowResource, narrowPerson, "read only"))
	if accepted.Code != http.StatusNoContent {
		t.Fatalf("updated_request = %d %s", accepted.Code, accepted.Body.String())
	}
	resumed, err := server.ResumeAuthorizationInteraction(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resumed.RequestedScopes(), []string{"records.read"}) {
		t.Fatalf("scopes = %#v", resumed.RequestedScopes())
	}
	rounds := resumed.Clarifications()
	if len(rounds) != 1 || rounds[0].Response != "read only" {
		t.Fatalf("clarification = %#v", rounds)
	}

	otherPerson := protocol.personTokenForUpdate(t, "authorization-person-token-3", "other-person")
	otherResource, err := aauth.MintResourceToken(protocol.resourceKey, aauth.ResourceTokenClaims{
		Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument, Audience: protocol.personServerID,
		JTI: "authorization-resource-token-3", PersonServer: protocol.personServerID, Subject: "other-person",
		PresentedJTI: "authorization-person-token-3", AgentJKT: thumbprint,
		IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(),
		Scope: "records.read", Tenant: protocol.tenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	mismatched := protocol.clarificationAction(t, server, location, protocol.agentKey, protocol.agentToken, updatedRequestBody(t, otherResource, otherPerson, "other subject"))
	assertAuthorizationInteractionProblem(t, mismatched, http.StatusBadRequest, "invalid_resource_token")
	resumed, err = server.ResumeAuthorizationInteraction(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resumed.RequestedScopes(), []string{"records.read"}) {
		t.Fatalf("scopes after mismatch = %#v", resumed.RequestedScopes())
	}
}

func TestUpdatedRequestRefusesReplacementsThatBreakThePendingRecord(t *testing.T) {
	t.Run("resource token expires before the pending deadline", func(t *testing.T) {
		protocol, store, server, location, reference := startClarifyingAuthorization(t)
		refused := protocol.postUpdatedRequest(t, server, location, "authorization-person-token-short", protocol.now.Add(2*time.Minute), nil)
		assertAuthorizationInteractionProblem(t, refused, http.StatusBadRequest, "invalid_resource_token")
		assertPendingAskUnchanged(t, server, store, reference, location, protocol)
	})

	t.Run("person token expires before the pending deadline", func(t *testing.T) {
		protocol, _, server, location, _ := startClarifyingAuthorization(t)
		thumbprint, err := protocol.agentKey.PublicJWK().Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		presented := protocol.personTokenForUpdateUntil(t, "authorization-person-token-short-person", protocol.subject, protocol.agentKey.PublicJWK(), protocol.now.Add(2*time.Minute))
		resource := protocol.resourceTokenForUpdate(t, "authorization-resource-token-short-person", "authorization-person-token-short-person", protocol.subject, thumbprint, protocol.now.Add(5*time.Minute), nil)
		refused := protocol.clarificationAction(t, server, location, protocol.agentKey, protocol.agentToken, updatedRequestBody(t, resource, presented, "short person token"))
		assertAuthorizationInteractionProblem(t, refused, http.StatusBadRequest, "invalid_resource_token")
	})

	t.Run("resource token exceeds the maximum lifetime", func(t *testing.T) {
		protocol, _, server, location, _ := startClarifyingAuthorization(t)
		refused := protocol.postUpdatedRequest(t, server, location, "authorization-person-token-long", protocol.now.Add(6*time.Minute), nil)
		assertAuthorizationInteractionProblem(t, refused, http.StatusBadRequest, "invalid_resource_token")
	})

	t.Run("account is rejected", func(t *testing.T) {
		protocol, _, server, location, _ := startClarifyingAuthorization(t)
		refused := protocol.postUpdatedRequest(t, server, location, "authorization-person-token-account", protocol.now.Add(5*time.Minute), testStringPointer("acct-1"))
		assertAuthorizationInteractionProblem(t, refused, http.StatusBadRequest, "invalid_request")
	})

	t.Run("pending budget offer is rejected", func(t *testing.T) {
		protocol, store, server, location, reference := startClarifyingAuthorization(t)
		unit, err := budgets.NewUnit("usd", 2)
		if err != nil {
			t.Fatal(err)
		}
		offer, err := budgets.NewValue(100, unit)
		if err != nil {
			t.Fatal(err)
		}
		store.mu.Lock()
		store.pending[reference].record.BudgetOffer = &offer
		store.mu.Unlock()
		refused := protocol.postUpdatedRequest(t, server, location, "authorization-person-token-budget", protocol.now.Add(5*time.Minute), nil)
		assertAuthorizationInteractionProblem(t, refused, http.StatusBadRequest, "invalid_request")
		resumed, err := server.ResumeAuthorizationInteraction(context.Background(), reference)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(resumed.RequestedScopes(), []string{"records.read", "records.write"}) {
			t.Fatalf("scopes = %#v", resumed.RequestedScopes())
		}
	})

	t.Run("parent key does not satisfy a sub-agent ask", func(t *testing.T) {
		protocol, store, server, location, reference := startClarifyingAuthorization(t)
		rememberSubagent(t, store, reference, protocol)
		refused := protocol.postUpdatedRequest(t, server, location, "authorization-person-token-parent", protocol.now.Add(5*time.Minute), nil)
		assertAuthorizationInteractionProblem(t, refused, http.StatusBadRequest, "invalid_resource_token")
	})

	t.Run("child key replaces a sub-agent ask", func(t *testing.T) {
		protocol, store, server, location, reference := startClarifyingAuthorization(t)
		child := rememberSubagent(t, store, reference, protocol)
		thumbprint, err := child.PublicJWK().Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		presented := protocol.personTokenForUpdateUntil(t, "authorization-person-token-child", protocol.subject, child.PublicJWK(), protocol.now.Add(20*time.Minute))
		resource := protocol.resourceTokenForUpdate(t, "authorization-resource-token-child", "authorization-person-token-child", protocol.subject, thumbprint, protocol.now.Add(5*time.Minute), nil)
		accepted := protocol.clarificationAction(t, server, location, protocol.agentKey, protocol.agentToken, updatedRequestBody(t, resource, presented, "child scope"))
		if accepted.Code != http.StatusNoContent {
			t.Fatalf("child updated_request = %d %s", accepted.Code, accepted.Body.String())
		}
		polled := protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken)
		if polled.Code != http.StatusAccepted {
			t.Fatalf("poll after child update = %d %s", polled.Code, polled.Body.String())
		}
	})

	t.Run("revoked agent binding", func(t *testing.T) {
		protocol := newAuthorizationInteractionProtocol(t)
		store := newMemoryDeferredAuthorizationStore()
		bindings := newMemoryAgentBindingRevocations()
		config := protocol.config(store)
		config.AgentBindingRevocations = bindings
		server, err := NewPSAuthorization(config)
		if err != nil {
			t.Fatal(err)
		}
		_, location, reference := continueClarification(t, protocol, server)
		if err := bindings.RevokeAgentBinding(context.Background(), AgentBinding{
			AgentProvider: protocol.providerID, Agent: protocol.agentID,
		}, protocol.now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		refused := protocol.postUpdatedRequest(t, server, location, "authorization-person-token-revoked-binding", protocol.now.Add(5*time.Minute), nil)
		assertAuthorizationInteractionProblem(t, refused, http.StatusBadRequest, "revoked_presented_token")
		assertPendingRecordUnchanged(t, server, store, reference, protocol)
		polled := protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken)
		assertAuthorizationInteractionProblem(t, polled, http.StatusBadRequest, "revoked_presented_token")
	})

	t.Run("retained person token disagrees", func(t *testing.T) {
		protocol := newAuthorizationInteractionProtocol(t)
		store := newMemoryDeferredAuthorizationStore()
		tokens := newMemoryTokenStore()
		if err := tokens.Commit(context.Background(), directPersonTokenRecord(
			"authorization-person-token", protocol.personServerID, protocol.resourceID, protocol.subject, protocol.tenant,
			protocol.providerID, protocol.agentID, protocol.agentKey.PublicJWK(), protocol.now.Add(20*time.Minute), protocol.now.Add(25*time.Minute),
		)); err != nil {
			t.Fatal(err)
		}
		if err := tokens.Commit(context.Background(), directPersonTokenRecord(
			"authorization-person-token-lineage", protocol.personServerID, protocol.resourceID, protocol.subject, protocol.tenant,
			protocol.providerID, "aauth:other@provider.example", protocol.agentKey.PublicJWK(), protocol.now.Add(20*time.Minute), protocol.now.Add(25*time.Minute),
		)); err != nil {
			t.Fatal(err)
		}
		config := protocol.config(store)
		config.Tokens = tokens
		server, err := NewPSAuthorization(config)
		if err != nil {
			t.Fatal(err)
		}
		_, location, reference := continueClarification(t, protocol, server)
		refused := protocol.postUpdatedRequest(t, server, location, "authorization-person-token-lineage", protocol.now.Add(5*time.Minute), nil)
		assertAuthorizationInteractionProblem(t, refused, http.StatusBadRequest, "invalid_resource_token")
		resumed, err := server.ResumeAuthorizationInteraction(context.Background(), reference)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(resumed.RequestedScopes(), []string{"records.read", "records.write"}) {
			t.Fatalf("scopes = %#v", resumed.RequestedScopes())
		}
	})

	t.Run("revoked sub-agent token", func(t *testing.T) {
		protocol := newAuthorizationInteractionProtocol(t)
		store := newMemoryDeferredAuthorizationStore()
		config := protocol.config(store)
		config.AgentTokenRevocations = jtiRevocationStore{jti: "revoked-child-token"}
		server, err := NewPSAuthorization(config)
		if err != nil {
			t.Fatal(err)
		}
		_, location, reference := continueClarification(t, protocol, server)
		child := rememberSubagent(t, store, reference, protocol)
		store.mu.Lock()
		store.pending[reference].record.SubagentTokenJTI = "revoked-child-token"
		store.mu.Unlock()
		thumbprint, err := child.PublicJWK().Thumbprint()
		if err != nil {
			t.Fatal(err)
		}
		presented := protocol.personTokenForUpdateUntil(t, "authorization-person-token-revoked-child", protocol.subject, child.PublicJWK(), protocol.now.Add(20*time.Minute))
		resource := protocol.resourceTokenForUpdate(t, "authorization-resource-token-revoked-child", "authorization-person-token-revoked-child", protocol.subject, thumbprint, protocol.now.Add(5*time.Minute), nil)
		refused := protocol.clarificationAction(t, server, location, protocol.agentKey, protocol.agentToken, updatedRequestBody(t, resource, presented, "revoked child"))
		assertAuthorizationInteractionProblem(t, refused, http.StatusForbidden, "revoked")
	})
}

func TestPersonServerOmitsSignatureKeyCache(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	server := protocol.newServer(t, newMemoryDeferredAuthorizationStore())
	pending := protocol.exchange(t, server, []string{"interaction"})
	if pending.Code != http.StatusAccepted {
		t.Fatalf("exchange = %d %s", pending.Code, pending.Body.String())
	}
	location := pending.Header().Get("Location")
	request := httptest.NewRequest(http.MethodGet, protocol.personServerID+location, nil)
	credential, err := signaturekey.NewJWTCredential(protocol.agentToken)
	if err != nil {
		t.Fatal(err)
	}
	credential, err = credential.WithCache()
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, protocol.agentKey, credential, protocol.clock, signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("cached signature poll = %d %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Signature-Key-Cache"); got != "" {
		t.Fatalf("Signature-Key-Cache = %q", got)
	}
}

func startClarifyingAuthorization(t *testing.T) (*authorizationInteractionProtocol, *memoryDeferredAuthorizationStore, *Server, string, string) {
	t.Helper()
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	_, location, reference := continueClarification(t, protocol, server)
	return protocol, store, server, location, reference
}

func continueClarification(t *testing.T, protocol *authorizationInteractionProtocol, server *Server) (*httptest.ResponseRecorder, string, string) {
	t.Helper()
	pending := protocol.exchange(t, server, []string{"interaction", "clarification"})
	requirement, err := aauth.ParseInteractionRequirement(pending.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	interaction, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.RequestAuthorizationClarification(context.Background(), interaction, AuthorizationClarificationRequest{
		Question: "Why write?", Lifetime: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	return pending, pending.Header().Get("Location"), reference
}

func (p *authorizationInteractionProtocol) postUpdatedRequest(
	t *testing.T,
	server *Server,
	location string,
	presentedJTI string,
	resourceExpires time.Time,
	account *string,
) *httptest.ResponseRecorder {
	t.Helper()
	thumbprint, err := p.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	presented := p.personTokenForUpdateUntil(t, presentedJTI, p.subject, p.agentKey.PublicJWK(), p.now.Add(20*time.Minute))
	resource := p.resourceTokenForUpdate(t, presentedJTI+"-resource", presentedJTI, p.subject, thumbprint, resourceExpires, account)
	return p.clarificationAction(t, server, location, p.agentKey, p.agentToken, updatedRequestBody(t, resource, presented, "narrow"))
}

func (p *authorizationInteractionProtocol) resourceTokenForUpdate(
	t *testing.T,
	jti string,
	presentedJTI string,
	subject string,
	agentJKT string,
	expires time.Time,
	account *string,
) string {
	t.Helper()
	compact, err := aauth.MintResourceToken(p.resourceKey, aauth.ResourceTokenClaims{
		Issuer: p.resourceID, DWK: aauth.ResourceDiscoveryDocument, Audience: p.personServerID,
		JTI: jti, PersonServer: p.personServerID, Subject: subject, PresentedJTI: presentedJTI,
		AgentJKT: agentJKT, IssuedAt: p.now.Unix(), ExpiresAt: expires.Unix(),
		Scope: "records.read", Tenant: p.tenant, Account: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (p *authorizationInteractionProtocol) personTokenForUpdateUntil(t *testing.T, jti, subject string, confirmation jose.JWK, expires time.Time) string {
	t.Helper()
	compact, err := aauth.MintPersonToken(p.personKey, aauth.PersonTokenClaims{
		Issuer: p.personServerID, DWK: aauth.PersonDiscoveryDocument, Audience: p.resourceID,
		Subject: subject, Confirmation: aauth.Confirmation{JWK: confirmation},
		JTI: jti, IssuedAt: p.now.Unix(), ExpiresAt: expires.Unix(), Tenant: p.tenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func rememberSubagent(t *testing.T, store *memoryDeferredAuthorizationStore, reference string, protocol *authorizationInteractionProtocol) jose.SigningKey {
	t.Helper()
	child := personServerTestKey(t, "updated-request-child-"+reference)
	store.mu.Lock()
	defer store.mu.Unlock()
	pending := store.pending[reference]
	pending.record.Subagent = "aauth:planner+worker@provider.example"
	pending.record.SubagentTokenJTI = "child-token"
	pending.record.SubagentConfirmation = child.PublicJWK()
	pending.record.SubagentExpiresAt = protocol.now.Add(10 * time.Minute)
	return child
}

func assertPendingAskUnchanged(
	t *testing.T,
	server *Server,
	store *memoryDeferredAuthorizationStore,
	reference string,
	location string,
	protocol *authorizationInteractionProtocol,
) {
	t.Helper()
	resumed, err := server.ResumeAuthorizationInteraction(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resumed.RequestedScopes(), []string{"records.read", "records.write"}) {
		t.Fatalf("scopes = %#v", resumed.RequestedScopes())
	}
	polled := protocol.poll(t, server, location, protocol.agentKey, protocol.agentToken)
	if polled.Code != http.StatusAccepted {
		t.Fatalf("poll = %d %s", polled.Code, polled.Body.String())
	}
	assertPendingRecordUnchanged(t, server, store, reference, protocol)
}

func assertPendingRecordUnchanged(
	t *testing.T,
	server *Server,
	store *memoryDeferredAuthorizationStore,
	reference string,
	protocol *authorizationInteractionProtocol,
) {
	t.Helper()
	resumed, err := server.ResumeAuthorizationInteraction(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resumed.RequestedScopes(), []string{"records.read", "records.write"}) {
		t.Fatalf("scopes = %#v", resumed.RequestedScopes())
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record := store.pending[reference].record
	if !record.ResourceTokenExpiresAt.Equal(protocol.now.Add(5*time.Minute)) || !record.PersonTokenExpiresAt.Equal(protocol.now.Add(20*time.Minute)) {
		t.Fatalf("expiries = %s %s", record.ResourceTokenExpiresAt, record.PersonTokenExpiresAt)
	}
}

type jtiRevocationStore struct{ jti string }

func (store jtiRevocationStore) Revoke(context.Context, aauth.RevocationRequest) error { return nil }

func (store jtiRevocationStore) IsRevoked(_ context.Context, reference aauth.TokenReference) (bool, error) {
	return reference.JTI == store.jti, nil
}

func updatedRequestBody(t *testing.T, resourceToken, presentedToken, justification string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"action": "updated_request", "resource_token": resourceToken,
		"presented_token": presentedToken, "justification": justification,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func (p *authorizationInteractionProtocol) personTokenForUpdate(t *testing.T, jti, subject string) string {
	t.Helper()
	compact, err := aauth.MintPersonToken(p.personKey, aauth.PersonTokenClaims{
		Issuer: p.personServerID, DWK: aauth.PersonDiscoveryDocument, Audience: p.resourceID,
		Subject: subject, Confirmation: aauth.Confirmation{JWK: p.agentKey.PublicJWK()},
		JTI: jti, IssuedAt: p.now.Unix(), ExpiresAt: p.now.Add(20 * time.Minute).Unix(),
		Tenant: p.tenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (p *authorizationInteractionProtocol) answerClarification(
	t *testing.T,
	server *Server,
	location string,
	key jose.SigningKey,
	token string,
	answer string,
) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"action": "clarification_response", "clarification_response": answer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p.clarificationAction(t, server, location, key, token, string(body))
}

func (p *authorizationInteractionProtocol) clarificationAction(
	t *testing.T,
	server *Server,
	location string,
	key jose.SigningKey,
	token string,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, p.personServerID+location, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, key, token, p.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func (p *authorizationInteractionProtocol) cancelClarification(
	t *testing.T,
	server *Server,
	location string,
	key jose.SigningKey,
	token string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodDelete, p.personServerID+location, nil)
	if err := signaturekey.SignJWTRequest(request, key, token, p.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}
