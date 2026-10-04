package personserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
)

func TestMissionDeferredAuthorizationCarriesExactContextThroughClarificationApprovalAndPoll(t *testing.T) {
	fixture := newMissionDeferredAuthorizationFixture(t)

	begin, err := fixture.reader.BeginExchange(context.Background(), clientagent.ExchangeRequest{
		PersonServer: fixture.protocol.personServerID, ResourceToken: fixture.protocol.resourceToken,
		PresentedToken: fixture.presentedToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := begin.Pending()
	if !ok || pending.Requirement() != aauth.RequirementInteraction || pending.InteractionCode() == "" {
		t.Fatalf("mission authorization BeginExchange = %#v, pending=%t", begin, ok)
	}
	assertMissionDeferredAuthorizationContext(t, fixture.protocol.lastAuthorization.Mission, fixture.mission)
	if !slices.Equal(fixture.protocol.requestCapabilities, []string{"interaction", "clarification"}) {
		t.Fatalf("mission capability fallback = %#v", fixture.protocol.requestCapabilities)
	}

	pendingRecord := fixture.store.onlyPending(t)
	if pendingRecord.MissionS256 != fixture.mission.S256 ||
		!pendingRecord.MissionExpiresAt.Equal(fixture.mission.ExpiresAt) ||
		!pendingRecord.ExpiresAt.Equal(fixture.mission.ExpiresAt) {
		t.Fatalf("mission pending record = %#v", pendingRecord)
	}

	reference := strings.TrimPrefix(pending.InteractionURL(), fixture.protocol.interactionURL+"/")
	interaction, err := fixture.server.ConsumeAuthorizationInteractionCode(
		context.Background(), reference, pending.InteractionCode(),
	)
	if err != nil {
		t.Fatal(err)
	}
	mission, ok := interaction.Mission()
	if !ok {
		t.Fatal("mission-bound authorization host handle has no mission")
	}
	assertMissionDeferredAuthorizationContext(t, &mission, fixture.mission)

	question := AuthorizationClarificationRequest{
		Question: "Should the report include the approved appendix?",
		Options:  []string{"Include it", "Omit it"},
		Lifetime: 30 * time.Second,
	}
	if err := fixture.server.RequestAuthorizationClarification(context.Background(), interaction, question); err != nil {
		t.Fatal(err)
	}
	clarificationResult, err := fixture.reader.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	clarifying, ok := clarificationResult.Pending()
	if !ok || clarifying.Requirement() != aauth.RequirementClarification {
		t.Fatalf("mission clarification poll = %#v, pending=%t", clarificationResult, ok)
	}
	answer := "Include only the appendix already named by the accepted update."
	if err := fixture.reader.AnswerClarification(context.Background(), clarifying, answer); err != nil {
		t.Fatal(err)
	}

	resumed, err := fixture.server.ResumeAuthorizationInteraction(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	resumedMission, ok := resumed.Mission()
	if !ok {
		t.Fatal("resumed mission-bound authorization has no mission")
	}
	assertMissionDeferredAuthorizationContext(t, &resumedMission, fixture.mission)
	rounds := resumed.Clarifications()
	if len(rounds) != 1 || rounds[0].Question != question.Question || rounds[0].Response != answer {
		t.Fatalf("mission clarification history = %#v", rounds)
	}

	decision := AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: 10 * time.Minute}
	if err := fixture.server.ApproveAuthorizationInteraction(context.Background(), resumed, decision); err != nil {
		t.Fatal(err)
	}
	approved, err := fixture.reader.PollExchange(context.Background(), clarifying)
	if err != nil {
		t.Fatal(err)
	}
	authToken, ok := approved.Token()
	if !ok {
		t.Fatalf("mission authorization terminal poll = %#v", approved)
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), authToken, fixture.protocol.resolver, fixture.protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.MissionS256 != fixture.mission.S256 || claims.ExpiresAt != fixture.mission.ExpiresAt.Unix() {
		t.Fatalf("mission-bound auth token = %#v", claims)
	}

	fixture.store.requireTransitions(t,
		"create", "clarification", "poll", "answer", "approve", "consume",
	)
}

func TestMissionDeferredAuthorizationExplicitEmptyCapabilitiesDoNotUseMissionFallback(t *testing.T) {
	fixture := newMissionDeferredAuthorizationFixture(t)
	_, err := fixture.reader.BeginExchange(context.Background(), clientagent.ExchangeRequest{
		PersonServer: fixture.protocol.personServerID, ResourceToken: fixture.protocol.resourceToken,
		PresentedToken: fixture.presentedToken,
		Capabilities:   []string{},
	})
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Code != "user_unreachable" {
		t.Fatalf("explicit empty capabilities = %T %v", err, err)
	}
	if len(fixture.protocol.requestCapabilities) != 0 || fixture.store.pendingCount() != 0 {
		t.Fatalf("explicit empty capabilities fell back: policy=%#v pending=%d",
			fixture.protocol.requestCapabilities, fixture.store.pendingCount())
	}
}

func TestMissionsWithSeparateAuthorizationStoreKeepMissionlessDeferredPath(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	tokens := newMemoryMissionStore()
	if err := tokens.Commit(context.Background(), directPersonTokenRecord(
		"authorization-person-token", protocol.personServerID, protocol.resourceID,
		protocol.subject, protocol.tenant, protocol.providerID, protocol.agentID,
		protocol.agentKey.PublicJWK(), protocol.now.Add(20*time.Minute), protocol.now.Add(25*time.Minute),
	)); err != nil {
		t.Fatal(err)
	}
	interactions := newMemoryDeferredAuthorizationStore()
	config := protocol.config(interactions)
	config.Tokens = tokens
	config.Missions = permissionMissionConfig()
	server, err := NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	response := protocol.exchange(t, server, []string{"interaction"})
	if response.Code != http.StatusAccepted || interactions.pendingCount() != 1 {
		t.Fatalf("missionless deferred request with missions configured = %d %s pending=%d",
			response.Code, response.Body.String(), interactions.pendingCount())
	}
}

func TestMissionDeferredAuthorizationRejectsMissionUpdateAfterHostHandleConstruction(t *testing.T) {
	fixture := newMissionDeferredAuthorizationFixture(t)
	pendingResponse := fixture.protocol.exchange(t, fixture.server, []string{"interaction"})
	if pendingResponse.Code != http.StatusAccepted {
		t.Fatalf("mission authorization exchange = %d %s", pendingResponse.Code, pendingResponse.Body.String())
	}
	requirement, err := aauth.ParseInteractionRequirement(pendingResponse.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, fixture.protocol.interactionURL+"/")
	interaction, err := fixture.server.ConsumeAuthorizationInteractionCode(
		context.Background(), reference, requirement.Code,
	)
	if err != nil {
		t.Fatal(err)
	}

	update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{
		Action: "update", Description: "Use a newly approved destination.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.AppendMissionUpdate(
		context.Background(), fixture.mission, fixture.protocol.now, update,
	); err != nil {
		t.Fatal(err)
	}

	err = fixture.server.ApproveAuthorizationInteraction(context.Background(), interaction, AuthorizationDecision{
		Scopes: []string{"records.read"}, Lifetime: time.Minute,
	})
	if !errors.Is(err, ErrMissionConflict) {
		t.Fatalf("approval after mission update = %v, want %v", err, ErrMissionConflict)
	}
	snapshot, err := fixture.store.LoadPendingAuthorization(context.Background(), reference, fixture.protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != AuthorizationPollInteracting || fixture.protocol.tokenIDCalls() != 0 {
		t.Fatalf("stale host decision changed authorization: state=%v token_ids=%d", snapshot.State, fixture.protocol.tokenIDCalls())
	}
}

func TestMissionDeferredAuthorizationRejectsUpdateCommittedBeforeAuthorizationTransaction(t *testing.T) {
	fixture := newMissionDeferredAuthorizationFixture(t)
	pendingResponse := fixture.protocol.exchange(t, fixture.server, []string{"interaction"})
	if pendingResponse.Code != http.StatusAccepted {
		t.Fatalf("mission authorization exchange = %d %s", pendingResponse.Code, pendingResponse.Body.String())
	}
	requirement, err := aauth.ParseInteractionRequirement(pendingResponse.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, fixture.protocol.interactionURL+"/")
	interaction, err := fixture.server.ConsumeAuthorizationInteractionCode(
		context.Background(), reference, requirement.Code,
	)
	if err != nil {
		t.Fatal(err)
	}

	transitionEntered := make(chan struct{})
	releaseTransition := make(chan struct{})
	fixture.store.beforeTransition = func(name string) {
		if name != "approve" {
			return
		}
		close(transitionEntered)
		<-releaseTransition
	}
	approvalResult := make(chan error, 1)
	go func() {
		approvalResult <- fixture.server.ApproveAuthorizationInteraction(
			context.Background(), interaction, AuthorizationDecision{
				Scopes: []string{"records.read"}, Lifetime: time.Minute,
			},
		)
	}()
	<-transitionEntered

	update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{
		Action: "update", Description: "Adopt the concurrently approved destination.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.AppendMissionUpdate(
		context.Background(), fixture.mission, fixture.protocol.now, update,
	); err != nil {
		t.Fatal(err)
	}
	close(releaseTransition)
	if err := <-approvalResult; !errors.Is(err, ErrMissionConflict) {
		t.Fatalf("approval racing mission update = %v, want %v", err, ErrMissionConflict)
	}

	snapshot, err := fixture.store.LoadPendingAuthorization(context.Background(), reference, fixture.protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != AuthorizationPollInteracting {
		t.Fatalf("racing mission update let authorization transition land: state=%v", snapshot.State)
	}
	fixture.store.memoryMissionStore.mu.Lock()
	authTokens := len(fixture.store.memoryMissionStore.authTokens)
	fixture.store.memoryMissionStore.mu.Unlock()
	if authTokens != 0 {
		t.Fatalf("racing mission update retained %d auth tokens", authTokens)
	}
}

func TestMissionDeferredAuthorizationSerializesUpdateAfterApprovalTransactionBegins(t *testing.T) {
	fixture := newMissionDeferredAuthorizationFixture(t)
	pendingResponse := fixture.protocol.exchange(t, fixture.server, []string{"interaction"})
	if pendingResponse.Code != http.StatusAccepted {
		t.Fatalf("mission authorization exchange = %d %s", pendingResponse.Code, pendingResponse.Body.String())
	}
	requirement, err := aauth.ParseInteractionRequirement(pendingResponse.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, fixture.protocol.interactionURL+"/")
	interaction, err := fixture.server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}

	missionChecked := make(chan struct{})
	releaseApproval := make(chan struct{})
	fixture.store.afterMissionCheck = func(name string) {
		if name == "approve" {
			close(missionChecked)
			<-releaseApproval
		}
	}
	approvalResult := make(chan error, 1)
	go func() {
		approvalResult <- fixture.server.ApproveAuthorizationInteraction(
			context.Background(), interaction,
			AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute},
		)
	}()
	<-missionChecked

	update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{
		Action: "update", Description: "Apply immediately after the authorization decision.",
	})
	if err != nil {
		t.Fatal(err)
	}
	updateResult := make(chan error, 1)
	go func() {
		_, updateErr := fixture.store.AppendMissionUpdate(
			context.Background(), fixture.mission, fixture.protocol.now, update,
		)
		updateResult <- updateErr
	}()
	select {
	case updateErr := <-updateResult:
		t.Fatalf("mission update crossed active approval transaction: %v", updateErr)
	default:
	}
	close(releaseApproval)
	if err := <-approvalResult; err != nil {
		t.Fatalf("serialized approval = %v", err)
	}
	if err := <-updateResult; err != nil {
		t.Fatalf("serialized mission update = %v", err)
	}
	snapshot, err := fixture.store.LoadPendingAuthorization(context.Background(), reference, fixture.protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != AuthorizationPollApproved {
		t.Fatalf("serialized approval state = %v", snapshot.State)
	}
}

func TestMissionDeferredAuthorizationRefusesTerminalDeliveryAfterTermination(t *testing.T) {
	fixture := newMissionDeferredAuthorizationFixture(t)
	begin, err := fixture.reader.BeginExchange(context.Background(), clientagent.ExchangeRequest{
		PersonServer: fixture.protocol.personServerID, ResourceToken: fixture.protocol.resourceToken,
		PresentedToken: fixture.presentedToken,
		Capabilities:   []string{"interaction"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := begin.Pending()
	if !ok {
		t.Fatalf("mission authorization BeginExchange = %#v", begin)
	}
	reference := strings.TrimPrefix(pending.InteractionURL(), fixture.protocol.interactionURL+"/")
	interaction, err := fixture.server.ConsumeAuthorizationInteractionCode(
		context.Background(), reference, pending.InteractionCode(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.server.ApproveAuthorizationInteraction(context.Background(), interaction, AuthorizationDecision{
		Scopes: []string{"records.read"}, Lifetime: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}

	fixture.store.terminateMission(fixture.mission.Agent, fixture.mission.S256, "revoked")
	polled, err := fixture.reader.PollExchange(context.Background(), pending)
	if token, present := polled.Token(); present || token != "" {
		t.Fatalf("terminated mission released token %q", token)
	}
	var problem *aauth.ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Code != "mission_terminated" ||
		problem.MissionStatus != "terminated" || problem.TerminationReason != "revoked" {
		t.Fatalf("terminated mission poll = %T %#v", err, err)
	}

	snapshot, err := fixture.store.LoadPendingAuthorization(context.Background(), reference, fixture.protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != AuthorizationPollApproved || fixture.store.consumeCalls != 0 {
		t.Fatalf("terminated mission delivered or consumed result: state=%v consumes=%d", snapshot.State, fixture.store.consumeCalls)
	}
}

func TestMissionDeferredAuthorizationDeliversApprovedTokenAfterMissionUpdate(t *testing.T) {
	fixture := newMissionDeferredAuthorizationFixture(t)
	begin, err := fixture.reader.BeginExchange(context.Background(), clientagent.ExchangeRequest{
		PersonServer: fixture.protocol.personServerID, ResourceToken: fixture.protocol.resourceToken,
		PresentedToken: fixture.presentedToken,
		Capabilities:   []string{"interaction"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := begin.Pending()
	if !ok || pending.InteractionCode() == "" {
		t.Fatalf("mission authorization BeginExchange = %#v, pending=%t", begin, ok)
	}
	reference := strings.TrimPrefix(pending.InteractionURL(), fixture.protocol.interactionURL+"/")
	interaction, err := fixture.server.ConsumeAuthorizationInteractionCode(
		context.Background(), reference, pending.InteractionCode(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.server.ApproveAuthorizationInteraction(context.Background(), interaction, AuthorizationDecision{
		Scopes: []string{"records.read"}, Lifetime: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}

	update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{
		Action: "update", Description: "Use the replacement approved delivery channel.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.AppendMissionUpdate(
		context.Background(), fixture.mission, fixture.protocol.now, update,
	); err != nil {
		t.Fatal(err)
	}

	polled, err := fixture.reader.PollExchange(context.Background(), pending)
	if err != nil {
		t.Fatal(err)
	}
	token, ok := polled.Token()
	if !ok || token == "" {
		t.Fatalf("poll after accepted mission update = %#v", polled)
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), token, fixture.protocol.resolver, fixture.protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.MissionS256 != fixture.mission.S256 {
		t.Fatalf("updated-mission token = %#v", claims)
	}
	snapshot, err := fixture.store.LoadPendingAuthorization(context.Background(), reference, fixture.protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != AuthorizationPollGone || fixture.store.consumeCalls != 1 {
		t.Fatalf("updated mission delivery: state=%v consumes=%d", snapshot.State, fixture.store.consumeCalls)
	}
	fixture.store.memoryMissionStore.mu.Lock()
	retainedTokens := len(fixture.store.memoryMissionStore.authTokens)
	fixture.store.memoryMissionStore.mu.Unlock()
	if retainedTokens != 1 {
		t.Fatalf("approved token retention = %d, want 1 delivered token", retainedTokens)
	}
}

func TestMissionDeferredAuthorizationUpdateBetweenReadAndPollStillDelivers(t *testing.T) {
	fixture := newMissionDeferredAuthorizationFixture(t)
	pending, reference := approveMissionDeferredAuthorization(t, &fixture)

	pollEntered := make(chan struct{})
	releasePoll := make(chan struct{})
	fixture.store.beforeTransition = func(name string) {
		if name == "poll" {
			close(pollEntered)
			<-releasePoll
		}
	}
	type pollResult struct {
		result clientagent.ExchangeResult
		err    error
	}
	result := make(chan pollResult, 1)
	go func() {
		polled, pollErr := fixture.reader.PollExchange(context.Background(), pending)
		result <- pollResult{result: polled, err: pollErr}
	}()
	<-pollEntered
	appendMissionDeferredUpdate(t, &fixture, "Update committed after the handler read the mission.")
	close(releasePoll)
	polled := <-result
	if polled.err != nil {
		t.Fatal(polled.err)
	}
	if token, ok := polled.result.Token(); !ok || token == "" {
		t.Fatalf("read-to-poll update result = %#v", polled.result)
	}
	assertMissionDeferredConsumed(t, &fixture, reference)
}

func TestMissionDeferredAuthorizationUpdateBetweenPollAndConsumeStillDelivers(t *testing.T) {
	fixture := newMissionDeferredAuthorizationFixture(t)
	pending, reference := approveMissionDeferredAuthorization(t, &fixture)

	pollComplete := make(chan struct{})
	releaseConsume := make(chan struct{})
	fixture.store.afterTransition = func(name string) {
		if name == "poll" {
			close(pollComplete)
			<-releaseConsume
		}
	}
	type pollResult struct {
		result clientagent.ExchangeResult
		err    error
	}
	result := make(chan pollResult, 1)
	go func() {
		polled, pollErr := fixture.reader.PollExchange(context.Background(), pending)
		result <- pollResult{result: polled, err: pollErr}
	}()
	<-pollComplete
	appendMissionDeferredUpdate(t, &fixture, "Update committed after poll and before terminal consume.")
	close(releaseConsume)
	polled := <-result
	if polled.err != nil {
		t.Fatal(polled.err)
	}
	if token, ok := polled.result.Token(); !ok || token == "" {
		t.Fatalf("poll-to-consume update result = %#v", polled.result)
	}
	assertMissionDeferredConsumed(t, &fixture, reference)
}

func approveMissionDeferredAuthorization(
	t *testing.T,
	fixture *missionDeferredAuthorizationFixture,
) (clientagent.PendingExchange, string) {
	t.Helper()
	begin, err := fixture.reader.BeginExchange(context.Background(), clientagent.ExchangeRequest{
		PersonServer: fixture.protocol.personServerID, ResourceToken: fixture.protocol.resourceToken,
		PresentedToken: fixture.presentedToken,
		Capabilities:   []string{"interaction"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := begin.Pending()
	if !ok || pending.InteractionCode() == "" {
		t.Fatalf("mission authorization BeginExchange = %#v", begin)
	}
	reference := strings.TrimPrefix(pending.InteractionURL(), fixture.protocol.interactionURL+"/")
	interaction, err := fixture.server.ConsumeAuthorizationInteractionCode(
		context.Background(), reference, pending.InteractionCode(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.server.ApproveAuthorizationInteraction(context.Background(), interaction, AuthorizationDecision{
		Scopes: []string{"records.read"}, Lifetime: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	return pending, reference
}

func appendMissionDeferredUpdate(t *testing.T, fixture *missionDeferredAuthorizationFixture, description string) {
	t.Helper()
	update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{Action: "update", Description: description})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.AppendMissionUpdate(
		context.Background(), fixture.mission, fixture.protocol.now, update,
	); err != nil {
		t.Fatal(err)
	}
}

func assertMissionDeferredConsumed(t *testing.T, fixture *missionDeferredAuthorizationFixture, reference string) {
	t.Helper()
	snapshot, err := fixture.store.LoadPendingAuthorization(context.Background(), reference, fixture.protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != AuthorizationPollGone || fixture.store.consumeCalls != 1 {
		t.Fatalf("mission result was not consumed: state=%v consumes=%d", snapshot.State, fixture.store.consumeCalls)
	}
}

func TestMissionlessDeferredAuthorizationRemainsUnbound(t *testing.T) {
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMemoryDeferredAuthorizationStore()
	server := protocol.newServer(t, store)
	pendingResponse := protocol.exchange(t, server, []string{"interaction"})
	if pendingResponse.Code != http.StatusAccepted {
		t.Fatalf("missionless authorization exchange = %d %s", pendingResponse.Code, pendingResponse.Body.String())
	}
	requirement, err := aauth.ParseInteractionRequirement(pendingResponse.Header().Values("AAuth-Requirement"))
	if err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(requirement.URL, protocol.interactionURL+"/")
	interaction, err := server.ConsumeAuthorizationInteractionCode(context.Background(), reference, requirement.Code)
	if err != nil {
		t.Fatal(err)
	}
	if mission, ok := interaction.Mission(); ok {
		t.Fatalf("missionless host handle carried mission: %#v, present=%t", mission, ok)
	}
	if err := server.ApproveAuthorizationInteraction(context.Background(), interaction, AuthorizationDecision{
		Scopes: []string{"records.read"}, Lifetime: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	approved := protocol.poll(t, server, pendingResponse.Header().Get("Location"), protocol.agentKey, protocol.agentToken)
	if approved.Code != http.StatusOK {
		t.Fatalf("missionless authorization terminal poll = %d %s", approved.Code, approved.Body.String())
	}
	var result struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(approved.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAuthToken(context.Background(), result.AuthToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.MissionS256 != "" {
		t.Fatalf("missionless auth token mission_s256 = %q", claims.MissionS256)
	}
}

type missionDeferredAuthorizationFixture struct {
	protocol *authorizationInteractionProtocol
	store    *missionDeferredAuthorizationTestStore
	server   *Server
	reader   *clientagent.Client
	mission  MissionRecord
	// presentedToken is the Person token the retained record describes.
	presentedToken string
}

func newMissionDeferredAuthorizationFixture(t *testing.T) missionDeferredAuthorizationFixture {
	t.Helper()
	protocol := newAuthorizationInteractionProtocol(t)
	store := newMissionDeferredAuthorizationTestStore()
	expiresAt := protocol.now.Add(90 * time.Second)
	approved, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: protocol.personServerID, Agent: protocol.agentID,
		ApprovedAt: protocol.now.Add(-time.Minute), ExpiresAt: &expiresAt,
		Description: "Prepare and publish the reviewed report.",
	})
	if err != nil {
		t.Fatal(err)
	}
	update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{
		Action: "update", Description: "Include only the already reviewed appendix.",
	})
	if err != nil {
		t.Fatal(err)
	}
	mission := MissionRecord{
		S256: approved.S256, Agent: protocol.agentID, ExactJSON: approved.ExactJSON,
		ApprovedAt: approved.Blob.ApprovedAt, ExpiresAt: expiresAt,
		Capabilities: []string{"interaction", "clarification"}, State: MissionActive,
		AcceptedUpdates: []MissionUpdateRecord{{
			Document: update, AcceptedAt: protocol.now.Add(-30 * time.Second),
		}},
	}
	person := directPersonTokenRecord(
		"authorization-person-token", protocol.personServerID, protocol.resourceID,
		protocol.subject, protocol.tenant, protocol.providerID, protocol.agentID,
		protocol.agentKey.PublicJWK(), expiresAt, expiresAt.Add(5*time.Minute),
	)
	person.MissionS256 = mission.S256
	if err := store.CommitMission(context.Background(), mission, []PersonTokenRecord{person}); err != nil {
		t.Fatal(err)
	}
	thumbprint, err := protocol.agentKey.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	protocol.resourceToken, err = aauth.MintResourceToken(protocol.resourceKey, aauth.ResourceTokenClaims{
		Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument, Audience: protocol.personServerID,
		JTI: "authorization-resource-token", PersonServer: protocol.personServerID, Subject: protocol.subject,
		PresentedJTI: person.JTI, AgentJKT: thumbprint, IssuedAt: protocol.now.Unix(), ExpiresAt: expiresAt.Unix(),
		Scope: "records.read records.write", MissionS256: mission.S256, Tenant: protocol.tenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	config := PSAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: protocol.nextTokenID, Tokens: store, Missions: permissionMissionConfig(),
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) { return Person{}, nil },
		Authorize: func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
			protocol.authorizeCalls++
			protocol.lastAuthorization = request
			return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: 10 * time.Minute}, nil
		},
		RequireAuthorizationInteraction: func(_ context.Context, request AuthorizationRequest) (AuthorizationInteractionPolicy, bool, error) {
			protocol.policyCalls++
			protocol.lastAuthorization = request
			protocol.requestCapabilities = append([]string(nil), request.Capabilities...)
			return AuthorizationInteractionPolicy{
				URL: protocol.interactionURL, Lifetime: 4 * time.Minute, RetryAfter: 3 * time.Second,
			}, true, nil
		},
	}
	server, err := NewPSAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := clientagent.New(context.Background(), clientagent.Config{
		Identifier: protocol.agentID, SigningKey: protocol.agentKey, AgentToken: protocol.agentToken,
		KeyResolver: protocol.resolver,
		HTTPClient:  &http.Client{Transport: missionDeferredAuthorizationRoundTripper{handler: server.Handler()}},
		Clock:       protocol.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return missionDeferredAuthorizationFixture{
		protocol: protocol, store: store, server: server, reader: reader, mission: cloneMissionRecord(mission),
		presentedToken: testPresentedPersonToken(
			t, protocol.personKey, protocol.resourceToken, protocol.agentKey.PublicJWK(), protocol.now, expiresAt,
		),
	}
}

type missionDeferredAuthorizationRoundTripper struct {
	handler http.Handler
}

func (transport missionDeferredAuthorizationRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	response := httptest.NewRecorder()
	transport.handler.ServeHTTP(response, request)
	result := response.Result()
	result.Request = request
	return result, nil
}

func assertMissionDeferredAuthorizationContext(t *testing.T, got *MissionContext, want MissionRecord) {
	t.Helper()
	if got == nil || got.S256 != want.S256 || !strings.Contains(got.Blob.Description, "reviewed report") ||
		string(got.ExactJSON) != string(want.ExactJSON) || len(got.AcceptedUpdates) != len(want.AcceptedUpdates) {
		t.Fatalf("mission authorization context = %#v, want %#v", got, want)
	}
	for index := range want.AcceptedUpdates {
		if !equalMissionUpdateRecord(got.AcceptedUpdates[index], want.AcceptedUpdates[index]) {
			t.Fatalf("mission authorization update %d = %#v, want %#v", index, got.AcceptedUpdates[index], want.AcceptedUpdates[index])
		}
	}
}

type missionAuthorizationTransition struct {
	name    string
	mission MissionRecord
}

type missionDeferredAuthorizationTestStore struct {
	*memoryMissionStore
	*memoryDeferredAuthorizationStore
	txMu              sync.Mutex
	beforeTransition  func(string)
	afterMissionCheck func(string)
	afterTransition   func(string)
	observedMu        sync.Mutex
	observed          []missionAuthorizationTransition
}

func newMissionDeferredAuthorizationTestStore() *missionDeferredAuthorizationTestStore {
	return &missionDeferredAuthorizationTestStore{
		memoryMissionStore:               newMemoryMissionStore(),
		memoryDeferredAuthorizationStore: newMemoryDeferredAuthorizationStore(),
	}
}

func (store *missionDeferredAuthorizationTestStore) observeActiveMission(
	name string,
	expected MissionRecord,
	at time.Time,
) error {
	store.memoryMissionStore.mu.Lock()
	err := store.memoryMissionStore.requireActiveMissionLocked(expected, at)
	store.memoryMissionStore.mu.Unlock()
	if err != nil {
		return err
	}
	store.observedMu.Lock()
	store.observed = append(store.observed, missionAuthorizationTransition{
		name: name, mission: cloneMissionRecord(expected),
	})
	store.observedMu.Unlock()
	if store.afterMissionCheck != nil {
		store.afterMissionCheck(name)
	}
	return nil
}

func (store *missionDeferredAuthorizationTestStore) observeStableActiveMission(
	name string,
	expected MissionRecord,
	at time.Time,
) error {
	store.memoryMissionStore.mu.Lock()
	key := expected.Agent + "\x00" + expected.S256
	current, exists := store.memoryMissionStore.missions[key]
	if !exists {
		store.memoryMissionStore.mu.Unlock()
		return ErrMissionNotFound
	}
	if current.State == MissionActive && !current.ExpiresAt.IsZero() && !at.Before(current.ExpiresAt) {
		current.State = MissionTerminated
		current.TerminationReason = "expired"
		store.memoryMissionStore.missions[key] = cloneMissionRecord(current)
	}
	store.memoryMissionStore.mu.Unlock()
	if current.State == MissionTerminated {
		return &MissionTerminatedError{TerminationReason: current.TerminationReason}
	}
	store.observedMu.Lock()
	store.observed = append(store.observed, missionAuthorizationTransition{
		name: name, mission: cloneMissionRecord(current),
	})
	store.observedMu.Unlock()
	return nil
}

func (store *missionDeferredAuthorizationTestStore) beginMissionAuthorizationTransition(name string) {
	if store.beforeTransition != nil {
		store.beforeTransition(name)
	}
	store.txMu.Lock()
}

func (store *missionDeferredAuthorizationTestStore) endMissionAuthorizationTransition() {
	store.txMu.Unlock()
}

func (store *missionDeferredAuthorizationTestStore) CreateMissionPendingAuthorization(
	ctx context.Context,
	expected MissionRecord,
	record PendingAuthorizationRecord,
	at time.Time,
) error {
	store.beginMissionAuthorizationTransition("create")
	defer store.endMissionAuthorizationTransition()
	if record.MissionS256 != expected.S256 || !record.MissionExpiresAt.Equal(expected.ExpiresAt) {
		return ErrMissionConflict
	}
	if err := store.observeActiveMission("create", expected, at); err != nil {
		return err
	}
	return store.CreatePendingAuthorization(ctx, record)
}

func (store *missionDeferredAuthorizationTestStore) ApproveMissionPendingAuthorization(
	ctx context.Context,
	expected MissionRecord,
	id string,
	approval AuthorizationApproval,
	issued IssuedAuthTokenRecord,
	at time.Time,
) (AuthorizationApproval, error) {
	store.beginMissionAuthorizationTransition("approve")
	defer store.endMissionAuthorizationTransition()
	if issued.MissionS256 != expected.S256 {
		return AuthorizationApproval{}, ErrMissionConflict
	}
	if err := store.observeActiveMission("approve", expected, at); err != nil {
		return AuthorizationApproval{}, err
	}
	store.memoryMissionStore.mu.Lock()
	key := issued.Reference.Issuer + "\x00" + issued.Reference.JTI
	if _, exists := store.memoryMissionStore.authTokens[key]; exists {
		store.memoryMissionStore.mu.Unlock()
		return AuthorizationApproval{}, errors.New("auth token already exists")
	}
	store.memoryMissionStore.mu.Unlock()
	canonical, err := store.ApprovePendingAuthorization(ctx, id, approval)
	if err != nil {
		return AuthorizationApproval{}, err
	}
	store.memoryMissionStore.mu.Lock()
	store.memoryMissionStore.authTokens[key] = issued
	store.memoryMissionStore.mu.Unlock()
	return canonical, nil
}

func (store *missionDeferredAuthorizationTestStore) DenyMissionPendingAuthorization(
	ctx context.Context, expected MissionRecord, id string, at time.Time,
) error {
	store.beginMissionAuthorizationTransition("deny")
	defer store.endMissionAuthorizationTransition()
	if err := store.observeActiveMission("deny", expected, at); err != nil {
		return err
	}
	return store.DenyPendingAuthorization(ctx, id, at)
}

func (store *missionDeferredAuthorizationTestStore) AbandonMissionPendingAuthorization(
	ctx context.Context, expected MissionRecord, id string, at time.Time,
) error {
	store.beginMissionAuthorizationTransition("abandon")
	defer store.endMissionAuthorizationTransition()
	if err := store.observeActiveMission("abandon", expected, at); err != nil {
		return err
	}
	return store.AbandonPendingAuthorization(ctx, id, at)
}

func (store *missionDeferredAuthorizationTestStore) FailMissionPendingAuthorization(
	ctx context.Context, expected MissionRecord, id string, at time.Time,
) error {
	store.beginMissionAuthorizationTransition("fail")
	defer store.endMissionAuthorizationTransition()
	if err := store.observeActiveMission("fail", expected, at); err != nil {
		return err
	}
	return store.FailPendingAuthorization(ctx, id, at)
}

func (store *missionDeferredAuthorizationTestStore) PollMissionPendingAuthorization(
	ctx context.Context,
	expected MissionRecord,
	id string,
	identity AuthorizationPollIdentity,
	at time.Time,
) (AuthorizationPollRecord, error) {
	store.beginMissionAuthorizationTransition("poll")
	if err := store.observeStableActiveMission("poll", expected, at); err != nil {
		store.endMissionAuthorizationTransition()
		return AuthorizationPollRecord{}, err
	}
	result, err := store.PollPendingAuthorization(ctx, id, identity, at)
	store.endMissionAuthorizationTransition()
	if store.afterTransition != nil {
		store.afterTransition("poll")
	}
	return result, err
}

func (store *missionDeferredAuthorizationTestStore) ConsumeMissionPendingAuthorizationResult(
	ctx context.Context,
	expected MissionRecord,
	id string,
	result AuthorizationPollRecord,
	at time.Time,
) error {
	store.beginMissionAuthorizationTransition("consume")
	defer store.endMissionAuthorizationTransition()
	if err := store.observeStableActiveMission("consume", expected, at); err != nil {
		return err
	}
	return store.ConsumePendingAuthorizationResult(ctx, id, result)
}

func (store *missionDeferredAuthorizationTestStore) RequestMissionPendingAuthorizationClarification(
	ctx context.Context,
	expected MissionRecord,
	id string,
	request AuthorizationClarificationRequest,
	at time.Time,
) (AuthorizationClarificationRound, error) {
	store.beginMissionAuthorizationTransition("clarification")
	defer store.endMissionAuthorizationTransition()
	if err := store.observeActiveMission("clarification", expected, at); err != nil {
		return AuthorizationClarificationRound{}, err
	}
	return store.RequestPendingAuthorizationClarification(ctx, id, request, at)
}

func (store *missionDeferredAuthorizationTestStore) AnswerMissionPendingAuthorizationClarification(
	ctx context.Context,
	expected MissionRecord,
	id string,
	identity AuthorizationPollIdentity,
	answer string,
	at time.Time,
) error {
	store.beginMissionAuthorizationTransition("answer")
	defer store.endMissionAuthorizationTransition()
	if err := store.observeActiveMission("answer", expected, at); err != nil {
		return err
	}
	return store.AnswerPendingAuthorizationClarification(ctx, id, identity, answer, at)
}

func (store *missionDeferredAuthorizationTestStore) CancelMissionPendingAuthorizationClarification(
	ctx context.Context,
	expected MissionRecord,
	id string,
	identity AuthorizationPollIdentity,
	at time.Time,
) error {
	store.beginMissionAuthorizationTransition("cancel")
	defer store.endMissionAuthorizationTransition()
	if err := store.observeActiveMission("cancel", expected, at); err != nil {
		return err
	}
	return store.CancelPendingAuthorizationClarification(ctx, id, identity, at)
}

func (store *missionDeferredAuthorizationTestStore) AppendMissionUpdate(
	ctx context.Context,
	expected MissionRecord,
	acceptedAt time.Time,
	document aauth.MissionUpdateDocument,
) (MissionRecord, error) {
	store.txMu.Lock()
	defer store.txMu.Unlock()
	return store.memoryMissionStore.AppendMissionUpdate(ctx, expected, acceptedAt, document)
}

func (store *missionDeferredAuthorizationTestStore) terminateMission(agent, s256, reason string) {
	store.txMu.Lock()
	defer store.txMu.Unlock()
	store.memoryMissionStore.terminateMission(agent, s256, reason)
}

func (store *missionDeferredAuthorizationTestStore) requireTransitions(t *testing.T, names ...string) {
	t.Helper()
	store.observedMu.Lock()
	observed := append([]missionAuthorizationTransition(nil), store.observed...)
	store.observedMu.Unlock()
	for _, name := range names {
		found := false
		for _, transition := range observed {
			if transition.name == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("mission transition %q was not used; observed=%#v", name, observed)
		}
	}
	for _, transition := range observed {
		if !transition.mission.Equal(store.missionForObservation(t)) {
			t.Fatalf("mission transition %q used changed context: %#v", transition.name, transition.mission)
		}
	}
}

func (store *missionDeferredAuthorizationTestStore) missionForObservation(t *testing.T) MissionRecord {
	t.Helper()
	store.memoryMissionStore.mu.Lock()
	defer store.memoryMissionStore.mu.Unlock()
	if len(store.memoryMissionStore.missions) != 1 {
		t.Fatalf("missions = %d", len(store.memoryMissionStore.missions))
	}
	for _, mission := range store.memoryMissionStore.missions {
		return cloneMissionRecord(mission)
	}
	panic("unreachable")
}

var (
	_ MissionDeferredAuthorizationStore      = (*missionDeferredAuthorizationTestStore)(nil)
	_ MissionAuthorizationClarificationStore = (*missionDeferredAuthorizationTestStore)(nil)
)
