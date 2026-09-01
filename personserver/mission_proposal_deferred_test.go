package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestMissionProposalStatesHaveStableDurableNames(t *testing.T) {
	t.Parallel()

	states := map[MissionProposalState]string{
		MissionProposalPending: "pending", MissionProposalApproved: "approved",
		MissionProposalDenied: "denied", MissionProposalExpired: "expired",
	}
	if len(states) != 4 {
		t.Fatalf("mission proposal states = %#v", states)
	}
	for state, want := range states {
		if string(state) != want {
			t.Fatalf("mission proposal state = %q, want %q", state, want)
		}
	}
}

func TestDeferredMissionProposalRetainsExactVerifiedProposalBefore202(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	store := &missionProposalCaptureStore{
		memoryMissionStore: protocol.store,
		proposals:          make(map[string]MissionProposalSnapshot),
	}
	immediateApprovalCalls := 0
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, Tokens: store, NewID: func() string { return "unused-token-id" },
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{Subject: "person-123", Lifetime: time.Hour}, nil
		},
		Authorize: func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: request.Scopes, Lifetime: time.Minute}, nil
		},
		Missions: &MissionConfig{
			Approve: func(context.Context, MissionApprovalRequest) (MissionDecision, error) {
				immediateApprovalCalls++
				return MissionDecision{}, errors.New("immediate approval must not run")
			},
			DeferProposal: func(context.Context, MissionApprovalRequest) (MissionProposalPendingPolicy, bool, error) {
				return MissionProposalPendingPolicy{Lifetime: 10 * time.Minute, RetryAfter: 3 * time.Second}, true, nil
			},
			AcceptUpdate:                    func(context.Context, MissionUpdatePolicyRequest) error { return nil },
			ConfirmPersonAcceptedCompletion: func(context.Context, MissionCompletionPolicyRequest) error { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	exact := []byte("{\n  \"description\": \"Read records\",\n  \"resources\": [\"https://resource.example\"],\n  \"extension\": {\"purpose\": \"test\"}\n}\n")
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/mission", bytes.NewReader(exact))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Retry-After") != "3" {
		t.Fatalf("deferred mission proposal = %d, headers=%v, body=%s", response.Code, response.Header(), response.Body.String())
	}
	requirement, err := aauth.ParseRequirement(response.Header().Values("AAuth-Requirement"))
	if err != nil || requirement != aauth.RequirementApproval {
		t.Fatalf("mission proposal requirement = %q, %v", requirement, err)
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Status != "pending" {
		t.Fatalf("deferred mission body = %#v, %v", body, err)
	}
	location := response.Header().Get("Location")
	if !strings.HasPrefix(location, "/mission/pending/") {
		t.Fatalf("mission proposal Location = %q", location)
	}
	reference := strings.TrimPrefix(location, "/mission/pending/")
	if len(reference) < 20 {
		t.Fatalf("mission proposal reference is not unguessable: %q", reference)
	}

	snapshot, err := store.LoadMissionProposal(context.Background(), reference, protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	record := snapshot.Record
	var parsed aauth.MissionProposal
	if err := json.Unmarshal(record.ExactJSON, &parsed); err != nil {
		t.Fatal(err)
	}
	if snapshot.State != MissionProposalPending || record.ID != reference || record.PersonServer != protocol.personServerID ||
		record.AgentProvider != protocol.agentProviderID || record.Agent != protocol.agentID ||
		!record.Confirmation.Equal(protocol.agentKey.PublicJWK()) || !record.CreatedAt.Equal(protocol.now) ||
		!record.ExpiresAt.Equal(protocol.now.Add(10*time.Minute)) || record.RetryAfter != 3*time.Second ||
		!bytes.Equal(record.ExactJSON, exact) || parsed.Description != "Read records" ||
		len(parsed.Resources) != 1 || parsed.Resources[0] != protocol.resourceID {
		t.Fatalf("retained mission proposal = %#v", snapshot)
	}
	record.ExactJSON[0] ^= 0xff
	record.Confirmation.Kid = "changed"
	reloaded, err := store.LoadMissionProposal(context.Background(), reference, protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reloaded.Record.ExactJSON, exact) ||
		!reloaded.Record.Confirmation.Equal(protocol.agentKey.PublicJWK()) {
		t.Fatalf("caller mutated retained mission proposal: %#v", reloaded.Record)
	}
	store.memoryMissionStore.mu.Lock()
	missionCount := len(store.memoryMissionStore.missions)
	tokenCount := len(store.memoryMissionStore.records)
	store.memoryMissionStore.mu.Unlock()
	if immediateApprovalCalls != 0 || missionCount != 0 || tokenCount != 0 {
		t.Fatalf("deferred proposal released consequences: approvals=%d missions=%d tokens=%d", immediateApprovalCalls, missionCount, tokenCount)
	}
}

func TestDeferredMissionProposalHostApprovalCommitsMissionAndTokensAtomically(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	store := &missionProposalCaptureStore{
		memoryMissionStore: protocol.store,
		proposals:          make(map[string]MissionProposalSnapshot),
	}
	newServer := func() *Server {
		t.Helper()
		server, err := NewPSAuthorization(PSAuthorizationConfig{
			Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
			Clock: protocol.clock, Tokens: store, NewID: func() string { return "deferred-mission-person-token" },
			BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
				return Person{Subject: "person-123", Lifetime: time.Hour}, nil
			},
			Authorize: func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
				return AuthorizationDecision{Scopes: request.Scopes, Lifetime: time.Minute}, nil
			},
			Missions: &MissionConfig{
				Approve: func(context.Context, MissionApprovalRequest) (MissionDecision, error) {
					return MissionDecision{}, errors.New("immediate approval must not run")
				},
				DeferProposal: func(context.Context, MissionApprovalRequest) (MissionProposalPendingPolicy, bool, error) {
					return MissionProposalPendingPolicy{Lifetime: 10 * time.Minute, RetryAfter: time.Second}, true, nil
				},
				AcceptUpdate:                    func(context.Context, MissionUpdatePolicyRequest) error { return nil },
				ConfirmPersonAcceptedCompletion: func(context.Context, MissionCompletionPolicyRequest) error { return nil },
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}

	exact := []byte(`{"description":"Read records","resources":["https://resource.example"]}`)
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/mission", bytes.NewReader(exact))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	newServer().Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("deferred mission proposal = %d %s", response.Code, response.Body.String())
	}
	reference := strings.TrimPrefix(response.Header().Get("Location"), "/mission/pending/")

	// A recomposed server proves the host decision depends on retained state,
	// not the process that accepted the Agent's proposal.
	recomposed := newServer()
	review, err := recomposed.ResumeMissionProposal(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if review.Reference() != reference || review.Agent() != protocol.agentID ||
		review.Proposal().Description != "Read records" || !bytes.Equal(review.ExactJSON(), exact) {
		t.Fatalf("resumed mission proposal = %#v", review)
	}
	expiresAt := protocol.now.Add(20 * time.Minute)
	decision := MissionDecision{
		Description: "Read the approved records", ApprovedResources: []string{protocol.resourceID},
		ExpiresAt: &expiresAt, Capabilities: []string{"interaction"},
	}
	if err := recomposed.ApproveMissionProposal(context.Background(), review, decision); err != nil {
		t.Fatal(err)
	}

	snapshot, err := store.LoadMissionProposal(context.Background(), reference, protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != MissionProposalApproved || snapshot.Approval.Mission.S256 == "" ||
		!snapshot.DecidedAt.Equal(protocol.now) || snapshot.DeliveredAt.IsZero() == false {
		t.Fatalf("approved mission proposal = %#v", snapshot)
	}
	mission, err := store.LoadMissionForAgent(context.Background(), protocol.agentID, snapshot.Approval.Mission.S256, protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	if !mission.Equal(snapshot.Approval.Mission) || mission.State != MissionActive ||
		mission.ExpiresAt != expiresAt || len(snapshot.Approval.PersonTokens) != 1 ||
		snapshot.Approval.PersonTokens[protocol.resourceID] == "" || len(snapshot.Approval.PersonTokenRecords) != 1 {
		t.Fatalf("atomic mission approval = %#v", snapshot.Approval)
	}
	if err := recomposed.ApproveMissionProposal(context.Background(), review, decision); err != nil {
		t.Fatalf("same host approval replay = %v", err)
	}
	replayed, err := store.LoadMissionProposal(context.Background(), reference, protocol.now)
	if err != nil || replayed.Approval.Mission.S256 != snapshot.Approval.Mission.S256 ||
		replayed.Approval.PersonTokens[protocol.resourceID] != snapshot.Approval.PersonTokens[protocol.resourceID] {
		t.Fatalf("host approval replay changed canonical artifacts = %#v, %v", replayed.Approval, err)
	}
	record := snapshot.Approval.PersonTokenRecords[0]
	retainedToken, err := store.Load(context.Background(), record.PersonServer, record.JTI)
	if err != nil || retainedToken != record || record.MissionS256 != mission.S256 || record.Agent != protocol.agentID {
		t.Fatalf("retained mission person token = %#v, %v", retainedToken, err)
	}

	poll := func() *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, protocol.personServerID+"/mission/pending/"+reference, nil)
		if err := signaturekey.SignJWTRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		recomposed.Handler().ServeHTTP(response, request)
		return response
	}
	terminal := poll()
	if terminal.Code != http.StatusOK || terminal.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("mission proposal poll = %d, headers=%v, body=%s", terminal.Code, terminal.Header(), terminal.Body.String())
	}
	var wire aauth.MissionApproval
	if err := json.Unmarshal(terminal.Body.Bytes(), &wire); err != nil || wire.S256 != mission.S256 ||
		wire.PersonTokens[protocol.resourceID] == "" {
		t.Fatalf("mission proposal terminal response = %#v, %v", wire, err)
	}
	afterDelivery, err := store.LoadMissionProposal(context.Background(), reference, protocol.now)
	if err != nil || afterDelivery.DeliveredAt.IsZero() {
		t.Fatalf("mission proposal delivery = %#v, %v", afterDelivery, err)
	}
	again := poll()
	assertMissionProblem(t, again, http.StatusGone, "invalid_code", "", "")
}

func TestDeferredMissionProposalDenialIsRetainedAndTyped(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	store := &missionProposalCaptureStore{
		memoryMissionStore: protocol.store,
		proposals:          make(map[string]MissionProposalSnapshot),
	}
	server := newDeferredMissionProposalTestServer(t, protocol, store)
	reference := postDeferredMissionProposal(t, protocol, server, []byte(`{"description":"Do not approve this"}`))
	review, err := server.ResumeMissionProposal(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.DenyMissionProposal(context.Background(), review); err != nil {
		t.Fatal(err)
	}

	poll := func() *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, protocol.personServerID+"/mission/pending/"+reference, nil)
		if err := signaturekey.SignJWTRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	denied := poll()
	assertMissionProblem(t, denied, http.StatusForbidden, "denied", "", "")
	snapshot, err := store.LoadMissionProposal(context.Background(), reference, protocol.now)
	if err != nil || snapshot.State != MissionProposalDenied || snapshot.DecidedAt.IsZero() || snapshot.DeliveredAt.IsZero() {
		t.Fatalf("retained mission denial = %#v, %v", snapshot, err)
	}
	store.memoryMissionStore.mu.Lock()
	missionCount, tokenCount := len(store.memoryMissionStore.missions), len(store.memoryMissionStore.records)
	store.memoryMissionStore.mu.Unlock()
	if missionCount != 0 || tokenCount != 0 {
		t.Fatalf("denied mission proposal released missions=%d tokens=%d", missionCount, tokenCount)
	}
	assertMissionProblem(t, poll(), http.StatusGone, "invalid_code", "", "")
}

func TestDeferredMissionProposalApprovalExpiresBeforeDelivery(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	store := &missionProposalCaptureStore{
		memoryMissionStore: protocol.store,
		proposals:          make(map[string]MissionProposalSnapshot),
	}
	server := newDeferredMissionProposalTestServer(t, protocol, store)
	reference := postDeferredMissionProposal(t, protocol, server, []byte(`{"description":"Read records","resources":["https://resource.example"]}`))
	review, err := server.ResumeMissionProposal(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := protocol.now.Add(2 * time.Minute)
	if err := server.ApproveMissionProposal(context.Background(), review, MissionDecision{
		Description: review.Proposal().Description, ApprovedResources: []string{protocol.resourceID}, ExpiresAt: &expiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	protocol.now = expiresAt
	poll := func() *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, protocol.personServerID+"/mission/pending/"+reference, nil)
		if err := signaturekey.SignJWTRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	assertMissionProblem(t, poll(), http.StatusRequestTimeout, "expired", "", "")
	assertMissionProblem(t, poll(), http.StatusGone, "invalid_code", "", "")
	snapshot, err := store.LoadMissionProposal(context.Background(), reference, protocol.now)
	if err != nil || snapshot.State != MissionProposalExpired || snapshot.DeliveredAt.IsZero() || snapshot.Approval.Mission.S256 != "" {
		t.Fatalf("expired approved proposal = %#v, %v", snapshot, err)
	}
}

func TestDeferredMissionProposalPollCloaksAnotherAgentOrKey(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	store := &missionProposalCaptureStore{
		memoryMissionStore: protocol.store,
		proposals:          make(map[string]MissionProposalSnapshot),
	}
	server := newDeferredMissionProposalTestServer(t, protocol, store)
	reference := postDeferredMissionProposal(t, protocol, server, []byte(`{"description":"Read records"}`))
	otherKey := personServerTestKey(t, "other-deferred-mission-agent")
	otherToken, err := aauth.MintAgentToken(protocol.agentProviderID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:other@provider.example", PersonServer: protocol.personServerID,
		PublicKey: otherKey.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, "other-deferred-mission-token")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, protocol.personServerID+"/mission/pending/"+reference, nil)
	if err := signaturekey.SignJWTRequest(request, otherKey, otherToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	assertMissionProblem(t, response, http.StatusGone, "invalid_code", "", "")
	rotatedKey := personServerTestKey(t, "rotated-deferred-mission-agent")
	rotatedToken, err := aauth.MintAgentToken(protocol.agentProviderID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: protocol.agentID, PersonServer: protocol.personServerID,
		PublicKey: rotatedKey.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, "rotated-deferred-mission-token")
	if err != nil {
		t.Fatal(err)
	}
	rotatedPoll := httptest.NewRequest(http.MethodGet, protocol.personServerID+"/mission/pending/"+reference, nil)
	if err := signaturekey.SignJWTRequest(rotatedPoll, rotatedKey, rotatedToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	rotatedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(rotatedResponse, rotatedPoll)
	assertMissionProblem(t, rotatedResponse, http.StatusGone, "invalid_code", "", "")
	snapshot, err := store.LoadMissionProposal(context.Background(), reference, protocol.now)
	if err != nil || snapshot.State != MissionProposalPending || !snapshot.DeliveredAt.IsZero() {
		t.Fatalf("wrong Agent changed proposal = %#v, %v", snapshot, err)
	}
}

func TestDeferredMissionProposalDeadlineReturnsOneTypedExpiry(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	store := &missionProposalCaptureStore{
		memoryMissionStore: protocol.store,
		proposals:          make(map[string]MissionProposalSnapshot),
	}
	server := newDeferredMissionProposalTestServer(t, protocol, store)
	reference := postDeferredMissionProposal(t, protocol, server, []byte(`{"description":"Read records"}`))
	protocol.now = protocol.now.Add(10 * time.Minute)
	poll := func() *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, protocol.personServerID+"/mission/pending/"+reference, nil)
		if err := signaturekey.SignJWTRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	assertMissionProblem(t, poll(), http.StatusRequestTimeout, "expired", "", "")
	assertMissionProblem(t, poll(), http.StatusGone, "invalid_code", "", "")
	if _, err := server.ResumeMissionProposal(context.Background(), reference); !errors.Is(err, ErrMissionProposalExpired) {
		t.Fatalf("resume expired mission proposal error = %v", err)
	}
}

func TestDeferredMissionProposalConcurrentDifferentDecisionsHaveOneWinner(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	store := &missionProposalCaptureStore{
		memoryMissionStore: protocol.store,
		proposals:          make(map[string]MissionProposalSnapshot),
	}
	server := newDeferredMissionProposalTestServer(t, protocol, store)
	reference := postDeferredMissionProposal(t, protocol, server, []byte(`{"description":"Read records","resources":["https://resource.example"]}`))
	review, err := server.ResumeMissionProposal(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := protocol.now.Add(20 * time.Minute)
	decisions := []MissionDecision{
		{Description: "Read records A", ApprovedResources: []string{protocol.resourceID}, ExpiresAt: &expiresAt},
		{Description: "Read records B", ApprovedResources: []string{protocol.resourceID}, ExpiresAt: &expiresAt},
	}
	results := make(chan error, len(decisions))
	for _, decision := range decisions {
		decision := decision
		go func() { results <- server.ApproveMissionProposal(context.Background(), review, decision) }()
	}
	var succeeded, conflicted int
	for range decisions {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrMissionProposalConflict):
			conflicted++
		default:
			t.Fatalf("concurrent mission decision error = %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent mission decisions = succeeded %d, conflicted %d", succeeded, conflicted)
	}
	snapshot, err := store.LoadMissionProposal(context.Background(), reference, protocol.now)
	if err != nil || snapshot.State != MissionProposalApproved {
		t.Fatalf("canonical mission decision = %#v, %v", snapshot, err)
	}
}

func TestDeferredMissionProposalApprovalFailureReleasesNothing(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	store := &missionProposalCaptureStore{
		memoryMissionStore: protocol.store,
		proposals:          make(map[string]MissionProposalSnapshot),
		approveError:       errors.New("commit unavailable"),
	}
	server := newDeferredMissionProposalTestServer(t, protocol, store)
	reference := postDeferredMissionProposal(t, protocol, server, []byte(`{"description":"Read records","resources":["https://resource.example"]}`))
	review, err := server.ResumeMissionProposal(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := protocol.now.Add(20 * time.Minute)
	err = server.ApproveMissionProposal(context.Background(), review, MissionDecision{
		Description: "Read records", ApprovedResources: []string{protocol.resourceID}, ExpiresAt: &expiresAt,
	})
	if err == nil || !strings.Contains(err.Error(), "commit unavailable") {
		t.Fatalf("mission proposal approval error = %v", err)
	}
	snapshot, err := store.LoadMissionProposal(context.Background(), reference, protocol.now)
	if err != nil || snapshot.State != MissionProposalPending {
		t.Fatalf("failed approval changed proposal = %#v, %v", snapshot, err)
	}
	store.memoryMissionStore.mu.Lock()
	missionCount, tokenCount := len(store.memoryMissionStore.missions), len(store.memoryMissionStore.records)
	store.memoryMissionStore.mu.Unlock()
	if missionCount != 0 || tokenCount != 0 {
		t.Fatalf("failed approval released missions=%d tokens=%d", missionCount, tokenCount)
	}
}

func TestDeferredMissionProposalHostQueueSurvivesServerRecomposition(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	store := &missionProposalCaptureStore{
		memoryMissionStore: protocol.store,
		proposals:          make(map[string]MissionProposalSnapshot),
	}
	server := newDeferredMissionProposalTestServer(t, protocol, store)
	reference := postDeferredMissionProposal(t, protocol, server, []byte(`{"description":"Read after restart"}`))

	recomposed := newDeferredMissionProposalTestServer(t, protocol, store)
	reviews, err := recomposed.PendingMissionProposals(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(reviews) != 1 || reviews[0].Reference() != reference ||
		reviews[0].Proposal().Description != "Read after restart" {
		t.Fatalf("recomposed host queue = %#v", reviews)
	}
	reviews[0].record.ExactJSON[0] ^= 0xff
	reloaded, err := recomposed.ResumeMissionProposal(context.Background(), reference)
	if err != nil || reloaded.Proposal().Description != "Read after restart" {
		t.Fatalf("host queue caller mutated retained proposal = %#v, %v", reloaded, err)
	}
}

func newDeferredMissionProposalTestServer(
	t *testing.T,
	protocol *missionProtocol,
	store *missionProposalCaptureStore,
) *Server {
	t.Helper()
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, Tokens: store, NewID: func() string { return "deferred-mission-token" },
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{Subject: "person-123", Lifetime: time.Hour}, nil
		},
		Authorize: func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: request.Scopes, Lifetime: time.Minute}, nil
		},
		Missions: &MissionConfig{
			DeferProposal: func(context.Context, MissionApprovalRequest) (MissionProposalPendingPolicy, bool, error) {
				return MissionProposalPendingPolicy{Lifetime: 10 * time.Minute, RetryAfter: time.Second}, true, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func postDeferredMissionProposal(
	t *testing.T,
	protocol *missionProtocol,
	server *Server,
	exact []byte,
) string {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/mission", bytes.NewReader(exact))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("deferred mission proposal = %d %s", response.Code, response.Body.String())
	}
	return strings.TrimPrefix(response.Header().Get("Location"), "/mission/pending/")
}

type missionProposalCaptureStore struct {
	*memoryMissionStore
	proposalMu   sync.Mutex
	proposals    map[string]MissionProposalSnapshot
	approveError error
}

func (store *missionProposalCaptureStore) CreateMissionProposal(_ context.Context, record MissionProposalRecord) error {
	store.proposalMu.Lock()
	defer store.proposalMu.Unlock()
	if _, exists := store.proposals[record.ID]; exists {
		return ErrMissionProposalConflict
	}
	store.proposals[record.ID] = MissionProposalSnapshot{State: MissionProposalPending, Record: cloneMissionProposalRecord(record)}
	return nil
}

func (store *missionProposalCaptureStore) LoadMissionProposal(_ context.Context, reference string, at time.Time) (MissionProposalSnapshot, error) {
	store.proposalMu.Lock()
	defer store.proposalMu.Unlock()
	snapshot, ok := store.proposals[reference]
	if !ok {
		return MissionProposalSnapshot{}, ErrMissionProposalNotFound
	}
	if materializeMissionProposalExpiry(&snapshot, at) {
		store.proposals[reference] = cloneMissionProposalSnapshot(snapshot)
	}
	return cloneMissionProposalSnapshot(snapshot), nil
}

func (store *missionProposalCaptureStore) ListPendingMissionProposals(
	_ context.Context, at time.Time, limit int,
) ([]MissionProposalRecord, error) {
	store.proposalMu.Lock()
	defer store.proposalMu.Unlock()
	records := make([]MissionProposalRecord, 0, len(store.proposals))
	for reference, snapshot := range store.proposals {
		if materializeMissionProposalExpiry(&snapshot, at) {
			store.proposals[reference] = cloneMissionProposalSnapshot(snapshot)
		}
		if snapshot.State == MissionProposalPending {
			records = append(records, cloneMissionProposalRecord(snapshot.Record))
		}
	}
	sort.Slice(records, func(left, right int) bool {
		if records[left].CreatedAt.Equal(records[right].CreatedAt) {
			return records[left].ID < records[right].ID
		}
		return records[left].CreatedAt.Before(records[right].CreatedAt)
	})
	if len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

func (store *missionProposalCaptureStore) ApproveMissionProposal(
	_ context.Context, expected MissionProposalRecord, approval MissionProposalApproval, at time.Time,
) (MissionProposalApproval, error) {
	store.proposalMu.Lock()
	defer store.proposalMu.Unlock()
	store.memoryMissionStore.mu.Lock()
	defer store.memoryMissionStore.mu.Unlock()
	snapshot, ok := store.proposals[expected.ID]
	if !ok || !missionProposalRecordsEqual(snapshot.Record, expected) {
		return MissionProposalApproval{}, ErrMissionProposalConflict
	}
	if materializeMissionProposalExpiry(&snapshot, at) {
		store.proposals[expected.ID] = cloneMissionProposalSnapshot(snapshot)
	}
	if snapshot.State == MissionProposalApproved {
		if missionApprovalsSemanticallyEqual(snapshot.Approval, approval) {
			return cloneMissionProposalApproval(snapshot.Approval), nil
		}
		return MissionProposalApproval{}, ErrMissionProposalConflict
	}
	if snapshot.State == MissionProposalExpired || !at.Before(snapshot.Record.ExpiresAt) {
		return MissionProposalApproval{}, ErrMissionProposalExpired
	}
	if snapshot.State != MissionProposalPending {
		return MissionProposalApproval{}, ErrMissionProposalConflict
	}
	if store.approveError != nil {
		return MissionProposalApproval{}, store.approveError
	}
	missionKey := approval.Mission.Agent + "\x00" + approval.Mission.S256
	if _, exists := store.memoryMissionStore.missions[missionKey]; exists {
		return MissionProposalApproval{}, ErrMissionProposalConflict
	}
	batch := make(map[string]struct{}, len(approval.PersonTokenRecords))
	for _, token := range approval.PersonTokenRecords {
		key := token.PersonServer + "\x00" + token.JTI
		if _, exists := store.memoryMissionStore.records[key]; exists {
			return MissionProposalApproval{}, ErrMissionProposalConflict
		}
		if _, duplicate := batch[key]; duplicate {
			return MissionProposalApproval{}, ErrMissionProposalConflict
		}
		batch[key] = struct{}{}
	}
	store.memoryMissionStore.missions[missionKey] = cloneMissionRecord(approval.Mission)
	for _, token := range approval.PersonTokenRecords {
		store.memoryMissionStore.records[token.PersonServer+"\x00"+token.JTI] = token
	}
	snapshot.State = MissionProposalApproved
	snapshot.Approval = cloneMissionProposalApproval(approval)
	snapshot.DecidedAt = at
	store.proposals[expected.ID] = cloneMissionProposalSnapshot(snapshot)
	return cloneMissionProposalApproval(snapshot.Approval), nil
}

func (store *missionProposalCaptureStore) DenyMissionProposal(
	_ context.Context, expected MissionProposalRecord, at time.Time,
) error {
	store.proposalMu.Lock()
	defer store.proposalMu.Unlock()
	snapshot, ok := store.proposals[expected.ID]
	if !ok || !missionProposalRecordsEqual(snapshot.Record, expected) {
		return ErrMissionProposalConflict
	}
	if materializeMissionProposalExpiry(&snapshot, at) {
		store.proposals[expected.ID] = cloneMissionProposalSnapshot(snapshot)
	}
	if snapshot.State == MissionProposalDenied {
		return nil
	}
	if snapshot.State == MissionProposalExpired || !at.Before(snapshot.Record.ExpiresAt) {
		return ErrMissionProposalExpired
	}
	if snapshot.State != MissionProposalPending {
		return ErrMissionProposalConflict
	}
	snapshot.State = MissionProposalDenied
	snapshot.DecidedAt = at
	store.proposals[expected.ID] = cloneMissionProposalSnapshot(snapshot)
	return nil
}

func (store *missionProposalCaptureStore) PollMissionProposal(
	_ context.Context, reference string, identity MissionProposalPollIdentity, at time.Time,
) (MissionProposalSnapshot, error) {
	store.proposalMu.Lock()
	defer store.proposalMu.Unlock()
	snapshot, ok := store.proposals[reference]
	if !ok {
		return MissionProposalSnapshot{}, ErrMissionProposalNotFound
	}
	thumbprint, err := snapshot.Record.Confirmation.Thumbprint()
	if err != nil || snapshot.Record.PersonServer != identity.PersonServer ||
		snapshot.Record.AgentProvider != identity.AgentProvider || snapshot.Record.Agent != identity.Agent ||
		thumbprint != identity.ConfirmationThumbprint {
		return MissionProposalSnapshot{}, ErrMissionProposalNotFound
	}
	if !snapshot.DeliveredAt.IsZero() {
		return MissionProposalSnapshot{}, ErrMissionProposalGone
	}
	materializeMissionProposalExpiry(&snapshot, at)
	if snapshot.State != MissionProposalPending {
		snapshot.DeliveredAt = at
	}
	store.proposals[reference] = cloneMissionProposalSnapshot(snapshot)
	return cloneMissionProposalSnapshot(snapshot), nil
}

func materializeMissionProposalExpiry(snapshot *MissionProposalSnapshot, at time.Time) bool {
	if snapshot == nil {
		return false
	}
	switch {
	case (snapshot.State == MissionProposalPending || snapshot.State == MissionProposalApproved) &&
		!at.Before(snapshot.Record.ExpiresAt):
		wasPending := snapshot.State == MissionProposalPending
		snapshot.State = MissionProposalExpired
		snapshot.Approval = MissionProposalApproval{}
		if wasPending {
			snapshot.DecidedAt = at
		}
		return true
	case snapshot.State == MissionProposalApproved && snapshot.Approval.Expired(at):
		snapshot.State = MissionProposalExpired
		snapshot.Approval = MissionProposalApproval{}
		return true
	default:
		return false
	}
}
