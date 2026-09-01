package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestInteractionQuestionConfigurationAndExactAnswerInBothPersonServerModes(t *testing.T) {
	for _, mode := range []string{"direct", "federated"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			protocol := newInteractionQuestionProtocol(t)
			without := protocol.newServer(t, mode, nil)
			metadata := interactionQuestionMetadata(t, without)
			if _, present := metadata["interaction_endpoint"]; present {
				t.Fatal("interaction_endpoint advertised without explicit configuration")
			}
			response := interactionQuestionRequest(t, protocol, without, protocol.agentKey, protocol.agentToken,
				`{"type":"question","question":"Which route?"}`)
			if response.Code != http.StatusNotFound {
				t.Fatalf("unconfigured route = %d %s", response.Code, response.Body.String())
			}
			if _, err := protocol.construct(mode, &InteractionQuestionConfig{}); err == nil {
				t.Fatal("question configuration without policy was accepted")
			}

			body := []byte("{\n" +
				`  "question": "Which **route** should I take?",` + "\n" +
				`  "type": "question",` + "\n" +
				`  "description": "A route decision is required.",` + "\n" +
				`  "extension": {"trace": true}` + "\n" +
				"}")
			var policyRequest InteractionQuestionPolicyRequest
			calls := 0
			server := protocol.newServer(t, mode, &InteractionQuestionConfig{
				Policy: func(_ context.Context, request InteractionQuestionPolicyRequest) (InteractionQuestionPolicyResult, error) {
					calls++
					policyRequest = request
					decision := InteractionQuestionDecision{Answer: "Take the northern route."}
					return InteractionQuestionPolicyResult{Immediate: &decision}, nil
				},
			})
			metadata = interactionQuestionMetadata(t, server)
			if metadata["interaction_endpoint"] != protocol.personServerID+"/interaction" {
				t.Fatalf("interaction_endpoint = %q", metadata["interaction_endpoint"])
			}
			response = interactionQuestionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, string(body))
			if response.Code != http.StatusOK || response.Body.String() != `{"answer":"Take the northern route."}` ||
				response.Header().Get("Content-Type") != "application/json" ||
				response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("question response = %d headers=%#v body=%q", response.Code, response.Header(), response.Body.String())
			}
			if calls != 1 || policyRequest.Agent != protocol.agentID ||
				policyRequest.Document.Question.Question != "Which **route** should I take?" ||
				policyRequest.Document.Question.Description != "A route decision is required." ||
				!bytes.Equal(policyRequest.Document.ExactJSON, body) || !policyRequest.ReceivedAt.Equal(protocol.now) {
				t.Fatalf("policy request = %#v, calls=%d", policyRequest, calls)
			}
			body[0] = '['
			if policyRequest.Document.ExactJSON[0] != '{' {
				t.Fatal("policy request aliases caller body")
			}
		})
	}
}

func TestMissionInteractionQuestionPolicyReceivesExactActiveMission(t *testing.T) {
	protocol := newInteractionQuestionProtocol(t)
	store := newMemoryMissionStore()
	expiresAt := protocol.now.Add(20 * time.Minute)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: protocol.personServerID, Agent: protocol.agentID,
		ApprovedAt: protocol.now.Add(-time.Minute), ExpiresAt: &expiresAt,
		Description: "Choose the route for the approved trip.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitMission(context.Background(), MissionRecord{
		S256: mission.S256, Agent: protocol.agentID, ExactJSON: mission.ExactJSON,
		ApprovedAt: mission.Blob.ApprovedAt, ExpiresAt: expiresAt, State: MissionActive,
	}, nil); err != nil {
		t.Fatal(err)
	}
	server, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: func() string { return "question-token" }, Tokens: store,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{Subject: "person", Lifetime: time.Minute}, nil
		},
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: []string{"read"}, Lifetime: time.Minute}, nil
		},
		Missions: permissionMissionConfig(),
		InteractionQuestion: &InteractionQuestionConfig{
			Policy: func(_ context.Context, request InteractionQuestionPolicyRequest) (InteractionQuestionPolicyResult, error) {
				if request.Mission == nil || request.Mission.S256 != mission.S256 ||
					request.Mission.Blob.Description != mission.Blob.Description {
					t.Fatalf("mission question policy = %#v", request.Mission)
				}
				decision := InteractionQuestionDecision{Answer: "Take the northern route."}
				return InteractionQuestionPolicyResult{Immediate: &decision}, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := interactionQuestionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
		`{"type":"question","question":"Which route?","mission_s256":"`+mission.S256+`"}`)
	if response.Code != http.StatusOK || response.Body.String() != `{"answer":"Take the northern route."}` {
		t.Fatalf("mission question response = %d %s", response.Code, response.Body.String())
	}
	if len(store.questions) != 1 {
		t.Fatalf("retained mission questions = %d", len(store.questions))
	}
	for _, record := range store.questions {
		if record.State != InteractionQuestionAnswered || record.Document.Question.MissionS256 != mission.S256 ||
			record.Answer.Answer.Answer != "Take the northern route." {
			t.Fatalf("retained immediate mission question = %#v", record)
		}
	}
}

func TestMissionInteractionQuestionIsAvailableInFederatedMode(t *testing.T) {
	protocol := newInteractionQuestionProtocol(t)
	store := newMemoryMissionStore()
	expiresAt := protocol.now.Add(20 * time.Minute)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: protocol.personServerID, Agent: protocol.agentID,
		ApprovedAt: protocol.now.Add(-time.Minute), ExpiresAt: &expiresAt,
		Description: "Choose the route for the approved trip.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitMission(context.Background(), MissionRecord{
		S256: mission.S256, Agent: protocol.agentID, ExactJSON: mission.ExactJSON,
		ApprovedAt: mission.Blob.ApprovedAt, ExpiresAt: expiresAt, State: MissionActive,
	}, nil); err != nil {
		t.Fatal(err)
	}
	server, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: func() string { return "question-token" }, Tokens: store,
		HTTPClient: &http.Client{}, AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://access.example/token", nil
		},
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{Subject: "person", Lifetime: time.Minute}, nil
		},
		Consent:  func(context.Context, AuthorizationRequest) error { return nil },
		Missions: permissionMissionConfig(),
		InteractionQuestion: &InteractionQuestionConfig{
			Policy: func(_ context.Context, request InteractionQuestionPolicyRequest) (InteractionQuestionPolicyResult, error) {
				if request.Mission == nil || request.Mission.S256 != mission.S256 {
					t.Fatalf("federated mission question policy = %#v", request.Mission)
				}
				decision := InteractionQuestionDecision{Answer: "Take the northern route."}
				return InteractionQuestionPolicyResult{Immediate: &decision}, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := interactionQuestionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
		`{"type":"question","question":"Which route?","mission_s256":"`+mission.S256+`"}`)
	if response.Code != http.StatusOK || len(store.questions) != 1 {
		t.Fatalf("federated mission question response=%d %s records=%d", response.Code, response.Body.String(), len(store.questions))
	}
}

func TestDeferredMissionInteractionQuestionUsesExactMissionThroughConsume(t *testing.T) {
	protocol := newInteractionQuestionProtocol(t)
	store := newMemoryMissionStore()
	expiresAt := protocol.now.Add(20 * time.Minute)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: protocol.personServerID, Agent: protocol.agentID,
		ApprovedAt: protocol.now.Add(-time.Minute), ExpiresAt: &expiresAt,
		Description: "Choose the route for the approved trip.",
	})
	if err != nil {
		t.Fatal(err)
	}
	missionRecord := MissionRecord{
		S256: mission.S256, Agent: protocol.agentID, ExactJSON: mission.ExactJSON,
		ApprovedAt: mission.Blob.ApprovedAt, ExpiresAt: expiresAt, State: MissionActive,
	}
	if err := store.CommitMission(context.Background(), missionRecord, nil); err != nil {
		t.Fatal(err)
	}
	newServer := func() *Server {
		server, err := NewPSAuthorization(PSAuthorizationConfig{
			Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
			Clock: protocol.clock, NewID: func() string { return "question-token" }, Tokens: store,
			BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
				return Person{Subject: "person", Lifetime: time.Minute}, nil
			},
			Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
				return AuthorizationDecision{Scopes: []string{"read"}, Lifetime: time.Minute}, nil
			},
			Missions: permissionMissionConfig(),
			InteractionQuestion: &InteractionQuestionConfig{
				Policy: func(_ context.Context, request InteractionQuestionPolicyRequest) (InteractionQuestionPolicyResult, error) {
					if request.Mission == nil || request.Mission.S256 != mission.S256 {
						t.Fatalf("deferred mission question policy = %#v", request.Mission)
					}
					return InteractionQuestionPolicyResult{Deferred: &InteractionQuestionPendingPolicy{
						Lifetime: 5 * time.Minute, RetryAfter: time.Second,
					}}, nil
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	server := newServer()
	response := interactionQuestionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
		`{"type":"question","question":"Which route?","mission_s256":"`+mission.S256+`"}`)
	if response.Code != http.StatusAccepted {
		t.Fatalf("deferred mission question = %d %s", response.Code, response.Body.String())
	}
	reference := strings.TrimPrefix(response.Header().Get("Location"), "/interaction/pending/")
	server = newServer()
	handle, err := server.ResumeInteractionQuestion(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	missionContext, ok := handle.Mission()
	if !ok || missionContext.S256 != mission.S256 {
		t.Fatalf("mission question host context = %#v, %t", missionContext, ok)
	}
	update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{Action: "update", Description: "Prefer the safer route."})
	if err != nil {
		t.Fatal(err)
	}
	updatedMission, err := store.AppendMissionUpdate(context.Background(), missionRecord, protocol.now.Add(time.Second), update)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.AnswerInteractionQuestion(context.Background(), handle, "Take the northern route."); !errors.Is(err, ErrMissionConflict) {
		t.Fatalf("answer against unseen mission update = %v", err)
	}
	handle, err = server.ResumeInteractionQuestion(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	missionContext, ok = handle.Mission()
	if !ok || len(missionContext.AcceptedUpdates) != 1 {
		t.Fatalf("updated mission question context = %#v, %t", missionContext, ok)
	}
	if err := server.AnswerInteractionQuestion(context.Background(), handle, "Take the northern route."); err != nil {
		t.Fatal(err)
	}
	poll := pollInteractionQuestion(t, protocol, server, response.Header().Get("Location"))
	if poll.Code != http.StatusOK || poll.Body.String() != `{"answer":"Take the northern route."}` {
		t.Fatalf("mission question poll = %d %s", poll.Code, poll.Body.String())
	}

	response = interactionQuestionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
		`{"type":"question","question":"Should I continue?","mission_s256":"`+mission.S256+`"}`)
	if response.Code != http.StatusAccepted {
		t.Fatalf("second mission question = %d %s", response.Code, response.Body.String())
	}
	reference = strings.TrimPrefix(response.Header().Get("Location"), "/interaction/pending/")
	handle, err = server.ResumeInteractionQuestion(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.AnswerInteractionQuestion(context.Background(), handle, "Continue."); err != nil {
		t.Fatal(err)
	}
	store.terminateMission(updatedMission.Agent, updatedMission.S256, "revoked")
	poll = pollInteractionQuestion(t, protocol, server, response.Header().Get("Location"))
	assertAuditProblem(t, poll, http.StatusForbidden, "mission_terminated", "terminated", "revoked")
}

func TestInteractionQuestionRejectsUnsupportedShapeUnconfiguredMissionAndTopologyBeforePolicy(t *testing.T) {
	protocol := newInteractionQuestionProtocol(t)
	policyCalls := 0
	server := protocol.newServer(t, "direct", &InteractionQuestionConfig{
		Policy: func(context.Context, InteractionQuestionPolicyRequest) (InteractionQuestionPolicyResult, error) {
			policyCalls++
			decision := InteractionQuestionDecision{Answer: "unexpected"}
			return InteractionQuestionPolicyResult{Immediate: &decision}, nil
		},
	})
	mission := aauth.MissionS256([]byte("question mission"))
	for _, test := range []struct {
		body   string
		status int
	}{
		{body: `[]`, status: http.StatusBadRequest},
		{body: `{"type":"question"}`, status: http.StatusBadRequest},
		{body: `{"type":"interaction","url":"https://resource.example/act","code":"ABCD-EFGH"}`, status: http.StatusFailedDependency},
		{body: `{"type":"payment","url":"https://resource.example/pay","code":"ABCD-EFGH"}`, status: http.StatusFailedDependency},
		{body: `{"type":"question","question":"Choose?","mission_s256":"` + mission + `"}`, status: http.StatusBadRequest},
		{body: `{"type":"question","question":"Choose?","url":"https://resource.example/act"}`, status: http.StatusBadRequest},
	} {
		response := interactionQuestionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, test.body)
		if response.Code != test.status {
			t.Fatalf("unsupported question body %s = %d %s", test.body, response.Code, response.Body.String())
		}
	}

	unsigned := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/interaction", strings.NewReader(
		`{"type":"question","question":"Choose?"}`,
	))
	unsigned.Header.Set("Content-Type", "application/json")
	unsignedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(unsignedResponse, unsigned)
	if unsignedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned question = %d %s", unsignedResponse.Code, unsignedResponse.Body.String())
	}

	childKey := personServerTestKey(t, "interaction-question-child")
	childToken, err := aauth.MintAgentToken(protocol.providerID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:operator+child@provider.example", ParentAgent: protocol.agentID,
		PersonServer: protocol.personServerID, PublicKey: childKey.PublicJWK(), Lifetime: time.Minute,
	}, protocol.now, "interaction-question-child-token")
	if err != nil {
		t.Fatal(err)
	}
	child := interactionQuestionRequest(t, protocol, server, childKey, childToken,
		`{"type":"question","question":"Choose?"}`)
	if child.Code != http.StatusBadRequest {
		t.Fatalf("child question = %d %s", child.Code, child.Body.String())
	}

	oversized := `{"type":"question","question":"` + strings.Repeat("q", int(maxRequestBytes)) + `"}`
	oversizedRequest := httptest.NewRequest(
		http.MethodPost, protocol.personServerID+"/interaction", strings.NewReader(oversized),
	)
	oversizedRequest.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWTRequestWithOptions(
		oversizedRequest, protocol.agentKey, protocol.agentToken, protocol.clock,
		signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
			MaxBodyBytes:         int64(len(oversized) + 1),
		},
	); err != nil {
		t.Fatal(err)
	}
	oversizedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(oversizedResponse, oversizedRequest)
	if oversizedResponse.Code == http.StatusOK {
		t.Fatalf("oversized question = %d %s", oversizedResponse.Code, oversizedResponse.Body.String())
	}
	if policyCalls != 0 {
		t.Fatalf("invalid requests reached policy %d times", policyCalls)
	}
}

func TestInteractionQuestionMapsUnreachableAndOperationalPolicyFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		answer InteractionQuestionDecision
		err    error
		status int
		code   string
	}{
		{name: "unreachable", err: ErrInteractionUserUnreachable, status: http.StatusForbidden, code: "user_unreachable"},
		{name: "operational", err: errors.New("question channel failed"), status: http.StatusInternalServerError, code: "server_error"},
		{name: "invalid answer", answer: InteractionQuestionDecision{Answer: string([]byte{0xff})}, status: http.StatusInternalServerError, code: "server_error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newInteractionQuestionProtocol(t)
			server := protocol.newServer(t, "direct", &InteractionQuestionConfig{
				Policy: func(context.Context, InteractionQuestionPolicyRequest) (InteractionQuestionPolicyResult, error) {
					return InteractionQuestionPolicyResult{Immediate: &test.answer}, test.err
				},
			})
			response := interactionQuestionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
				`{"type":"question","question":"Which route?"}`)
			assertAuditProblem(t, response, test.status, test.code, "", "")
		})
	}
}

func (store *memoryMissionStore) CreateInteractionQuestion(_ context.Context, record InteractionQuestionRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.createInteractionQuestionLocked(record)
}

func (store *memoryMissionStore) LoadInteractionQuestion(_ context.Context, id string, at time.Time) (InteractionQuestionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loadInteractionQuestionLocked(id, at)
}

func (store *memoryMissionStore) ResolveInteractionQuestion(
	_ context.Context, id string, state InteractionQuestionState,
	answer aauth.InteractionAnswerDocument, at time.Time,
) (InteractionQuestionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.resolveInteractionQuestionLocked(id, state, answer, at)
}

func (store *memoryMissionStore) PollInteractionQuestion(
	_ context.Context, id string, identity InteractionQuestionPollIdentity, at time.Time,
) (InteractionQuestionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.loadInteractionQuestionLocked(id, at)
	if err != nil {
		return InteractionQuestionRecord{}, err
	}
	if record.PersonServer != identity.PersonServer || record.AgentProvider != identity.AgentProvider ||
		record.Agent != identity.Agent || record.ConfirmationThumbprint != identity.ConfirmationThumbprint {
		return InteractionQuestionRecord{}, ErrInteractionQuestionNotFound
	}
	return record, nil
}

func (store *memoryMissionStore) ConsumeInteractionQuestion(
	_ context.Context, id string, expected InteractionQuestionRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.consumeInteractionQuestionLocked(id, expected)
}

func (store *memoryMissionStore) CommitMissionInteractionQuestion(
	_ context.Context, expected MissionRecord, record InteractionQuestionRecord, at time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMissionLocked(expected, at); err != nil {
		return err
	}
	if record.Agent != expected.Agent || record.Document.Question.MissionS256 != expected.S256 {
		return ErrMissionConflict
	}
	return store.createInteractionQuestionLocked(record)
}

func (store *memoryMissionStore) ResolveMissionInteractionQuestion(
	_ context.Context, expected MissionRecord, id string, state InteractionQuestionState,
	answer aauth.InteractionAnswerDocument, at time.Time,
) (InteractionQuestionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMissionLocked(expected, at); err != nil {
		return InteractionQuestionRecord{}, err
	}
	if err := store.requireMissionQuestionLocked(id, expected); err != nil {
		return InteractionQuestionRecord{}, err
	}
	return store.resolveInteractionQuestionLocked(id, state, answer, at)
}

func (store *memoryMissionStore) PollMissionInteractionQuestion(
	_ context.Context, expected MissionRecord, id string,
	identity InteractionQuestionPollIdentity, at time.Time,
) (InteractionQuestionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMissionLocked(expected, at); err != nil {
		return InteractionQuestionRecord{}, err
	}
	if err := store.requireMissionQuestionLocked(id, expected); err != nil {
		return InteractionQuestionRecord{}, err
	}
	record, err := store.loadInteractionQuestionLocked(id, at)
	if err != nil {
		return InteractionQuestionRecord{}, err
	}
	if record.PersonServer != identity.PersonServer || record.AgentProvider != identity.AgentProvider ||
		record.Agent != identity.Agent || record.ConfirmationThumbprint != identity.ConfirmationThumbprint {
		return InteractionQuestionRecord{}, ErrInteractionQuestionNotFound
	}
	return record, nil
}

func (store *memoryMissionStore) ConsumeMissionInteractionQuestion(
	_ context.Context, expected MissionRecord, id string,
	record InteractionQuestionRecord, at time.Time,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMissionLocked(expected, at); err != nil {
		return err
	}
	if err := store.requireMissionQuestionLocked(id, expected); err != nil {
		return err
	}
	return store.consumeInteractionQuestionLocked(id, record)
}

func (store *memoryMissionStore) createInteractionQuestionLocked(record InteractionQuestionRecord) error {
	if _, exists := store.questions[record.ID]; exists {
		return ErrInteractionQuestionConflict
	}
	store.questions[record.ID] = cloneInteractionQuestionRecord(record)
	return nil
}

func (store *memoryMissionStore) loadInteractionQuestionLocked(id string, at time.Time) (InteractionQuestionRecord, error) {
	record, exists := store.questions[id]
	if !exists {
		return InteractionQuestionRecord{}, ErrInteractionQuestionNotFound
	}
	if record.State == InteractionQuestionGone {
		return InteractionQuestionRecord{}, ErrInteractionQuestionGone
	}
	if record.State == InteractionQuestionPending && !at.Before(record.ExpiresAt) {
		record.State = InteractionQuestionExpired
		store.questions[id] = cloneInteractionQuestionRecord(record)
	}
	return cloneInteractionQuestionRecord(record), nil
}

func (store *memoryMissionStore) resolveInteractionQuestionLocked(
	id string, state InteractionQuestionState, answer aauth.InteractionAnswerDocument, at time.Time,
) (InteractionQuestionRecord, error) {
	record, err := store.loadInteractionQuestionLocked(id, at)
	if err != nil {
		return InteractionQuestionRecord{}, err
	}
	if record.State != InteractionQuestionPending ||
		state != InteractionQuestionAnswered && state != InteractionQuestionUnreachable {
		return InteractionQuestionRecord{}, ErrInteractionQuestionConflict
	}
	record.State, record.Answer, record.AnsweredAt = state, cloneInteractionAnswerDocument(answer), at
	store.questions[id] = cloneInteractionQuestionRecord(record)
	return cloneInteractionQuestionRecord(record), nil
}

func (store *memoryMissionStore) consumeInteractionQuestionLocked(id string, expected InteractionQuestionRecord) error {
	record, exists := store.questions[id]
	if !exists {
		return ErrInteractionQuestionNotFound
	}
	if record.State == InteractionQuestionGone {
		return ErrInteractionQuestionGone
	}
	if !reflect.DeepEqual(record, expected) {
		return ErrInteractionQuestionConflict
	}
	record.State = InteractionQuestionGone
	store.questions[id] = cloneInteractionQuestionRecord(record)
	return nil
}

func (store *memoryMissionStore) requireMissionQuestionLocked(id string, mission MissionRecord) error {
	record, exists := store.questions[id]
	if !exists {
		return ErrInteractionQuestionNotFound
	}
	if record.Agent != mission.Agent || record.Document.Question.MissionS256 != mission.S256 {
		return ErrMissionConflict
	}
	return nil
}

type interactionQuestionProtocol struct {
	now            time.Time
	clock          aauth.Clock
	providerID     string
	personServerID string
	agentID        string
	providerKey    jose.SigningKey
	personKey      jose.SigningKey
	agentKey       jose.SigningKey
	resolver       signaturekey.KeyResolver
	agentToken     string
	tokens         TokenStore
}

func newInteractionQuestionProtocol(t *testing.T) *interactionQuestionProtocol {
	t.Helper()
	protocol := &interactionQuestionProtocol{
		now:        time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC),
		providerID: "https://provider.example", personServerID: "https://person.example",
		agentID: "aauth:operator@provider.example", providerKey: personServerTestKey(t, "question-provider"),
		personKey: personServerTestKey(t, "question-person"), agentKey: personServerTestKey(t, "question-agent"),
		tokens: newMemoryTokenStore(),
	}
	protocol.clock = aauth.ClockFunc(func() time.Time { return protocol.now })
	protocol.resolver = signaturekey.StaticKeyResolver{
		{Issuer: protocol.providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: protocol.providerKey.ID()}: protocol.providerKey.PublicJWK(),
	}
	var err error
	protocol.agentToken, err = aauth.MintAgentToken(protocol.providerID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: protocol.agentID, PersonServer: protocol.personServerID,
		PublicKey: protocol.agentKey.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, "interaction-question-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	return protocol
}

func (protocol *interactionQuestionProtocol) construct(
	mode string,
	questions *InteractionQuestionConfig,
) (*Server, error) {
	if mode == "federated" {
		return NewFederatedAuthorization(FederatedAuthorizationConfig{
			Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
			Clock: protocol.clock, NewID: func() string { return "question-token" }, Tokens: protocol.tokens,
			HTTPClient: &http.Client{}, AccessServerEndpoint: func(context.Context, string) (string, error) {
				return "https://access.example/token", nil
			},
			BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
				return Person{Subject: "person", Lifetime: time.Minute}, nil
			},
			Consent: func(context.Context, AuthorizationRequest) error { return nil }, InteractionQuestion: questions,
		})
	}
	return NewPSAuthorization(PSAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: func() string { return "question-token" }, Tokens: protocol.tokens,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{Subject: "person", Lifetime: time.Minute}, nil
		},
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: []string{"read"}, Lifetime: time.Minute}, nil
		},
		InteractionQuestion: questions,
	})
}

func (protocol *interactionQuestionProtocol) newServer(t *testing.T, mode string, questions *InteractionQuestionConfig) *Server {
	t.Helper()
	server, err := protocol.construct(mode, questions)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func interactionQuestionRequest(
	t *testing.T,
	protocol *interactionQuestionProtocol,
	server *Server,
	key jose.SigningKey,
	token string,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/interaction", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, key, token, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func interactionQuestionMetadata(t *testing.T, server *Server) map[string]string {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://person.example/.well-known/aauth-person.json", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("metadata response = %d %s", response.Code, response.Body.String())
	}
	var metadata map[string]string
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	return metadata
}

func pollInteractionQuestion(
	t *testing.T,
	protocol *interactionQuestionProtocol,
	server *Server,
	location string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, protocol.personServerID+location, nil)
	if err := signaturekey.SignJWTRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}
