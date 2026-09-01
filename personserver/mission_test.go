package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestMissionApprovalRetainsExactBlobAndIssuesBoundPersonTokens(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	requestBody := []byte(`{"description":"# Review report\n\nReview and publish the report.","tools":[{"name":"Publish","description":"Publish the reviewed report"}],"resources":["https://resource.example"]}`)
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/mission", bytes.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	protocol.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("mission approval = %d, headers=%v, body=%s", response.Code, response.Header(), response.Body.String())
	}
	var approval aauth.MissionApproval
	if err := json.Unmarshal(response.Body.Bytes(), &approval); err != nil {
		t.Fatal(err)
	}
	mission, err := aauth.DecodeMission(approval.S256, approval.Mission)
	if err != nil {
		t.Fatal(err)
	}
	if mission.Blob.Approver != protocol.personServerID || mission.Blob.Agent != protocol.agentID ||
		mission.Blob.Description != "# Reviewed report\n\nPublish only the reviewed report." ||
		!mission.Blob.ApprovedAt.Equal(protocol.now) || mission.Blob.ExpiresAt == nil ||
		!mission.Blob.ExpiresAt.Equal(protocol.now.Add(12*time.Minute)) ||
		!reflect.DeepEqual(mission.Blob.ApprovedTools, []aauth.MissionTool{{Name: "Publish", Description: "Publish the reviewed report"}}) ||
		!slices.Equal(mission.Blob.ApprovedResources, []string{protocol.resourceID}) {
		t.Fatalf("approved mission = %#v", mission.Blob)
	}
	if !slices.Equal(approval.Capabilities, []string{"interaction"}) {
		t.Fatalf("capabilities = %#v", approval.Capabilities)
	}
	personToken := approval.PersonTokens[protocol.resourceID]
	claims, err := aauth.VerifyPersonToken(context.Background(), personToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.MissionS256 != approval.S256 || claims.Audience != protocol.resourceID ||
		claims.Subject != "person-123" || claims.ExpiresAt != protocol.now.Add(12*time.Minute).Unix() {
		t.Fatalf("mission person token = %#v", claims)
	}
	record, err := protocol.store.LoadMissionForAgent(
		context.Background(), protocol.agentID, approval.S256, protocol.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.Agent != protocol.agentID || record.State != MissionActive || string(record.ExactJSON) != string(mission.ExactJSON) ||
		!record.ApprovedAt.Equal(protocol.now) || !record.ExpiresAt.Equal(protocol.now.Add(12*time.Minute)) ||
		!slices.Equal(record.Capabilities, []string{"interaction"}) {
		t.Fatalf("retained mission = %#v", record)
	}
	if len(protocol.approvals) != 1 || protocol.approvals[0].Agent != protocol.agentID ||
		protocol.approvals[0].Proposal.Description != "# Review report\n\nReview and publish the report." {
		t.Fatalf("approval request = %#v", protocol.approvals)
	}
	if len(protocol.bindings) != 1 || protocol.bindings[0].Mission == nil || protocol.bindings[0].Mission.S256 != approval.S256 {
		t.Fatalf("person bindings = %#v", protocol.bindings)
	}
}

func TestMissionBoundPersonTokenRequiresActiveOwnedMission(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
	call := func(agentToken string, key jose.SigningKey, s256 string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"resource": protocol.resourceID, "mission_s256": s256})
		request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/person", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := signPersonServerTestRequest(request, key, agentToken, protocol.clock); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		protocol.server.Handler().ServeHTTP(response, request)
		return response
	}

	response := call(protocol.agentToken, protocol.agentKey, mission.S256)
	if response.Code != http.StatusOK {
		t.Fatalf("active mission = %d %s", response.Code, response.Body.String())
	}
	var output struct {
		PersonToken string `json:"person_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyPersonToken(context.Background(), output.PersonToken, protocol.resolver, protocol.clock)
	if err != nil || claims.MissionS256 != mission.S256 || claims.ExpiresAt != protocol.now.Add(10*time.Minute).Unix() {
		t.Fatalf("active mission claims = %#v, %v", claims, err)
	}

	missing := call(protocol.agentToken, protocol.agentKey, aauth.MissionS256([]byte("missing")))
	assertMissionProblem(t, missing, http.StatusBadRequest, "invalid_request", "", "")

	otherKey := personServerTestKey(t, "other-agent")
	otherToken, err := aauth.MintAgentToken(protocol.agentProviderID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:other@provider.example", PersonServer: protocol.personServerID,
		PublicKey: otherKey.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, "other-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	wrongOwner := call(otherToken, otherKey, mission.S256)
	assertMissionProblem(t, wrongOwner, http.StatusBadRequest, "invalid_request", "", "")
	if missing.Body.String() != wrongOwner.Body.String() || !reflect.DeepEqual(missing.Header(), wrongOwner.Header()) {
		t.Fatalf("missing and wrong-owner missions differ:\nmissing=%v %s\nwrong=%v %s", missing.Header(), missing.Body.String(), wrongOwner.Header(), wrongOwner.Body.String())
	}
	protocol.store.mu.Lock()
	key := mission.Agent + "\x00" + mission.S256
	corrupt := protocol.store.missions[key]
	corrupt.ExactJSON = []byte(`{"not":"a mission"}`)
	protocol.store.missions[key] = corrupt
	protocol.store.mu.Unlock()
	wrongOwnerCorrupt := call(otherToken, otherKey, mission.S256)
	assertMissionProblem(t, wrongOwnerCorrupt, http.StatusBadRequest, "invalid_request", "", "")
	if missing.Body.String() != wrongOwnerCorrupt.Body.String() || !reflect.DeepEqual(missing.Header(), wrongOwnerCorrupt.Header()) {
		t.Fatalf("missing and corrupt wrong-owner missions differ:\nmissing=%v %s\nwrong=%v %s", missing.Header(), missing.Body.String(), wrongOwnerCorrupt.Header(), wrongOwnerCorrupt.Body.String())
	}

	expired := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Second), MissionActive, "")
	protocol.now = expired.ExpiresAt
	expiredResponse := call(protocol.agentToken, protocol.agentKey, expired.S256)
	assertMissionProblem(t, expiredResponse, http.StatusForbidden, "mission_terminated", "terminated", "expired")
	protocol.now = expired.ExpiresAt.Add(-5 * time.Second)
	reloaded, err := protocol.store.LoadMissionForAgent(
		context.Background(), protocol.agentID, expired.S256, protocol.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.State != MissionTerminated || reloaded.TerminationReason != "expired" {
		t.Fatalf("mission resurrected after clock rollback: %#v", reloaded)
	}
	assertMissionProblem(t, call(protocol.agentToken, protocol.agentKey, expired.S256), http.StatusForbidden, "mission_terminated", "terminated", "expired")
	protocol.now = expired.ExpiresAt.Add(time.Second)

	terminated := protocol.commitMission(t, protocol.agentID, protocol.now.Add(time.Hour), MissionTerminated, "revoked")
	terminatedResponse := call(protocol.agentToken, protocol.agentKey, terminated.S256)
	assertMissionProblem(t, terminatedResponse, http.StatusForbidden, "mission_terminated", "terminated", "revoked")
}

func TestMissionBoundPersonTokenRechecksMissionAfterPolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*missionProtocol, MissionRecord)
		reason string
	}{
		{
			name: "revoked",
			change: func(protocol *missionProtocol, mission MissionRecord) {
				protocol.store.terminateMission(mission.Agent, mission.S256, "revoked")
			},
			reason: "revoked",
		},
		{
			name: "expired",
			change: func(protocol *missionProtocol, mission MissionRecord) {
				protocol.now = mission.ExpiresAt
			},
			reason: "expired",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			protocol := newMissionProtocol(t)
			mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
			protocol.server.bindPerson = func(_ context.Context, request PersonTokenRequest) (Person, error) {
				if request.Mission == nil || request.Mission.S256 != mission.S256 {
					return Person{}, errors.New("missing mission policy context")
				}
				test.change(protocol, mission)
				return Person{Subject: "person-123", Lifetime: time.Minute}, nil
			}
			body, _ := json.Marshal(map[string]string{"resource": protocol.resourceID, "mission_s256": mission.S256})
			request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/person", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			protocol.server.Handler().ServeHTTP(response, request)
			assertMissionProblem(t, response, http.StatusForbidden, "mission_terminated", "terminated", test.reason)
			protocol.store.mu.Lock()
			retained := len(protocol.store.records)
			protocol.store.mu.Unlock()
			if retained != 0 {
				t.Fatalf("mission transition retained %d person tokens", retained)
			}
		})
	}
}

func TestMissionBoundAuthorizationRechecksMissionAfterPolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*missionProtocol, MissionRecord)
		reason string
	}{
		{
			name: "revoked",
			change: func(protocol *missionProtocol, mission MissionRecord) {
				protocol.store.terminateMission(mission.Agent, mission.S256, "revoked")
			},
			reason: "revoked",
		},
		{
			name: "expired",
			change: func(protocol *missionProtocol, mission MissionRecord) {
				protocol.now = mission.ExpiresAt
			},
			reason: "expired",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			protocol := newMissionProtocol(t)
			mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
			personRecord := PersonTokenRecord{
				JTI: "mission-person", PersonServer: protocol.personServerID, Resource: protocol.resourceID,
				Subject: "person-123", MissionS256: mission.S256,
				AgentProvider: protocol.agentProviderID, Agent: protocol.agentID,
				Confirmation: protocol.agentKey.PublicJWK(), ExpiresAt: protocol.now.Add(10 * time.Minute),
				RetainUntil: protocol.now.Add(15 * time.Minute),
			}
			if err := protocol.store.Commit(context.Background(), personRecord); err != nil {
				t.Fatal(err)
			}
			thumbprint, err := protocol.agentKey.PublicJWK().Thumbprint()
			if err != nil {
				t.Fatal(err)
			}
			resourceToken, err := aauth.MintResourceToken(protocol.resourceKey, aauth.ResourceTokenClaims{
				Issuer: protocol.resourceID, DWK: aauth.ResourceDiscoveryDocument,
				Audience: protocol.personServerID, JTI: "mission-resource", AgentJKT: thumbprint,
				IssuedAt: protocol.now.Unix(), ExpiresAt: protocol.now.Add(5 * time.Minute).Unix(), Scope: "records.read",
				PersonServer: protocol.personServerID, Subject: personRecord.Subject,
				PresentedJTI: personRecord.JTI, MissionS256: mission.S256,
			})
			if err != nil {
				t.Fatal(err)
			}
			protocol.server.authorize = func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
				if request.Mission == nil || request.Mission.S256 != mission.S256 {
					return AuthorizationDecision{}, errors.New("missing mission policy context")
				}
				test.change(protocol, mission)
				return AuthorizationDecision{Scopes: request.Scopes, Lifetime: time.Minute}, nil
			}
			body, _ := json.Marshal(map[string]string{"resource_token": resourceToken})
			request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/token", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			protocol.server.Handler().ServeHTTP(response, request)
			assertMissionProblem(t, response, http.StatusForbidden, "mission_terminated", "terminated", test.reason)
			protocol.store.mu.Lock()
			retained := len(protocol.store.authTokens)
			protocol.store.mu.Unlock()
			if retained != 0 {
				t.Fatalf("mission transition retained %d auth tokens", retained)
			}
		})
	}
}

func TestMissionApprovalRejectsDuplicateReturnedPersonTokenIdentity(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	protocol.server.newID = func() string { return "duplicate-person-token" }
	body := []byte(`{"description":"Work","resources":["https://resource.example","https://second.example"]}`)
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/mission", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	protocol.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("duplicate token identities = %d %s", response.Code, response.Body.String())
	}
	protocol.store.mu.Lock()
	missions, tokens := len(protocol.store.missions), len(protocol.store.records)
	protocol.store.mu.Unlock()
	if missions != 0 || tokens != 0 {
		t.Fatalf("duplicate token identities retained missions=%d tokens=%d", missions, tokens)
	}
}

func TestMissionStoreRejectsDuplicateApprovalBatch(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: protocol.personServerID, Agent: protocol.agentID, ApprovedAt: protocol.now,
		Description: "Work",
	})
	if err != nil {
		t.Fatal(err)
	}
	record := MissionRecord{
		S256: mission.S256, Agent: protocol.agentID, ExactJSON: mission.ExactJSON,
		ApprovedAt: protocol.now, State: MissionActive,
	}
	token := PersonTokenRecord{PersonServer: protocol.personServerID, JTI: "duplicate"}
	if err := protocol.store.CommitMission(context.Background(), record, []PersonTokenRecord{token, token}); err == nil {
		t.Fatal("duplicate Person-token identities were retained")
	}
	protocol.store.mu.Lock()
	missions, tokens := len(protocol.store.missions), len(protocol.store.records)
	protocol.store.mu.Unlock()
	if missions != 0 || tokens != 0 {
		t.Fatalf("duplicate batch retained missions=%d tokens=%d", missions, tokens)
	}
}

func TestMissionApprovalDoesNotReleaseAnUnretainedResult(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	protocol.store.commitMissionError = errors.New("mission storage unavailable")
	request := httptest.NewRequest(
		http.MethodPost,
		protocol.personServerID+"/mission",
		bytes.NewReader([]byte(`{"description":"Work","resources":["https://resource.example"]}`)),
	)
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	protocol.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || bytes.Contains(response.Body.Bytes(), []byte(`"s256"`)) ||
		bytes.Contains(response.Body.Bytes(), []byte(`"person_tokens"`)) {
		t.Fatalf("retention failure = %d %s", response.Code, response.Body.String())
	}
	protocol.store.mu.Lock()
	missions, tokens := len(protocol.store.missions), len(protocol.store.records)
	protocol.store.mu.Unlock()
	if missions != 0 || tokens != 0 {
		t.Fatalf("retention failure stored missions=%d tokens=%d", missions, tokens)
	}
}

func TestMissionApprovalPolicyDenialIsTypedAndDoesNotRetain(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	protocol.server.missionApprove = func(context.Context, MissionApprovalRequest) (MissionDecision, error) {
		return MissionDecision{}, fmt.Errorf("%w: person declined", ErrMissionDenied)
	}
	request := httptest.NewRequest(
		http.MethodPost, protocol.personServerID+"/mission", bytes.NewReader([]byte(`{"description":"Work"}`)),
	)
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	protocol.server.Handler().ServeHTTP(response, request)
	assertMissionProblem(t, response, http.StatusForbidden, "mission_denied", "", "")
	protocol.store.mu.Lock()
	retained := len(protocol.store.missions)
	protocol.store.mu.Unlock()
	if retained != 0 {
		t.Fatalf("denied mission retained %d records", retained)
	}
}

func TestMissionApprovalOperationalFailureIsNotReportedAsDenial(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	protocol.server.missionApprove = func(context.Context, MissionApprovalRequest) (MissionDecision, error) {
		return MissionDecision{}, errors.New("policy store unavailable")
	}
	request := httptest.NewRequest(
		http.MethodPost, protocol.personServerID+"/mission", bytes.NewReader([]byte(`{"description":"Work"}`)),
	)
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	protocol.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"error":"server_error"`)) {
		t.Fatalf("operational approval failure = %d %s", response.Code, response.Body.String())
	}
}

func TestMissionConfigurationIsOptionalAndCoherent(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	metadataRequest := httptest.NewRequest(http.MethodGet, protocol.personServerID+"/.well-known/aauth-person.json", nil)
	metadataResponse := httptest.NewRecorder()
	protocol.server.Handler().ServeHTTP(metadataResponse, metadataRequest)
	var metadata map[string]string
	if err := json.Unmarshal(metadataResponse.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["mission_endpoint"] != protocol.personServerID+"/mission" {
		t.Fatalf("mission endpoint = %q", metadata["mission_endpoint"])
	}

	base := PSAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: func() string { return "id" }, Tokens: newMemoryTokenStore(),
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{Subject: "person", Lifetime: time.Minute}, nil
		},
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}, nil
		},
	}
	withoutMission, err := NewPSAuthorization(base)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	withoutMission.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, base.Issuer+"/.well-known/aauth-person.json", nil))
	metadata = nil
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if _, exists := metadata["mission_endpoint"]; exists {
		t.Fatalf("unconfigured metadata = %#v", metadata)
	}

	base.Missions = &MissionConfig{
		Approve: protocol.server.missionApprove,
		AcceptUpdate: func(context.Context, MissionUpdatePolicyRequest) error {
			return nil
		},
		ConfirmPersonAcceptedCompletion: func(context.Context, MissionCompletionPolicyRequest) error {
			return nil
		},
	}
	if _, err := NewPSAuthorization(base); err == nil {
		t.Fatal("mission policy with a token-only store was accepted")
	}
	base.Tokens = protocol.store
	base.Missions = &MissionConfig{}
	if _, err := NewPSAuthorization(base); err == nil {
		t.Fatal("mission configuration without approval policy was accepted")
	}
	base.Missions = &MissionConfig{
		Approve:                         protocol.server.missionApprove,
		ConfirmPersonAcceptedCompletion: func(context.Context, MissionCompletionPolicyRequest) error { return nil },
	}
	if _, err := NewPSAuthorization(base); err == nil {
		t.Fatal("mission configuration without update acceptance was accepted")
	}
	base.Missions = &MissionConfig{
		Approve:      protocol.server.missionApprove,
		AcceptUpdate: func(context.Context, MissionUpdatePolicyRequest) error { return nil },
	}
	if _, err := NewPSAuthorization(base); err == nil {
		t.Fatal("mission configuration without completion acceptance was accepted")
	}

	missionConfig := &MissionConfig{
		Approve:      protocol.server.missionApprove,
		AcceptUpdate: func(context.Context, MissionUpdatePolicyRequest) error { return nil },
		ConfirmPersonAcceptedCompletion: func(context.Context, MissionCompletionPolicyRequest) error {
			return nil
		},
	}
	federated, err := NewFederatedAuthorization(FederatedAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: func() string { return "id" }, HTTPClient: &http.Client{},
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return "https://as.example/token", nil
		},
		Tokens: protocol.store, Missions: missionConfig,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{Subject: "person", Lifetime: time.Minute}, nil
		},
		Consent: func(context.Context, AuthorizationRequest) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	federated.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, base.Issuer+"/.well-known/aauth-person.json", nil))
	metadata = nil
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["mission_endpoint"] != protocol.personServerID+"/mission" {
		t.Fatalf("federated mission endpoint = %q", metadata["mission_endpoint"])
	}
}

func TestMissionDecisionCannotApproveAnExpiredMission(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 20, 15, 0, 0, time.UTC)
	for _, expiresAt := range []time.Time{now, now.Add(-time.Second)} {
		decision := MissionDecision{Description: "Work", ExpiresAt: &expiresAt}
		if err := validateMissionDecision(decision, aauth.MissionProposal{Description: "Work"}, now); err == nil {
			t.Fatalf("expiry %s was accepted at %s", expiresAt, now)
		}
	}
}

func TestMemoryMissionStoreCopiesUpdateAndCompletionRecords(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 0, 0, 0, time.UTC)
	store := newMemoryMissionStore()
	expiresAt := now.Add(time.Hour)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: "https://person.example", Agent: "aauth:agent@example", ApprovedAt: now,
		Description: "Test the reference store", ExpiresAt: &expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	record := MissionRecord{
		S256: mission.S256, Agent: mission.Blob.Agent, ExactJSON: mission.ExactJSON,
		ApprovedAt: mission.Blob.ApprovedAt, ExpiresAt: *mission.Blob.ExpiresAt,
		Capabilities: []string{"interaction"}, State: MissionActive,
	}
	if err := store.CommitMission(context.Background(), record, nil); err != nil {
		t.Fatal(err)
	}
	record.Capabilities[0] = "mutated"
	expected, err := store.LoadMissionForAgent(context.Background(), record.Agent, record.S256, now)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(expected.Capabilities, []string{"interaction"}) {
		t.Fatalf("retained mission capabilities = %#v", expected.Capabilities)
	}
	update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{Action: "update", Description: "Refined scope"})
	if err != nil {
		t.Fatal(err)
	}
	updateBytes := append([]byte(nil), update.ExactJSON...)
	updated, err := store.AppendMissionUpdate(context.Background(), expected, now.Add(time.Minute), update)
	if err != nil {
		t.Fatal(err)
	}
	update.ExactJSON[0] ^= 0xff
	updated.AcceptedUpdates[0].Document.ExactJSON[0] ^= 0xff
	reloaded, err := store.LoadMissionForAgent(context.Background(), record.Agent, record.S256, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.AcceptedUpdates) != 1 ||
		!bytes.Equal(reloaded.AcceptedUpdates[0].Document.ExactJSON, updateBytes) ||
		!reloaded.AcceptedUpdates[0].AcceptedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("retained update = %#v", reloaded.AcceptedUpdates)
	}

	completion, err := aauth.EncodeMissionCompletion(aauth.MissionCompletion{
		Action: "completion", Summary: "Reference-store exercise complete",
	})
	if err != nil {
		t.Fatal(err)
	}
	completionBytes := append([]byte(nil), completion.ExactJSON...)
	completed, err := store.CompleteMission(context.Background(), reloaded, now.Add(3*time.Minute), completion)
	if err != nil {
		t.Fatal(err)
	}
	completion.ExactJSON[0] ^= 0xff
	completed.Completion.Document.ExactJSON[0] ^= 0xff
	reloaded, err = store.LoadMissionForAgent(context.Background(), record.Agent, record.S256, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.State != MissionTerminated || reloaded.TerminationReason != "completed" ||
		reloaded.Completion == nil || !bytes.Equal(reloaded.Completion.Document.ExactJSON, completionBytes) ||
		!reloaded.Completion.AcceptedAt.Equal(now.Add(3*time.Minute)) {
		t.Fatalf("completed mission = %#v", reloaded)
	}
}

func TestMemoryMissionStoreLifecycleCASMaterializesExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 21, 0, 0, 0, time.UTC)
	store := newMemoryMissionStore()
	expiresAt := now.Add(time.Minute)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: "https://person.example", Agent: "aauth:agent@example", ApprovedAt: now,
		Description: "Expire the reference store", ExpiresAt: &expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	record := MissionRecord{
		S256: mission.S256, Agent: mission.Blob.Agent, ExactJSON: mission.ExactJSON,
		ApprovedAt: mission.Blob.ApprovedAt, ExpiresAt: *mission.Blob.ExpiresAt, State: MissionActive,
	}
	if err := store.CommitMission(context.Background(), record, nil); err != nil {
		t.Fatal(err)
	}
	update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{Action: "update", Description: "Too late"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.AppendMissionUpdate(context.Background(), record, record.ExpiresAt, update)
	var terminated *MissionTerminatedError
	if !errors.As(err, &terminated) || terminated.TerminationReason != "expired" {
		t.Fatalf("expired append error = %v", err)
	}
	reloaded, err := store.LoadMissionForAgent(context.Background(), record.Agent, record.S256, now)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.State != MissionTerminated || reloaded.TerminationReason != "expired" ||
		len(reloaded.AcceptedUpdates) != 0 || reloaded.Completion != nil {
		t.Fatalf("materialized expiry = %#v", reloaded)
	}
}

type missionProtocol struct {
	now             time.Time
	clock           aauth.Clock
	agentProviderID string
	agentID         string
	personServerID  string
	resourceID      string
	providerKey     jose.SigningKey
	agentKey        jose.SigningKey
	personKey       jose.SigningKey
	resourceKey     jose.SigningKey
	agentToken      string
	resolver        signaturekey.StaticKeyResolver
	store           *memoryMissionStore
	approvals       []MissionApprovalRequest
	updates         []MissionUpdatePolicyRequest
	completions     []MissionCompletionPolicyRequest
	bindings        []PersonTokenRequest
	server          *Server
}

func newMissionProtocol(t *testing.T) *missionProtocol {
	t.Helper()
	protocol := &missionProtocol{
		now:             time.Date(2026, 8, 30, 20, 15, 0, 0, time.UTC),
		agentProviderID: "https://provider.example", agentID: "aauth:planner@provider.example",
		personServerID: "https://person.example", resourceID: "https://resource.example",
		providerKey: personServerTestKey(t, "mission-provider"), agentKey: personServerTestKey(t, "mission-agent"),
		personKey: personServerTestKey(t, "mission-person"), resourceKey: personServerTestKey(t, "mission-resource"),
		store: newMemoryMissionStore(),
	}
	protocol.clock = aauth.ClockFunc(func() time.Time { return protocol.now })
	protocol.resolver = signaturekey.StaticKeyResolver{
		{Issuer: protocol.agentProviderID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: protocol.providerKey.ID()}: protocol.providerKey.PublicJWK(),
		{Issuer: protocol.personServerID, DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: protocol.personKey.ID()}:   protocol.personKey.PublicJWK(),
		{Issuer: protocol.resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: protocol.resourceKey.ID()}:   protocol.resourceKey.PublicJWK(),
	}
	var err error
	protocol.agentToken, err = aauth.MintAgentToken(protocol.agentProviderID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: protocol.agentID, PersonServer: protocol.personServerID,
		PublicKey: protocol.agentKey.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, "mission-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	ids := 0
	protocol.server, err = NewPSAuthorization(PSAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, Tokens: protocol.store, NewID: func() string {
			ids++
			return "mission-token-" + string(rune('0'+ids))
		},
		BindPerson: func(_ context.Context, request PersonTokenRequest) (Person, error) {
			protocol.bindings = append(protocol.bindings, request)
			return Person{Subject: "person-123", Lifetime: time.Hour}, nil
		},
		Authorize: func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: request.Scopes, Lifetime: time.Hour}, nil
		},
		Missions: &MissionConfig{
			Approve: func(_ context.Context, request MissionApprovalRequest) (MissionDecision, error) {
				protocol.approvals = append(protocol.approvals, request)
				expiresAt := protocol.now.Add(12 * time.Minute)
				return MissionDecision{
					Description:   "# Reviewed report\n\nPublish only the reviewed report.",
					ApprovedTools: request.Proposal.Tools, ApprovedResources: request.Proposal.Resources,
					ExpiresAt: &expiresAt, Capabilities: []string{"interaction"},
				}, nil
			},
			AcceptUpdate: func(_ context.Context, request MissionUpdatePolicyRequest) error {
				protocol.updates = append(protocol.updates, request)
				return nil
			},
			ConfirmPersonAcceptedCompletion: func(_ context.Context, request MissionCompletionPolicyRequest) error {
				protocol.completions = append(protocol.completions, request)
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return protocol
}

func (protocol *missionProtocol) commitMission(t *testing.T, agent string, expiresAt time.Time, state MissionState, reason string) MissionRecord {
	t.Helper()
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: protocol.personServerID, Agent: agent, ApprovedAt: protocol.now.Add(-time.Minute),
		ExpiresAt: &expiresAt, Description: "Test mission",
	})
	if err != nil {
		t.Fatal(err)
	}
	record := MissionRecord{
		S256: mission.S256, Agent: agent, ExactJSON: mission.ExactJSON,
		ApprovedAt: mission.Blob.ApprovedAt, ExpiresAt: expiresAt,
		State: state, TerminationReason: reason,
	}
	if err := protocol.store.CommitMission(context.Background(), record, nil); err != nil {
		t.Fatal(err)
	}
	return record
}

type memoryMissionStore struct {
	mu                   sync.Mutex
	missions             map[string]MissionRecord
	records              map[string]PersonTokenRecord
	authTokens           map[string]IssuedAuthTokenRecord
	questions            map[string]InteractionQuestionRecord
	commitMissionError   error
	appendMissionError   error
	completeMissionError error
}

func newMemoryMissionStore() *memoryMissionStore {
	return &memoryMissionStore{
		missions: make(map[string]MissionRecord), records: make(map[string]PersonTokenRecord),
		authTokens: make(map[string]IssuedAuthTokenRecord), questions: make(map[string]InteractionQuestionRecord),
	}
}

func (store *memoryMissionStore) Commit(_ context.Context, record PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if _, exists := store.records[key]; exists {
		return errors.New("person token already exists")
	}
	store.records[key] = record
	return nil
}

func (store *memoryMissionStore) Load(_ context.Context, issuer, jti string) (PersonTokenRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[issuer+"\x00"+jti]
	if !exists {
		return PersonTokenRecord{}, ErrPersonTokenNotFound
	}
	return record, nil
}

func (store *memoryMissionStore) CommitMission(_ context.Context, mission MissionRecord, tokens []PersonTokenRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.commitMissionError != nil {
		return store.commitMissionError
	}
	missionKey := mission.Agent + "\x00" + mission.S256
	if _, exists := store.missions[missionKey]; exists {
		return errors.New("mission already exists")
	}
	batch := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		key := token.PersonServer + "\x00" + token.JTI
		if _, exists := store.records[key]; exists {
			return errors.New("person token already exists")
		}
		if _, duplicate := batch[key]; duplicate {
			return errors.New("person token is duplicated within mission approval")
		}
		batch[key] = struct{}{}
	}
	store.missions[missionKey] = cloneMissionRecord(mission)
	for _, token := range tokens {
		store.records[token.PersonServer+"\x00"+token.JTI] = token
	}
	return nil
}

func (store *memoryMissionStore) LoadMissionForAgent(_ context.Context, agent, s256 string, at time.Time) (MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := agent + "\x00" + s256
	record, exists := store.missions[key]
	if !exists {
		return MissionRecord{}, ErrMissionNotFound
	}
	if record.State == MissionActive && !record.ExpiresAt.IsZero() && !at.Before(record.ExpiresAt) {
		record.State = MissionTerminated
		record.TerminationReason = "expired"
		store.missions[key] = cloneMissionRecord(record)
	}
	return cloneMissionRecord(record), nil
}

func (store *memoryMissionStore) AppendMissionUpdate(
	_ context.Context, expected MissionRecord, acceptedAt time.Time, document aauth.MissionUpdateDocument,
) (MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.appendMissionError != nil {
		return MissionRecord{}, store.appendMissionError
	}
	if err := validateMissionAcceptanceInstant(acceptedAt); err != nil {
		return MissionRecord{}, err
	}
	if err := store.requireActiveMissionLocked(expected, acceptedAt); err != nil {
		return MissionRecord{}, err
	}
	key := expected.Agent + "\x00" + expected.S256
	current := store.missions[key]
	current.AcceptedUpdates = append(current.AcceptedUpdates, MissionUpdateRecord{
		Document: cloneTestMissionUpdateDocument(document), AcceptedAt: acceptedAt,
	})
	store.missions[key] = cloneMissionRecord(current)
	return cloneMissionRecord(current), nil
}

func (store *memoryMissionStore) CompleteMission(
	_ context.Context, expected MissionRecord, acceptedAt time.Time, document aauth.MissionCompletionDocument,
) (MissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.completeMissionError != nil {
		return MissionRecord{}, store.completeMissionError
	}
	if err := validateMissionAcceptanceInstant(acceptedAt); err != nil {
		return MissionRecord{}, err
	}
	if err := store.requireActiveMissionLocked(expected, acceptedAt); err != nil {
		return MissionRecord{}, err
	}
	key := expected.Agent + "\x00" + expected.S256
	current := store.missions[key]
	current.State = MissionTerminated
	current.TerminationReason = "completed"
	current.Completion = &MissionCompletionRecord{
		Document: cloneTestMissionCompletionDocument(document), AcceptedAt: acceptedAt,
	}
	store.missions[key] = cloneMissionRecord(current)
	return cloneMissionRecord(current), nil
}

func (store *memoryMissionStore) CommitMissionPersonToken(
	_ context.Context, expected MissionRecord, decidedAt time.Time, token PersonTokenRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMissionLocked(expected, decidedAt); err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 || token.Agent != expected.Agent {
		return ErrMissionConflict
	}
	key := token.PersonServer + "\x00" + token.JTI
	if _, exists := store.records[key]; exists {
		return errors.New("person token already exists")
	}
	store.records[key] = token
	return nil
}

func (store *memoryMissionStore) CommitMissionAuthToken(
	_ context.Context, expected MissionRecord, decidedAt time.Time, token IssuedAuthTokenRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireActiveMissionLocked(expected, decidedAt); err != nil {
		return err
	}
	if token.MissionS256 != expected.S256 {
		return ErrMissionConflict
	}
	key := token.Reference.Issuer + "\x00" + token.Reference.JTI
	if _, exists := store.authTokens[key]; exists {
		return errors.New("auth token already exists")
	}
	store.authTokens[key] = token
	return nil
}

func (store *memoryMissionStore) terminateMission(agent, s256, reason string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := agent + "\x00" + s256
	record := store.missions[key]
	record.State = MissionTerminated
	record.TerminationReason = reason
	store.missions[key] = record
}

func (store *memoryMissionStore) requireActiveMissionLocked(expected MissionRecord, at time.Time) error {
	key := expected.Agent + "\x00" + expected.S256
	current, exists := store.missions[key]
	if !exists {
		return ErrMissionNotFound
	}
	if current.State == MissionActive && !current.ExpiresAt.IsZero() && !at.Before(current.ExpiresAt) {
		current.State = MissionTerminated
		current.TerminationReason = "expired"
		store.missions[key] = cloneMissionRecord(current)
	}
	if current.State == MissionTerminated {
		return &MissionTerminatedError{TerminationReason: current.TerminationReason}
	}
	if !current.Equal(expected) {
		return ErrMissionConflict
	}
	return nil
}

func cloneMissionRecord(record MissionRecord) MissionRecord {
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	record.Capabilities = append([]string(nil), record.Capabilities...)
	record.AcceptedUpdates = append([]MissionUpdateRecord(nil), record.AcceptedUpdates...)
	for index := range record.AcceptedUpdates {
		record.AcceptedUpdates[index].Document = cloneTestMissionUpdateDocument(record.AcceptedUpdates[index].Document)
	}
	if record.Completion != nil {
		completion := *record.Completion
		completion.Document = cloneTestMissionCompletionDocument(completion.Document)
		record.Completion = &completion
	}
	return record
}

func cloneTestMissionUpdateDocument(document aauth.MissionUpdateDocument) aauth.MissionUpdateDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}

func cloneTestMissionCompletionDocument(document aauth.MissionCompletionDocument) aauth.MissionCompletionDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}

func assertMissionProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code, missionStatus, reason string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, status, response.Body.String())
	}
	var problem struct {
		Error             string `json:"error"`
		MissionStatus     string `json:"mission_status"`
		TerminationReason string `json:"termination_reason"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Error != code || problem.MissionStatus != missionStatus || problem.TerminationReason != reason {
		t.Fatalf("problem = %#v", problem)
	}
}
