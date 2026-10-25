package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestMissionCompositionRejectsSubagentBeforePolicyOrRetention(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{"person", "token"} {
		endpoint := endpoint
		t.Run(endpoint, func(t *testing.T) {
			t.Parallel()

			protocol := newSubagentPersonServerProtocol(t)
			store := newMemoryMissionStore()
			mission := commitCompositionMission(
				t, store, "https://ps.example", "aauth:planner@ap.example", protocol.now,
			)
			server, err := NewPSAuthorization(PSAuthorizationConfig{
				Issuer: "https://ps.example", SigningKey: protocol.personKey,
				KeyResolver: protocol.resolver, Clock: protocol.clock,
				NewID: func() string { return "unreachable-token" }, Tokens: store,
				BindPerson: protocol.policyPerson, Authorize: protocol.policyAuthorization,
				Missions: unusedCompositionMissionConfig(),
			})
			if err != nil {
				t.Fatal(err)
			}
			assertValidCompositionSubagent(t, protocol)
			before := snapshotCompositionMissionStore(store)

			var response *httptest.ResponseRecorder
			switch endpoint {
			case "person":
				response = signedCompositionRequest(t, server, "https://ps.example/person", map[string]any{
					"resource":       "https://resource.example",
					"mission_s256":   mission.S256,
					"subagent_token": protocol.childToken,
				}, protocol.parentKey, protocol.parentToken, protocol.clock)
			case "token":
				resourceToken := mintCompositionResourceToken(
					t, protocol.resourceKey, "https://resource.example", "https://ps.example",
					"https://ps.example", "person-123", "unreachable-person-token",
					protocol.childKey.PublicJWK(), mission.S256, protocol.now,
				)
				response = signedCompositionRequest(t, server, "https://ps.example/token", map[string]any{
					"resource_token":  resourceToken,
					"presented_token": testPresentedPersonToken(t, protocol.personKey, resourceToken, protocol.childKey.PublicJWK(), protocol.now, protocol.now.Add(10*time.Minute)),
					"subagent_token":  protocol.childToken,
				}, protocol.parentKey, protocol.parentToken, protocol.clock)
			}

			assertCompositionProblem(t, response, http.StatusBadRequest, "invalid_request")
			if protocol.bindCalls != 0 || protocol.authorizationCalls != 0 {
				t.Fatalf("unsupported mission/sub-agent composition reached policy: bind=%d authorize=%d", protocol.bindCalls, protocol.authorizationCalls)
			}
			assertCompositionMissionStoreUnchanged(t, store, before)
		})
	}
}

func TestMissionCompositionRejectsCallChainBeforePolicyOrRetention(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{"person", "token"} {
		endpoint := endpoint
		t.Run(endpoint, func(t *testing.T) {
			t.Parallel()

			protocol := newCallChainingProtocol(t)
			store := newMemoryMissionStore()
			mission := commitCompositionMission(
				t, store, protocol.personServerID,
				"aauth:resource-one@resource-one.example", protocol.now,
			)
			config := protocol.config()
			config.Tokens = store
			config.Missions = unusedCompositionMissionConfig()
			server := protocol.newServer(t, config)
			assertValidCompositionUpstream(t, protocol)
			before := snapshotCompositionMissionStore(store)

			var response *httptest.ResponseRecorder
			switch endpoint {
			case "person":
				response = signedCompositionRequest(t, server, protocol.personServerID+"/person", map[string]any{
					"resource":       protocol.resourceTwoID,
					"mission_s256":   mission.S256,
					"upstream_token": protocol.upstreamToken,
				}, protocol.resourceOneProofKey, protocol.resourceOneIDToken, protocol.clock)
			case "token":
				resourceToken := mintCompositionResourceToken(
					t, protocol.resourceTwoKey, protocol.resourceTwoID, protocol.personServerID,
					protocol.personServerID, protocol.downstreamSubject, "unreachable-person-token",
					protocol.resourceOneProofKey.PublicJWK(), mission.S256, protocol.now,
				)
				response = signedCompositionRequest(t, server, protocol.personServerID+"/token", map[string]any{
					"resource_token":  resourceToken,
					"presented_token": testPresentedPersonToken(t, protocol.personServerKey, resourceToken, protocol.resourceOneProofKey.PublicJWK(), protocol.now, protocol.now.Add(10*time.Minute)),
					"upstream_token":  protocol.upstreamToken,
				}, protocol.resourceOneProofKey, protocol.resourceOneIDToken, protocol.clock)
			}

			assertCompositionProblem(t, response, http.StatusBadRequest, "invalid_request")
			if protocol.ordinaryBindCalls != 0 || protocol.chainBindCalls != 0 ||
				protocol.ordinaryAuthorizeCalls != 0 || protocol.chainAuthorizeCalls != 0 {
				t.Fatalf(
					"unsupported mission/call-chain composition reached policy: ordinary=%d/%d chain=%d/%d",
					protocol.ordinaryBindCalls, protocol.ordinaryAuthorizeCalls,
					protocol.chainBindCalls, protocol.chainAuthorizeCalls,
				)
			}
			assertCompositionMissionStoreUnchanged(t, store, before)
		})
	}
}

func TestMissionCompositionRejectsDeferredPersonBeforeBindingOrRetention(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
	interactions := newMemoryDeferredTokenStore()
	requireCalls := 0
	protocol.server.deferredTokens = interactions
	protocol.server.requirePersonTokenInteraction = func(context.Context, PersonTokenRequest) (PersonTokenInteractionPolicy, bool, error) {
		requireCalls++
		return PersonTokenInteractionPolicy{}, true, nil
	}
	before := snapshotCompositionMissionStore(protocol.store)

	response := signedCompositionRequest(t, protocol.server, protocol.personServerID+"/person", map[string]any{
		"resource": protocol.resourceID, "mission_s256": mission.S256, "capabilities": []string{"interaction"},
	}, protocol.agentKey, protocol.agentToken, protocol.clock)

	assertCompositionProblem(t, response, http.StatusInternalServerError, "server_error")
	if requireCalls != 1 || len(protocol.bindings) != 0 {
		t.Fatalf("mission/deferred person path calls: requirement=%d binding=%d", requireCalls, len(protocol.bindings))
	}
	if interactions.pendingCount() != 0 || interactions.tokenCommitCount() != 0 {
		t.Fatalf("mission/deferred person path retained state: pending=%d tokens=%d", interactions.pendingCount(), interactions.tokenCommitCount())
	}
	assertCompositionMissionStoreUnchanged(t, protocol.store, before)
}

func TestMissionCompositionRejectsDeferredAuthorizationBeforeAuthorizationOrRetention(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	resourceKey := personServerTestKey(t, "mission-composition-resource")
	protocol.resolver[signaturekey.StaticKeyReference{
		Issuer: protocol.resourceID, DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: resourceKey.ID(),
	}] = resourceKey.PublicJWK()
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")

	personResponse := signedCompositionRequest(t, protocol.server, protocol.personServerID+"/person", map[string]any{
		"resource": protocol.resourceID, "mission_s256": mission.S256,
	}, protocol.agentKey, protocol.agentToken, protocol.clock)
	if personResponse.Code != http.StatusOK {
		t.Fatalf("prepare mission person token = %d %s", personResponse.Code, personResponse.Body.String())
	}
	var personOutput struct {
		PersonToken string `json:"person_token"`
	}
	if err := json.Unmarshal(personResponse.Body.Bytes(), &personOutput); err != nil {
		t.Fatal(err)
	}
	personClaims, err := aauth.VerifyPersonToken(context.Background(), personOutput.PersonToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	resourceToken := mintCompositionResourceToken(
		t, resourceKey, protocol.resourceID, protocol.personServerID,
		protocol.personServerID, personClaims.Subject, personClaims.JTI,
		protocol.agentKey.PublicJWK(), mission.S256, protocol.now,
	)

	interactions := newMemoryDeferredAuthorizationStore()
	requireCalls := 0
	authorizeCalls := 0
	protocol.server.authorizationInteractions = interactions
	protocol.server.requireAuthorizationInteraction = func(context.Context, AuthorizationRequest) (AuthorizationInteractionPolicy, bool, error) {
		requireCalls++
		return AuthorizationInteractionPolicy{}, true, nil
	}
	protocol.server.authorize = func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
		authorizeCalls++
		return AuthorizationDecision{Scopes: []string{"records.read"}, Lifetime: time.Minute}, nil
	}
	before := snapshotCompositionMissionStore(protocol.store)

	response := signedCompositionRequest(t, protocol.server, protocol.personServerID+"/token", map[string]any{
		"resource_token":  resourceToken,
		"presented_token": personOutput.PersonToken,
		"capabilities":    []string{"interaction"},
	}, protocol.agentKey, protocol.agentToken, protocol.clock)

	assertCompositionProblem(t, response, http.StatusInternalServerError, "server_error")
	if requireCalls != 1 || authorizeCalls != 0 {
		t.Fatalf("mission/deferred authorization calls: requirement=%d authorization=%d", requireCalls, authorizeCalls)
	}
	if interactions.pendingCount() != 0 {
		t.Fatalf("mission/deferred authorization retained %d pending records", interactions.pendingCount())
	}
	assertCompositionMissionStoreUnchanged(t, protocol.store, before)
}

func unusedCompositionMissionConfig() *MissionConfig {
	return &MissionConfig{
		Approve: func(context.Context, MissionApprovalRequest) (MissionDecision, error) {
			return MissionDecision{Description: "unreachable approval"}, nil
		},
		AcceptUpdate: func(context.Context, MissionUpdatePolicyRequest) error { return nil },
		ConfirmPersonAcceptedCompletion: func(context.Context, MissionCompletionPolicyRequest) error {
			return nil
		},
	}
}

func commitCompositionMission(
	t *testing.T,
	store *memoryMissionStore,
	personServer string,
	agent string,
	now time.Time,
) MissionRecord {
	t.Helper()
	expiresAt := now.Add(10 * time.Minute)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: personServer, Agent: agent, ApprovedAt: now.Add(-time.Minute),
		ExpiresAt: &expiresAt, Description: "Composition boundary test",
	})
	if err != nil {
		t.Fatal(err)
	}
	record := MissionRecord{
		S256: mission.S256, Agent: agent, ExactJSON: append([]byte(nil), mission.ExactJSON...),
		ApprovedAt: mission.Blob.ApprovedAt, ExpiresAt: expiresAt, State: MissionActive,
	}
	if err := store.CommitMission(context.Background(), record, nil); err != nil {
		t.Fatal(err)
	}
	return record
}

func assertValidCompositionSubagent(t *testing.T, protocol *subagentPersonServerProtocol) {
	t.Helper()
	claims, err := aauth.VerifyAgentToken(context.Background(), protocol.childToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ParentAgent != "aauth:planner@ap.example" || claims.Subject != "aauth:planner+search@ap.example" {
		t.Fatalf("sub-agent token = %#v", claims)
	}
}

func assertValidCompositionUpstream(t *testing.T, protocol *callChainingProtocol) {
	t.Helper()
	claims, err := aauth.VerifyAuthToken(context.Background(), protocol.upstreamToken, protocol.resolver, protocol.clock)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != protocol.personServerID || claims.Audience != protocol.resourceOneID || claims.JTI != protocol.upstreamClaims.JTI {
		t.Fatalf("upstream token = %#v", claims)
	}
}

func mintCompositionResourceToken(
	t *testing.T,
	issuerKey jose.SigningKey,
	issuer string,
	audience string,
	personServer string,
	subject string,
	presentedJTI string,
	agentKey jose.JWK,
	missionS256 string,
	now time.Time,
) string {
	t.Helper()
	jkt, err := agentKey.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	compact, err := aauth.MintResourceToken(issuerKey, aauth.ResourceTokenClaims{
		Issuer: issuer, DWK: aauth.ResourceDiscoveryDocument,
		Audience: audience, JTI: "mission-composition-resource-token", AgentJKT: jkt,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix(), Scope: "records.read",
		PersonServer: personServer, Subject: subject, PresentedJTI: presentedJTI,
		MissionS256: missionS256,
	})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func signedCompositionRequest(
	t *testing.T,
	server *Server,
	endpoint string,
	body any,
	key jose.SigningKey,
	agentToken string,
	clock aauth.Clock,
) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, key, agentToken, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

type compositionMissionStoreSnapshot struct {
	missions map[string]MissionRecord
	records  map[string]PersonTokenRecord
	auth     map[string]IssuedAuthTokenRecord
}

func snapshotCompositionMissionStore(store *memoryMissionStore) compositionMissionStoreSnapshot {
	store.mu.Lock()
	defer store.mu.Unlock()
	snapshot := compositionMissionStoreSnapshot{
		missions: make(map[string]MissionRecord, len(store.missions)),
		records:  make(map[string]PersonTokenRecord, len(store.records)),
		auth:     make(map[string]IssuedAuthTokenRecord, len(store.authTokens)),
	}
	for key, mission := range store.missions {
		snapshot.missions[key] = cloneMissionRecord(mission)
	}
	for key, record := range store.records {
		snapshot.records[key] = record
	}
	for key, record := range store.authTokens {
		snapshot.auth[key] = record
	}
	return snapshot
}

func assertCompositionMissionStoreUnchanged(
	t *testing.T,
	store *memoryMissionStore,
	want compositionMissionStoreSnapshot,
) {
	t.Helper()
	got := snapshotCompositionMissionStore(store)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unsupported composition mutated mission store:\ngot  %#v\nwant %#v", got, want)
	}
}

func assertCompositionProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var problem struct {
		Code string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem: %v; status=%d body=%s", err, response.Code, response.Body.String())
	}
	if response.Code != status || problem.Code != code {
		t.Fatalf("problem = %d %#v, want %d %q; body=%s", response.Code, problem, status, code, response.Body.String())
	}
}
