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
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestPermissionConfigurationAndMetadataAreExplicitForBothPersonServerModes(t *testing.T) {
	for _, mode := range []string{"direct", "federated"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			protocol := newPermissionProtocol(t)
			base := protocol.config(mode, nil)
			server := protocol.newServer(t, mode, base)
			metadata := permissionMetadata(t, server)
			if _, present := metadata["permission_endpoint"]; present {
				t.Fatal("permission_endpoint advertised without explicit configuration")
			}
			response := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, `{"action":"SendEmail"}`)
			assertPermissionProblem(t, response, http.StatusNotFound, "")

			for _, test := range []struct {
				name       string
				permission *PermissionConfig
			}{
				{name: "policy only", permission: &PermissionConfig{Policy: protocol.policy}},
				{name: "store only", permission: &PermissionConfig{Store: newMemoryPermissionStore()}},
			} {
				t.Run(test.name, func(t *testing.T) {
					if _, err := protocol.construct(mode, test.permission); err == nil {
						t.Fatal("unpaired Permission configuration was accepted")
					}
				})
			}

			store := newMemoryPermissionStore()
			server = protocol.newServer(t, mode, protocol.config(mode, &PermissionConfig{Policy: protocol.policy, Store: store}))
			metadata = permissionMetadata(t, server)
			if metadata["permission_endpoint"] != protocol.personServerID+"/permission" {
				t.Fatalf("permission_endpoint = %q", metadata["permission_endpoint"])
			}
		})
	}
}

func TestMissionPermissionConfigurationUsesTheMissionTokenStoreBoundary(t *testing.T) {
	protocol := newPermissionProtocol(t)
	config := protocol.config("direct", nil).(PSAuthorizationConfig)
	config.Missions = permissionMissionConfig()
	config.Permission = &PermissionConfig{Policy: protocol.policy}
	config.Tokens = newMemoryMissionStore()
	if _, err := NewPSAuthorization(config); err == nil || !strings.Contains(err.Error(), "MissionPermissionStore") {
		t.Fatalf("mission-only Tokens error = %v", err)
	}

	store := newMissionPermissionTestStore()
	config.Tokens = store
	config.Permission.Store = store
	if _, err := NewPSAuthorization(config); err == nil || !strings.Contains(err.Error(), "supplied through Tokens") {
		t.Fatalf("duplicated store configuration error = %v", err)
	}
	config.Permission.Store = nil
	if _, err := NewPSAuthorization(config); err != nil {
		t.Fatalf("mission permission configuration = %v", err)
	}
}

func TestPermissionImmediateDecisionRetainedBeforeResponse(t *testing.T) {
	for _, permission := range []aauth.Permission{aauth.PermissionGranted, aauth.PermissionDenied} {
		permission := permission
		t.Run(string(permission), func(t *testing.T) {
			protocol := newPermissionProtocol(t)
			store := newMemoryPermissionStore()
			protocol.policyResult = PermissionPolicyResult{Immediate: &PermissionDecision{Permission: permission}}
			if permission == aauth.PermissionDenied {
				protocol.policyResult.Immediate.Reason = "**Person policy** refused this action"
			}
			server := protocol.newServer(t, "direct", protocol.config("direct", &PermissionConfig{
				Policy: protocol.policy, Store: store,
			}))
			response := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
				`{"action":"SendEmail","description":"Send the itinerary","parameters":{"to":"person@example"}}`)
			if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("immediate response = %d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
			}
			var body struct {
				Permission aauth.Permission `json:"permission"`
				Reason     string           `json:"reason"`
			}
			if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Permission != permission || body.Reason != protocol.policyResult.Immediate.Reason {
				t.Fatalf("immediate body = %#v", body)
			}
			record := store.onlyRecord(t)
			if record.State != permissionStateForDecision(*protocol.policyResult.Immediate) ||
				record.Decision != *protocol.policyResult.Immediate || record.PersonServer != protocol.personServerID ||
				record.AgentProvider != protocol.providerID || record.Agent != protocol.agentID ||
				record.Action != "SendEmail" || record.Description != "Send the itinerary" ||
				!bytes.Equal(record.Parameters, []byte(`{"to":"person@example"}`)) ||
				!record.CreatedAt.Equal(protocol.now) || !record.DecidedAt.Equal(protocol.now) {
				t.Fatalf("retained immediate record = %#v", record)
			}
			if got := record.AgentAdditionalClaims["platform_attestation"]; !bytes.Equal(got, []byte(`{"level":"example"}`)) {
				t.Fatalf("retained Agent claims = %s", got)
			}
		})
	}
}

func TestPermissionPolicyInputIsOwnedAndNeverExecutesTheAction(t *testing.T) {
	protocol := newPermissionProtocol(t)
	store := newMemoryPermissionStore()
	policyCalls := 0
	policy := func(_ context.Context, request PermissionPolicyRequest) (PermissionPolicyResult, error) {
		policyCalls++
		if request.AgentProvider != protocol.providerID || request.Agent != protocol.agentID ||
			request.Action != "DeleteFile" || request.Description != "Delete an obsolete draft" ||
			!bytes.Equal(request.Parameters, []byte(`{"path":"draft.txt"}`)) {
			return PermissionPolicyResult{}, errors.New("unexpected permission policy request")
		}
		request.Parameters[0] = '['
		request.AgentAdditionalClaims["platform_attestation"][0] = '['
		return PermissionPolicyResult{Immediate: &PermissionDecision{Permission: aauth.PermissionGranted}}, nil
	}
	server := protocol.newServer(t, "direct", protocol.config("direct", &PermissionConfig{Policy: policy, Store: store}))
	response := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
		`{"action":"DeleteFile","description":"Delete an obsolete draft","parameters":{"path":"draft.txt"}}`)
	if response.Code != http.StatusOK || policyCalls != 1 {
		t.Fatalf("response/policy calls = %d/%d body=%s", response.Code, policyCalls, response.Body.String())
	}
	record := store.onlyRecord(t)
	if !bytes.Equal(record.Parameters, []byte(`{"path":"draft.txt"}`)) ||
		!bytes.Equal(record.AgentAdditionalClaims["platform_attestation"], []byte(`{"level":"example"}`)) {
		t.Fatalf("policy mutation escaped into retained record = %#v", record)
	}
}

func TestMissionPermissionImmediateDecisionUsesExactActiveMission(t *testing.T) {
	protocol := newPermissionProtocol(t)
	store := newMissionPermissionTestStore()
	expiresAt := protocol.now.Add(20 * time.Minute)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: protocol.personServerID, Agent: protocol.agentID,
		ApprovedAt: protocol.now.Add(-time.Minute), ExpiresAt: &expiresAt,
		Description: "Prepare and send the reviewed itinerary.",
	})
	if err != nil {
		t.Fatal(err)
	}
	update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{
		Action: "update", Description: "Use the final approved recipient list.",
	})
	if err != nil {
		t.Fatal(err)
	}
	missionRecord := MissionRecord{
		S256: mission.S256, Agent: protocol.agentID, ExactJSON: mission.ExactJSON,
		ApprovedAt: mission.Blob.ApprovedAt, ExpiresAt: expiresAt, State: MissionActive,
		AcceptedUpdates: []MissionUpdateRecord{{
			Document:   update,
			AcceptedAt: protocol.now.Add(-30 * time.Second),
		}},
	}
	if err := store.CommitMission(context.Background(), missionRecord, nil); err != nil {
		t.Fatal(err)
	}
	policyCalls := 0
	policy := func(_ context.Context, request PermissionPolicyRequest) (PermissionPolicyResult, error) {
		policyCalls++
		if request.Mission == nil || request.Mission.S256 != mission.S256 ||
			request.Mission.Blob.Description != mission.Blob.Description ||
			len(request.Mission.AcceptedUpdates) != 1 {
			t.Fatalf("mission policy context = %#v", request.Mission)
		}
		request.Mission.ExactJSON[0] = 'x'
		request.Mission.AcceptedUpdates[0].Document.ExactJSON[0] = 'x'
		return PermissionPolicyResult{Immediate: &PermissionDecision{Permission: aauth.PermissionGranted}}, nil
	}
	config := protocol.config("direct", nil).(PSAuthorizationConfig)
	config.Tokens = store
	config.Missions = permissionMissionConfig()
	config.Permission = &PermissionConfig{Policy: policy}
	server := protocol.newServer(t, "direct", config)
	response := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
		`{"action":"SendEmail","mission_s256":"`+mission.S256+`"}`)
	if response.Code != http.StatusOK || policyCalls != 1 || store.createMissionCalls != 1 {
		t.Fatalf("response=%d %s policy=%d mission creates=%d", response.Code, response.Body.String(), policyCalls, store.createMissionCalls)
	}
	retained := store.onlyRecord(t)
	if retained.MissionS256 != mission.S256 || retained.State != PermissionStateGranted {
		t.Fatalf("retained mission permission = %#v", retained)
	}
	reloaded, err := store.LoadMissionForAgent(context.Background(), protocol.agentID, mission.S256, protocol.now)
	if err != nil || reloaded.ExactJSON[0] != '{' || reloaded.AcceptedUpdates[0].Document.ExactJSON[0] != '{' {
		t.Fatalf("policy mutation changed mission = %#v, %v", reloaded, err)
	}
}

func TestMissionPermissionImmediateDecisionRefusesExpiryDuringPolicy(t *testing.T) {
	protocol := newPermissionProtocol(t)
	store := newMissionPermissionTestStore()
	expiresAt := protocol.now.Add(time.Minute)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: protocol.personServerID, Agent: protocol.agentID,
		ApprovedAt: protocol.now.Add(-time.Minute), ExpiresAt: &expiresAt,
		Description: "Prepare the reviewed itinerary.",
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
	policy := func(context.Context, PermissionPolicyRequest) (PermissionPolicyResult, error) {
		protocol.now = expiresAt
		return PermissionPolicyResult{Immediate: &PermissionDecision{Permission: aauth.PermissionGranted}}, nil
	}
	config := protocol.config("direct", nil).(PSAuthorizationConfig)
	config.Tokens = store
	config.Missions = permissionMissionConfig()
	config.Permission = &PermissionConfig{Policy: policy}
	server := protocol.newServer(t, "direct", config)
	response := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
		`{"action":"files.write","mission_s256":"`+mission.S256+`"}`)
	assertPermissionProblem(t, response, http.StatusForbidden, "mission_terminated")
	if store.count() != 0 {
		t.Fatalf("expired mission retained %d permission records", store.count())
	}
}

func TestMissionPermissionDeferredGrantRefusesTerminatedMission(t *testing.T) {
	protocol := newPermissionProtocol(t)
	store := newMissionPermissionTestStore()
	expiresAt := protocol.now.Add(20 * time.Minute)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: protocol.personServerID, Agent: protocol.agentID,
		ApprovedAt: protocol.now.Add(-time.Minute), ExpiresAt: &expiresAt,
		Description: "Prepare the reviewed itinerary.",
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
	policy := func(context.Context, PermissionPolicyRequest) (PermissionPolicyResult, error) {
		return PermissionPolicyResult{Deferred: &PermissionPendingPolicy{Lifetime: 5 * time.Minute}}, nil
	}
	config := protocol.config("direct", nil).(PSAuthorizationConfig)
	config.Tokens = store
	config.Missions = permissionMissionConfig()
	config.Permission = &PermissionConfig{Policy: policy}
	server := protocol.newServer(t, "direct", config)
	response := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
		`{"action":"files.write","mission_s256":"`+mission.S256+`"}`)
	if response.Code != http.StatusAccepted {
		t.Fatalf("deferred response = %d %s", response.Code, response.Body.String())
	}
	otherKey := personServerTestKey(t, "mission-permission-other-agent")
	otherToken, err := aauth.MintAgentToken(protocol.providerID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:other@provider.example", PersonServer: protocol.personServerID,
		PublicKey: otherKey.PublicJWK(), Lifetime: 30 * time.Minute,
	}, protocol.now, "mission-permission-other-token")
	if err != nil {
		t.Fatal(err)
	}
	wrongAgent := pollPermission(
		t, protocol, server, otherKey, otherToken, response.Header().Get("Location"),
	)
	assertPermissionProblem(t, wrongAgent, http.StatusGone, "invalid_code")
	record := store.onlyRecord(t)
	handle, err := server.ResumePermission(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	missionContext, ok := handle.Mission()
	if !ok || missionContext.S256 != mission.S256 || missionContext.Blob.Description != mission.Blob.Description {
		t.Fatalf("deferred mission context = %#v, %t", missionContext, ok)
	}
	update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{
		Action: "update", Description: "Use the final approved message body.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendMissionUpdate(context.Background(), missionRecord, protocol.now.Add(time.Second), update); err != nil {
		t.Fatal(err)
	}
	if err := server.GrantPermission(context.Background(), handle); !errors.Is(err, ErrMissionConflict) {
		t.Fatalf("grant against changed mission = %v", err)
	}
	handle, err = server.ResumePermission(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	missionContext, ok = handle.Mission()
	if !ok || len(missionContext.AcceptedUpdates) != 1 {
		t.Fatalf("resumed updated mission context = %#v, %t", missionContext, ok)
	}
	store.terminateMission(protocol.agentID, mission.S256, "revoked")
	if err := server.GrantPermission(context.Background(), handle); err == nil {
		t.Fatal("grant succeeded after mission termination")
	} else {
		var terminated *MissionTerminatedError
		if !errors.As(err, &terminated) || terminated.TerminationReason != "revoked" {
			t.Fatalf("grant error = %T %v", err, err)
		}
	}
	retained := store.onlyRecord(t)
	if retained.State != PermissionStatePending || retained.Decision != (PermissionDecision{}) {
		t.Fatalf("terminated mission changed permission = %#v", retained)
	}
}

func TestMissionPermissionPollDoesNotDeliverGrantAfterTermination(t *testing.T) {
	protocol := newPermissionProtocol(t)
	store := newMissionPermissionTestStore()
	expiresAt := protocol.now.Add(20 * time.Minute)
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Approver: protocol.personServerID, Agent: protocol.agentID,
		ApprovedAt: protocol.now.Add(-time.Minute), ExpiresAt: &expiresAt,
		Description: "Prepare the reviewed itinerary.",
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
	policy := func(context.Context, PermissionPolicyRequest) (PermissionPolicyResult, error) {
		return PermissionPolicyResult{Deferred: &PermissionPendingPolicy{Lifetime: 5 * time.Minute}}, nil
	}
	config := protocol.config("direct", nil).(PSAuthorizationConfig)
	config.Tokens = store
	config.Missions = permissionMissionConfig()
	config.Permission = &PermissionConfig{Policy: policy}
	server := protocol.newServer(t, "direct", config)
	response := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
		`{"action":"files.write","mission_s256":"`+mission.S256+`"}`)
	if response.Code != http.StatusAccepted {
		t.Fatalf("deferred response = %d %s", response.Code, response.Body.String())
	}
	record := store.onlyRecord(t)
	handle, err := server.ResumePermission(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.GrantPermission(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	store.terminateMission(protocol.agentID, mission.S256, "revoked")
	poll := pollPermission(t, protocol, server, protocol.agentKey, protocol.agentToken, response.Header().Get("Location"))
	assertPermissionProblem(t, poll, http.StatusForbidden, "mission_terminated")
	retained := store.onlyRecord(t)
	if retained.State != PermissionStateGranted {
		t.Fatalf("poll after termination changed permission = %#v", retained)
	}
}

func TestPermissionRejectsMissionAndInvalidShapesBeforePolicyOrStore(t *testing.T) {
	protocol := newPermissionProtocol(t)
	store := newMemoryPermissionStore()
	server := protocol.newServer(t, "direct", protocol.config("direct", &PermissionConfig{Policy: protocol.policy, Store: store}))
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "mission", body: `{"action":"SendEmail","mission_s256":null}`},
		{name: "empty action", body: `{"action":"   "}`},
		{name: "invalid UTF-8 action", body: "{\"action\":\"" + string([]byte{0xff}) + "\"}"},
		{name: "oversized action", body: `{"action":"` + strings.Repeat("a", maximumPermissionActionBytes+1) + `"}`},
		{name: "invalid UTF-8 description", body: "{\"action\":\"SendEmail\",\"description\":\"" + string([]byte{0xff}) + "\"}"},
		{name: "oversized description", body: `{"action":"SendEmail","description":"` + strings.Repeat("d", maximumPermissionDescriptionBytes+1) + `"}`},
		{name: "null parameters", body: `{"action":"SendEmail","parameters":null}`},
		{name: "array parameters", body: `{"action":"SendEmail","parameters":[]}`},
		{name: "scalar parameters", body: `{"action":"SendEmail","parameters":1}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, test.body)
			assertPermissionProblem(t, response, http.StatusBadRequest, "invalid_request")
		})
	}
	if protocol.policyCalls != 0 || store.count() != 0 {
		t.Fatalf("invalid requests reached policy/store = %d/%d", protocol.policyCalls, store.count())
	}
}

func TestPermissionRejectsInvalidPolicyResultAndStoreFailure(t *testing.T) {
	for _, test := range []struct {
		name   string
		result PermissionPolicyResult
	}{
		{name: "empty"},
		{name: "both", result: PermissionPolicyResult{
			Immediate: &PermissionDecision{Permission: aauth.PermissionGranted},
			Deferred:  &PermissionPendingPolicy{Lifetime: time.Minute},
		}},
		{name: "unknown decision", result: PermissionPolicyResult{Immediate: &PermissionDecision{Permission: aauth.Permission("future")}}},
		{name: "granted reason", result: PermissionPolicyResult{Immediate: &PermissionDecision{Permission: aauth.PermissionGranted, Reason: "not allowed"}}},
		{name: "oversized reason", result: PermissionPolicyResult{Immediate: &PermissionDecision{Permission: aauth.PermissionDenied, Reason: strings.Repeat("r", maximumPermissionReasonBytes+1)}}},
		{name: "invalid UTF-8 reason", result: PermissionPolicyResult{Immediate: &PermissionDecision{Permission: aauth.PermissionDenied, Reason: string([]byte{0xff})}}},
		{name: "zero lifetime", result: PermissionPolicyResult{Deferred: &PermissionPendingPolicy{}}},
		{name: "fractional lifetime", result: PermissionPolicyResult{Deferred: &PermissionPendingPolicy{Lifetime: time.Second + time.Nanosecond}}},
		{name: "negative retry", result: PermissionPolicyResult{Deferred: &PermissionPendingPolicy{Lifetime: time.Minute, RetryAfter: -time.Second}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newPermissionProtocol(t)
			protocol.policyResult = test.result
			store := newMemoryPermissionStore()
			server := protocol.newServer(t, "direct", protocol.config("direct", &PermissionConfig{Policy: protocol.policy, Store: store}))
			response := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, `{"action":"SendEmail"}`)
			assertPermissionProblem(t, response, http.StatusInternalServerError, "server_error")
			if store.count() != 0 {
				t.Fatalf("invalid policy result retained %d records", store.count())
			}
		})
	}

	protocol := newPermissionProtocol(t)
	store := newMemoryPermissionStore()
	store.createErr = errors.New("permission store unavailable")
	server := protocol.newServer(t, "direct", protocol.config("direct", &PermissionConfig{Policy: protocol.policy, Store: store}))
	response := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, `{"action":"SendEmail"}`)
	assertPermissionProblem(t, response, http.StatusInternalServerError, "server_error")
}

func TestDeferredPermissionSurvivesRecompositionAndConsumesEachDecision(t *testing.T) {
	for _, decision := range []PermissionDecision{
		{Permission: aauth.PermissionGranted},
		{Permission: aauth.PermissionDenied, Reason: "**Person policy** denied this request"},
	} {
		decision := decision
		t.Run(string(decision.Permission), func(t *testing.T) {
			protocol := newPermissionProtocol(t)
			store := newMemoryPermissionStore()
			protocol.policyResult = PermissionPolicyResult{Deferred: &PermissionPendingPolicy{
				Lifetime: 2 * time.Minute, RetryAfter: 3 * time.Second,
			}}
			config := protocol.config("direct", &PermissionConfig{Policy: protocol.policy, Store: store})
			server := protocol.newServer(t, "direct", config)
			response := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
				`{"action":"SendEmail","description":"Send the itinerary","parameters":{"to":"person@example"}}`)
			if response.Code != http.StatusAccepted || response.Header().Get("Cache-Control") != "no-store" ||
				response.Header().Get("Retry-After") != "3" {
				t.Fatalf("deferred response = %d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
			}
			location := response.Header().Get("Location")
			if !strings.HasPrefix(location, "/permission/pending/") {
				t.Fatalf("pending Location = %q", location)
			}
			record := store.onlyRecord(t)
			if record.State != PermissionStatePending || record.Decision != (PermissionDecision{}) ||
				!record.ExpiresAt.Equal(protocol.now.Add(2*time.Minute)) || record.RetryAfter != 3*time.Second {
				t.Fatalf("retained deferred record = %#v", record)
			}

			// A newly composed server can reconstruct the private host handle from
			// the shared purpose-specific store after process restart.
			recomposed := protocol.newServer(t, "direct", protocol.config("direct", &PermissionConfig{
				Policy: protocol.policy, Store: store,
			}))
			handle, err := recomposed.ResumePermission(context.Background(), record.ID)
			if err != nil {
				t.Fatal(err)
			}
			if handle.Reference() != record.ID || handle.AgentProvider() != protocol.providerID ||
				handle.Agent() != protocol.agentID || handle.Action() != "SendEmail" ||
				handle.Description() != "Send the itinerary" || !handle.ExpiresAt().Equal(record.ExpiresAt) {
				t.Fatalf("resumed permission = %#v", handle)
			}
			parameters := handle.Parameters()
			claims := handle.AgentAdditionalClaims()
			parameters[0] = '['
			claims["platform_attestation"][0] = '['
			if !bytes.Equal(handle.Parameters(), []byte(`{"to":"person@example"}`)) ||
				!bytes.Equal(handle.AgentAdditionalClaims()["platform_attestation"], []byte(`{"level":"example"}`)) {
				t.Fatal("permission handle exposed retained mutable values")
			}

			if decision.Permission == aauth.PermissionGranted {
				err = recomposed.GrantPermission(context.Background(), handle)
			} else {
				err = recomposed.DenyPermission(context.Background(), handle, decision.Reason)
			}
			if err != nil {
				t.Fatal(err)
			}
			terminal := store.onlyRecord(t)
			if terminal.State != permissionStateForDecision(decision) || terminal.Decision != decision ||
				!terminal.DecidedAt.Equal(protocol.now) {
				t.Fatalf("terminal permission record = %#v", terminal)
			}

			poll := pollPermission(t, protocol, recomposed, protocol.agentKey, protocol.agentToken, location)
			if poll.Code != http.StatusOK || poll.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("terminal poll = %d headers=%#v body=%s", poll.Code, poll.Header(), poll.Body.String())
			}
			var body PermissionDecision
			if err := json.NewDecoder(poll.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body != decision {
				t.Fatalf("terminal poll decision = %#v, want %#v", body, decision)
			}
			if store.onlyRecord(t).State != PermissionStateGone {
				t.Fatal("terminal result was not consumed before delivery")
			}
			poll = pollPermission(t, protocol, recomposed, protocol.agentKey, protocol.agentToken, location)
			assertPermissionProblem(t, poll, http.StatusGone, "invalid_code")
		})
	}
}

func TestPermissionPollCloaksWrongIdentityAndConsumesExpiry(t *testing.T) {
	protocol := newPermissionProtocol(t)
	store := newMemoryPermissionStore()
	protocol.policyResult = PermissionPolicyResult{Deferred: &PermissionPendingPolicy{Lifetime: time.Minute, RetryAfter: time.Second}}
	server := protocol.newServer(t, "direct", protocol.config("direct", &PermissionConfig{Policy: protocol.policy, Store: store}))
	created := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, `{"action":"SendEmail"}`)
	if created.Code != http.StatusAccepted {
		t.Fatalf("create response = %d %s", created.Code, created.Body.String())
	}
	location := created.Header().Get("Location")

	otherKey := personServerTestKey(t, "permission-other-agent")
	otherToken, err := aauth.MintAgentToken(protocol.providerID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:other@provider.example", PersonServer: protocol.personServerID,
		PublicKey: otherKey.PublicJWK(), Lifetime: 30 * time.Minute,
	}, protocol.now, "permission-other-token")
	if err != nil {
		t.Fatal(err)
	}
	wrong := pollPermission(t, protocol, server, otherKey, otherToken, location)
	assertPermissionProblem(t, wrong, http.StatusGone, "invalid_code")
	if store.onlyRecord(t).State != PermissionStatePending {
		t.Fatal("wrong-identity poll mutated the permission record")
	}

	protocol.now = protocol.now.Add(time.Minute)
	expired := pollPermission(t, protocol, server, protocol.agentKey, protocol.agentToken, location)
	assertPermissionProblem(t, expired, http.StatusRequestTimeout, "expired")
	if store.onlyRecord(t).State != PermissionStateGone {
		t.Fatal("expired result was not consumed before delivery")
	}
	again := pollPermission(t, protocol, server, protocol.agentKey, protocol.agentToken, location)
	assertPermissionProblem(t, again, http.StatusGone, "invalid_code")
}

func TestPermissionHostDecisionIsRaceSafeAndExactlyReplayable(t *testing.T) {
	protocol := newPermissionProtocol(t)
	store := newMemoryPermissionStore()
	protocol.policyResult = PermissionPolicyResult{Deferred: &PermissionPendingPolicy{Lifetime: time.Minute}}
	server := protocol.newServer(t, "direct", protocol.config("direct", &PermissionConfig{Policy: protocol.policy, Store: store}))
	created := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, `{"action":"DeleteFile"}`)
	if created.Code != http.StatusAccepted {
		t.Fatalf("create response = %d %s", created.Code, created.Body.String())
	}
	handle, err := server.ResumePermission(context.Background(), store.onlyRecord(t).ID)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errorsByDecision := make(chan error, 2)
	go func() {
		<-start
		errorsByDecision <- server.GrantPermission(context.Background(), handle)
	}()
	go func() {
		<-start
		errorsByDecision <- server.DenyPermission(context.Background(), handle, "denied")
	}()
	close(start)
	first, second := <-errorsByDecision, <-errorsByDecision
	if (first == nil) == (second == nil) || (first != nil && !errors.Is(first, ErrPermissionConflict)) ||
		(second != nil && !errors.Is(second, ErrPermissionConflict)) {
		t.Fatalf("racing decision errors = %v, %v", first, second)
	}
	terminal := store.onlyRecord(t)
	if terminal.State == PermissionStateGranted {
		if err := server.GrantPermission(context.Background(), handle); err != nil {
			t.Fatalf("exact grant replay: %v", err)
		}
		if err := server.DenyPermission(context.Background(), handle, "denied"); !errors.Is(err, ErrPermissionConflict) {
			t.Fatalf("changed denial replay = %v", err)
		}
	} else {
		if err := server.DenyPermission(context.Background(), handle, "denied"); err != nil {
			t.Fatalf("exact denial replay: %v", err)
		}
		if err := server.GrantPermission(context.Background(), handle); !errors.Is(err, ErrPermissionConflict) {
			t.Fatalf("changed grant replay = %v", err)
		}
	}
	if err := server.GrantPermission(context.Background(), PermissionRequest{}); !errors.Is(err, ErrPermissionConflict) {
		t.Fatalf("zero permission handle = %v", err)
	}
}

func TestPermissionRejectsMalformedStoreResultsWithoutConsumption(t *testing.T) {
	protocol := newPermissionProtocol(t)
	store := newMemoryPermissionStore()
	protocol.policyResult = PermissionPolicyResult{Deferred: &PermissionPendingPolicy{Lifetime: time.Minute}}
	server := protocol.newServer(t, "direct", protocol.config("direct", &PermissionConfig{Policy: protocol.policy, Store: store}))
	created := permissionRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, `{"action":"SendEmail","parameters":{"to":"person@example"}}`)
	if created.Code != http.StatusAccepted {
		t.Fatalf("create response = %d %s", created.Code, created.Body.String())
	}
	location := created.Header().Get("Location")
	id := store.onlyRecord(t).ID

	corruptLoad := &corruptPermissionStore{PermissionStore: store, load: func(record *PermissionRecord) { record.ID = "different" }}
	corruptServer := protocol.newServer(t, "direct", protocol.config("direct", &PermissionConfig{Policy: protocol.policy, Store: corruptLoad}))
	if _, err := corruptServer.ResumePermission(context.Background(), id); !errors.Is(err, ErrPermissionConflict) {
		t.Fatalf("malformed resume result = %v", err)
	}

	handle, err := server.ResumePermission(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	corruptDecision := &corruptPermissionStore{PermissionStore: store, decide: func(record *PermissionRecord) {
		record.Action = "DifferentAction"
	}}
	corruptServer = protocol.newServer(t, "direct", protocol.config("direct", &PermissionConfig{Policy: protocol.policy, Store: corruptDecision}))
	if err := corruptServer.GrantPermission(context.Background(), handle); !errors.Is(err, ErrPermissionConflict) {
		t.Fatalf("malformed decision result = %v", err)
	}

	if err := server.GrantPermission(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	corruptPoll := &corruptPermissionStore{PermissionStore: store, poll: func(record *PermissionRecord) { record.Agent = "aauth:other@provider.example" }}
	corruptServer = protocol.newServer(t, "direct", protocol.config("direct", &PermissionConfig{Policy: protocol.policy, Store: corruptPoll}))
	poll := pollPermission(t, protocol, corruptServer, protocol.agentKey, protocol.agentToken, location)
	assertPermissionProblem(t, poll, http.StatusInternalServerError, "server_error")
	if store.onlyRecord(t).State != PermissionStateGranted {
		t.Fatal("malformed terminal store result was consumed")
	}
}

func TestPermissionStoreFixtureContract(t *testing.T) {
	store := newMemoryPermissionStore()
	now := time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC)
	record := PermissionRecord{
		ID: "reference", PersonServer: "https://person.example", AgentProvider: "https://provider.example",
		Agent: "aauth:operator@provider.example", ConfirmationThumbprint: "thumbprint", AgentExpiresAt: now.Add(time.Hour),
		AgentAdditionalClaims: map[string]json.RawMessage{"claim": json.RawMessage(`{"value":1}`)},
		Action:                "SendEmail", Parameters: json.RawMessage(`{"to":"person@example"}`), State: PermissionStatePending,
		CreatedAt: now, ExpiresAt: now.Add(time.Minute), RetryAfter: time.Second,
	}
	if err := store.CreatePermission(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	record.Parameters[0] = '['
	record.AgentAdditionalClaims["claim"][0] = '['
	loaded, err := store.LoadPermission(context.Background(), "reference", now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.Parameters, []byte(`{"to":"person@example"}`)) || !bytes.Equal(loaded.AgentAdditionalClaims["claim"], []byte(`{"value":1}`)) {
		t.Fatal("CreatePermission did not own mutable input")
	}
	loaded.Parameters[0] = '['
	loaded, err = store.LoadPermission(context.Background(), "reference", now)
	if err != nil || !bytes.Equal(loaded.Parameters, []byte(`{"to":"person@example"}`)) {
		t.Fatal("LoadPermission did not return an owned copy")
	}
	identity := PermissionPollIdentity{
		PersonServer: "https://person.example", AgentProvider: "https://provider.example",
		Agent: "aauth:operator@provider.example", ConfirmationThumbprint: "thumbprint",
	}
	wrong := identity
	wrong.Agent = "aauth:other@provider.example"
	if _, err := store.PollPermission(context.Background(), "reference", wrong, now); !errors.Is(err, ErrPermissionNotFound) {
		t.Fatalf("wrong identity poll = %v", err)
	}
	decision := PermissionDecision{Permission: aauth.PermissionDenied, Reason: "denied"}
	terminal, err := store.DecidePermission(context.Background(), "reference", decision, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := store.DecidePermission(context.Background(), "reference", decision, now.Add(2*time.Second)); err != nil || !permissionRecordsEqual(replay, terminal) {
		t.Fatalf("exact decision replay = %#v, %v", replay, err)
	}
	if _, err := store.DecidePermission(context.Background(), "reference", PermissionDecision{Permission: aauth.PermissionGranted}, now); !errors.Is(err, ErrPermissionConflict) {
		t.Fatalf("changed decision replay = %v", err)
	}
	poll, err := store.PollPermission(context.Background(), "reference", identity, now)
	if err != nil || !permissionRecordsEqual(poll, terminal) {
		t.Fatalf("terminal poll = %#v, %v", poll, err)
	}
	if err := store.ConsumePermissionResult(context.Background(), "reference", poll); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PollPermission(context.Background(), "reference", identity, now); !errors.Is(err, ErrPermissionGone) {
		t.Fatalf("consumed poll = %v", err)
	}
}

type permissionProtocol struct {
	t              *testing.T
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
	policyResult   PermissionPolicyResult
	policyCalls    int
}

func newPermissionProtocol(t *testing.T) *permissionProtocol {
	t.Helper()
	protocol := &permissionProtocol{
		t: t, now: time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC),
		providerID: "https://provider.example", personServerID: "https://person.example",
		agentID:      "aauth:operator@provider.example",
		policyResult: PermissionPolicyResult{Immediate: &PermissionDecision{Permission: aauth.PermissionGranted}},
	}
	protocol.clock = aauth.ClockFunc(func() time.Time { return protocol.now })
	protocol.providerKey = personServerTestKey(t, "permission-provider")
	protocol.personKey = personServerTestKey(t, "permission-person")
	protocol.agentKey = personServerTestKey(t, "permission-agent")
	protocol.resolver = signaturekey.StaticKeyResolver{
		{Issuer: protocol.providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: protocol.providerKey.ID()}: protocol.providerKey.PublicJWK(),
	}
	var err error
	protocol.agentToken, err = aauth.MintAgentToken(protocol.providerID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: protocol.agentID, PersonServer: protocol.personServerID,
		PublicKey: protocol.agentKey.PublicJWK(), Lifetime: 30 * time.Minute,
		AdditionalClaims: map[string]json.RawMessage{"platform_attestation": json.RawMessage(`{"level":"example"}`)},
	}, protocol.now, "permission-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	return protocol
}

func (protocol *permissionProtocol) policy(_ context.Context, _ PermissionPolicyRequest) (PermissionPolicyResult, error) {
	protocol.policyCalls++
	return protocol.policyResult, nil
}

func (protocol *permissionProtocol) config(mode string, permission *PermissionConfig) any {
	tokens := newMemoryTokenStore()
	if mode == "federated" {
		return FederatedAuthorizationConfig{
			Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
			Clock: protocol.clock, NewID: func() string { return "permission-token" },
			HTTPClient: &http.Client{}, Tokens: tokens, Permission: permission,
			AccessServerEndpoint: func(context.Context, string) (string, error) { return "https://access.example/token", nil },
			BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
				return Person{Subject: "person", Lifetime: time.Minute}, nil
			},
			Consent: func(context.Context, AuthorizationRequest) error { return nil },
		}
	}
	return PSAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: func() string { return "permission-token" }, Tokens: tokens,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{Subject: "person", Lifetime: time.Minute}, nil
		},
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: []string{"read"}, Lifetime: time.Minute}, nil
		},
		Permission: permission,
	}
}

func (protocol *permissionProtocol) construct(mode string, permission *PermissionConfig) (*Server, error) {
	config := protocol.config(mode, permission)
	if mode == "federated" {
		return NewFederatedAuthorization(config.(FederatedAuthorizationConfig))
	}
	return NewPSAuthorization(config.(PSAuthorizationConfig))
}

func (protocol *permissionProtocol) newServer(t *testing.T, mode string, config any) *Server {
	t.Helper()
	var server *Server
	var err error
	if mode == "federated" {
		server, err = NewFederatedAuthorization(config.(FederatedAuthorizationConfig))
	} else {
		server, err = NewPSAuthorization(config.(PSAuthorizationConfig))
	}
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func permissionMetadata(t *testing.T, server *Server) map[string]string {
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

func permissionRequest(
	t *testing.T,
	protocol *permissionProtocol,
	server *Server,
	key jose.SigningKey,
	token string,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/permission", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, key, token, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func pollPermission(
	t *testing.T,
	protocol *permissionProtocol,
	server *Server,
	key jose.SigningKey,
	token string,
	location string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, protocol.personServerID+location, nil)
	if err := signaturekey.SignJWTRequest(request, key, token, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func assertPermissionProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("permission response = %d, want %d; body=%s", response.Code, status, response.Body.String())
	}
	if code == "" {
		return
	}
	var problem struct {
		Code string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != code {
		t.Fatalf("permission problem = %q, want %q", problem.Code, code)
	}
}

func permissionMissionConfig() *MissionConfig {
	return &MissionConfig{
		Approve: func(context.Context, MissionApprovalRequest) (MissionDecision, error) {
			return MissionDecision{}, errors.New("unused mission approval")
		},
		AcceptUpdate: func(context.Context, MissionUpdatePolicyRequest) error {
			return errors.New("unused mission update")
		},
		ConfirmPersonAcceptedCompletion: func(context.Context, MissionCompletionPolicyRequest) error {
			return errors.New("unused mission completion")
		},
	}
}

type missionPermissionTestStore struct {
	*memoryMissionStore
	*memoryPermissionStore
	createMissionCalls int
}

func newMissionPermissionTestStore() *missionPermissionTestStore {
	return &missionPermissionTestStore{
		memoryMissionStore:    newMemoryMissionStore(),
		memoryPermissionStore: newMemoryPermissionStore(),
	}
}

func (store *missionPermissionTestStore) CreateMissionPermission(
	_ context.Context,
	expected MissionRecord,
	record PermissionRecord,
	at time.Time,
) error {
	store.memoryMissionStore.mu.Lock()
	defer store.memoryMissionStore.mu.Unlock()
	store.memoryPermissionStore.mu.Lock()
	defer store.memoryPermissionStore.mu.Unlock()
	store.createMissionCalls++
	if err := store.memoryMissionStore.requireActiveMissionLocked(expected, at); err != nil {
		return err
	}
	if _, exists := store.memoryPermissionStore.records[record.ID]; exists {
		return ErrPermissionConflict
	}
	store.memoryPermissionStore.records[record.ID] = clonePermissionRecord(record)
	return nil
}

func (store *missionPermissionTestStore) DecideMissionPermission(
	_ context.Context,
	expected MissionRecord,
	id string,
	decision PermissionDecision,
	at time.Time,
) (PermissionRecord, error) {
	store.memoryMissionStore.mu.Lock()
	defer store.memoryMissionStore.mu.Unlock()
	store.memoryPermissionStore.mu.Lock()
	defer store.memoryPermissionStore.mu.Unlock()
	if err := store.memoryMissionStore.requireActiveMissionLocked(expected, at); err != nil {
		return PermissionRecord{}, err
	}
	record, ok := store.memoryPermissionStore.records[id]
	if !ok {
		return PermissionRecord{}, ErrPermissionNotFound
	}
	materializePermissionExpiry(&record, at)
	if record.State == PermissionStateExpired {
		store.memoryPermissionStore.records[id] = record
		return PermissionRecord{}, ErrPermissionExpired
	}
	if record.State == PermissionStateGranted || record.State == PermissionStateDenied {
		if record.Decision == decision {
			return clonePermissionRecord(record), nil
		}
		return PermissionRecord{}, ErrPermissionConflict
	}
	if record.State != PermissionStatePending {
		return PermissionRecord{}, ErrPermissionGone
	}
	record.State = permissionStateForDecision(decision)
	record.Decision = decision
	record.DecidedAt = at
	store.memoryPermissionStore.records[id] = record
	return clonePermissionRecord(record), nil
}

func (store *missionPermissionTestStore) PollMissionPermission(
	_ context.Context,
	expected MissionRecord,
	id string,
	identity PermissionPollIdentity,
	at time.Time,
) (PermissionRecord, error) {
	store.memoryMissionStore.mu.Lock()
	defer store.memoryMissionStore.mu.Unlock()
	store.memoryPermissionStore.mu.Lock()
	defer store.memoryPermissionStore.mu.Unlock()
	if err := store.memoryMissionStore.requireActiveMissionLocked(expected, at); err != nil {
		return PermissionRecord{}, err
	}
	record, ok := store.memoryPermissionStore.records[id]
	if !ok || !permissionIdentityMatches(record, identity) {
		return PermissionRecord{}, ErrPermissionNotFound
	}
	materializePermissionExpiry(&record, at)
	store.memoryPermissionStore.records[id] = record
	if record.State == PermissionStateGone {
		return PermissionRecord{}, ErrPermissionGone
	}
	return clonePermissionRecord(record), nil
}

func (store *missionPermissionTestStore) ConsumeMissionPermissionResult(
	_ context.Context,
	expected MissionRecord,
	id string,
	want PermissionRecord,
	at time.Time,
) error {
	store.memoryMissionStore.mu.Lock()
	defer store.memoryMissionStore.mu.Unlock()
	store.memoryPermissionStore.mu.Lock()
	defer store.memoryPermissionStore.mu.Unlock()
	if err := store.memoryMissionStore.requireActiveMissionLocked(expected, at); err != nil {
		return err
	}
	record, ok := store.memoryPermissionStore.records[id]
	if !ok {
		return ErrPermissionNotFound
	}
	if record.State == PermissionStateGone {
		return ErrPermissionGone
	}
	if !reflect.DeepEqual(record, want) ||
		(record.State != PermissionStateGranted && record.State != PermissionStateDenied && record.State != PermissionStateExpired) {
		return ErrPermissionConflict
	}
	record.State = PermissionStateGone
	store.memoryPermissionStore.records[id] = record
	return nil
}

type memoryPermissionStore struct {
	mu        sync.Mutex
	records   map[string]PermissionRecord
	createErr error
}

type corruptPermissionStore struct {
	PermissionStore
	load   func(*PermissionRecord)
	decide func(*PermissionRecord)
	poll   func(*PermissionRecord)
}

func (store *corruptPermissionStore) LoadPermission(ctx context.Context, id string, now time.Time) (PermissionRecord, error) {
	record, err := store.PermissionStore.LoadPermission(ctx, id, now)
	if err == nil && store.load != nil {
		store.load(&record)
	}
	return record, err
}

func (store *corruptPermissionStore) DecidePermission(
	ctx context.Context,
	id string,
	decision PermissionDecision,
	now time.Time,
) (PermissionRecord, error) {
	record, err := store.PermissionStore.DecidePermission(ctx, id, decision, now)
	if err == nil && store.decide != nil {
		store.decide(&record)
	}
	return record, err
}

func (store *corruptPermissionStore) PollPermission(
	ctx context.Context,
	id string,
	identity PermissionPollIdentity,
	now time.Time,
) (PermissionRecord, error) {
	record, err := store.PermissionStore.PollPermission(ctx, id, identity, now)
	if err == nil && store.poll != nil {
		store.poll(&record)
	}
	return record, err
}

func newMemoryPermissionStore() *memoryPermissionStore {
	return &memoryPermissionStore{records: make(map[string]PermissionRecord)}
}

func (store *memoryPermissionStore) CreatePermission(_ context.Context, record PermissionRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.createErr != nil {
		return store.createErr
	}
	if _, exists := store.records[record.ID]; exists {
		return ErrPermissionConflict
	}
	store.records[record.ID] = clonePermissionRecord(record)
	return nil
}

func (store *memoryPermissionStore) LoadPermission(_ context.Context, id string, now time.Time) (PermissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[id]
	if !ok {
		return PermissionRecord{}, ErrPermissionNotFound
	}
	materializePermissionExpiry(&record, now)
	store.records[id] = record
	return clonePermissionRecord(record), nil
}

func (store *memoryPermissionStore) DecidePermission(_ context.Context, id string, decision PermissionDecision, now time.Time) (PermissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[id]
	if !ok {
		return PermissionRecord{}, ErrPermissionNotFound
	}
	materializePermissionExpiry(&record, now)
	if record.State == PermissionStateExpired {
		store.records[id] = record
		return PermissionRecord{}, ErrPermissionExpired
	}
	if record.State == PermissionStateGranted || record.State == PermissionStateDenied {
		if record.Decision == decision {
			return clonePermissionRecord(record), nil
		}
		return PermissionRecord{}, ErrPermissionConflict
	}
	if record.State != PermissionStatePending {
		return PermissionRecord{}, ErrPermissionGone
	}
	record.State = permissionStateForDecision(decision)
	record.Decision = decision
	record.DecidedAt = now
	store.records[id] = record
	return clonePermissionRecord(record), nil
}

func (store *memoryPermissionStore) PollPermission(_ context.Context, id string, identity PermissionPollIdentity, now time.Time) (PermissionRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[id]
	if !ok || !permissionIdentityMatches(record, identity) {
		return PermissionRecord{}, ErrPermissionNotFound
	}
	materializePermissionExpiry(&record, now)
	store.records[id] = record
	if record.State == PermissionStateGone {
		return PermissionRecord{}, ErrPermissionGone
	}
	return clonePermissionRecord(record), nil
}

func (store *memoryPermissionStore) ConsumePermissionResult(_ context.Context, id string, expected PermissionRecord) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[id]
	if !ok {
		return ErrPermissionNotFound
	}
	if record.State == PermissionStateGone {
		return ErrPermissionGone
	}
	if !reflect.DeepEqual(record, expected) ||
		(record.State != PermissionStateGranted && record.State != PermissionStateDenied && record.State != PermissionStateExpired) {
		return ErrPermissionConflict
	}
	record.State = PermissionStateGone
	store.records[id] = record
	return nil
}

func (store *memoryPermissionStore) count() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.records)
}

func (store *memoryPermissionStore) onlyRecord(t *testing.T) PermissionRecord {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.records) != 1 {
		t.Fatalf("permission records = %d, want 1", len(store.records))
	}
	for _, record := range store.records {
		return clonePermissionRecord(record)
	}
	panic("unreachable")
}

func clonePermissionRecord(record PermissionRecord) PermissionRecord {
	record.Parameters = append(json.RawMessage(nil), record.Parameters...)
	record.AgentAdditionalClaims = cloneClaims(record.AgentAdditionalClaims)
	return record
}

func materializePermissionExpiry(record *PermissionRecord, now time.Time) {
	if record.State == PermissionStatePending && !now.Before(record.ExpiresAt) {
		record.State = PermissionStateExpired
	}
}

func permissionIdentityMatches(record PermissionRecord, identity PermissionPollIdentity) bool {
	return record.PersonServer == identity.PersonServer && record.AgentProvider == identity.AgentProvider &&
		record.Agent == identity.Agent && record.ConfirmationThumbprint == identity.ConfirmationThumbprint
}
