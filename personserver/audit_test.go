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

func TestAuditConfigurationAndExactAppendInBothPersonServerModes(t *testing.T) {
	for _, mode := range []string{"direct", "federated"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			protocol := newAuditProtocol(t)
			withoutAudit := protocol.newServer(t, mode, protocol.store, protocol.missionConfig(), nil)
			metadata := auditMetadata(t, withoutAudit)
			if _, present := metadata["audit_endpoint"]; present {
				t.Fatal("audit_endpoint advertised without explicit configuration")
			}
			response := auditRequest(t, protocol, withoutAudit, protocol.agentKey, protocol.agentToken,
				`{"mission_s256":"missing","action":"files.write"}`)
			if response.Code != http.StatusNotFound {
				t.Fatalf("unconfigured audit route = %d %s", response.Code, response.Body.String())
			}

			if _, err := protocol.construct(mode, protocol.store, nil, &AuditConfig{}); err == nil {
				t.Fatal("Audit configuration without Missions was accepted")
			}
			if _, err := protocol.construct(mode, protocol.store.memoryMissionStore, protocol.missionConfig(), &AuditConfig{}); err == nil {
				t.Fatal("Audit configuration accepted Tokens without MissionAuditStore")
			}

			server := protocol.newServer(t, mode, protocol.store, protocol.missionConfig(), &AuditConfig{})
			metadata = auditMetadata(t, server)
			if metadata["audit_endpoint"] != protocol.personServerID+"/audit" {
				t.Fatalf("audit_endpoint = %q", metadata["audit_endpoint"])
			}
			mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
			body := []byte("{\n" +
				`  "mission_s256": "` + mission.S256 + `",` + "\n" +
				`  "action": "files.write",` + "\n" +
				`  "description": "Wrote the reviewed **report**.",` + "\n" +
				`  "parameters": {"path":"report.md"},` + "\n" +
				`  "result": {"bytes":128},` + "\n" +
				`  "extension": {"trace":"kept"}` + "\n" +
				"}")
			writer := newAuditResponseWriter()
			protocol.store.beforeAppendReturn = func() {
				if writer.status != 0 {
					t.Fatalf("HTTP status %d written before audit append returned", writer.status)
				}
			}
			request := protocol.signedAuditRequest(t, protocol.agentKey, protocol.agentToken, body)
			server.Handler().ServeHTTP(writer, request)
			if writer.status != http.StatusCreated || writer.body.Len() != 0 ||
				writer.header.Get("Content-Type") != "" || writer.header.Get("Cache-Control") != "no-store" {
				t.Fatalf("audit response = %d headers=%#v body=%q", writer.status, writer.header, writer.body.String())
			}
			records, err := protocol.store.LoadMissionAuditsForAgent(
				context.Background(), protocol.agentID, mission.S256, protocol.now,
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 1 || !bytes.Equal(records[0].Document.ExactJSON, body) ||
				records[0].Document.Entry.MissionS256 != mission.S256 ||
				records[0].Document.Entry.Action != "files.write" || !records[0].RecordedAt.Equal(protocol.now) {
				t.Fatalf("retained audit records = %#v", records)
			}
			if protocol.actionCallbacks != 0 {
				t.Fatalf("audit endpoint executed %d mission/action callbacks", protocol.actionCallbacks)
			}
		})
	}
}

func TestAuditCloaksWrongOwnerAndRejectsTerminatedOrExpiredMission(t *testing.T) {
	protocol := newAuditProtocol(t)
	server := protocol.newServer(t, "direct", protocol.store, protocol.missionConfig(), &AuditConfig{})
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
	body := func(s256 string) string {
		return `{"mission_s256":"` + s256 + `","action":"messages.send"}`
	}

	otherKey := personServerTestKey(t, "audit-other-agent")
	otherToken, err := aauth.MintAgentToken(protocol.providerID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:other@provider.example", PersonServer: protocol.personServerID,
		PublicKey: otherKey.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, "audit-other-token")
	if err != nil {
		t.Fatal(err)
	}
	wrongOwner := auditRequest(t, protocol, server, otherKey, otherToken, body(mission.S256))
	assertAuditProblem(t, wrongOwner, http.StatusNotFound, "mission_not_found", "", "")
	missingS256 := aauth.MissionS256([]byte("missing audit mission"))
	missing := auditRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, body(missingS256))
	assertAuditProblem(t, missing, http.StatusNotFound, "mission_not_found", "", "")
	if wrongOwner.Body.String() != missing.Body.String() || !reflect.DeepEqual(wrongOwner.Header(), missing.Header()) {
		t.Fatalf("wrong-owner and missing responses differ:\nwrong=%v %s\nmissing=%v %s",
			wrongOwner.Header(), wrongOwner.Body.String(), missing.Header(), missing.Body.String())
	}

	terminated := protocol.commitMission(t, protocol.agentID, protocol.now.Add(time.Hour), MissionTerminated, "revoked")
	response := auditRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, body(terminated.S256))
	assertAuditProblem(t, response, http.StatusForbidden, "mission_terminated", "terminated", "revoked")

	expired := protocol.commitMission(t, protocol.agentID, protocol.now.Add(time.Second), MissionActive, "")
	protocol.now = expired.ExpiresAt
	response = auditRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, body(expired.S256))
	assertAuditProblem(t, response, http.StatusForbidden, "mission_terminated", "terminated", "expired")
	if protocol.store.auditCount() != 0 {
		t.Fatalf("invalid mission attempts retained %d audits", protocol.store.auditCount())
	}
}

func TestAuditEvaluatesMissionExpiryAfterCompleteSignedBodyValidation(t *testing.T) {
	protocol := newAuditProtocol(t)
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(time.Second), MissionActive, "")
	body := []byte(`{"mission_s256":"` + mission.S256 + `","action":"files.write"}`)
	request := protocol.signedAuditRequest(t, protocol.agentKey, protocol.agentToken, body)
	protocol.now = mission.ExpiresAt.Add(-time.Nanosecond)
	request.Body = &auditClockAdvancingBody{
		Reader: bytes.NewReader(body),
		advance: func() {
			protocol.now = mission.ExpiresAt
		},
	}
	response := httptest.NewRecorder()
	protocol.newServer(t, "direct", protocol.store, protocol.missionConfig(), &AuditConfig{}).
		Handler().ServeHTTP(response, request)
	assertAuditProblem(t, response, http.StatusForbidden, "mission_terminated", "terminated", "expired")
	if protocol.store.auditCount() != 0 {
		t.Fatalf("slow body appended %d audits after mission expiry", protocol.store.auditCount())
	}
}

func TestAuditRejectsMalformedInputAndOperationalStoreFailures(t *testing.T) {
	for _, body := range []string{
		`[]`,
		`{"action":"files.write"}`,
		`{"mission_s256":"invalid","action":"files.write"}`,
		`{"mission_s256":"` + aauth.MissionS256([]byte("mission")) + `","action":""}`,
		`{"mission_s256":"` + aauth.MissionS256([]byte("mission")) + `","action":"read","action":"write"}`,
		`{"mission_s256":"` + aauth.MissionS256([]byte("mission")) + `","action":"read","parameters":null}`,
		`{"mission_s256":"` + aauth.MissionS256([]byte("mission")) + `","action":"read","result":[]}`,
	} {
		protocol := newAuditProtocol(t)
		server := protocol.newServer(t, "direct", protocol.store, protocol.missionConfig(), &AuditConfig{})
		response := auditRequest(t, protocol, server, protocol.agentKey, protocol.agentToken, body)
		assertAuditProblem(t, response, http.StatusBadRequest, "invalid_request", "", "")
		if protocol.store.auditCount() != 0 {
			t.Fatalf("malformed audit retained state: %s", body)
		}
	}

	protocol := newAuditProtocol(t)
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(time.Minute), MissionActive, "")
	protocol.store.appendErr = errors.New("audit store unavailable")
	server := protocol.newServer(t, "direct", protocol.store, protocol.missionConfig(), &AuditConfig{})
	response := auditRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
		`{"mission_s256":"`+mission.S256+`","action":"files.write"}`)
	assertAuditProblem(t, response, http.StatusInternalServerError, "server_error", "", "")
	if protocol.store.auditCount() != 0 {
		t.Fatal("failed append retained an audit")
	}

	protocol.store.appendErr = nil
	forged := &forgedMissionAuditStore{memoryMissionAuditStore: protocol.store}
	server = protocol.newServer(t, "direct", forged, protocol.missionConfig(), &AuditConfig{})
	response = auditRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
		`{"mission_s256":"`+mission.S256+`","action":"files.write"}`)
	assertAuditProblem(t, response, http.StatusInternalServerError, "server_error", "", "")
	if protocol.store.auditCount() != 0 {
		t.Fatal("forged mission result retained an audit")
	}
}

func TestAuditMapsAtomicAppendMissionChangesAfterSuccessfulLoad(t *testing.T) {
	for _, test := range []struct {
		name          string
		appendErr     error
		status        int
		code          string
		missionStatus string
		reason        string
	}{
		{name: "missing", appendErr: ErrMissionNotFound, status: http.StatusNotFound, code: "mission_not_found"},
		{name: "revoked", appendErr: &MissionTerminatedError{TerminationReason: "revoked"}, status: http.StatusForbidden, code: "mission_terminated", missionStatus: "terminated", reason: "revoked"},
		{name: "expired", appendErr: &MissionTerminatedError{TerminationReason: "expired"}, status: http.StatusForbidden, code: "mission_terminated", missionStatus: "terminated", reason: "expired"},
		{name: "changed", appendErr: ErrMissionConflict, status: http.StatusInternalServerError, code: "server_error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := newAuditProtocol(t)
			mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(time.Minute), MissionActive, "")
			protocol.store.appendErr = test.appendErr
			server := protocol.newServer(t, "direct", protocol.store, protocol.missionConfig(), &AuditConfig{})
			response := auditRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
				`{"mission_s256":"`+mission.S256+`","action":"files.write"}`)
			assertAuditProblem(t, response, test.status, test.code, test.missionStatus, test.reason)
			if protocol.store.auditCount() != 0 {
				t.Fatalf("append-time %s retained an audit", test.name)
			}
		})
	}

	protocol := newAuditProtocol(t)
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(time.Minute), MissionActive, "")
	changing := &terminatingMissionAuditStore{memoryMissionAuditStore: protocol.store}
	server := protocol.newServer(t, "direct", changing, protocol.missionConfig(), &AuditConfig{})
	response := auditRequest(t, protocol, server, protocol.agentKey, protocol.agentToken,
		`{"mission_s256":"`+mission.S256+`","action":"files.write"}`)
	assertAuditProblem(t, response, http.StatusForbidden, "mission_terminated", "terminated", "revoked-after-load")
	if protocol.store.auditCount() != 0 {
		t.Fatal("post-load mission termination retained an audit")
	}
}

func TestAuditRequiresVerifiedTopLevelAgentAndBoundedSignedBody(t *testing.T) {
	protocol := newAuditProtocol(t)
	server := protocol.newServer(t, "direct", protocol.store, protocol.missionConfig(), &AuditConfig{})
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(time.Minute), MissionActive, "")
	body := []byte(`{"mission_s256":"` + mission.S256 + `","action":"files.write"}`)

	unsignedRequest := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/audit", bytes.NewReader(body))
	unsignedRequest.Header.Set("Content-Type", "application/json")
	unsigned := httptest.NewRecorder()
	server.Handler().ServeHTTP(unsigned, unsignedRequest)
	assertAuditProblem(t, unsigned, http.StatusUnauthorized, "invalid_agent_token", "", "")

	childKey := personServerTestKey(t, "audit-child")
	childToken, err := aauth.MintAgentToken(protocol.providerID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: "aauth:operator+child@provider.example", ParentAgent: protocol.agentID,
		PersonServer: protocol.personServerID, PublicKey: childKey.PublicJWK(), Lifetime: time.Minute,
	}, protocol.now, "audit-child-token")
	if err != nil {
		t.Fatal(err)
	}
	child := auditRequest(t, protocol, server, childKey, childToken, string(body))
	assertAuditProblem(t, child, http.StatusBadRequest, "invalid_agent_token", "", "")

	oversizedBody := []byte(`{"mission_s256":"` + mission.S256 + `","action":"files.write","extension":"` +
		strings.Repeat("x", int(maxRequestBytes)) + `"}`)
	oversizedRequest := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/audit", bytes.NewReader(oversizedBody))
	oversizedRequest.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWTRequestWithOptions(
		oversizedRequest, protocol.agentKey, protocol.agentToken, protocol.clock,
		signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
			MaxBodyBytes:         int64(len(oversizedBody) + 1),
		},
	); err != nil {
		t.Fatal(err)
	}
	oversized := httptest.NewRecorder()
	server.Handler().ServeHTTP(oversized, oversizedRequest)
	if oversized.Code == http.StatusCreated {
		t.Fatalf("oversized audit was accepted: headers=%#v", oversized.Header())
	}
	if protocol.store.auditCount() != 0 {
		t.Fatalf("invalid proof/body attempts retained %d audits", protocol.store.auditCount())
	}
}

func TestMissionAuditStorePreservesOrderCopiesAndIdenticalEntries(t *testing.T) {
	protocol := newAuditProtocol(t)
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(time.Minute), MissionActive, "")
	exact := []byte(`{"mission_s256":"` + mission.S256 + `","action":"files.write","parameters":{"path":"report.md"},"result":{"ok":true}}`)
	document, err := aauth.DecodeAudit(exact)
	if err != nil {
		t.Fatal(err)
	}
	wantDocument := cloneTestAuditDocument(document)
	first := MissionAuditRecord{Document: document, RecordedAt: protocol.now}
	second := cloneTestMissionAuditRecord(first)
	thirdDocument, err := aauth.EncodeAudit(aauth.AuditEntry{MissionS256: mission.S256, Action: "messages.send"})
	if err != nil {
		t.Fatal(err)
	}
	third := MissionAuditRecord{Document: thirdDocument, RecordedAt: protocol.now.Add(time.Second)}
	if err := protocol.store.AppendMissionAudit(context.Background(), cloneMissionRecord(mission), first); err != nil {
		t.Fatal(err)
	}
	if err := protocol.store.AppendMissionAudit(context.Background(), cloneMissionRecord(mission), second); err != nil {
		t.Fatal(err)
	}
	if err := protocol.store.AppendMissionAudit(context.Background(), cloneMissionRecord(mission), third); err != nil {
		t.Fatal(err)
	}
	exact[0] = '['
	first.Document.ExactJSON[0] = '['
	first.Document.Entry.Parameters[0] = '['
	first.Document.Entry.Result[0] = '['

	records, err := protocol.store.LoadMissionAuditsForAgent(
		context.Background(), protocol.agentID, mission.S256, protocol.now.Add(2*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 || !records[0].RecordedAt.Equal(protocol.now) || !records[1].RecordedAt.Equal(protocol.now) ||
		!records[2].RecordedAt.Equal(protocol.now.Add(time.Second)) ||
		!bytes.Equal(records[0].Document.ExactJSON, wantDocument.ExactJSON) ||
		!bytes.Equal(records[1].Document.ExactJSON, wantDocument.ExactJSON) ||
		records[2].Document.Entry.Action != "messages.send" {
		t.Fatalf("ordered audit records = %#v", records)
	}
	records[0].Document.ExactJSON[0] = '['
	records[0].Document.Entry.Parameters[0] = '['
	records[0].Document.Entry.Result[0] = '['
	if records[1].Document.ExactJSON[0] != '{' || records[1].Document.Entry.Parameters[0] != '{' ||
		records[1].Document.Entry.Result[0] != '{' {
		t.Fatal("identical returned audit records alias each other")
	}
	reloaded, err := protocol.store.LoadMissionAuditsForAgent(
		context.Background(), protocol.agentID, mission.S256, protocol.now.Add(2*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded[0].Document.ExactJSON[0] != '{' || reloaded[0].Document.Entry.Parameters[0] != '{' ||
		reloaded[0].Document.Entry.Result[0] != '{' {
		t.Fatal("audit load exposed store-owned mutable state")
	}
	if _, err := protocol.store.LoadMissionAuditsForAgent(
		context.Background(), "aauth:other@provider.example", mission.S256, protocol.now,
	); !errors.Is(err, ErrMissionNotFound) {
		t.Fatalf("wrong-owner audit load = %v", err)
	}
}

func TestMissionAuditAppendIsAtomicWithMissionTermination(t *testing.T) {
	protocol := newAuditProtocol(t)
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(time.Minute), MissionActive, "")
	document, err := aauth.EncodeAudit(aauth.AuditEntry{MissionS256: mission.S256, Action: "files.write"})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	appendResult := make(chan error, 1)
	terminated := make(chan struct{})
	go func() {
		<-start
		appendResult <- protocol.store.AppendMissionAudit(context.Background(), mission, MissionAuditRecord{
			Document: document, RecordedAt: protocol.now,
		})
	}()
	go func() {
		<-start
		protocol.store.terminateMission(protocol.agentID, mission.S256, "revoked")
		close(terminated)
	}()
	close(start)
	appendErr := <-appendResult
	<-terminated
	count := protocol.store.auditCount()
	if appendErr == nil {
		if count != 1 {
			t.Fatalf("winning atomic append retained %d audits", count)
		}
	} else {
		var missionTerminated *MissionTerminatedError
		if !errors.As(appendErr, &missionTerminated) || missionTerminated.TerminationReason != "revoked" || count != 0 {
			t.Fatalf("losing atomic append = %v, audits=%d", appendErr, count)
		}
	}
	current, err := protocol.store.LoadMissionForAgent(
		context.Background(), mission.Agent, mission.S256, protocol.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if current.State != MissionTerminated || current.TerminationReason != "revoked" {
		t.Fatalf("racing termination state = %#v", current)
	}

	secondProtocol := newAuditProtocol(t)
	secondMission := secondProtocol.commitMission(
		t, secondProtocol.agentID, secondProtocol.now.Add(time.Minute), MissionActive, "",
	)
	secondDocument, err := aauth.EncodeAudit(aauth.AuditEntry{MissionS256: secondMission.S256, Action: "files.write"})
	if err != nil {
		t.Fatal(err)
	}
	secondProtocol.store.terminateMission(secondProtocol.agentID, secondMission.S256, "revoked")
	err = secondProtocol.store.AppendMissionAudit(context.Background(), secondMission, MissionAuditRecord{
		Document: secondDocument, RecordedAt: secondProtocol.now,
	})
	var missionTerminated *MissionTerminatedError
	if !errors.As(err, &missionTerminated) || missionTerminated.TerminationReason != "revoked" ||
		secondProtocol.store.auditCount() != 0 {
		t.Fatalf("append after termination = %v, audits=%d", err, secondProtocol.store.auditCount())
	}
}

func TestMissionAuditStoreComparesStableMissionStateAndMaterializesExpiry(t *testing.T) {
	protocol := newAuditProtocol(t)
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(time.Minute), MissionActive, "")
	document, err := aauth.EncodeAudit(aauth.AuditEntry{MissionS256: mission.S256, Action: "files.write"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		change  func(*MissionRecord)
		wantErr error
	}{
		{name: "S256", change: func(record *MissionRecord) { record.S256 = aauth.MissionS256([]byte("different mission")) }, wantErr: ErrMissionNotFound},
		{name: "Agent", change: func(record *MissionRecord) { record.Agent = "aauth:other@provider.example" }, wantErr: ErrMissionNotFound},
		{name: "ExactJSON", change: func(record *MissionRecord) { record.ExactJSON[0] = '[' }, wantErr: ErrMissionConflict},
		{name: "ApprovedAt", change: func(record *MissionRecord) { record.ApprovedAt = record.ApprovedAt.Add(time.Second) }, wantErr: ErrMissionConflict},
		{name: "ExpiresAt", change: func(record *MissionRecord) { record.ExpiresAt = record.ExpiresAt.Add(time.Second) }, wantErr: ErrMissionConflict},
		{name: "State", change: func(record *MissionRecord) { record.State = MissionTerminated }, wantErr: ErrMissionConflict},
		{name: "TerminationReason", change: func(record *MissionRecord) { record.TerminationReason = "forged" }, wantErr: ErrMissionConflict},
		{name: "Completion", change: func(record *MissionRecord) { record.Completion = &MissionCompletionRecord{AcceptedAt: protocol.now} }, wantErr: ErrMissionConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneMissionRecord(mission)
			test.change(&changed)
			appendDocument := document
			if test.name == "S256" {
				var encodeErr error
				appendDocument, encodeErr = aauth.EncodeAudit(aauth.AuditEntry{
					MissionS256: changed.S256, Action: "files.write",
				})
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
			}
			err := protocol.store.AppendMissionAudit(context.Background(), changed, MissionAuditRecord{
				Document: appendDocument, RecordedAt: protocol.now,
			})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("append against changed %s = %v, want %v", test.name, err, test.wantErr)
			}
			if protocol.store.auditCount() != 0 {
				t.Fatalf("changed %s appended an audit", test.name)
			}
		})
	}

	err = protocol.store.AppendMissionAudit(context.Background(), mission, MissionAuditRecord{
		Document: document, RecordedAt: mission.ExpiresAt,
	})
	var terminated *MissionTerminatedError
	if !errors.As(err, &terminated) || terminated.TerminationReason != "expired" {
		t.Fatalf("append at mission expiry = %v", err)
	}
	loaded, err := protocol.store.LoadMissionForAgent(
		context.Background(), mission.Agent, mission.S256, mission.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State != MissionTerminated || loaded.TerminationReason != "expired" || protocol.store.auditCount() != 0 {
		t.Fatalf("materialized mission expiry = %#v, audits=%d", loaded, protocol.store.auditCount())
	}
	logs, err := protocol.store.LoadMissionAuditsForAgent(
		context.Background(), mission.Agent, mission.S256, mission.ExpiresAt,
	)
	if err != nil || len(logs) != 0 {
		t.Fatalf("load retained audit history after expiry = %#v, %v", logs, err)
	}
}

type auditProtocol struct {
	now             time.Time
	clock           aauth.Clock
	providerID      string
	personServerID  string
	agentID         string
	providerKey     jose.SigningKey
	personKey       jose.SigningKey
	agentKey        jose.SigningKey
	resolver        signaturekey.KeyResolver
	agentToken      string
	store           *memoryMissionAuditStore
	actionCallbacks int
}

func newAuditProtocol(t *testing.T) *auditProtocol {
	t.Helper()
	protocol := &auditProtocol{
		now:        time.Date(2026, 8, 31, 23, 30, 0, 0, time.UTC),
		providerID: "https://provider.example", personServerID: "https://person.example",
		agentID:     "aauth:operator@provider.example",
		providerKey: personServerTestKey(t, "audit-provider"), personKey: personServerTestKey(t, "audit-person"),
		agentKey: personServerTestKey(t, "audit-agent"), store: newMemoryMissionAuditStore(),
	}
	protocol.clock = aauth.ClockFunc(func() time.Time { return protocol.now })
	protocol.resolver = signaturekey.StaticKeyResolver{
		{Issuer: protocol.providerID, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: protocol.providerKey.ID()}: protocol.providerKey.PublicJWK(),
	}
	var err error
	protocol.agentToken, err = aauth.MintAgentToken(protocol.providerID, protocol.providerKey, aauth.AgentTokenRequest{
		Agent: protocol.agentID, PersonServer: protocol.personServerID,
		PublicKey: protocol.agentKey.PublicJWK(), Lifetime: time.Hour,
	}, protocol.now, "audit-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	return protocol
}

func (protocol *auditProtocol) missionConfig() *MissionConfig {
	return &MissionConfig{
		Approve: func(context.Context, MissionApprovalRequest) (MissionDecision, error) {
			protocol.actionCallbacks++
			return MissionDecision{}, errors.New("audit must not approve a mission")
		},
		AcceptUpdate: func(context.Context, MissionUpdatePolicyRequest) error {
			protocol.actionCallbacks++
			return errors.New("audit must not update a mission")
		},
		ConfirmPersonAcceptedCompletion: func(context.Context, MissionCompletionPolicyRequest) error {
			protocol.actionCallbacks++
			return errors.New("audit must not complete a mission")
		},
	}
}

func (protocol *auditProtocol) construct(
	mode string,
	tokens TokenStore,
	missions *MissionConfig,
	audit *AuditConfig,
) (*Server, error) {
	if mode == "federated" {
		return NewFederatedAuthorization(FederatedAuthorizationConfig{
			Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
			Clock: protocol.clock, NewID: func() string { return "audit-token" }, Tokens: tokens,
			HTTPClient: &http.Client{}, AccessServerEndpoint: func(context.Context, string) (string, error) {
				return "https://access.example/token", nil
			},
			BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
				return Person{Subject: "person", Lifetime: time.Minute}, nil
			},
			Consent: func(context.Context, AuthorizationRequest) error { return nil }, Missions: missions, Audit: audit,
		})
	}
	return NewPSAuthorization(PSAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: func() string { return "audit-token" }, Tokens: tokens,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{Subject: "person", Lifetime: time.Minute}, nil
		},
		Authorize: func(context.Context, AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: []string{"read"}, Lifetime: time.Minute}, nil
		},
		Missions: missions, Audit: audit,
	})
}

func (protocol *auditProtocol) newServer(
	t *testing.T,
	mode string,
	tokens TokenStore,
	missions *MissionConfig,
	audit *AuditConfig,
) *Server {
	t.Helper()
	server, err := protocol.construct(mode, tokens, missions, audit)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func (protocol *auditProtocol) commitMission(
	t *testing.T,
	agent string,
	expiresAt time.Time,
	state MissionState,
	reason string,
) MissionRecord {
	t.Helper()
	mission, err := aauth.EncodeMission(aauth.MissionBlob{
		Agent: agent, ApprovedAt: protocol.now.Add(-time.Minute),
		ExpiresAt: &expiresAt, Description: "Audit test mission",
	})
	if err != nil {
		t.Fatal(err)
	}
	record := MissionRecord{
		S256: mission.S256, Agent: agent, ExactJSON: append([]byte(nil), mission.ExactJSON...),
		ApprovedAt: mission.Blob.ApprovedAt, ExpiresAt: expiresAt, State: state, TerminationReason: reason,
	}
	if err := protocol.store.CommitMission(context.Background(), record, nil); err != nil {
		t.Fatal(err)
	}
	return record
}

func (protocol *auditProtocol) signedAuditRequest(
	t *testing.T,
	key jose.SigningKey,
	token string,
	body []byte,
) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/audit", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, key, token, protocol.clock); err != nil {
		t.Fatal(err)
	}
	return request
}

func auditRequest(
	t *testing.T,
	protocol *auditProtocol,
	server *Server,
	key jose.SigningKey,
	token string,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, protocol.signedAuditRequest(t, key, token, []byte(body)))
	return response
}

func auditMetadata(t *testing.T, server *Server) map[string]string {
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

func assertAuditProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code, missionStatus, reason string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("audit response = %d, want %d; body=%s", response.Code, status, response.Body.String())
	}
	var problem struct {
		Code              string `json:"error"`
		MissionStatus     string `json:"mission_status"`
		TerminationReason string `json:"termination_reason"`
	}
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != code || problem.MissionStatus != missionStatus || problem.TerminationReason != reason {
		t.Fatalf("audit problem = %#v", problem)
	}
}

type auditResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

type auditClockAdvancingBody struct {
	*bytes.Reader
	advance  func()
	advanced bool
}

func (body *auditClockAdvancingBody) Read(buffer []byte) (int, error) {
	if !body.advanced {
		body.advanced = true
		body.advance()
	}
	return body.Reader.Read(buffer)
}

func (*auditClockAdvancingBody) Close() error { return nil }

func newAuditResponseWriter() *auditResponseWriter {
	return &auditResponseWriter{header: make(http.Header)}
}

func (writer *auditResponseWriter) Header() http.Header { return writer.header }

func (writer *auditResponseWriter) WriteHeader(status int) {
	if writer.status == 0 {
		writer.status = status
	}
}

func (writer *auditResponseWriter) Write(value []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	return writer.body.Write(value)
}

type memoryMissionAuditStore struct {
	*memoryMissionStore
	audits             map[string][]MissionAuditRecord
	appendErr          error
	beforeAppendReturn func()
}

func newMemoryMissionAuditStore() *memoryMissionAuditStore {
	return &memoryMissionAuditStore{
		memoryMissionStore: newMemoryMissionStore(), audits: make(map[string][]MissionAuditRecord),
	}
}

func (store *memoryMissionAuditStore) AppendMissionAudit(
	_ context.Context,
	expected MissionRecord,
	record MissionAuditRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.appendErr != nil {
		return store.appendErr
	}
	if record.RecordedAt.IsZero() || record.Document.Entry.MissionS256 != expected.S256 {
		return ErrMissionConflict
	}
	decoded, err := aauth.DecodeAudit(record.Document.ExactJSON)
	if err != nil || !auditDocumentEqual(decoded, record.Document) {
		return ErrMissionConflict
	}
	if err := store.requireActiveMissionForAuditLocked(expected, record.RecordedAt); err != nil {
		return err
	}
	key := expected.Agent + "\x00" + expected.S256
	store.audits[key] = append(store.audits[key], cloneTestMissionAuditRecord(record))
	if store.beforeAppendReturn != nil {
		store.beforeAppendReturn()
	}
	return nil
}

func (store *memoryMissionAuditStore) requireActiveMissionForAuditLocked(expected MissionRecord, at time.Time) error {
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
	current.AcceptedUpdates = nil
	expected.AcceptedUpdates = nil
	if !current.Equal(expected) {
		return ErrMissionConflict
	}
	return nil
}

func (store *memoryMissionAuditStore) LoadMissionAuditsForAgent(
	_ context.Context,
	agent string,
	s256 string,
	at time.Time,
) ([]MissionAuditRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := agent + "\x00" + s256
	mission, exists := store.missions[key]
	if !exists {
		return nil, ErrMissionNotFound
	}
	if mission.State == MissionActive && !mission.ExpiresAt.IsZero() && !at.Before(mission.ExpiresAt) {
		mission.State = MissionTerminated
		mission.TerminationReason = "expired"
		store.missions[key] = cloneMissionRecord(mission)
	}
	records := store.audits[key]
	cloned := make([]MissionAuditRecord, len(records))
	for index := range records {
		cloned[index] = cloneTestMissionAuditRecord(records[index])
	}
	return cloned, nil
}

func (store *memoryMissionAuditStore) auditCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	count := 0
	for _, records := range store.audits {
		count += len(records)
	}
	return count
}

type forgedMissionAuditStore struct {
	*memoryMissionAuditStore
}

type terminatingMissionAuditStore struct {
	*memoryMissionAuditStore
}

func (store *terminatingMissionAuditStore) AppendMissionAudit(
	ctx context.Context,
	expected MissionRecord,
	record MissionAuditRecord,
) error {
	store.terminateMission(expected.Agent, expected.S256, "revoked-after-load")
	return store.memoryMissionAuditStore.AppendMissionAudit(ctx, expected, record)
}

func (store *forgedMissionAuditStore) LoadMissionForAgent(
	ctx context.Context,
	agent string,
	s256 string,
	at time.Time,
) (MissionRecord, error) {
	record, err := store.memoryMissionAuditStore.LoadMissionForAgent(ctx, agent, s256, at)
	if err == nil {
		record.Agent = "aauth:forged@provider.example"
	}
	return record, err
}

func cloneTestMissionAuditRecord(record MissionAuditRecord) MissionAuditRecord {
	record.Document = cloneTestAuditDocument(record.Document)
	return record
}

func cloneTestAuditDocument(document aauth.AuditDocument) aauth.AuditDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	document.Entry.Parameters = append(json.RawMessage(nil), document.Entry.Parameters...)
	document.Entry.Result = append(json.RawMessage(nil), document.Entry.Result...)
	return document
}

func auditDocumentEqual(left, right aauth.AuditDocument) bool {
	return bytes.Equal(left.ExactJSON, right.ExactJSON) && left.Entry.MissionS256 == right.Entry.MissionS256 &&
		left.Entry.Action == right.Entry.Action && left.Entry.Description == right.Entry.Description &&
		bytes.Equal(left.Entry.Parameters, right.Entry.Parameters) && bytes.Equal(left.Entry.Result, right.Entry.Result)
}

var _ MissionAuditStore = (*memoryMissionAuditStore)(nil)
var _ MissionAuditStore = (*forgedMissionAuditStore)(nil)
var _ MissionAuditStore = (*terminatingMissionAuditStore)(nil)
