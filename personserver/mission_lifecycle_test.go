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
	"sync"
	"testing"
	"time"

	aauth "aauth-go"
)

func TestMissionUpdatesRetainExactOrderedPolicyContext(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(20*time.Minute), MissionActive, "")
	bodies := [][]byte{
		[]byte("{\n  \"action\": \"update\", \"description\": \"First change\", \"extension\": {\"kept\": true}\n}"),
		[]byte(`{"action":"update","description":"Second change"}`),
	}
	for index, body := range bodies {
		response := protocol.signedMissionAction(t, mission.S256, body)
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("update %d = %d headers=%v body=%s", index, response.Code, response.Header(), response.Body.String())
		}
		var output aauth.MissionUpdateResponse
		if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
			t.Fatal(err)
		}
		if output.S256 != aauth.MissionS256(body) {
			t.Fatalf("update %d s256 = %q, want exact body digest %q", index, output.S256, aauth.MissionS256(body))
		}
	}

	record, err := protocol.store.LoadMissionForAgent(
		context.Background(), protocol.agentID, mission.S256, protocol.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != MissionActive || len(record.AcceptedUpdates) != 2 {
		t.Fatalf("updated mission = %#v", record)
	}
	for index, update := range record.AcceptedUpdates {
		if !bytes.Equal(update.Document.ExactJSON, bodies[index]) ||
			update.Document.S256 != aauth.MissionS256(bodies[index]) ||
			update.AcceptedAt.IsZero() {
			t.Fatalf("retained update %d = %#v", index, update)
		}
	}
	if len(protocol.updates) != 2 || len(protocol.updates[1].Mission.AcceptedUpdates) != 1 ||
		protocol.updates[1].Mission.AcceptedUpdates[0].Document.Update.Description != "First change" {
		t.Fatalf("update policy contexts = %#v", protocol.updates)
	}

	body, _ := json.Marshal(map[string]string{"resource": protocol.resourceID, "mission_s256": mission.S256})
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/person", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	protocol.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("later Person token = %d %s", response.Code, response.Body.String())
	}
	context := protocol.bindings[len(protocol.bindings)-1].Mission
	if context == nil || len(context.AcceptedUpdates) != 2 ||
		context.AcceptedUpdates[0].Document.Update.Description != "First change" ||
		context.AcceptedUpdates[1].Document.Update.Description != "Second change" {
		t.Fatalf("later Person policy context = %#v", context)
	}
}

func TestMissionCompletionRetainsPersonAcceptanceAndTerminates(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(20*time.Minute), MissionActive, "")
	updateBody := []byte(`{"action":"update","description":"Scope refined"}`)
	if response := protocol.signedMissionAction(t, mission.S256, updateBody); response.Code != http.StatusOK {
		t.Fatalf("update = %d %s", response.Code, response.Body.String())
	}
	completionBody := []byte("{\n \"action\": \"completion\", \"summary\": \"Finished the agreed work\", \"extension\": true\n}")
	response := protocol.signedMissionAction(t, mission.S256, completionBody)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("completion = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if len(protocol.completions) != 1 || protocol.completions[0].Mission.S256 != mission.S256 ||
		len(protocol.completions[0].Mission.AcceptedUpdates) != 1 ||
		protocol.completions[0].Document.Completion.Summary != "Finished the agreed work" {
		t.Fatalf("completion policy request = %#v", protocol.completions)
	}
	record, err := protocol.store.LoadMissionForAgent(
		context.Background(), protocol.agentID, mission.S256, protocol.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != MissionTerminated || record.TerminationReason != "completed" || record.Completion == nil ||
		!bytes.Equal(record.Completion.Document.ExactJSON, completionBody) || record.Completion.AcceptedAt.IsZero() {
		t.Fatalf("completed mission = %#v", record)
	}
	assertMissionProblem(
		t, protocol.signedMissionAction(t, mission.S256, updateBody),
		http.StatusForbidden, "mission_terminated", "terminated", "completed",
	)
}

func TestMissionUpdateAndCompletionRecheckLifecycleAfterPersonPolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		body   []byte
		change func(*missionProtocol, MissionRecord)
		reason string
	}{
		{
			name: "update revoked",
			body: []byte(`{"action":"update","description":"Change"}`),
			change: func(protocol *missionProtocol, mission MissionRecord) {
				protocol.store.terminateMission(mission.Agent, mission.S256, "revoked")
			},
			reason: "revoked",
		},
		{
			name: "completion expired",
			body: []byte(`{"action":"completion","summary":"Done"}`),
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
			protocol.server.missionAcceptUpdate = func(_ context.Context, request MissionUpdatePolicyRequest) error {
				test.change(protocol, mission)
				return nil
			}
			protocol.server.missionConfirmPersonCompletion = func(_ context.Context, request MissionCompletionPolicyRequest) error {
				test.change(protocol, mission)
				return nil
			}
			response := protocol.signedMissionAction(t, mission.S256, test.body)
			assertMissionProblem(t, response, http.StatusForbidden, "mission_terminated", "terminated", test.reason)
			record, err := protocol.store.LoadMissionForAgent(
				context.Background(), protocol.agentID, mission.S256, protocol.now,
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(record.AcceptedUpdates) != 0 || record.Completion != nil {
				t.Fatalf("failed lifecycle transition mutated log: %#v", record)
			}
		})
	}
}

func TestMissionStoreSerializesConcurrentUpdates(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
	expected, err := protocol.store.LoadMissionForAgent(
		context.Background(), protocol.agentID, mission.S256, protocol.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	documents := make([]aauth.MissionUpdateDocument, 2)
	for index, description := range []string{"First", "Second"} {
		documents[index], err = aauth.EncodeMissionUpdate(aauth.MissionUpdate{Action: "update", Description: description})
		if err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	errorsOut := make(chan error, 2)
	var wait sync.WaitGroup
	for _, document := range documents {
		document := document
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := protocol.store.AppendMissionUpdate(context.Background(), expected, protocol.now, document)
			errorsOut <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errorsOut)
	var succeeded, conflicted int
	for err := range errorsOut {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrMissionConflict):
			conflicted++
		default:
			t.Fatalf("concurrent append error = %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent updates succeeded=%d conflicted=%d", succeeded, conflicted)
	}
	current, err := protocol.store.LoadMissionForAgent(
		context.Background(), protocol.agentID, mission.S256, protocol.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.AcceptedUpdates) != 1 {
		t.Fatalf("concurrent updates retained %d entries", len(current.AcceptedUpdates))
	}
}

func TestMissionStoreSerializesTerminalRaces(t *testing.T) {
	for _, test := range []struct {
		name       string
		operations []string
	}{
		{name: "update versus completion", operations: []string{"update", "completion"}},
		{name: "completion versus completion", operations: []string{"completion", "completion"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			protocol := newMissionProtocol(t)
			mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
			expected, err := protocol.store.LoadMissionForAgent(
				context.Background(), protocol.agentID, mission.S256, protocol.now,
			)
			if err != nil {
				t.Fatal(err)
			}
			update, err := aauth.EncodeMissionUpdate(aauth.MissionUpdate{Action: "update", Description: "Changed work"})
			if err != nil {
				t.Fatal(err)
			}
			completion, err := aauth.EncodeMissionCompletion(aauth.MissionCompletion{Action: "completion", Summary: "Done"})
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			errorsOut := make(chan error, len(test.operations))
			var wait sync.WaitGroup
			for _, operation := range test.operations {
				operation := operation
				wait.Add(1)
				go func() {
					defer wait.Done()
					<-start
					if operation == "update" {
						_, err := protocol.store.AppendMissionUpdate(context.Background(), expected, protocol.now, update)
						errorsOut <- err
						return
					}
					_, err := protocol.store.CompleteMission(context.Background(), expected, protocol.now, completion)
					errorsOut <- err
				}()
			}
			close(start)
			wait.Wait()
			close(errorsOut)
			var succeeded, refused int
			for err := range errorsOut {
				switch {
				case err == nil:
					succeeded++
				case errors.Is(err, ErrMissionConflict):
					refused++
				default:
					var terminated *MissionTerminatedError
					if !errors.As(err, &terminated) || terminated.TerminationReason != "completed" {
						t.Fatalf("terminal race error = %v", err)
					}
					refused++
				}
			}
			if succeeded != 1 || refused != 1 {
				t.Fatalf("terminal race succeeded=%d refused=%d", succeeded, refused)
			}
			current, err := protocol.store.LoadMissionForAgent(
				context.Background(), protocol.agentID, mission.S256, protocol.now,
			)
			if err != nil {
				t.Fatal(err)
			}
			switch current.State {
			case MissionActive:
				if test.name != "update versus completion" || len(current.AcceptedUpdates) != 1 || current.Completion != nil {
					t.Fatalf("active terminal-race state = %#v", current)
				}
			case MissionTerminated:
				if current.TerminationReason != "completed" || current.Completion == nil || len(current.AcceptedUpdates) != 0 {
					t.Fatalf("completed terminal-race state = %#v", current)
				}
			default:
				t.Fatalf("terminal-race state = %#v", current)
			}
		})
	}
}

func TestMissionActionHidesMissingAndDifferentOwner(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	unknown := aauth.MissionS256([]byte("unknown mission"))
	missing := protocol.signedMissionAction(
		t, unknown, []byte(`{"action":"update","description":"Change"}`),
	)
	other := protocol.commitMission(
		t, "aauth:other@provider.example", protocol.now.Add(10*time.Minute), MissionActive, "",
	)
	wrongOwner := protocol.signedMissionAction(
		t, other.S256, []byte(`{"action":"update","description":"Change"}`),
	)
	protocol.server.missions = ownerLeakingMissionStore{MissionStore: protocol.store, record: other}
	leakyStore := protocol.signedMissionAction(
		t, unknown, []byte(`{"action":"update","description":"Change"}`),
	)
	if missing.Code != http.StatusNotFound || wrongOwner.Code != http.StatusNotFound ||
		leakyStore.Code != http.StatusNotFound ||
		missing.Body.String() != wrongOwner.Body.String() || missing.Body.String() != leakyStore.Body.String() ||
		!reflect.DeepEqual(missing.Header(), wrongOwner.Header()) ||
		!reflect.DeepEqual(missing.Header(), leakyStore.Header()) ||
		!bytes.Contains(missing.Body.Bytes(), []byte(`"error":"mission_not_found"`)) {
		t.Fatalf("missing=%d %s different-owner=%d %s leaky-store=%d %s", missing.Code, missing.Body.String(), wrongOwner.Code, wrongOwner.Body.String(), leakyStore.Code, leakyStore.Body.String())
	}
}

func TestMissionActionRejectsMalformedRequestsBeforePolicy(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
	unknown := aauth.MissionS256([]byte("unknown mission"))
	tests := []struct {
		name string
		s256 string
		body []byte
	}{
		{name: "identifier", s256: "not-a-digest", body: []byte(`{"action":"update","description":"Change"}`)},
		{name: "missing action", s256: unknown, body: []byte(`{"description":"Change"}`)},
		{name: "unknown action", s256: unknown, body: []byte(`{"action":"replace","description":"Change"}`)},
		{name: "empty update", s256: mission.S256, body: []byte(`{"action":"update","description":""}`)},
		{name: "empty completion", s256: mission.S256, body: []byte(`{"action":"completion","summary":""}`)},
		{name: "duplicate action", s256: mission.S256, body: []byte(`{"action":"update","action":"update","description":"Change"}`)},
		{name: "case variant", s256: mission.S256, body: []byte(`{"Action":"update","description":"Change"}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := protocol.signedMissionAction(t, test.s256, test.body)
			if response.Code != http.StatusBadRequest ||
				!bytes.Contains(response.Body.Bytes(), []byte(`"error":"invalid_request"`)) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}
	if len(protocol.updates) != 0 || len(protocol.completions) != 0 {
		t.Fatalf("malformed requests reached policy: updates=%d completions=%d", len(protocol.updates), len(protocol.completions))
	}
}

func TestMissionActionPolicyDenialIsTypedAndDoesNotMutate(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
		code string
		deny func(*missionProtocol)
	}{
		{
			name: "update", body: []byte(`{"action":"update","description":"Change"}`),
			code: "mission_update_denied",
			deny: func(protocol *missionProtocol) {
				protocol.server.missionAcceptUpdate = func(context.Context, MissionUpdatePolicyRequest) error {
					return fmt.Errorf("%w: person declined update", ErrMissionDenied)
				}
			},
		},
		{
			name: "completion", body: []byte(`{"action":"completion","summary":"Done"}`),
			code: "mission_completion_denied",
			deny: func(protocol *missionProtocol) {
				protocol.server.missionConfirmPersonCompletion = func(context.Context, MissionCompletionPolicyRequest) error {
					return fmt.Errorf("%w: person declined completion", ErrMissionDenied)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			protocol := newMissionProtocol(t)
			mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
			test.deny(protocol)
			response := protocol.signedMissionAction(t, mission.S256, test.body)
			if response.Code != http.StatusForbidden ||
				!bytes.Contains(response.Body.Bytes(), []byte(`"error":"`+test.code+`"`)) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
			current, err := protocol.store.LoadMissionForAgent(context.Background(), protocol.agentID, mission.S256, protocol.now)
			if err != nil {
				t.Fatal(err)
			}
			if current.State != MissionActive || len(current.AcceptedUpdates) != 0 || current.Completion != nil {
				t.Fatalf("denial mutated mission: %#v", current)
			}
		})
	}
}

func TestMissionActionOperationalCallbackFailureIsNotReportedAsDenial(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
		fail func(*missionProtocol)
	}{
		{
			name: "update", body: []byte(`{"action":"update","description":"Change"}`),
			fail: func(protocol *missionProtocol) {
				protocol.server.missionAcceptUpdate = func(context.Context, MissionUpdatePolicyRequest) error {
					return errors.New("policy database unavailable")
				}
			},
		},
		{
			name: "completion", body: []byte(`{"action":"completion","summary":"Done"}`),
			fail: func(protocol *missionProtocol) {
				protocol.server.missionConfirmPersonCompletion = func(context.Context, MissionCompletionPolicyRequest) error {
					return errors.New("person channel unavailable")
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			protocol := newMissionProtocol(t)
			mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
			test.fail(protocol)
			response := protocol.signedMissionAction(t, mission.S256, test.body)
			if response.Code != http.StatusInternalServerError ||
				!bytes.Contains(response.Body.Bytes(), []byte(`"error":"server_error"`)) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestMissionActionDoesNotPublishAnUnretainedTransition(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
		fail func(*memoryMissionStore)
	}{
		{
			name: "update", body: []byte(`{"action":"update","description":"Change"}`),
			fail: func(store *memoryMissionStore) { store.appendMissionError = errors.New("update store unavailable") },
		},
		{
			name: "completion", body: []byte(`{"action":"completion","summary":"Done"}`),
			fail: func(store *memoryMissionStore) {
				store.completeMissionError = errors.New("completion store unavailable")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			protocol := newMissionProtocol(t)
			mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
			test.fail(protocol.store)
			response := protocol.signedMissionAction(t, mission.S256, test.body)
			if response.Code != http.StatusInternalServerError ||
				bytes.Contains(response.Body.Bytes(), []byte(`"s256"`)) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
			current, err := protocol.store.LoadMissionForAgent(context.Background(), protocol.agentID, mission.S256, protocol.now)
			if err != nil {
				t.Fatal(err)
			}
			if current.State != MissionActive || len(current.AcceptedUpdates) != 0 || current.Completion != nil {
				t.Fatalf("retention failure mutated mission: %#v", current)
			}
		})
	}
}

func TestMissionActionRejectsZeroAcceptanceInstantBeforeStoreMutation(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "update", body: []byte(`{"action":"update","description":"Change"}`)},
		{name: "completion", body: []byte(`{"action":"completion","summary":"Done"}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			protocol := newMissionProtocol(t)
			mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
			protocol.server.missionAcceptUpdate = func(context.Context, MissionUpdatePolicyRequest) error {
				protocol.now = time.Time{}
				return nil
			}
			protocol.server.missionConfirmPersonCompletion = func(context.Context, MissionCompletionPolicyRequest) error {
				protocol.now = time.Time{}
				return nil
			}
			response := protocol.signedMissionAction(t, mission.S256, test.body)
			if response.Code != http.StatusInternalServerError ||
				!bytes.Contains(response.Body.Bytes(), []byte(`"error":"server_error"`)) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
			current, err := protocol.store.LoadMissionForAgent(context.Background(), protocol.agentID, mission.S256, protocol.now)
			if err != nil {
				t.Fatal(err)
			}
			if current.State != MissionActive || len(current.AcceptedUpdates) != 0 || current.Completion != nil {
				t.Fatalf("zero acceptance instant mutated mission: %#v", current)
			}
		})
	}
}

func TestMissionActionRejectsAStoreThatMisreportsTheTransition(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
		mode string
	}{
		{name: "update", body: []byte(`{"action":"update","description":"Change"}`), mode: "update"},
		{name: "completion", body: []byte(`{"action":"completion","summary":"Done"}`), mode: "completion"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			protocol := newMissionProtocol(t)
			mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
			protocol.server.missions = invalidTransitionMissionStore{MissionStore: protocol.store, mode: test.mode}
			response := protocol.signedMissionAction(t, mission.S256, test.body)
			if response.Code != http.StatusInternalServerError ||
				!bytes.Contains(response.Body.Bytes(), []byte(`"error":"server_error"`)) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
			current, err := protocol.store.LoadMissionForAgent(context.Background(), protocol.agentID, mission.S256, protocol.now)
			if err != nil {
				t.Fatal(err)
			}
			if current.State != MissionActive || len(current.AcceptedUpdates) != 0 || current.Completion != nil {
				t.Fatalf("misreported transition mutated mission: %#v", current)
			}
		})
	}
}

func TestMissionActionStoreCannotRewritePolicyTimeHistoryThroughAliases(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
		mode string
	}{
		{name: "update", body: []byte(`{"action":"update","description":"Second"}`), mode: "update"},
		{name: "completion", body: []byte(`{"action":"completion","summary":"Done"}`), mode: "completion"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			protocol := newMissionProtocol(t)
			mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
			if response := protocol.signedMissionAction(
				t, mission.S256, []byte(`{"action":"update","description":"First"}`),
			); response.Code != http.StatusOK {
				t.Fatalf("first update = %d %s", response.Code, response.Body.String())
			}
			protocol.server.missions = aliasMutatingMissionStore{MissionStore: protocol.store, mode: test.mode}
			response := protocol.signedMissionAction(t, mission.S256, test.body)
			if response.Code != http.StatusInternalServerError ||
				!bytes.Contains(response.Body.Bytes(), []byte(`"error":"server_error"`)) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
			current, err := protocol.store.LoadMissionForAgent(context.Background(), protocol.agentID, mission.S256, protocol.now)
			if err != nil {
				t.Fatal(err)
			}
			if current.State != MissionActive || len(current.AcceptedUpdates) != 1 ||
				current.AcceptedUpdates[0].Document.Update.Description != "First" || current.Completion != nil {
				t.Fatalf("hostile store changed durable history: %#v", current)
			}
		})
	}
}

type invalidTransitionMissionStore struct {
	MissionStore
	mode string
}

type ownerLeakingMissionStore struct {
	MissionStore
	record MissionRecord
}

type aliasMutatingMissionStore struct {
	MissionStore
	mode string
}

func (store aliasMutatingMissionStore) AppendMissionUpdate(
	ctx context.Context, expected MissionRecord, acceptedAt time.Time, document aauth.MissionUpdateDocument,
) (MissionRecord, error) {
	if store.mode != "update" {
		return store.MissionStore.AppendMissionUpdate(ctx, expected, acceptedAt, document)
	}
	expected.ExactJSON[0] ^= 0xff
	expected.AcceptedUpdates[0].Document.ExactJSON[0] ^= 0xff
	document.ExactJSON[0] ^= 0xff
	expected.AcceptedUpdates = append(expected.AcceptedUpdates, MissionUpdateRecord{
		Document: document, AcceptedAt: acceptedAt,
	})
	return expected, nil
}

func (store aliasMutatingMissionStore) CompleteMission(
	ctx context.Context, expected MissionRecord, acceptedAt time.Time, document aauth.MissionCompletionDocument,
) (MissionRecord, error) {
	if store.mode != "completion" {
		return store.MissionStore.CompleteMission(ctx, expected, acceptedAt, document)
	}
	expected.ExactJSON[0] ^= 0xff
	expected.AcceptedUpdates[0].Document.ExactJSON[0] ^= 0xff
	document.ExactJSON[0] ^= 0xff
	expected.State = MissionTerminated
	expected.TerminationReason = "completed"
	expected.Completion = &MissionCompletionRecord{Document: document, AcceptedAt: acceptedAt}
	return expected, nil
}

func (store ownerLeakingMissionStore) LoadMissionForAgent(
	context.Context, string, string, time.Time,
) (MissionRecord, error) {
	return cloneMissionRecord(store.record), nil
}

func (store invalidTransitionMissionStore) AppendMissionUpdate(
	ctx context.Context, expected MissionRecord, acceptedAt time.Time, document aauth.MissionUpdateDocument,
) (MissionRecord, error) {
	if store.mode == "update" {
		return expected, nil
	}
	return store.MissionStore.AppendMissionUpdate(ctx, expected, acceptedAt, document)
}

func (store invalidTransitionMissionStore) CompleteMission(
	ctx context.Context, expected MissionRecord, acceptedAt time.Time, document aauth.MissionCompletionDocument,
) (MissionRecord, error) {
	if store.mode == "completion" {
		return expected, nil
	}
	return store.MissionStore.CompleteMission(ctx, expected, acceptedAt, document)
}

func TestMissionUpdateSurvivesServerRecompositionWithExactBytes(t *testing.T) {
	t.Parallel()

	protocol := newMissionProtocol(t)
	mission := protocol.commitMission(t, protocol.agentID, protocol.now.Add(10*time.Minute), MissionActive, "")
	firstBody := []byte("{\n  \"action\":\"update\", \"description\":\"First\", \"extension\":true\n}")
	if response := protocol.signedMissionAction(t, mission.S256, firstBody); response.Code != http.StatusOK {
		t.Fatalf("first update = %d %s", response.Code, response.Body.String())
	}

	recomposed, err := NewPSAuthorization(PSAuthorizationConfig{
		Issuer: protocol.personServerID, SigningKey: protocol.personKey, KeyResolver: protocol.resolver,
		Clock: protocol.clock, NewID: func() string { return "recomposed-token" }, Tokens: protocol.store,
		BindPerson: func(context.Context, PersonTokenRequest) (Person, error) {
			return Person{Subject: "person-123", Lifetime: time.Minute}, nil
		},
		Authorize: func(_ context.Context, request AuthorizationRequest) (AuthorizationDecision, error) {
			return AuthorizationDecision{Scopes: request.Scopes, Lifetime: time.Minute}, nil
		},
		Missions: &MissionConfig{
			Approve: protocol.server.missionApprove,
			AcceptUpdate: func(_ context.Context, request MissionUpdatePolicyRequest) error {
				if len(request.Mission.AcceptedUpdates) != 1 ||
					!bytes.Equal(request.Mission.AcceptedUpdates[0].Document.ExactJSON, firstBody) {
					return errors.New("recomposed policy did not receive exact prior update")
				}
				return nil
			},
			ConfirmPersonAcceptedCompletion: func(context.Context, MissionCompletionPolicyRequest) error { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	secondBody := []byte(`{"action":"update","description":"Second"}`)
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/mission/"+mission.S256, bytes.NewReader(secondBody))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	recomposed.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("recomposed update = %d %s", response.Code, response.Body.String())
	}
	current, err := protocol.store.LoadMissionForAgent(context.Background(), protocol.agentID, mission.S256, protocol.now)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.AcceptedUpdates) != 2 ||
		!bytes.Equal(current.AcceptedUpdates[0].Document.ExactJSON, firstBody) ||
		!bytes.Equal(current.AcceptedUpdates[1].Document.ExactJSON, secondBody) {
		t.Fatalf("recomposed state = %#v", current.AcceptedUpdates)
	}
}

func (protocol *missionProtocol) signedMissionAction(t *testing.T, s256 string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, protocol.personServerID+"/mission/"+s256, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signPersonServerTestRequest(request, protocol.agentKey, protocol.agentToken, protocol.clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	protocol.server.Handler().ServeHTTP(response, request)
	return response
}
