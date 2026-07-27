package reference

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// RequestCompletionClarification records one trusted host question and moves
// the agent-facing continuation into the clarification state.
func (server *PersonServer) RequestCompletionClarification(
	pendingID string,
	question string,
	decidedBy string,
) error {
	question = strings.TrimSpace(question)
	decidedBy = strings.TrimSpace(decidedBy)
	if question == "" || decidedBy == "" {
		return errors.New("reference: completion clarification question and actor are required")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	pending, exists := server.completionPending[pendingID]
	if !exists {
		return errors.New("reference: completion review does not exist")
	}
	if pending.state != completionWaiting {
		return errors.New("reference: completion review is not awaiting a host decision")
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		return ErrCompletionExpired
	}
	if pending.clarificationRounds >= maxCompletionClarificationRounds {
		return errors.New("reference: completion clarification round limit reached")
	}
	var input aauth.InteractionRequest
	if err := decodeJSONBytes(bytes.NewReader(pending.requestBody), &input); err != nil {
		return err
	}
	mission, err := server.activeMissionForAgentLocked(pending.agent, *input.Mission)
	if err != nil {
		return err
	}
	questionBody, err := json.Marshal(map[string]string{"clarification": question})
	if err != nil {
		return err
	}
	previousPending := pending
	previousMission := mission
	pending.state = completionClarification
	pending.clarification = question
	pending.clarificationRounds++
	server.completionPending[pendingID] = pending
	mission.log = append(mission.log, aauth.MissionLogEntry{
		Sequence:       uint64(len(mission.log) + 1),
		Kind:           aauth.MissionLogClarification,
		RecordedAt:     server.clock.Now().UTC(),
		Agent:          pending.agent,
		DecidedBy:      decidedBy,
		RequestProofID: pending.requestReplayKey,
		Response:       questionBody,
	})
	server.missions[input.Mission.S256] = mission
	if err := server.persistGovernanceLocked(); err != nil {
		if governanceSaveDefinitelyFailed(err) {
			server.completionPending[pendingID] = previousPending
			server.missions[input.Mission.S256] = previousMission
		}
		return err
	}
	return nil
}

// AcceptCompletion records the trusted host acceptance and atomically
// terminates the reviewed mission.
func (server *PersonServer) AcceptCompletion(
	pendingID string,
	decidedBy string,
) error {
	decidedBy = strings.TrimSpace(decidedBy)
	if decidedBy == "" {
		return errors.New("reference: completion decision actor is required")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	pending, exists := server.completionPending[pendingID]
	if !exists {
		return errors.New("reference: completion review does not exist")
	}
	if pending.state != completionWaiting {
		return errors.New("reference: completion review is not awaiting acceptance")
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		return ErrCompletionExpired
	}
	var input aauth.InteractionRequest
	if err := decodeJSONBytes(bytes.NewReader(pending.requestBody), &input); err != nil {
		return err
	}
	mission, err := server.activeMissionForAgentLocked(pending.agent, *input.Mission)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"status": "completed"})
	if err != nil {
		return err
	}
	previousPending := pending
	previousMission := mission
	previousHistory := copyInteractionHistory(server.interactionHistory)
	now := server.clock.Now().UTC()
	pending.state = completionAccepted
	pending.decidedBy = decidedBy
	pending.decidedAt = now
	pending.responseBody = append([]byte(nil), body...)
	server.completionPending[pendingID] = pending
	if err := server.completeInteractionRecordLocked(
		pending.requestReplayKey,
		body,
		decidedBy,
		now,
	); err != nil {
		server.completionPending[pendingID] = previousPending
		return err
	}
	mission.log = append(mission.log,
		aauth.MissionLogEntry{
			Sequence:       uint64(len(mission.log) + 1),
			Kind:           aauth.MissionLogInteractionResponse,
			RecordedAt:     now,
			Agent:          pending.agent,
			DecidedBy:      decidedBy,
			RequestProofID: pending.requestReplayKey,
			Response:       append([]byte(nil), body...),
		},
		aauth.MissionLogEntry{
			Sequence:   uint64(len(mission.log) + 2),
			Kind:       aauth.MissionLogTermination,
			RecordedAt: now,
			Agent:      pending.agent,
			DecidedBy:  decidedBy,
		},
	)
	mission.status = aauth.MissionTerminated
	server.missions[input.Mission.S256] = mission
	if err := server.persistGovernanceLocked(); err != nil {
		if governanceSaveDefinitelyFailed(err) {
			server.completionPending[pendingID] = previousPending
			server.interactionHistory = previousHistory
			server.missions[input.Mission.S256] = previousMission
		}
		return err
	}
	return nil
}

func (server *PersonServer) commitCompletionTerminalLocked(
	pendingID string,
	pending pendingCompletion,
	body []byte,
	decidedBy string,
	appendMissionResponse bool,
) error {
	previousPending := server.completionPending[pendingID]
	previousHistory := copyInteractionHistory(server.interactionHistory)
	var input aauth.InteractionRequest
	if err := decodeJSONBytes(bytes.NewReader(pending.requestBody), &input); err != nil {
		return err
	}
	mission := server.missions[input.Mission.S256]
	previousMission := mission
	now := server.clock.Now().UTC()
	pending.state = completionServed
	pending.clarification = ""
	pending.decidedBy = decidedBy
	pending.decidedAt = now
	pending.responseBody = append([]byte(nil), body...)
	server.completionPending[pendingID] = pending
	if err := server.completeInteractionRecordLocked(
		pending.requestReplayKey,
		body,
		decidedBy,
		now,
	); err != nil {
		server.completionPending[pendingID] = previousPending
		return err
	}
	if appendMissionResponse {
		mission.log = append(mission.log, aauth.MissionLogEntry{
			Sequence:       uint64(len(mission.log) + 1),
			Kind:           aauth.MissionLogInteractionResponse,
			RecordedAt:     now,
			Agent:          pending.agent,
			DecidedBy:      decidedBy,
			RequestProofID: pending.requestReplayKey,
			Response:       append([]byte(nil), body...),
		})
		server.missions[input.Mission.S256] = mission
	}
	if err := server.persistGovernanceLocked(); err != nil {
		if governanceSaveDefinitelyFailed(err) {
			server.completionPending[pendingID] = previousPending
			server.interactionHistory = previousHistory
			if appendMissionResponse {
				server.missions[input.Mission.S256] = previousMission
			}
		}
		return err
	}
	return nil
}

func (server *PersonServer) completeInteractionRecordLocked(
	requestReplayKey string,
	body []byte,
	decidedBy string,
	decidedAt time.Time,
) error {
	for index, record := range server.interactionHistory {
		if record.Proof != nil && record.Proof.ReplayKey == requestReplayKey {
			if len(record.Response) != 0 {
				return errors.New("reference: interaction request is already terminal")
			}
			record.DecidedAt = decidedAt
			record.DecidedBy = decidedBy
			record.Response = append([]byte(nil), body...)
			server.interactionHistory[index] = record
			return nil
		}
	}
	return errors.New("reference: interaction request record is missing")
}

func copyInteractionRecord(record aauth.InteractionRecord) aauth.InteractionRecord {
	copied := record
	copied.Request = append([]byte(nil), record.Request...)
	copied.Response = append([]byte(nil), record.Response...)
	copied.Proof = copyRequestProof(record.Proof)
	return copied
}

func copyInteractionHistory(records []aauth.InteractionRecord) []aauth.InteractionRecord {
	copied := make([]aauth.InteractionRecord, len(records))
	for index, record := range records {
		copied[index] = copyInteractionRecord(record)
	}
	return copied
}
