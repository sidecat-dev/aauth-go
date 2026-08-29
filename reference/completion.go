package reference

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type completionState string

const (
	completionWaiting       completionState = "waiting"
	completionClarification completionState = "clarification"
	completionAccepted      completionState = "accepted"
	completionServed        completionState = "served"
)

const maxCompletionClarificationRounds = 5

// ErrCompletionExpired means the host attempted to change a completion review
// after its bounded pending lifetime. The agent-facing poll remains responsible
// for receiving and recording the terminal expiry response.
var ErrCompletionExpired = errors.New("reference: completion review expired")

type pendingCompletion struct {
	id                     string
	agent                  string
	pollingAgentThumbprint string
	expiresAt              time.Time
	requestReplayKey       string
	requestBody            []byte
	state                  completionState
	clarification          string
	clarificationRounds    int
	decidedBy              string
	decidedAt              time.Time
	responseBody           []byte
}

func (server *PersonServer) InteractionHistory() []aauth.InteractionRecord {
	server.mu.RLock()
	defer server.mu.RUnlock()
	return copyInteractionHistory(server.interactionHistory)
}

func (server *PersonServer) handleAgentInteraction(
	response http.ResponseWriter,
	request *http.Request,
) {
	body, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	verified, err := aauth.VerifyRequest(
		request.Context(),
		request,
		server.keyResolver,
		server.clock,
		aauth.VerifyRequestOptions{
			RequiredComponents:     []string{"content-digest"},
			AllowedCredentialTypes: []string{aauth.AgentTokenType},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	if server.governanceReplayExists(verified.ReplayKey) {
		writeSignatureFailure(response, errGovernanceReplay)
		return
	}
	var input aauth.InteractionRequest
	if err := decodeJSONBytes(bytes.NewReader(body), &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := input.Validate(); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if input.Type != aauth.InteractionTypeCompletion {
		writeProblem(
			response,
			http.StatusFailedDependency,
			"interaction_unavailable",
			errors.New("reference: only mission completion review is configured"),
		)
		return
	}
	if _, err := server.activeMissionForAgent(verified.Agent, *input.Mission); err != nil {
		server.writeMissionError(response, err)
		return
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", nil)
		return
	}
	now := server.clock.Now()
	expiresAt := now.Add(server.pendingLifetime)
	agentClaims, err := claimsWithoutAuthorization(*verified.AgentToken)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	tokenExpiry := time.Unix(agentClaims.ExpiresAt, 0)
	if tokenExpiry.Before(expiresAt) {
		expiresAt = tokenExpiry
	}
	if !expiresAt.After(now) {
		writeSignatureFailure(response, &signaturekey.Error{
			Code:  signaturekey.ErrorExpiredJWT,
			Cause: errors.New("reference: agent credential expired while beginning completion review"),
		})
		return
	}
	server.randomMu.Lock()
	pendingID, err := aauth.GeneratePendingID(server.random)
	server.randomMu.Unlock()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	proof := requestProof(request, verified)
	pending := pendingCompletion{
		id:                     pendingID,
		agent:                  verified.Agent,
		pollingAgentThumbprint: thumbprint,
		expiresAt:              expiresAt,
		requestReplayKey:       verified.ReplayKey,
		requestBody:            append([]byte(nil), body...),
		state:                  completionWaiting,
	}
	if err := server.commitCompletionRequest(
		pending,
		*input.Mission,
		proof,
		verified.Created.Add(signaturekey.DefaultSignatureWindow),
	); err != nil {
		server.writeMissionError(response, err)
		return
	}
	server.writeCompletionPending(response, pending)
}

func (server *PersonServer) commitCompletionRequest(
	pending pendingCompletion,
	missionReference aauth.MissionReference,
	proof *aauth.RequestProof,
	replayExpiresAt time.Time,
) error {
	server.mu.Lock()
	defer server.mu.Unlock()
	if _, replayed := server.governanceReplays[proof.ReplayKey]; replayed {
		return errGovernanceReplay
	}
	if _, exists := server.completionPending[pending.id]; exists {
		return errors.New("reference: completion pending identifier is duplicated")
	}
	mission, err := server.activeMissionForAgentLocked(pending.agent, missionReference)
	if err != nil {
		return err
	}
	previousMission := mission
	previousHistory := copyInteractionHistory(server.interactionHistory)
	previousReplays := copyGovernanceReplays(server.governanceReplays)
	server.interactionHistory = append(server.interactionHistory, aauth.InteractionRecord{
		Sequence:   uint64(len(server.interactionHistory) + 1),
		RecordedAt: proof.VerifiedAt,
		Agent:      pending.agent,
		Request:    append([]byte(nil), pending.requestBody...),
		Proof:      copyRequestProof(proof),
		PendingID:  pending.id,
	})
	mission.log = append(mission.log, aauth.MissionLogEntry{
		Sequence:       uint64(len(mission.log) + 1),
		Kind:           aauth.MissionLogInteractionRequest,
		RecordedAt:     proof.VerifiedAt,
		Agent:          pending.agent,
		RequestProofID: proof.ReplayKey,
		Request:        append([]byte(nil), pending.requestBody...),
		Proof:          copyRequestProof(proof),
	})
	server.missions[missionReference.S256] = mission
	server.completionPending[pending.id] = pending
	server.addGovernanceReplayLocked(proof.ReplayKey, replayExpiresAt)
	if err := server.persistGovernanceLocked(); err != nil {
		if governanceSaveDefinitelyFailed(err) {
			server.missions[missionReference.S256] = previousMission
			server.interactionHistory = previousHistory
			server.governanceReplays = previousReplays
			delete(server.completionPending, pending.id)
		}
		return err
	}
	return nil
}

func (server *PersonServer) handlePendingAgentInteraction(
	response http.ResponseWriter,
	request *http.Request,
) {
	verified, err := aauth.VerifyRequest(
		request.Context(),
		request,
		server.keyResolver,
		server.clock,
		aauth.VerifyRequestOptions{
			RequiredComponents:     requiredBodyComponents(request.Method),
			AllowedCredentialTypes: []string{aauth.AgentTokenType},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", nil)
		return
	}
	switch request.Method {
	case http.MethodGet:
		server.pollCompletion(response, request.PathValue("id"), verified.Agent, thumbprint)
	case http.MethodPost:
		server.receiveCompletionClarification(
			response,
			request,
			verified,
			thumbprint,
		)
	default:
		writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("GET or POST is required"))
	}
}

func requiredBodyComponents(method string) []string {
	if method == http.MethodPost {
		return []string{"content-digest"}
	}
	return nil
}

func (server *PersonServer) pollCompletion(
	response http.ResponseWriter,
	pendingID string,
	agent string,
	thumbprint string,
) {
	server.mu.Lock()
	pending, exists := server.completionPending[pendingID]
	if !exists {
		server.mu.Unlock()
		writeProblem(response, http.StatusGone, "gone", errors.New("completion review is unknown"))
		return
	}
	if pending.agent != agent || pending.pollingAgentThumbprint != thumbprint {
		server.mu.Unlock()
		writeProblem(response, http.StatusForbidden, "invalid_pending", errors.New("completion review belongs to another agent key"))
		return
	}
	var input aauth.InteractionRequest
	if err := decodeJSONBytes(bytes.NewReader(pending.requestBody), &input); err != nil {
		server.mu.Unlock()
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	mission, missionExists := server.missions[input.Mission.S256]
	if !missionExists || mission.reference != *input.Mission || mission.agent != agent {
		server.mu.Unlock()
		writeProblem(response, http.StatusForbidden, "invalid_mission", ErrMissionUnknown)
		return
	}
	if mission.status == aauth.MissionTerminated &&
		pending.state != completionAccepted &&
		pending.state != completionServed {
		body := problemBody(
			http.StatusForbidden,
			"mission_terminated",
			ErrMissionTerminated,
			map[string]any{"mission_status": string(aauth.MissionTerminated)},
		)
		if err := server.commitCompletionTerminalLocked(
			pendingID,
			pending,
			body,
			"",
			false,
		); err != nil {
			server.mu.Unlock()
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		server.mu.Unlock()
		writeProblemBody(response, http.StatusForbidden, body)
		return
	}
	if pending.state != completionAccepted &&
		pending.state != completionServed &&
		!pending.expiresAt.After(server.clock.Now()) {
		body := problemBody(
			http.StatusRequestTimeout,
			"expired",
			errors.New("completion review expired"),
			nil,
		)
		if err := server.commitCompletionTerminalLocked(
			pendingID,
			pending,
			body,
			"",
			true,
		); err != nil {
			server.mu.Unlock()
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		server.mu.Unlock()
		writeProblemBody(response, http.StatusRequestTimeout, body)
		return
	}
	switch pending.state {
	case completionWaiting, completionClarification:
		server.mu.Unlock()
		server.writeCompletionPending(response, pending)
	case completionAccepted:
		original := pending
		pending.state = completionServed
		server.completionPending[pendingID] = pending
		if err := server.persistGovernanceLocked(); err != nil {
			if governanceSaveDefinitelyFailed(err) {
				server.completionPending[pendingID] = original
			}
			server.mu.Unlock()
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		body := append([]byte(nil), pending.responseBody...)
		server.mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(body)
	default:
		server.mu.Unlock()
		writeProblem(response, http.StatusGone, "gone", errors.New("completion review already returned its terminal response"))
	}
}

func (server *PersonServer) writeCompletionPending(
	response http.ResponseWriter,
	pending pendingCompletion,
) {
	requirementType := aauth.RequirementApproval
	body := map[string]any{"status": "pending"}
	if pending.state == completionClarification {
		requirementType = aauth.RequirementClarification
		body["clarification"] = pending.clarification
		remaining := pending.expiresAt.Sub(server.clock.Now())
		if remaining < 0 {
			remaining = 0
		}
		body["timeout"] = int64(remaining.Seconds())
	}
	requirement, err := aauth.FormatRequirementHeader(aauth.Requirement{Type: requirementType})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.Header().Set("Location", "/interaction/pending/"+pending.id)
	response.Header().Set("Retry-After", "0")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("AAuth-Requirement", requirement)
	writeJSON(response, http.StatusAccepted, body)
}

func (server *PersonServer) receiveCompletionClarification(
	response http.ResponseWriter,
	request *http.Request,
	verified aauth.VerifiedRequest,
	thumbprint string,
) {
	if server.governanceReplayExists(verified.ReplayKey) {
		writeSignatureFailure(response, errGovernanceReplay)
		return
	}
	body, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	var input aauth.ClarificationResponse
	if err := decodeJSONBytes(bytes.NewReader(body), &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if input.Action != "clarification_response" ||
		strings.TrimSpace(input.ClarificationResponse) == "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("clarification_response action and answer are required"))
		return
	}
	proof := requestProof(request, verified)
	server.mu.Lock()
	pending, exists := server.completionPending[request.PathValue("id")]
	if !exists {
		server.mu.Unlock()
		writeProblem(response, http.StatusGone, "gone", errors.New("completion review is unknown"))
		return
	}
	if pending.agent != verified.Agent || pending.pollingAgentThumbprint != thumbprint {
		server.mu.Unlock()
		writeProblem(response, http.StatusForbidden, "invalid_pending", errors.New("completion review belongs to another agent key"))
		return
	}
	if pending.state != completionClarification {
		server.mu.Unlock()
		writeProblem(response, http.StatusConflict, "invalid_request", errors.New("completion review is not awaiting clarification"))
		return
	}
	var interaction aauth.InteractionRequest
	if err := decodeJSONBytes(bytes.NewReader(pending.requestBody), &interaction); err != nil {
		server.mu.Unlock()
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	missionState, missionExists := server.missions[interaction.Mission.S256]
	if !missionExists ||
		missionState.reference != *interaction.Mission ||
		missionState.agent != pending.agent {
		server.mu.Unlock()
		writeProblem(response, http.StatusForbidden, "invalid_mission", ErrMissionUnknown)
		return
	}
	if missionState.status == aauth.MissionTerminated {
		body := problemBody(
			http.StatusForbidden,
			"mission_terminated",
			ErrMissionTerminated,
			map[string]any{"mission_status": string(aauth.MissionTerminated)},
		)
		if err := server.commitCompletionTerminalLocked(
			pending.id,
			pending,
			body,
			"",
			false,
		); err != nil {
			server.mu.Unlock()
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		server.mu.Unlock()
		writeProblemBody(response, http.StatusForbidden, body)
		return
	}
	if !pending.expiresAt.After(server.clock.Now()) {
		body := problemBody(
			http.StatusRequestTimeout,
			"expired",
			errors.New("completion review expired"),
			nil,
		)
		if err := server.commitCompletionTerminalLocked(
			pending.id,
			pending,
			body,
			"",
			true,
		); err != nil {
			server.mu.Unlock()
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		server.mu.Unlock()
		writeProblemBody(response, http.StatusRequestTimeout, body)
		return
	}
	mission, err := server.activeMissionForAgentLocked(pending.agent, *interaction.Mission)
	if err != nil {
		server.mu.Unlock()
		server.writeMissionError(response, err)
		return
	}
	if _, replayed := server.governanceReplays[proof.ReplayKey]; replayed {
		server.mu.Unlock()
		writeSignatureFailure(response, errGovernanceReplay)
		return
	}
	previousPending := pending
	previousMission := mission
	previousReplays := copyGovernanceReplays(server.governanceReplays)
	pending.state = completionWaiting
	pending.clarification = ""
	server.completionPending[pending.id] = pending
	mission.log = append(mission.log, aauth.MissionLogEntry{
		Sequence:       uint64(len(mission.log) + 1),
		Kind:           aauth.MissionLogClarification,
		RecordedAt:     proof.VerifiedAt,
		Agent:          pending.agent,
		RequestProofID: proof.ReplayKey,
		Request:        append([]byte(nil), body...),
		Proof:          copyRequestProof(proof),
	})
	server.missions[interaction.Mission.S256] = mission
	server.addGovernanceReplayLocked(
		proof.ReplayKey,
		verified.Created.Add(signaturekey.DefaultSignatureWindow),
	)
	if err := server.persistGovernanceLocked(); err != nil {
		if governanceSaveDefinitelyFailed(err) {
			server.completionPending[pending.id] = previousPending
			server.missions[interaction.Mission.S256] = previousMission
			server.governanceReplays = previousReplays
		}
		server.mu.Unlock()
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	server.mu.Unlock()
	server.writeCompletionPending(response, pending)
}
