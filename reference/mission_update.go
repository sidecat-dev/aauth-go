package reference

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func (server *PersonServer) handleMissionUpdate(
	response http.ResponseWriter,
	request *http.Request,
) {
	if request.URL.RawQuery != "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("mission update endpoint does not accept query parameters"))
		return
	}
	body, err := readBoundedRequestBody(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	var action struct {
		Action string `json:"action"`
	}
	if json.Unmarshal(body, &action) == nil && action.Action == "completion" {
		server.handleMissionCompletion(response, request, body)
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
	agentClaims, err := verified.AgentClaims()
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	if !server.requireCurrentPersonServer(response, request.Context(), verified) {
		return
	}
	reference := aauth.MissionReference{
		Approver: server.identifier,
		S256:     request.PathValue("s256"),
	}
	if err := reference.Validate(); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}

	server.missionIssuanceMu.Lock()
	defer server.missionIssuanceMu.Unlock()
	if server.recoverMissionUpdate(response, verified.ReplayKey, verified.Agent, request.URL.Path) {
		return
	}
	if server.governanceReplayExists(verified.ReplayKey) {
		writeSignatureFailure(response, errGovernanceReplay)
		return
	}
	var input aauth.MissionUpdate
	if err := decodeJSONBytes(bytes.NewReader(body), &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := input.Validate(); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	mission, err := server.activeMissionForAgent(verified.Agent, reference)
	if err != nil {
		server.writeMissionError(response, err)
		return
	}
	updateEvaluation := aauth.MissionUpdateEvaluation{
		Agent:          verified.Agent,
		Mission:        mission,
		Description:    input.Description,
		Confirmation:   verified.PublicKey,
		AgentExpiresAt: time.Unix(agentClaims.ExpiresAt, 0).UTC(),
		PersonServer:   server.identifier,
	}
	if server.missionUpdatePolicy != nil {
		err = server.missionUpdatePolicy(request.Context(), updateEvaluation)
	} else {
		_, err = server.currentMissionPolicy(request.Context(), aauth.MissionEvaluation{
			Agent:          verified.Agent,
			Proposal:       aauth.MissionProposal{Description: input.Description},
			Confirmation:   verified.PublicKey,
			AgentExpiresAt: updateEvaluation.AgentExpiresAt,
			PersonServer:   server.identifier,
		})
	}
	if err != nil {
		writeHostPolicyRefusal(response, "mission_denied", "mission update policy denied the request")
		return
	}
	result := aauth.MissionUpdateResult{S256: aauth.S256([]byte(input.Description))}
	responseBody, err := json.Marshal(result)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	entry := aauth.MissionLogEntry{
		Kind:           aauth.MissionLogUpdate,
		RecordedAt:     verified.VerifiedAt,
		Agent:          verified.Agent,
		RequestProofID: verified.ReplayKey,
		Request:        append([]byte(nil), body...),
		Response:       append([]byte(nil), responseBody...),
		Proof:          requestProof(request, verified),
	}
	if err := server.appendMissionLogWithReplay(
		verified.Agent,
		reference,
		entry,
		verified.ReplayKey,
		verified.Created.Add(signaturekey.DefaultSignatureWindow),
	); err != nil {
		server.writeMissionError(response, err)
		return
	}
	writeExactJSON(response, http.StatusOK, responseBody)
}

func (server *PersonServer) recoverMissionUpdate(
	response http.ResponseWriter,
	replayKey string,
	agent string,
	target string,
) bool {
	server.mu.RLock()
	var responseBody []byte
	for _, mission := range server.missions {
		for _, entry := range mission.log {
			if entry.Kind != aauth.MissionLogUpdate || entry.RequestProofID != replayKey ||
				entry.Agent != agent || entry.Proof == nil || entry.Proof.Target != target {
				continue
			}
			responseBody = append([]byte(nil), entry.Response...)
			break
		}
		if responseBody != nil {
			break
		}
	}
	server.mu.RUnlock()
	if responseBody == nil {
		return false
	}
	var result aauth.MissionUpdateResult
	if err := decodeJSONBytes(bytes.NewReader(responseBody), &result); err != nil || result.Validate() != nil {
		writeProblem(response, http.StatusServiceUnavailable, "server_error", nil)
		return true
	}
	writeExactJSON(response, http.StatusOK, responseBody)
	return true
}
