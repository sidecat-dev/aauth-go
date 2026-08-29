package reference

import (
	"bytes"
	"errors"
	"net/http"
	"time"

	"gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func (server *PersonServer) handleMissionCompletion(
	response http.ResponseWriter,
	request *http.Request,
	body []byte,
) {
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
	if !server.requireCurrentPersonServer(response, verified) {
		return
	}
	reference := aauth.MissionReference{Approver: server.identifier, S256: request.PathValue("s256")}
	if err := reference.Validate(); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	var input aauth.MissionCompletion
	if err := decodeJSONBytes(bytes.NewReader(body), &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := input.Validate(); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	server.beginCompletionReview(response, request, verified, body, reference)
}

func (server *PersonServer) beginCompletionReview(
	response http.ResponseWriter,
	request *http.Request,
	verified aauth.VerifiedRequest,
	body []byte,
	missionReference aauth.MissionReference,
) {
	if server.governanceReplayExists(verified.ReplayKey) {
		writeSignatureFailure(response, errGovernanceReplay)
		return
	}
	if _, err := server.activeMissionForAgent(verified.Agent, missionReference); err != nil {
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
	agentClaims, err := verified.AgentClaims()
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
		missionReference:       missionReference,
		agent:                  verified.Agent,
		pollingAgentThumbprint: thumbprint,
		expiresAt:              expiresAt,
		requestReplayKey:       verified.ReplayKey,
		requestBody:            append([]byte(nil), body...),
		state:                  completionWaiting,
	}
	if err := server.commitCompletionRequest(
		pending,
		missionReference,
		proof,
		verified.Created.Add(signaturekey.DefaultSignatureWindow),
	); err != nil {
		server.writeMissionError(response, err)
		return
	}
	server.writeCompletionPending(response, pending)
}
