package reference

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func missionReferenceFromCompletionBody(
	body []byte,
	target string,
	personServer string,
) (aauth.MissionReference, error) {
	if strings.HasPrefix(target, "/mission/") {
		var completion aauth.MissionCompletion
		if err := decodeJSONBytes(bytes.NewReader(body), &completion); err != nil {
			return aauth.MissionReference{}, err
		}
		if err := completion.Validate(); err != nil {
			return aauth.MissionReference{}, err
		}
		reference := aauth.MissionReference{
			Approver: personServer,
			S256:     strings.TrimPrefix(target, "/mission/"),
		}
		if err := reference.Validate(); err != nil {
			return aauth.MissionReference{}, err
		}
		return reference, nil
	}
	if target != "/interaction" {
		return aauth.MissionReference{}, errors.New("completion request target is invalid")
	}
	var interaction aauth.InteractionRequest
	if err := decodeJSONBytes(bytes.NewReader(body), &interaction); err != nil {
		return aauth.MissionReference{}, err
	}
	if err := interaction.Validate(); err != nil ||
		interaction.Type != aauth.InteractionTypeCompletion ||
		interaction.Mission == nil ||
		interaction.Mission.Approver != personServer {
		return aauth.MissionReference{}, errors.New("completion request is not a local mission completion")
	}
	return *interaction.Mission, nil
}

func decodeGovernanceInteractionRecord(
	encoded aauth.InteractionRecord,
	sequence uint64,
	personServer string,
	missions map[string]storedMission,
) (aauth.InteractionRecord, error) {
	if encoded.Sequence != sequence ||
		encoded.RecordedAt.IsZero() ||
		encoded.Proof == nil {
		return aauth.InteractionRecord{}, errors.New("interaction record ordering or evidence is invalid")
	}
	if err := aauth.ValidateAgentIdentifier(encoded.Agent); err != nil {
		return aauth.InteractionRecord{}, err
	}
	missionReference, err := missionReferenceFromCompletionBody(encoded.Request, encoded.Proof.Target, personServer)
	if err != nil {
		return aauth.InteractionRecord{}, err
	}
	mission, exists := missions[missionReference.S256]
	if !exists || mission.reference != missionReference || mission.agent != encoded.Agent {
		return aauth.InteractionRecord{}, errors.New("interaction record mission is absent or has the wrong owner")
	}
	if err := validateStoredRequestProof(
		encoded.Proof,
		encoded.Request,
		encoded.Agent,
		personServer,
		encoded.Proof.Target,
	); err != nil {
		return aauth.InteractionRecord{}, err
	}
	if !encoded.RecordedAt.Equal(encoded.Proof.VerifiedAt) {
		return aauth.InteractionRecord{}, errors.New("interaction record time does not match its verified proof")
	}
	decodedID, err := base64.RawURLEncoding.DecodeString(encoded.PendingID)
	if err != nil || len(decodedID) != 16 {
		return aauth.InteractionRecord{}, errors.New("interaction record pending id is invalid")
	}
	if len(encoded.Response) == 0 {
		if !encoded.DecidedAt.IsZero() || encoded.DecidedBy != "" {
			return aauth.InteractionRecord{}, errors.New("unterminated interaction record is inconsistent")
		}
	} else {
		if encoded.DecidedAt.IsZero() ||
			encoded.DecidedAt.Before(encoded.RecordedAt) {
			return aauth.InteractionRecord{}, errors.New("interaction decision time is invalid")
		}
		kind, err := interactionResponseKind(encoded.Response)
		if err != nil {
			return aauth.InteractionRecord{}, err
		}
		if kind == "completed" && strings.TrimSpace(encoded.DecidedBy) == "" {
			return aauth.InteractionRecord{}, errors.New("completed interaction record requires a decision actor")
		}
	}
	return copyInteractionRecord(encoded), nil
}

func decodeGovernancePendingCompletion(
	encoded governancePendingCompletion,
	personServer string,
	missions map[string]storedMission,
	interactions []aauth.InteractionRecord,
) (pendingCompletion, error) {
	var pending pendingCompletion
	decodedID, err := base64.RawURLEncoding.DecodeString(encoded.ID)
	if err != nil || len(decodedID) != 16 {
		return pending, errors.New("completion pending id is invalid")
	}
	if err := aauth.ValidateAgentIdentifier(encoded.Agent); err != nil {
		return pending, err
	}
	thumbprint, err := base64.RawURLEncoding.DecodeString(encoded.PollingAgentThumbprint)
	if err != nil || len(thumbprint) != sha256.Size {
		return pending, errors.New("completion pending agent-key thumbprint is invalid")
	}
	if !validReplayKey(encoded.RequestReplayKey) {
		return pending, errors.New("completion pending request proof id is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, encoded.ExpiresAt)
	if err != nil || expiresAt.IsZero() {
		return pending, errors.New("completion pending expiry is invalid")
	}
	var interaction *aauth.InteractionRecord
	for index := range interactions {
		record := &interactions[index]
		if record.Proof != nil && record.Proof.ReplayKey == encoded.RequestReplayKey {
			interaction = record
			break
		}
	}
	if interaction == nil ||
		interaction.Agent != encoded.Agent ||
		interaction.PendingID != encoded.ID ||
		!bytes.Equal(interaction.Request, encoded.RequestBody) {
		return pending, errors.New("completion pending state does not match its interaction record")
	}
	missionReference, err := missionReferenceFromCompletionBody(
		encoded.RequestBody,
		interaction.Proof.Target,
		personServer,
	)
	if err != nil {
		return pending, err
	}
	if (encoded.Mission.Approver != "" || encoded.Mission.S256 != "") && encoded.Mission != missionReference {
		return pending, errors.New("completion pending mission does not match its request")
	}
	mission, exists := missions[missionReference.S256]
	if !exists || mission.reference != missionReference || mission.agent != encoded.Agent {
		return pending, errors.New("completion pending mission is absent or has the wrong owner")
	}
	state := encoded.State
	switch state {
	case completionWaiting,
		completionClarification,
		completionAccepted,
		completionServed:
	default:
		return pending, errors.New("completion pending state is invalid")
	}
	if encoded.ClarificationRounds < 0 ||
		encoded.ClarificationRounds > maxCompletionClarificationRounds {
		return pending, errors.New("completion clarification round count is invalid")
	}
	var decidedAt time.Time
	if encoded.DecidedAt != "" {
		decidedAt, err = time.Parse(time.RFC3339Nano, encoded.DecidedAt)
		if err != nil || decidedAt.IsZero() {
			return pending, errors.New("completion decision time is invalid")
		}
	}
	switch state {
	case completionWaiting:
		if encoded.Clarification != "" ||
			!decidedAt.IsZero() ||
			encoded.DecidedBy != "" ||
			len(encoded.ResponseBody) != 0 {
			return pending, errors.New("waiting completion state is inconsistent")
		}
	case completionClarification:
		if strings.TrimSpace(encoded.Clarification) == "" ||
			encoded.ClarificationRounds == 0 ||
			!decidedAt.IsZero() ||
			encoded.DecidedBy != "" ||
			len(encoded.ResponseBody) != 0 {
			return pending, errors.New("clarification completion state is inconsistent")
		}
	case completionAccepted, completionServed:
		if encoded.Clarification != "" ||
			decidedAt.IsZero() ||
			decidedAt.Before(interaction.RecordedAt) ||
			len(encoded.ResponseBody) == 0 ||
			!bytes.Equal(encoded.ResponseBody, interaction.Response) {
			return pending, fmt.Errorf(
				"terminal completion state is inconsistent (state=%s clarification=%t decided=%t before_request=%t response=%t response_matches=%t)",
				state,
				encoded.Clarification != "",
				!decidedAt.IsZero(),
				decidedAt.Before(interaction.RecordedAt),
				len(encoded.ResponseBody) != 0,
				bytes.Equal(encoded.ResponseBody, interaction.Response),
			)
		}
		kind, err := interactionResponseKind(encoded.ResponseBody)
		if err != nil {
			return pending, err
		}
		if state == completionAccepted && kind != "completed" {
			return pending, errors.New("an undelivered completion response must be an acceptance")
		}
		if kind == "completed" {
			if strings.TrimSpace(encoded.DecidedBy) == "" ||
				mission.status != aauth.MissionTerminated {
				return pending, errors.New("accepted completion does not terminate its mission")
			}
		}
	}
	return pendingCompletion{
		id:                     encoded.ID,
		missionReference:       missionReference,
		agent:                  encoded.Agent,
		pollingAgentThumbprint: encoded.PollingAgentThumbprint,
		expiresAt:              expiresAt,
		requestReplayKey:       encoded.RequestReplayKey,
		requestBody:            append([]byte(nil), encoded.RequestBody...),
		state:                  state,
		clarification:          encoded.Clarification,
		clarificationRounds:    encoded.ClarificationRounds,
		decidedBy:              encoded.DecidedBy,
		decidedAt:              decidedAt,
		responseBody:           append([]byte(nil), encoded.ResponseBody...),
	}, nil
}

func validPendingInteractionTarget(target string) bool {
	const prefix = "/interaction/pending/"
	if !strings.HasPrefix(target, prefix) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(target, prefix))
	return err == nil && len(decoded) == 16
}

func interactionResponseKind(body []byte) (string, error) {
	var completed struct {
		Status string `json:"status"`
	}
	if err := decodeJSONBytes(bytes.NewReader(body), &completed); err == nil &&
		completed.Status == "completed" {
		return "completed", nil
	}
	var wire struct {
		Status int `json:"status"`
	}
	if err := json.Unmarshal(body, &wire); err != nil || wire.Status == 0 {
		return "", errors.New("interaction response is invalid")
	}
	response := &http.Response{
		StatusCode: wire.Status,
		Header: http.Header{
			"Content-Type": {"application/problem+json"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}
	problem, err := aauth.DecodeProblemResponse(response)
	if err != nil {
		return "", errors.New("interaction problem response is invalid")
	}
	switch problem.Code {
	case "expired":
		if problem.Status == http.StatusRequestTimeout {
			return "expired", nil
		}
	case "mission_terminated":
		if problem.Status == http.StatusForbidden &&
			problem.MissionStatus == string(aauth.MissionTerminated) {
			return "mission_terminated", nil
		}
	}
	return "", errors.New("interaction problem code or status is invalid")
}
