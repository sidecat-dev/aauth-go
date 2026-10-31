package personserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

// ErrInteractionUserUnreachable tells the Interaction Endpoint that the host
// has no channel through which to ask the person this question.
var ErrInteractionUserUnreachable = errors.New("personserver: interaction user is unreachable")

// InteractionQuestionConfig enables immediate or deferred top-level questions.
// With missions, Store must be nil and the server's Tokens must implement
// MissionInteractionQuestionStore.
type InteractionQuestionConfig struct {
	// Policy selects one immediate answer or bounded deferred question.
	Policy func(context.Context, InteractionQuestionPolicyRequest) (InteractionQuestionPolicyResult, error)
	// Store is required only when Policy may defer.
	Store InteractionQuestionStore
}

// InteractionQuestionPolicyRequest supplies the verified Agent identity,
// exact untrusted question document, post-validation server instant, and an
// exact active mission context when the question named one.
type InteractionQuestionPolicyRequest struct {
	Agent      string
	Document   aauth.InteractionQuestionDocument
	ReceivedAt time.Time
	Mission    *MissionContext
}

// InteractionQuestionDecision is the host's immediate answer. Answer remains
// untrusted text when returned to the Agent application.
type InteractionQuestionDecision struct {
	Answer string
}

func interactionQuestionPolicy(config *InteractionQuestionConfig) func(
	context.Context,
	InteractionQuestionPolicyRequest,
) (InteractionQuestionPolicyResult, error) {
	if config == nil {
		return nil
	}
	return config.Policy
}

func (server *Server) handleInteraction(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("interaction endpoint requires POST"))
		return
	}
	_, agent, _, err := server.verifyAgentProof(request, []string{"content-type", "content-digest"})
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	if err := server.validateDirectAgentTopology(agent); err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	var raw any
	exactJSON, err := httpapi.DecodeExactJSON(request.Body, maxRequestBytes, &raw)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(exactJSON, &envelope); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("interaction request must be one JSON object"))
		return
	}
	recorder := &statusRecorder{ResponseWriter: response}
	switch envelope.Type {
	case "question":
		server.handleVerifiedInteractionQuestion(recorder, request, agent, exactJSON)
	case string(aauth.InteractionRelayInteraction), string(aauth.InteractionRelayPayment):
		server.handleVerifiedInteractionRelay(recorder, request, agent, exactJSON)
	default:
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("interaction type must be interaction, payment, or question"))
		return
	}
	// Once the Person Server has taken the request to the person, a supervised
	// Agent's supervisor is told: a relay is not a decision. The code is not
	// forwarded.
	if recorder.status == http.StatusOK || recorder.status == http.StatusAccepted {
		var relayed struct {
			URL         string `json:"url"`
			MissionS256 string `json:"mission_s256"`
		}
		_ = json.Unmarshal(exactJSON, &relayed)
		_ = server.notifyAgent(request.Context(), agent, supervision.Event{
			Name: supervision.EventInteractionRequested, Type: envelope.Type, URL: relayed.URL,
			MissionS256: relayed.MissionS256,
		})
	}
}

// statusRecorder notes the status a handler wrote, and forwards everything,
// including problem diagnostics, to the response it wraps.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (recorder *statusRecorder) WriteHeader(status int) {
	if recorder.status == 0 {
		recorder.status = status
	}
	recorder.ResponseWriter.WriteHeader(status)
}

func (recorder *statusRecorder) Write(data []byte) (int, error) {
	if recorder.status == 0 {
		recorder.status = http.StatusOK
	}
	return recorder.ResponseWriter.Write(data)
}

func (recorder *statusRecorder) ReportAAuthProblem(status int, code string, cause error) {
	httpapi.ReportProblem(recorder.ResponseWriter, status, code, cause)
}

func (server *Server) handleVerifiedInteractionQuestion(
	response http.ResponseWriter,
	request *http.Request,
	agent aauth.AgentTokenClaims,
	exactJSON []byte,
) {
	if server.interactionQuestionPolicy == nil {
		writeProblem(response, http.StatusNotFound, "not_found", errors.New("interaction questions are not configured"))
		return
	}
	document, err := aauth.DecodeInteractionQuestion(exactJSON)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	receivedAt := server.clock.Now().UTC()
	var missionRecord *MissionRecord
	var missionContext *MissionContext
	if document.Question.MissionS256 != "" {
		if server.missions == nil {
			writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("mission-bound interaction questions are not configured"))
			return
		}
		loaded, err := server.loadActiveMission(
			request.Context(), document.Question.MissionS256, agent.Subject, receivedAt,
		)
		if err != nil {
			writeMissionReferenceProblem(response, err)
			return
		}
		missionRecord = &loaded
		missionContext, err = missionContextFromRecord(loaded)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
	}
	result, err := server.interactionQuestionPolicy(request.Context(), InteractionQuestionPolicyRequest{
		Agent: agent.Subject, Document: cloneInteractionQuestionDocument(document), ReceivedAt: receivedAt,
		Mission: missionContext,
	})
	if err != nil {
		if errors.Is(err, ErrInteractionUserUnreachable) {
			if missionRecord != nil {
				if err := server.commitImmediateMissionInteractionQuestion(
					request.Context(), agent, document, aauth.InteractionAnswerDocument{},
					InteractionQuestionUnreachable, *missionRecord, receivedAt,
				); err != nil {
					writeMissionActionProblem(response, err)
					return
				}
			}
			writeProblem(response, http.StatusForbidden, "user_unreachable", err)
			return
		}
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := validateInteractionQuestionPolicyResult(result); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if missionRecord != nil {
		current, err := server.recheckActiveMission(request.Context(), *missionRecord, server.clock.Now().UTC())
		if err != nil {
			writeMissionReferenceProblem(response, err)
			return
		}
		missionRecord = &current
	}
	if result.Immediate != nil {
		answer, err := aauth.EncodeInteractionAnswer(aauth.InteractionAnswer{Answer: result.Immediate.Answer})
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if missionRecord != nil {
			if err := server.commitImmediateMissionInteractionQuestion(
				request.Context(), agent, document, answer,
				InteractionQuestionAnswered, *missionRecord, receivedAt,
			); err != nil {
				writeMissionActionProblem(response, err)
				return
			}
		}
		server.writeInteractionAnswerDocument(response, answer)
		return
	}
	if server.interactionQuestionStore == nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("deferred interaction question requires a store"))
		return
	}
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	createdAt := receivedAt
	agentExpiresAt := time.Unix(agent.ExpiresAt, 0).UTC()
	for attempt := 0; attempt < 3; attempt++ {
		id, err := interaction.GeneratePendingReference(nil)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		record := InteractionQuestionRecord{
			ID: id, PersonServer: server.issuer, AgentProvider: agent.Issuer,
			Agent: agent.Subject, ConfirmationThumbprint: thumbprint,
			AgentExpiresAt: agentExpiresAt, Document: cloneInteractionQuestionDocument(document),
			State: InteractionQuestionPending, CreatedAt: createdAt,
			ExpiresAt: createdAt.Add(result.Deferred.Lifetime), RetryAfter: result.Deferred.RetryAfter,
		}
		if agentExpiresAt.Before(record.ExpiresAt) {
			record.ExpiresAt = agentExpiresAt
		}
		if !record.ExpiresAt.After(createdAt) {
			writeProblem(response, http.StatusRequestTimeout, "expired", ErrInteractionQuestionExpired)
			return
		}
		if err := validateInteractionQuestionRecord(record); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		var createErr error
		if missionRecord != nil {
			createErr = server.missionInteractionQuestions.CommitMissionInteractionQuestion(
				request.Context(), cloneMissionRecordForTransition(*missionRecord),
				cloneInteractionQuestionRecord(record), server.clock.Now().UTC(),
			)
		} else {
			createErr = server.interactionQuestionStore.CreateInteractionQuestion(
				request.Context(), cloneInteractionQuestionRecord(record),
			)
		}
		if createErr != nil {
			if errors.Is(createErr, ErrInteractionQuestionConflict) {
				continue
			}
			if missionRecord != nil {
				writeMissionActionProblem(response, createErr)
				return
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", createErr)
			return
		}
		server.writePendingInteractionQuestion(response, "/interaction/pending/"+id, record.RetryAfter)
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("could not allocate interaction question reference"))
}

func (server *Server) writeInteractionAnswerDocument(response http.ResponseWriter, answer aauth.InteractionAnswerDocument) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(answer.ExactJSON)
}

func (server *Server) commitImmediateMissionInteractionQuestion(
	ctx context.Context,
	agent aauth.AgentTokenClaims,
	question aauth.InteractionQuestionDocument,
	answer aauth.InteractionAnswerDocument,
	state InteractionQuestionState,
	mission MissionRecord,
	at time.Time,
) error {
	if server.missionInteractionQuestions == nil {
		return errors.New("personserver: mission interaction question store is not configured")
	}
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil {
		return err
	}
	expiresAt := time.Unix(agent.ExpiresAt, 0).UTC()
	if !mission.ExpiresAt.IsZero() && mission.ExpiresAt.Before(expiresAt) {
		expiresAt = mission.ExpiresAt
	}
	for attempt := 0; attempt < 3; attempt++ {
		id, err := interaction.GeneratePendingReference(nil)
		if err != nil {
			return err
		}
		record := InteractionQuestionRecord{
			ID: id, PersonServer: server.issuer, AgentProvider: agent.Issuer,
			Agent: agent.Subject, ConfirmationThumbprint: thumbprint,
			AgentExpiresAt: time.Unix(agent.ExpiresAt, 0).UTC(),
			Document:       cloneInteractionQuestionDocument(question),
			State:          state, Answer: cloneInteractionAnswerDocument(answer),
			CreatedAt: at, ExpiresAt: expiresAt, AnsweredAt: at,
		}
		if err := validateInteractionQuestionRecord(record); err != nil {
			return err
		}
		err = server.missionInteractionQuestions.CommitMissionInteractionQuestion(
			ctx, cloneMissionRecordForTransition(mission), cloneInteractionQuestionRecord(record), server.clock.Now().UTC(),
		)
		if errors.Is(err, ErrInteractionQuestionConflict) {
			continue
		}
		return err
	}
	return errors.New("personserver: could not allocate mission interaction question record")
}

func (server *Server) writePendingInteractionQuestion(response http.ResponseWriter, location string, retryAfter time.Duration) {
	response.Header().Set("Location", location)
	response.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter/time.Second), 10))
	writePrivateJSON(response, http.StatusAccepted, struct {
		Status string `json:"status"`
	}{Status: "pending"})
}

func cloneInteractionQuestionDocument(document aauth.InteractionQuestionDocument) aauth.InteractionQuestionDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}
