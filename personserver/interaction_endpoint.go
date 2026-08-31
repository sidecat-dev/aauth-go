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
)

// ErrInteractionUserUnreachable tells the Interaction Endpoint that the host
// has no channel through which to ask the person this question.
var ErrInteractionUserUnreachable = errors.New("personserver: interaction user is unreachable")

// InteractionQuestionConfig enables immediate or deferred top-level questions.
type InteractionQuestionConfig struct {
	// Policy selects one immediate answer or bounded deferred question.
	Policy func(context.Context, InteractionQuestionPolicyRequest) (InteractionQuestionPolicyResult, error)
	// Store is required only when Policy may defer.
	Store InteractionQuestionStore
}

// InteractionQuestionPolicyRequest supplies the verified Agent identity,
// exact untrusted question document, and post-validation server instant.
type InteractionQuestionPolicyRequest struct {
	Agent      string
	Document   aauth.InteractionQuestionDocument
	ReceivedAt time.Time
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

func interactionQuestionStore(config *InteractionQuestionConfig) InteractionQuestionStore {
	if config == nil {
		return nil
	}
	return config.Store
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
	switch envelope.Type {
	case "question":
		server.handleVerifiedInteractionQuestion(response, request, agent, exactJSON)
	case string(aauth.InteractionRelayInteraction), string(aauth.InteractionRelayPayment):
		server.handleVerifiedInteractionRelay(response, request, agent, exactJSON)
	default:
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("interaction type must be interaction, payment, or question"))
	}
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
	if document.Question.MissionS256 != "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("mission-bound interaction questions are not implemented"))
		return
	}
	receivedAt := server.clock.Now().UTC()
	result, err := server.interactionQuestionPolicy(request.Context(), InteractionQuestionPolicyRequest{
		Agent: agent.Subject, Document: cloneInteractionQuestionDocument(document), ReceivedAt: receivedAt,
	})
	if err != nil {
		if errors.Is(err, ErrInteractionUserUnreachable) {
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
	if result.Immediate != nil {
		server.writeInteractionAnswer(response, *result.Immediate)
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
		if err := server.interactionQuestionStore.CreateInteractionQuestion(request.Context(), cloneInteractionQuestionRecord(record)); err != nil {
			if errors.Is(err, ErrInteractionQuestionConflict) {
				continue
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		server.writePendingInteractionQuestion(response, "/interaction/pending/"+id, record.RetryAfter)
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("could not allocate interaction question reference"))
}

func (server *Server) writeInteractionAnswer(response http.ResponseWriter, decision InteractionQuestionDecision) {
	answer, err := aauth.EncodeInteractionAnswer(aauth.InteractionAnswer{Answer: decision.Answer})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(answer.ExactJSON)
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
