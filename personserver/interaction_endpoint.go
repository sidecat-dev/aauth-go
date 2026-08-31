package personserver

import (
	"context"
	"errors"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
)

// ErrInteractionUserUnreachable tells the Interaction Endpoint that the host
// has no channel through which to ask the person this question.
var ErrInteractionUserUnreachable = errors.New("personserver: interaction user is unreachable")

// InteractionQuestionConfig enables one immediate top-level question path.
// Answer receives untrusted raw Markdown and is responsible for reaching the
// person. The library does not render either string or contact a person.
type InteractionQuestionConfig struct {
	Answer func(context.Context, InteractionQuestionPolicyRequest) (InteractionQuestionDecision, error)
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
) (InteractionQuestionDecision, error) {
	if config == nil {
		return nil
	}
	return config.Answer
}

func (server *Server) handleInteractionQuestion(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("interaction endpoint requires POST"))
		return
	}
	if server.interactionQuestionPolicy == nil {
		writeProblem(response, http.StatusNotFound, "not_found", errors.New("interaction endpoint is not configured"))
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
	decision, err := server.interactionQuestionPolicy(request.Context(), InteractionQuestionPolicyRequest{
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

func cloneInteractionQuestionDocument(document aauth.InteractionQuestionDocument) aauth.InteractionQuestionDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}
