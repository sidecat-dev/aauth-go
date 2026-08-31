package personserver

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

var (
	ErrInteractionQuestionNotFound = errors.New("personserver: interaction question not found")
	ErrInteractionQuestionConflict = errors.New("personserver: interaction question conflicts with retained state")
	ErrInteractionQuestionExpired  = errors.New("personserver: interaction question expired")
	ErrInteractionQuestionGone     = errors.New("personserver: interaction question is gone")
)

// InteractionQuestionState is the retained deferred-question state.
type InteractionQuestionState uint8

const (
	InteractionQuestionPending InteractionQuestionState = iota + 1
	InteractionQuestionAnswered
	InteractionQuestionUnreachable
	InteractionQuestionExpired
	InteractionQuestionGone
)

// InteractionQuestionPendingPolicy bounds one deferred question.
type InteractionQuestionPendingPolicy struct {
	Lifetime   time.Duration
	RetryAfter time.Duration
}

// InteractionQuestionPolicyResult selects one immediate or deferred outcome.
type InteractionQuestionPolicyResult struct {
	Immediate *InteractionQuestionDecision
	Deferred  *InteractionQuestionPendingPolicy
}

// InteractionQuestionRecord is the complete purpose-specific retained state.
type InteractionQuestionRecord struct {
	ID                     string
	PersonServer           string
	AgentProvider          string
	Agent                  string
	ConfirmationThumbprint string
	AgentExpiresAt         time.Time
	Document               aauth.InteractionQuestionDocument
	State                  InteractionQuestionState
	Answer                 aauth.InteractionAnswerDocument
	CreatedAt              time.Time
	ExpiresAt              time.Time
	AnsweredAt             time.Time
	RetryAfter             time.Duration
}

// InteractionQuestionPollIdentity binds polling to the original Agent and key.
type InteractionQuestionPollIdentity struct {
	PersonServer           string
	AgentProvider          string
	Agent                  string
	ConfirmationThumbprint string
}

// InteractionQuestionStore owns only deferred question and answer state.
type InteractionQuestionStore interface {
	CreateInteractionQuestion(context.Context, InteractionQuestionRecord) error
	LoadInteractionQuestion(context.Context, string, time.Time) (InteractionQuestionRecord, error)
	ResolveInteractionQuestion(context.Context, string, InteractionQuestionState, aauth.InteractionAnswerDocument, time.Time) (InteractionQuestionRecord, error)
	PollInteractionQuestion(context.Context, string, InteractionQuestionPollIdentity, time.Time) (InteractionQuestionRecord, error)
	ConsumeInteractionQuestion(context.Context, string, InteractionQuestionRecord) error
}

type interactionQuestionHandleKind uint8

const interactionQuestionHandleVerified interactionQuestionHandleKind = 1

// InteractionQuestionHandle is a non-authoritative host handle reconstructed
// from retained state. The host must authenticate the person separately.
type InteractionQuestionHandle struct {
	kind   interactionQuestionHandleKind
	record InteractionQuestionRecord
}

// Reference returns the opaque pending reference.
func (handle InteractionQuestionHandle) Reference() string {
	if handle.kind != interactionQuestionHandleVerified {
		return ""
	}
	return handle.record.ID
}

// Agent returns the verified top-level Agent.
func (handle InteractionQuestionHandle) Agent() string {
	if handle.kind != interactionQuestionHandleVerified {
		return ""
	}
	return handle.record.Agent
}

// Question returns a caller-owned copy of the untrusted exact question.
func (handle InteractionQuestionHandle) Question() aauth.InteractionQuestionDocument {
	if handle.kind != interactionQuestionHandleVerified {
		return aauth.InteractionQuestionDocument{}
	}
	return cloneInteractionQuestionDocument(handle.record.Document)
}

// ExpiresAt returns the answer deadline.
func (handle InteractionQuestionHandle) ExpiresAt() time.Time {
	if handle.kind != interactionQuestionHandleVerified {
		return time.Time{}
	}
	return handle.record.ExpiresAt
}

// ResumeInteractionQuestion reconstructs a non-authoritative host handle.
func (server *Server) ResumeInteractionQuestion(ctx context.Context, reference string) (InteractionQuestionHandle, error) {
	if server == nil || server.interactionQuestionStore == nil {
		return InteractionQuestionHandle{}, errors.New("personserver: deferred interaction questions are not configured")
	}
	if ctx == nil {
		return InteractionQuestionHandle{}, errors.New("personserver: context is required")
	}
	if reference == "" {
		return InteractionQuestionHandle{}, errors.New("personserver: interaction question reference is required")
	}
	now := server.clock.Now().UTC()
	record, err := server.interactionQuestionStore.LoadInteractionQuestion(ctx, reference, now)
	if err != nil {
		return InteractionQuestionHandle{}, err
	}
	if validateInteractionQuestionRecordAt(record, now) != nil || record.ID != reference || record.PersonServer != server.issuer {
		return InteractionQuestionHandle{}, ErrInteractionQuestionConflict
	}
	if record.State != InteractionQuestionPending {
		return InteractionQuestionHandle{}, interactionQuestionStateError(record.State)
	}
	return InteractionQuestionHandle{kind: interactionQuestionHandleVerified, record: cloneInteractionQuestionRecord(record)}, nil
}

// AnswerInteractionQuestion retains one host-authenticated answer.
func (server *Server) AnswerInteractionQuestion(ctx context.Context, handle InteractionQuestionHandle, answer string) error {
	document, err := aauth.EncodeInteractionAnswer(aauth.InteractionAnswer{Answer: answer})
	if err != nil {
		return err
	}
	return server.resolveInteractionQuestion(ctx, handle, InteractionQuestionAnswered, document)
}

// FailInteractionQuestionUnreachable records that no host channel can reach the person.
func (server *Server) FailInteractionQuestionUnreachable(ctx context.Context, handle InteractionQuestionHandle) error {
	return server.resolveInteractionQuestion(ctx, handle, InteractionQuestionUnreachable, aauth.InteractionAnswerDocument{})
}

func (server *Server) resolveInteractionQuestion(ctx context.Context, handle InteractionQuestionHandle, state InteractionQuestionState, answer aauth.InteractionAnswerDocument) error {
	if server == nil || server.interactionQuestionStore == nil {
		return errors.New("personserver: deferred interaction questions are not configured")
	}
	if ctx == nil {
		return errors.New("personserver: context is required")
	}
	if handle.kind != interactionQuestionHandleVerified || validateInteractionQuestionRecord(handle.record) != nil || handle.record.PersonServer != server.issuer {
		return ErrInteractionQuestionConflict
	}
	_, err := server.interactionQuestionStore.ResolveInteractionQuestion(ctx, handle.record.ID, state, cloneInteractionAnswerDocument(answer), server.clock.Now().UTC())
	return err
}

func interactionQuestionStateError(state InteractionQuestionState) error {
	switch state {
	case InteractionQuestionExpired:
		return ErrInteractionQuestionExpired
	case InteractionQuestionGone:
		return ErrInteractionQuestionGone
	default:
		return ErrInteractionQuestionConflict
	}
}

func validateInteractionQuestionPolicyResult(result InteractionQuestionPolicyResult) error {
	if (result.Immediate == nil) == (result.Deferred == nil) {
		return errors.New("personserver: question policy must select one immediate or deferred result")
	}
	if result.Immediate != nil {
		_, err := aauth.EncodeInteractionAnswer(aauth.InteractionAnswer{Answer: result.Immediate.Answer})
		return err
	}
	if result.Deferred.Lifetime <= 0 || result.Deferred.Lifetime%time.Second != 0 ||
		result.Deferred.RetryAfter < 0 || result.Deferred.RetryAfter%time.Second != 0 {
		return errors.New("personserver: deferred question times must be whole seconds with positive lifetime")
	}
	return nil
}

func validateInteractionQuestionRecord(record InteractionQuestionRecord) error {
	if record.ID == "" || record.PersonServer == "" || record.AgentProvider == "" || record.Agent == "" ||
		record.ConfirmationThumbprint == "" || record.AgentExpiresAt.IsZero() || record.CreatedAt.IsZero() {
		return ErrInteractionQuestionConflict
	}
	if aauth.ValidateServerIdentifier(record.PersonServer) != nil ||
		aauth.ValidateServerIdentifier(record.AgentProvider) != nil ||
		aauth.ValidateAgentIdentifier(record.Agent) != nil ||
		!record.ExpiresAt.After(record.CreatedAt) || record.AgentExpiresAt.Before(record.ExpiresAt) ||
		record.RetryAfter < 0 || record.RetryAfter%time.Second != 0 {
		return ErrInteractionQuestionConflict
	}
	decoded, err := aauth.DecodeInteractionQuestion(record.Document.ExactJSON)
	if err != nil || decoded.Question != record.Document.Question || !bytes.Equal(decoded.ExactJSON, record.Document.ExactJSON) || decoded.Question.MissionS256 != "" {
		return ErrInteractionQuestionConflict
	}
	switch record.State {
	case InteractionQuestionPending:
		if len(record.Answer.ExactJSON) != 0 || !record.AnsweredAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) || record.AgentExpiresAt.Before(record.ExpiresAt) {
			return ErrInteractionQuestionConflict
		}
	case InteractionQuestionAnswered:
		answer, err := aauth.DecodeInteractionAnswer(record.Answer.ExactJSON)
		if err != nil || answer.Answer != record.Answer.Answer || !bytes.Equal(answer.ExactJSON, record.Answer.ExactJSON) || record.AnsweredAt.Before(record.CreatedAt) || !record.AnsweredAt.Before(record.ExpiresAt) {
			return ErrInteractionQuestionConflict
		}
	case InteractionQuestionUnreachable:
		if len(record.Answer.ExactJSON) != 0 || record.AnsweredAt.Before(record.CreatedAt) || !record.AnsweredAt.Before(record.ExpiresAt) {
			return ErrInteractionQuestionConflict
		}
	case InteractionQuestionExpired:
		if len(record.Answer.ExactJSON) != 0 || !record.AnsweredAt.IsZero() {
			return ErrInteractionQuestionConflict
		}
	case InteractionQuestionGone:
		if record.AnsweredAt.IsZero() && len(record.Answer.ExactJSON) != 0 {
			return ErrInteractionQuestionConflict
		}
	default:
		return ErrInteractionQuestionConflict
	}
	return nil
}

func validateInteractionQuestionRecordAt(record InteractionQuestionRecord, now time.Time) error {
	if validateInteractionQuestionRecord(record) != nil || record.CreatedAt.After(now) {
		return ErrInteractionQuestionConflict
	}
	switch record.State {
	case InteractionQuestionPending:
		if !now.Before(record.ExpiresAt) || !now.Before(record.AgentExpiresAt) {
			return ErrInteractionQuestionConflict
		}
	case InteractionQuestionAnswered, InteractionQuestionUnreachable:
		if record.AnsweredAt.After(now) {
			return ErrInteractionQuestionConflict
		}
	case InteractionQuestionExpired:
		if now.Before(record.ExpiresAt) {
			return ErrInteractionQuestionConflict
		}
	}
	return nil
}

func cloneInteractionQuestionRecord(record InteractionQuestionRecord) InteractionQuestionRecord {
	record.Document = cloneInteractionQuestionDocument(record.Document)
	record.Answer = cloneInteractionAnswerDocument(record.Answer)
	return record
}

func cloneInteractionAnswerDocument(document aauth.InteractionAnswerDocument) aauth.InteractionAnswerDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}

func interactionQuestionPollIdentity(personServer string, agent aauth.AgentTokenClaims) (InteractionQuestionPollIdentity, error) {
	thumbprint, err := agent.Confirmation.JWK.Thumbprint()
	if err != nil {
		return InteractionQuestionPollIdentity{}, err
	}
	return InteractionQuestionPollIdentity{PersonServer: personServer, AgentProvider: agent.Issuer, Agent: agent.Subject, ConfirmationThumbprint: thumbprint}, nil
}

func (server *Server) handlePendingInteractionQuestion(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("interaction question polling requires GET"))
		return
	}
	if request.Body != nil && request.Body != http.NoBody {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("interaction question polling requires a bodyless GET"))
		return
	}
	_, agent, _, err := server.verifyAgentProof(request, nil)
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	if err := server.validateDirectAgentTopology(agent); err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	identity, err := interactionQuestionPollIdentity(server.issuer, agent)
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	id := request.PathValue("id")
	now := server.clock.Now().UTC()
	record, err := server.interactionQuestionStore.PollInteractionQuestion(request.Context(), id, identity, now)
	if err != nil {
		server.writeInteractionQuestionStoreError(response, err)
		return
	}
	if validateInteractionQuestionRecordAt(record, now) != nil || record.ID != id || record.PersonServer != identity.PersonServer || record.AgentProvider != identity.AgentProvider || record.Agent != identity.Agent || record.ConfirmationThumbprint != identity.ConfirmationThumbprint {
		writeProblem(response, http.StatusInternalServerError, "server_error", ErrInteractionQuestionConflict)
		return
	}
	switch record.State {
	case InteractionQuestionPending:
		server.writePendingInteractionQuestion(response, request.URL.Path, record.RetryAfter)
	case InteractionQuestionAnswered:
		if !server.consumeInteractionQuestion(response, request, record) {
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(record.Answer.ExactJSON)
	case InteractionQuestionUnreachable:
		if !server.consumeInteractionQuestion(response, request, record) {
			return
		}
		writeProblem(response, http.StatusForbidden, "user_unreachable", ErrInteractionUserUnreachable)
	case InteractionQuestionExpired:
		if !server.consumeInteractionQuestion(response, request, record) {
			return
		}
		writeProblem(response, http.StatusRequestTimeout, "expired", ErrInteractionQuestionExpired)
	default:
		server.writeInteractionQuestionStoreError(response, interactionQuestionStateError(record.State))
	}
}

func (server *Server) consumeInteractionQuestion(response http.ResponseWriter, request *http.Request, record InteractionQuestionRecord) bool {
	if err := server.interactionQuestionStore.ConsumeInteractionQuestion(request.Context(), record.ID, cloneInteractionQuestionRecord(record)); err != nil {
		server.writeInteractionQuestionStoreError(response, err)
		return false
	}
	return true
}

func (server *Server) writeInteractionQuestionStoreError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInteractionQuestionNotFound), errors.Is(err, ErrInteractionQuestionGone):
		writeProblem(response, http.StatusGone, "invalid_code", err)
	case errors.Is(err, ErrInteractionQuestionExpired):
		writeProblem(response, http.StatusRequestTimeout, "expired", err)
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
	}
}
