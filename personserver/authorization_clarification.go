package personserver

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Clarifications returns the complete retained dialogue in order. Questions
// and answers remain untrusted display input and must be sanitized by the host.
func (value AuthorizationInteraction) Clarifications() []AuthorizationClarificationRound {
	return cloneAuthorizationClarifications(value.clarifications)
}

// CancelledAt reports a durably retained Agent withdrawal. The host can use
// this observation to inform the person; Agent-facing polls still return 410.
func (value AuthorizationInteraction) CancelledAt() (time.Time, bool) {
	if value.kind != authorizationInteractionCorrelated || value.cancelledAt.IsZero() {
		return time.Time{}, false
	}
	return value.cancelledAt, true
}

func validateAuthorizationClarificationRequest(
	request AuthorizationClarificationRequest,
	now time.Time,
	pendingExpiry time.Time,
) error {
	if err := validateAuthorizationClarificationShape(request); err != nil {
		return err
	}
	if !now.Add(request.Lifetime).After(now) || now.Add(request.Lifetime).After(pendingExpiry) {
		return errors.New("personserver: clarification deadline exceeds the pending authorization")
	}
	return nil
}

func validateAuthorizationClarificationShape(request AuthorizationClarificationRequest) error {
	if strings.TrimSpace(request.Question) == "" || len(request.Question) > MaximumAuthorizationClarificationBytes {
		return errors.New("personserver: clarification question must be nonempty and at most 65536 bytes")
	}
	if request.Lifetime <= 0 || request.Lifetime%time.Second != 0 {
		return errors.New("personserver: clarification lifetime must be positive whole seconds")
	}
	if len(request.Options) > maximumAuthorizationClarificationOptions {
		return errors.New("personserver: clarification has too many options")
	}
	seen := make(map[string]struct{}, len(request.Options))
	for _, option := range request.Options {
		if strings.TrimSpace(option) == "" || len(option) > maximumAuthorizationClarificationOptionBytes {
			return errors.New("personserver: clarification option must be nonempty and at most 4096 bytes")
		}
		if _, duplicate := seen[option]; duplicate {
			return errors.New("personserver: clarification options must be distinct")
		}
		seen[option] = struct{}{}
	}
	return nil
}

func validateAuthorizationClarificationRound(round AuthorizationClarificationRound) error {
	request := AuthorizationClarificationRequest{
		Question: round.Question,
		Options:  round.Options,
		Lifetime: round.ExpiresAt.Sub(round.RequestedAt),
	}
	if round.RequestedAt.IsZero() || !round.ExpiresAt.After(round.RequestedAt) ||
		validateAuthorizationClarificationRequest(request, round.RequestedAt, round.ExpiresAt) != nil {
		return ErrPendingAuthorizationConflict
	}
	if round.Response == "" {
		if !round.RespondedAt.IsZero() {
			return ErrPendingAuthorizationConflict
		}
		return nil
	}
	if strings.TrimSpace(round.Response) == "" || len(round.Response) > MaximumAuthorizationClarificationBytes ||
		round.RespondedAt.Before(round.RequestedAt) || !round.RespondedAt.Before(round.ExpiresAt) {
		return ErrPendingAuthorizationConflict
	}
	return nil
}

func validateAuthorizationClarificationHistory(
	pending PendingAuthorizationRecord,
	state AuthorizationPollState,
	rounds []AuthorizationClarificationRound,
) error {
	if len(rounds) > MaximumAuthorizationClarificationRounds {
		return ErrPendingAuthorizationConflict
	}
	for index, round := range rounds {
		if err := validateAuthorizationClarificationRound(round); err != nil {
			return err
		}
		if round.RequestedAt.Before(pending.CreatedAt) || round.ExpiresAt.After(pending.ExpiresAt) ||
			(!round.RespondedAt.IsZero() && (round.RespondedAt.Before(pending.CreatedAt) || !round.RespondedAt.Before(pending.ExpiresAt))) {
			return ErrPendingAuthorizationConflict
		}
		if index > 0 && round.RequestedAt.Before(rounds[index-1].RespondedAt) {
			return ErrPendingAuthorizationConflict
		}
		if index < len(rounds)-1 && round.Response == "" {
			return ErrPendingAuthorizationConflict
		}
	}
	if state == AuthorizationPollClarifying || state == AuthorizationPollCancelled {
		if len(rounds) == 0 || rounds[len(rounds)-1].Response != "" {
			return ErrPendingAuthorizationConflict
		}
	} else if len(rounds) > 0 && rounds[len(rounds)-1].Response == "" &&
		state != AuthorizationPollExpired && state != AuthorizationPollGone && state != AuthorizationPollCancelled {
		return ErrPendingAuthorizationConflict
	}
	return nil
}

// RequestAuthorizationClarification durably attaches one bounded question to
// an authenticated pending authorization before an Agent can observe it. An
// exact repeat is idempotent; a changed question while one is active conflicts.
func (server *Server) RequestAuthorizationClarification(
	ctx context.Context,
	value AuthorizationInteraction,
	request AuthorizationClarificationRequest,
) error {
	now := server.clock.Now().UTC()
	snapshot, err := server.loadAuthorizationInteraction(ctx, value, now)
	if err != nil {
		return err
	}
	if !slices.Contains(snapshot.Record.Capabilities, "clarification") {
		return ErrAuthorizationClarificationUnsupported
	}
	clarifications, ok := server.authorizationInteractions.(AuthorizationClarificationStore)
	if !ok {
		return errors.New("personserver: authorization clarification store is not configured")
	}
	if err := validateAuthorizationClarificationShape(request); err != nil {
		return err
	}
	var expected AuthorizationClarificationRound
	switch snapshot.State {
	case AuthorizationPollInteracting:
		if err := validateAuthorizationClarificationRequest(request, now, snapshot.Record.ExpiresAt); err != nil {
			return err
		}
		expected = AuthorizationClarificationRound{
			Question: request.Question, Options: append([]string(nil), request.Options...),
			RequestedAt: now, ExpiresAt: now.Add(request.Lifetime),
		}
	case AuthorizationPollClarifying:
		if len(snapshot.Clarifications) == 0 {
			return ErrPendingAuthorizationConflict
		}
		expected = cloneAuthorizationClarification(snapshot.Clarifications[len(snapshot.Clarifications)-1])
		if expected.Question != request.Question || !reflect.DeepEqual(expected.Options, request.Options) ||
			expected.ExpiresAt.Sub(expected.RequestedAt) != request.Lifetime {
			return ErrPendingAuthorizationConflict
		}
	case AuthorizationPollExpired:
		return ErrPendingAuthorizationExpired
	case AuthorizationPollGone, AuthorizationPollCancelled:
		return ErrPendingAuthorizationGone
	default:
		return ErrPendingAuthorizationConflict
	}
	canonical, err := clarifications.RequestPendingAuthorizationClarification(
		ctx,
		value.record.ID,
		AuthorizationClarificationRequest{
			Question: request.Question,
			Options:  append([]string(nil), request.Options...),
			Lifetime: request.Lifetime,
		},
		now,
	)
	if err != nil {
		return err
	}
	if err := validateAuthorizationClarificationRound(canonical); err != nil ||
		!reflect.DeepEqual(canonical, expected) || canonical.Response != "" ||
		canonical.RequestedAt.Before(snapshot.Record.CreatedAt) || canonical.ExpiresAt.After(snapshot.Record.ExpiresAt) {
		return ErrPendingAuthorizationConflict
	}
	return nil
}

func (server *Server) handlePendingAuthorizationClarificationAnswer(response http.ResponseWriter, request *http.Request) {
	if server.authorizationInteractions == nil {
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingAuthorizationNotFound)
		return
	}
	clarifications, ok := server.authorizationInteractions.(AuthorizationClarificationStore)
	if !ok {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("authorization clarification is not configured"))
		return
	}
	_, agent, proof, err := server.verifyAgentRequest(request, []string{"content-type", "content-digest"})
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	identity, err := authorizationPollIdentity(server.issuer, agent)
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	var input struct {
		Action                string `json:"action"`
		ClarificationResponse string `json:"clarification_response"`
	}
	if err := decodeJSON(request.Body, &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if input.Action != "clarification_response" || strings.TrimSpace(input.ClarificationResponse) == "" ||
		len(input.ClarificationResponse) > MaximumAuthorizationClarificationBytes {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("authorization continuation requires one bounded clarification_response action"))
		return
	}
	id := request.PathValue("id")
	if id == "" {
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingAuthorizationNotFound)
		return
	}
	if err := clarifications.AnswerPendingAuthorizationClarification(
		request.Context(), id, identity, input.ClarificationResponse, proof.VerifiedAt(),
	); err != nil {
		writePendingAuthorizationMutationProblem(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func (server *Server) handlePendingAuthorizationCancellation(response http.ResponseWriter, request *http.Request) {
	if server.authorizationInteractions == nil {
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingAuthorizationNotFound)
		return
	}
	clarifications, ok := server.authorizationInteractions.(AuthorizationClarificationStore)
	if !ok {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("authorization clarification is not configured"))
		return
	}
	if request.Body != nil && request.Body != http.NoBody {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("authorization cancellation requires a bodyless DELETE"))
		return
	}
	_, agent, proof, err := server.verifyAgentRequest(request, nil)
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	identity, err := authorizationPollIdentity(server.issuer, agent)
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	id := request.PathValue("id")
	if id == "" {
		writeProblem(response, http.StatusGone, "invalid_code", ErrPendingAuthorizationNotFound)
		return
	}
	if err := clarifications.CancelPendingAuthorizationClarification(
		request.Context(), id, identity, proof.VerifiedAt(),
	); err != nil {
		writePendingAuthorizationMutationProblem(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func writePendingAuthorizationMutationProblem(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPendingAuthorizationNotFound), errors.Is(err, ErrPendingAuthorizationGone):
		writeProblem(response, http.StatusGone, "invalid_code", err)
	case errors.Is(err, ErrPendingAuthorizationExpired):
		writeProblem(response, http.StatusRequestTimeout, "expired", err)
	case errors.Is(err, ErrPendingAuthorizationConflict):
		writeProblem(response, http.StatusConflict, "conflict", err)
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
	}
}

func (server *Server) writePendingAuthorizationClarification(
	response http.ResponseWriter,
	location string,
	result AuthorizationPollRecord,
	now time.Time,
) {
	if result.Clarification == nil || result.State != AuthorizationPollClarifying ||
		validateAuthorizationClarificationRound(*result.Clarification) != nil ||
		!now.Before(result.Clarification.ExpiresAt) || result.RetryAfter < 0 || result.RetryAfter%time.Second != 0 {
		writeProblem(response, http.StatusInternalServerError, "server_error", ErrPendingAuthorizationConflict)
		return
	}
	timeout := int64(result.Clarification.ExpiresAt.Sub(now) / time.Second)
	response.Header().Set("Location", location)
	response.Header().Set("Retry-After", strconv.FormatInt(int64(result.RetryAfter/time.Second), 10))
	response.Header().Set("AAuth-Requirement", "requirement=clarification")
	writePrivateJSON(response, http.StatusAccepted, struct {
		Status        string   `json:"status"`
		Clarification string   `json:"clarification"`
		Timeout       int64    `json:"timeout"`
		Options       []string `json:"options,omitempty"`
	}{
		Status: "pending", Clarification: result.Clarification.Question,
		Timeout: timeout, Options: append([]string(nil), result.Clarification.Options...),
	})
}

func cloneAuthorizationClarification(round AuthorizationClarificationRound) AuthorizationClarificationRound {
	round.Options = append([]string(nil), round.Options...)
	return round
}

func cloneAuthorizationClarifications(rounds []AuthorizationClarificationRound) []AuthorizationClarificationRound {
	if len(rounds) == 0 {
		return nil
	}
	cloned := make([]AuthorizationClarificationRound, len(rounds))
	for index, round := range rounds {
		cloned[index] = cloneAuthorizationClarification(round)
	}
	return cloned
}
