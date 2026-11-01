package supervisionserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

// ErrNotPending reports a host resolution of a request that is no longer
// deciding or clarifying.
var ErrNotPending = errors.New("supervisionserver: the request is not pending")

// DecisionRequest is one supervision request as the decision policy sees it.
// Request is the decoded body and Body its exact bytes; both are what the
// Person Server forwarded, and every Agent-authored or forwarded member is
// untrusted input. Mission is the approved mission held for
// Request.MissionS256, and nil when the request names none. Rounds are the
// clarifications asked and answered so far, oldest first.
type DecisionRequest struct {
	PersonServer string
	Connection   Connection
	Request      supervision.Request
	Body         []byte
	Mission      *MissionRecord
	Rounds       []ClarificationRound
}

// DecisionResult is the decision policy's answer; exactly one member is set.
// Decision is a terminal allow, deny or ask, validated for the request's
// kind; its SDI may be left empty. Clarify asks the Agent a question first.
// Defer leaves the decision to the host, which calls ResolveDecision later.
type DecisionResult struct {
	Decision *supervision.Decision
	Clarify  *supervision.Clarification
	Defer    *Deferral
}

// Deferral bounds a request the host decides later. Lifetime and RetryAfter
// are whole seconds; zero selects DefaultDecisionLifetime and
// DefaultRetryAfter.
type Deferral struct {
	Lifetime   time.Duration
	RetryAfter time.Duration
}

func (server *Server) handleMissionProposal(response http.ResponseWriter, request *http.Request) {
	personServer, _, body, ok := server.authenticate(response, request, true)
	if !ok || !server.admit(response, request, personServer) {
		return
	}
	decoded, err := supervision.DecodeMissionProposal(body)
	if err != nil {
		writeProblem(response, supervision.ErrorInvalidRequest, err)
		return
	}
	server.supervise(response, request, personServer, body, decoded)
}

func (server *Server) handleMissionAction(response http.ResponseWriter, request *http.Request) {
	personServer, _, body, ok := server.authenticate(response, request, true)
	if !ok || !server.admit(response, request, personServer) {
		return
	}
	decoded, report, err := supervision.DecodeMissionAction(request.PathValue("s256"), body)
	if err != nil {
		writeProblem(response, supervision.ErrorInvalidRequest, err)
		return
	}
	if report != nil {
		server.handleReport(response, request, personServer, body, *report)
		return
	}
	server.supervise(response, request, personServer, body, *decoded)
}

func (server *Server) handleDecision(response http.ResponseWriter, request *http.Request) {
	personServer, _, body, ok := server.authenticate(response, request, true)
	if !ok || !server.admit(response, request, personServer) {
		return
	}
	decoded, err := supervision.DecodeDecisionRequest(body)
	if err != nil {
		writeProblem(response, supervision.ErrorInvalidRequest, err)
		return
	}
	server.supervise(response, request, personServer, body, decoded)
}

// supervise answers a first or repeated supervision request.
func (server *Server) supervise(response http.ResponseWriter, request *http.Request, personServer string, body []byte, decoded supervision.Request) {
	ctx := request.Context()
	connection, ok := server.requireConnection(response, request, personServer, decoded.Subject)
	if !ok {
		return
	}
	existing, err := server.store.LoadDecision(ctx, personServer, decoded.SDI)
	if err == nil {
		server.repeat(response, request, existing, decoded)
		return
	}
	if !errors.Is(err, ErrNotFound) {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	mission, ok := server.loadMission(response, request, personServer, decoded.Subject, decoded.MissionS256)
	if !ok {
		return
	}
	now := server.clock.Now().UTC()
	result, err := server.decide(ctx, DecisionRequest{
		PersonServer: personServer, Connection: connection, Request: decoded,
		Body: append([]byte(nil), body...), Mission: mission,
	})
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	record := DecisionRecord{
		PersonServer: personServer, SDI: decoded.SDI, Kind: decoded.Kind, Subject: decoded.Subject,
		Agent: decoded.Agent, MissionS256: decoded.MissionS256, Request: append([]byte(nil), body...),
		CreatedAt: now, Revision: 1,
	}
	if result.Decision == nil {
		if record.Pending, err = interaction.GeneratePendingReference(nil); err != nil {
			writeProblem(response, supervision.ErrorServerError, err)
			return
		}
	}
	record, err = server.apply(record, result, now)
	if err == nil && record.State == DecisionDecided && server.signingKey != nil {
		var signed RetainedResponse
		signed, err = server.sign(request, record.Decision)
		record.Responses = []RetainedResponse{signed}
	}
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	stored, created, err := server.store.CreateDecision(ctx, record)
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	if !created {
		server.repeat(response, request, stored, decoded)
		return
	}
	server.answer(response, request, stored, false)
}

// repeat answers a request under an sdi the SS already holds. It must be the
// same request, compared by its canonical encoding.
func (server *Server) repeat(response http.ResponseWriter, request *http.Request, record DecisionRecord, decoded supervision.Request) {
	retained, err := retainedRequest(record)
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	first, err := retained.Encode()
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	again, err := decoded.Encode()
	if err != nil || !bytes.Equal(first, again) {
		writeProblem(response, supervision.ErrorInvalidRequest, errors.New("supervisionserver: the sdi names a different request"))
		return
	}
	server.answer(response, request, record, false)
}

// answer writes the response the record's state calls for. atPending
// distinguishes a request to the pending URL from a repeat of the original
// request.
func (server *Server) answer(response http.ResponseWriter, request *http.Request, record DecisionRecord, atPending bool) {
	switch record.State {
	case DecisionDeciding, DecisionClarifying:
		if !server.clock.Now().Before(record.ExpiresAt) {
			// A pending URL the SS stopped deciding is one it no longer holds.
			writeProblem(response, supervision.ErrorUnknownPending, ErrExpired)
			return
		}
		writePending(response, record)
	case DecisionDecided:
		server.writeDecision(response, request, record)
	case DecisionCancelled:
		if atPending {
			writeStatusProblem(response, http.StatusGone, "invalid_code", ErrNotPending)
			return
		}
		writeProblem(response, supervision.ErrorInvalidRequest, errors.New("supervisionserver: the request was withdrawn"))
	default:
		writeProblem(response, supervision.ErrorServerError, fmt.Errorf("supervisionserver: unknown decision state %d", record.State))
	}
}

func writePending(response http.ResponseWriter, record DecisionRecord) {
	var clarification *supervision.Clarification
	if record.State == DecisionClarifying {
		clarification = record.Clarification
	}
	body, err := supervision.EncodePending(record.SDI, clarification)
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	header := response.Header()
	header.Set("Location", pendingLocation(PendingPath, record.Pending))
	header.Set("Retry-After", retryAfterValue(record.RetryAfter))
	header.Set("Cache-Control", "no-store")
	if clarification != nil {
		header.Set("AAuth-Requirement", "requirement=clarification")
	}
	header.Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusAccepted)
	_, _ = response.Write(body)
}

// writeDecision writes the decision. When the SS signs, it repeats the
// response retained for this request's binding, or signs one, retains it and
// sends that. Two concurrent first answers both sign; one is retained and
// both callers send it.
func (server *Server) writeDecision(response http.ResponseWriter, request *http.Request, record DecisionRecord) {
	if server.signingKey == nil {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(record.Decision)
		return
	}
	binding := requestBinding(request)
	for attempt := 0; attempt < maximumTransitionAttempts; attempt++ {
		for _, retained := range record.Responses {
			if retained.Binding == binding {
				writeRetained(response, retained)
				return
			}
		}
		signed, err := server.sign(request, record.Decision)
		if err != nil {
			writeProblem(response, supervision.ErrorServerError, err)
			return
		}
		if len(record.Responses) >= maximumRetainedResponses {
			writeRetained(response, signed)
			return
		}
		after := record.Clone()
		after.Responses = append(after.Responses, signed)
		after.Revision++
		err = server.store.ReplaceDecision(request.Context(), record, after)
		if err == nil {
			writeRetained(response, signed)
			return
		}
		if !errors.Is(err, ErrConflict) {
			writeProblem(response, supervision.ErrorServerError, err)
			return
		}
		if record, err = server.store.LoadDecision(request.Context(), record.PersonServer, record.SDI); err != nil {
			writeProblem(response, supervision.ErrorServerError, err)
			return
		}
	}
	writeProblem(response, supervision.ErrorServerError, ErrConflict)
}

// sign signs body as the 200 answering request.
func (server *Server) sign(request *http.Request, body []byte) (RetainedResponse, error) {
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	if err := supervision.SignDecision(header, http.StatusOK, body, request, *server.signingKey, server.issuer, server.clock); err != nil {
		return RetainedResponse{}, err
	}
	return RetainedResponse{Binding: requestBinding(request), Header: header, Body: append([]byte(nil), body...)}, nil
}

func writeRetained(response http.ResponseWriter, retained RetainedResponse) {
	for name, values := range retained.Header {
		response.Header()[name] = append([]string(nil), values...)
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(retained.Body)
}

// requestBinding names what a signed decision is bound to: the request
// components it covers, its authority, path and Content-Digest.
func requestBinding(request *http.Request) string {
	authority := request.Host
	if authority == "" {
		authority = request.URL.Host
	}
	return strings.ToLower(authority) + "\n" + request.URL.EscapedPath() + "\n" +
		strings.Join(request.Header.Values("Content-Digest"), ", ")
}

// apply moves record to the state result names at now. It does not change
// Revision.
func (server *Server) apply(record DecisionRecord, result DecisionResult, now time.Time) (DecisionRecord, error) {
	set := 0
	for _, present := range []bool{result.Decision != nil, result.Clarify != nil, result.Defer != nil} {
		if present {
			set++
		}
	}
	if set != 1 {
		return DecisionRecord{}, errors.New("supervisionserver: a decision result sets exactly one of decision, clarification or deferral")
	}
	switch {
	case result.Decision != nil:
		body, retainUntil, err := server.encodeDecision(record, *result.Decision, now)
		if err != nil {
			return DecisionRecord{}, err
		}
		record.State = DecisionDecided
		record.Decision = body
		record.Clarification = nil
		record.DecidedAt = now
		record.RetainUntil = retainUntil
	case result.Clarify != nil:
		if err := result.Clarify.Validate(); err != nil {
			return DecisionRecord{}, err
		}
		if record.Pending == "" {
			return DecisionRecord{}, errors.New("supervisionserver: a request answered at once cannot ask a question")
		}
		question := cloneClarification(*result.Clarify)
		lifetime := question.Timeout
		if lifetime == 0 {
			lifetime = DefaultDecisionLifetime
		}
		if lifetime > MaximumPendingLifetime {
			return DecisionRecord{}, errors.New("supervisionserver: clarification timeout is too long")
		}
		record.State = DecisionClarifying
		record.Clarification = &question
		record.ExpiresAt = now.Add(lifetime)
		record.RetryAfter = 0
	default:
		if record.Pending == "" {
			return DecisionRecord{}, errors.New("supervisionserver: a request answered at once cannot be deferred")
		}
		lifetime, retryAfter := result.Defer.Lifetime, result.Defer.RetryAfter
		if lifetime == 0 {
			lifetime = DefaultDecisionLifetime
		}
		if retryAfter == 0 {
			retryAfter = DefaultRetryAfter
		}
		if lifetime <= 0 || !validWholeSeconds(lifetime, MaximumPendingLifetime) || !validWholeSeconds(retryAfter, maximumRetryAfter) {
			return DecisionRecord{}, errors.New("supervisionserver: deferral lifetime and retry interval must be whole seconds within bounds")
		}
		record.State = DecisionDeciding
		record.Clarification = nil
		record.ExpiresAt = now.Add(lifetime)
		record.RetryAfter = retryAfter
	}
	return record, nil
}

// encodeDecision encodes decision for record and computes how long the
// record must be kept: the retention period, and no less than the exp the
// decision bounds a token to.
func (server *Server) encodeDecision(record DecisionRecord, decision supervision.Decision, now time.Time) ([]byte, time.Time, error) {
	if decision.SDI == "" {
		decision.SDI = record.SDI
	}
	if decision.SDI != record.SDI {
		return nil, time.Time{}, errors.New("supervisionserver: decision names another sdi")
	}
	body, err := decision.Encode(record.Kind)
	if err != nil {
		return nil, time.Time{}, err
	}
	retainUntil := now.Add(server.retention)
	if decision.ExpiresAt > 0 {
		if exp := time.Unix(decision.ExpiresAt, 0).UTC(); exp.After(retainUntil) {
			retainUntil = exp
		}
	}
	return body, retainUntil, nil
}

func (server *Server) loadMission(response http.ResponseWriter, request *http.Request, personServer, subject, s256 string) (*MissionRecord, bool) {
	if s256 == "" {
		return nil, true
	}
	mission, err := server.store.LoadMission(request.Context(), personServer, subject, s256)
	if errors.Is(err, ErrNotFound) {
		writeProblem(response, supervision.ErrorUnknownMission, err)
		return nil, false
	}
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return nil, false
	}
	return &mission, true
}

// retainedRequest decodes the exact request a record retains.
func retainedRequest(record DecisionRecord) (supervision.Request, error) {
	switch record.Kind {
	case supervision.KindMissionProposal:
		return supervision.DecodeMissionProposal(record.Request)
	case supervision.KindMissionUpdate, supervision.KindMissionCompletion:
		decoded, _, err := supervision.DecodeMissionAction(record.MissionS256, record.Request)
		if err != nil {
			return supervision.Request{}, err
		}
		if decoded == nil {
			return supervision.Request{}, errors.New("supervisionserver: retained request is a report")
		}
		return *decoded, nil
	default:
		return supervision.DecodeDecisionRequest(record.Request)
	}
}

// currentRequest is the request as the policy decides it: the retained
// request, with the resource token, presented token and justification of the
// latest updated_request in place.
func currentRequest(record DecisionRecord) (supervision.Request, error) {
	request, err := retainedRequest(record)
	if err != nil {
		return supervision.Request{}, err
	}
	for _, round := range record.Rounds {
		if round.Updated != nil {
			request.ResourceToken = round.Updated.ResourceToken
			request.PresentedToken = round.Updated.PresentedToken
			request.Justification = round.Updated.Justification
		}
	}
	return request, nil
}

// loadPending loads the request a pending URL names. A URL the SS does not
// hold, and one another Person Server made, are both unknown_pending.
func (server *Server) loadPending(response http.ResponseWriter, request *http.Request, personServer string) (DecisionRecord, bool) {
	record, err := server.store.LoadPendingDecision(request.Context(), request.PathValue("id"))
	if errors.Is(err, ErrNotFound) || (err == nil && record.PersonServer != personServer) {
		writeProblem(response, supervision.ErrorUnknownPending, ErrNotFound)
		return DecisionRecord{}, false
	}
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return DecisionRecord{}, false
	}
	return record, true
}

func (server *Server) handlePoll(response http.ResponseWriter, request *http.Request) {
	personServer, _, _, ok := server.authenticate(response, request, false)
	if !ok {
		return
	}
	record, ok := server.loadPending(response, request, personServer)
	if !ok {
		return
	}
	if _, ok := server.requireConnection(response, request, personServer, record.Subject); !ok {
		return
	}
	server.answer(response, request, record, true)
}

// handleClarificationAnswer takes the Agent's answer to the open question,
// or for an auth-token request its updated request, consults the policy again
// with the round recorded, and answers as a poll would. An answer to a request already decided or withdrawn is answered as
// a poll of it.
func (server *Server) handleClarificationAnswer(response http.ResponseWriter, request *http.Request) {
	personServer, _, body, ok := server.authenticate(response, request, true)
	if !ok {
		return
	}
	record, ok := server.loadPending(response, request, personServer)
	if !ok {
		return
	}
	connection, ok := server.requireConnection(response, request, personServer, record.Subject)
	if !ok {
		return
	}
	answer, err := supervision.DecodeClarificationResponse(body)
	if err != nil {
		writeProblem(response, supervision.ErrorInvalidRequest, err)
		return
	}
	now := server.clock.Now().UTC()
	if record.State == DecisionDeciding && now.Before(record.ExpiresAt) {
		writeProblem(response, supervision.ErrorInvalidRequest, errors.New("supervisionserver: the request is not waiting for a clarification"))
		return
	}
	if record.State != DecisionClarifying || !now.Before(record.ExpiresAt) {
		server.answer(response, request, record, true)
		return
	}
	if answer.Updated != nil && record.Kind != supervision.KindAuthToken {
		writeProblem(response, supervision.ErrorInvalidRequest, errors.New("supervisionserver: only an auth-token request can be replaced"))
		return
	}
	mission, ok := server.loadMission(response, request, personServer, record.Subject, record.MissionS256)
	if !ok {
		return
	}
	after := record.Clone()
	round := ClarificationRound{
		Question: cloneClarification(*record.Clarification), Answer: answer.Answer, AnsweredAt: now,
	}
	if answer.Updated != nil {
		updated := *answer.Updated
		round.Updated = &updated
	}
	after.Rounds = append(after.Rounds, round)
	decoded, err := currentRequest(after)
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	result, err := server.decide(request.Context(), DecisionRequest{
		PersonServer: personServer, Connection: connection, Request: decoded,
		Body: append([]byte(nil), record.Request...), Mission: mission,
		Rounds: after.Clone().Rounds,
	})
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	after, err = server.apply(after, result, now)
	if err == nil && after.State == DecisionDecided && server.signingKey != nil {
		var signed RetainedResponse
		signed, err = server.sign(request, after.Decision)
		after.Responses = append(after.Responses, signed)
	}
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return
	}
	after.Revision++
	if err := server.store.ReplaceDecision(request.Context(), record, after); err != nil {
		if !errors.Is(err, ErrConflict) {
			writeProblem(response, supervision.ErrorServerError, err)
			return
		}
		// Another answer, a resolution or a cancellation won; this answer
		// is not applied and the caller sees the current state.
		if after, err = server.store.LoadDecision(request.Context(), record.PersonServer, record.SDI); err != nil {
			writeProblem(response, supervision.ErrorServerError, err)
			return
		}
	}
	server.answer(response, request, after, true)
}

// handleCancel withdraws a request still deciding or clarifying, answering
// 200 with status cancelled. Later requests to the pending URL answer 410.
func (server *Server) handleCancel(response http.ResponseWriter, request *http.Request) {
	personServer, _, _, ok := server.authenticate(response, request, false)
	if !ok {
		return
	}
	record, ok := server.loadPending(response, request, personServer)
	if !ok {
		return
	}
	if _, ok := server.requireConnection(response, request, personServer, record.Subject); !ok {
		return
	}
	for attempt := 0; attempt < maximumTransitionAttempts; attempt++ {
		now := server.clock.Now().UTC()
		pending := record.State == DecisionDeciding || record.State == DecisionClarifying
		if !pending || !now.Before(record.ExpiresAt) {
			writeStatusProblem(response, http.StatusGone, "invalid_code", ErrNotPending)
			return
		}
		after := record.Clone()
		after.State = DecisionCancelled
		after.Clarification = nil
		after.DecidedAt = now
		after.RetainUntil = now.Add(server.retention)
		after.Revision++
		err := server.store.ReplaceDecision(request.Context(), record, after)
		if err == nil {
			writeStatus(response, http.StatusOK, "cancelled")
			return
		}
		if !errors.Is(err, ErrConflict) {
			writeProblem(response, supervision.ErrorServerError, err)
			return
		}
		if record, err = server.store.LoadDecision(request.Context(), record.PersonServer, record.SDI); err != nil {
			writeProblem(response, supervision.ErrorServerError, err)
			return
		}
	}
	writeProblem(response, supervision.ErrorServerError, ErrConflict)
}

// ResumeDecision returns a request that is deciding or clarifying as the
// policy saw it, so a host can put it to an operator after a restart. The sdi
// is not authority: the host authenticates whoever decides.
func (server *Server) ResumeDecision(ctx context.Context, personServer, sdi string) (DecisionRequest, error) {
	if ctx == nil {
		return DecisionRequest{}, errors.New("supervisionserver: context is required")
	}
	record, err := server.store.LoadDecision(ctx, personServer, sdi)
	if err != nil {
		return DecisionRequest{}, err
	}
	if record.State != DecisionDeciding && record.State != DecisionClarifying {
		return DecisionRequest{}, ErrNotPending
	}
	if !server.clock.Now().Before(record.ExpiresAt) {
		return DecisionRequest{}, ErrExpired
	}
	connection, err := server.store.LoadConnection(ctx, personServer, record.Subject)
	if err != nil {
		return DecisionRequest{}, err
	}
	decoded, err := currentRequest(record)
	if err != nil {
		return DecisionRequest{}, err
	}
	var mission *MissionRecord
	if record.MissionS256 != "" {
		loaded, err := server.store.LoadMission(ctx, personServer, record.Subject, record.MissionS256)
		if err != nil {
			return DecisionRequest{}, err
		}
		mission = &loaded
	}
	return DecisionRequest{
		PersonServer: personServer, Connection: connection, Request: decoded,
		Body: record.Request, Mission: mission, Rounds: record.Rounds,
	}, nil
}

// ResolveDecision answers a request that is deciding or clarifying with a
// decision, or asks the Agent a question about a request that is deciding.
// The Person Server receives it at its next poll. Resolving again with the
// same decision is not an error; a different one is ErrConflict.
func (server *Server) ResolveDecision(ctx context.Context, personServer, sdi string, result DecisionResult) error {
	if ctx == nil {
		return errors.New("supervisionserver: context is required")
	}
	if result.Defer != nil {
		return errors.New("supervisionserver: a resolution decides or asks; it does not defer")
	}
	for attempt := 0; attempt < maximumTransitionAttempts; attempt++ {
		record, err := server.store.LoadDecision(ctx, personServer, sdi)
		if err != nil {
			return err
		}
		now := server.clock.Now().UTC()
		switch record.State {
		case DecisionDecided:
			if result.Decision == nil {
				return ErrNotPending
			}
			body, _, err := server.encodeDecision(record, *result.Decision, now)
			if err != nil {
				return err
			}
			if bytes.Equal(body, record.Decision) {
				return nil
			}
			return ErrConflict
		case DecisionDeciding, DecisionClarifying:
			if !now.Before(record.ExpiresAt) {
				return ErrExpired
			}
			if result.Clarify != nil && record.State == DecisionClarifying {
				// The open question may already be with the Agent; its
				// answer must not be taken for a different one.
				return ErrConflict
			}
		default:
			return ErrNotPending
		}
		after, err := server.apply(record.Clone(), result, now)
		if err != nil {
			return err
		}
		after.Revision++
		if err := server.store.ReplaceDecision(ctx, record, after); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return err
		}
		return nil
	}
	return ErrConflict
}
