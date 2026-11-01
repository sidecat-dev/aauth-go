package personserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

const (
	supervisionPendingPath = "/pending/"
	supervisedRetryAfter   = 5 * time.Second
	// supervisionClaimLease is how long a host step holds a supervised
	// request while it calls the supervisor or completes the act. A claim
	// left by a process that stopped is taken over after it.
	supervisionClaimLease = 2 * supervision.DefaultWait
)

// SupervisedRequestState is the state of one Agent request the Person Server
// put to a supervisor and could not answer at once.
type SupervisedRequestState uint8

const (
	// SupervisedWaitingForSupervisor means the supervisor deferred its
	// decision, or must be asked again; the host calls AdvanceSupervision.
	SupervisedWaitingForSupervisor SupervisedRequestState = iota + 1
	// SupervisedClarifying means a question, from the supervisor or the
	// person, waits for the Agent's answer.
	SupervisedClarifying
	// SupervisedWaitingForPerson means the supervisor asked the person, or
	// could not be reached; the host calls ResolveSupervision.
	SupervisedWaitingForPerson
	// SupervisedDecided means the terminal response is retained for the
	// Agent's next poll.
	SupervisedDecided
	// SupervisedGone means the Agent received the terminal response or
	// cancelled the request.
	SupervisedGone
	// SupervisedWithAccessServer means the allowed request waits for the
	// Access Server. The wait has the request's Reference, and the host
	// advances it with AdvanceFederation; the Agent keeps polling its pending
	// URL.
	SupervisedWithAccessServer
)

// SupervisionQuestion is a question that waits for the Agent's answer. From
// is supervision.FromPerson for the person's own question; otherwise the
// supervisor asked it.
type SupervisionQuestion struct {
	From          string
	Clarification supervision.Clarification
	AskedAt       time.Time
}

// SupervisedAgentRequest is the Agent's exact signed request, kept so the
// Person Server can verify it again, as made, and complete the act once it is
// allowed.
type SupervisedAgentRequest struct {
	Method     string
	Host       string
	Path       string
	Header     map[string][]string
	Body       []byte
	VerifiedAt time.Time
}

// SupervisedResponse is the terminal response retained for the Agent.
type SupervisedResponse struct {
	Status int
	Header map[string][]string
	Body   []byte
}

// SupervisedRequest is one Agent request waiting on its supervisor or on the
// person. Reference is the last segment of the Agent's pending URL. Request
// is the exact supervision request body; a retry carries the same bytes under
// the same sdi. Ask is the supervisor's ask, nil when the supervisor was not
// reached and SupervisorUnavailable is set. Decision is the terminal decision
// once one is made, by the supervisor or the person, and Answer the person's
// answer. ClaimedAt fences a host step in progress.
//
// Reference, SDI, Kind, Supervisor, AgentProvider, Agent, AgentJKT,
// MissionS256, Request, AgentRequest, CreatedAt and ExpiresAt never change.
// Revision starts at one and each replacement increments it.
type SupervisedRequest struct {
	Reference             string
	SDI                   string
	Kind                  supervision.Kind
	Supervisor            Supervisor
	AgentProvider         string
	Agent                 string
	AgentJKT              string
	MissionS256           string
	Request               []byte
	AgentRequest          SupervisedAgentRequest
	State                 SupervisedRequestState
	SupervisorLocation    string
	NextPollAt            time.Time
	Question              *SupervisionQuestion
	Rounds                int
	Transcript            []supervision.TranscriptEntry
	Ask                   *supervision.Decision
	SupervisorUnavailable bool
	Decision              *supervision.Decision
	Answer                *SupervisionAnswer
	Response              *SupervisedResponse
	ClaimedAt             time.Time
	CreatedAt             time.Time
	ExpiresAt             time.Time
	Revision              uint64
}

// SupervisionAnswer is the person's answer to a supervised request the
// Person Server put to them. Answer is allow or deny. Apply is the reach the
// person gave it, one of the review's ApplyOptions values; empty means once.
// Mission is, for a mission proposal, the terms the person approved, after
// any edits; nil approves the supervisor's proposed refinement, or else the
// proposal as the Agent made it. Reason is an optional Markdown reason the
// person gave; a host must not require one.
type SupervisionAnswer struct {
	Answer  supervision.Answer
	Apply   string
	Reason  string
	Mission *supervision.MissionTerms
}

// SupervisionReview is a supervised request as the host presents it to the
// person. Request is what the Agent asked, as forwarded to the supervisor:
// the Agent-authored members (description, summary, justification, action
// and parameters) are the Agent's claims, and the forwarded tokens carry
// what the Resource asserted. Ask is the supervisor's summary,
// recommendation and proposed refinement; it is nil when the supervisor was
// unavailable. ApplyOptions are the reaches to offer: the supervisor's, or
// once, mission and always when it offered none.
type SupervisionReview struct {
	Reference             string
	SDI                   string
	Kind                  supervision.Kind
	Agent                 string
	MissionS256           string
	Supervisor            Supervisor
	State                 SupervisedRequestState
	Request               supervision.Request
	Ask                   *supervision.Decision
	SupervisorUnavailable bool
	ApplyOptions          []supervision.ApplyOption
	Question              *SupervisionQuestion
	Transcript            []supervision.TranscriptEntry
	ExpiresAt             time.Time
}

// supervisedAct is one act a handler puts to the Agent's supervisor.
// request carries the kind and the members the Agent sent; supervise adds
// the envelope. expiresAt lists the tokens the act depends on: a pending
// request ends no later than any of them. validate checks an allow against
// what was asked; an allow it refuses is a malformed answer.
type supervisedAct struct {
	request   supervision.Request
	agent     aauth.AgentTokenClaims
	proof     signaturekey.VerifiedRequest
	expiresAt []time.Time
	validate  func(supervision.Decision) error
	// unsupported refuses the act for a supervised Agent before anything is
	// put to its supervisor.
	unsupported *SupervisionCompositionError
}

// supervisionVerdict is a terminal decision a handler acts on: an allow with
// any narrowing, or a deny with its reason.
type supervisionVerdict struct {
	supervisor Supervisor
	agent      string
	sdi        string
	decision   supervision.Decision
}

func (verdict *supervisionVerdict) allowed() bool {
	return verdict.decision.Verdict == supervision.VerdictAllow
}

// denial is the error a handler reports for a deny: an intentional refusal
// that wraps sentinel, ErrAccessDenied or ErrMissionDenied, and keeps the
// supervisor's reason as its local diagnostic.
func (verdict *supervisionVerdict) denial(sentinel error) error {
	return &supervisionDenial{reason: verdict.decision.Reason, sentinel: sentinel}
}

// supervisionDenial is a supervisor's or the person's refusal.
type supervisionDenial struct {
	reason   string
	sentinel error
}

func (denial *supervisionDenial) Error() string {
	if denial.reason == "" {
		return "personserver: the supervisor denied the request"
	}
	return "personserver: the supervisor denied the request: " + denial.reason
}

func (denial *supervisionDenial) Unwrap() error { return denial.sentinel }

// reportIssued queues an issued-token event for the supervisor that decided
// the act, under its decision's sdi. A token issued without a supervisor is
// recorded under a sdi the Person Server mints, for replay to a supervisor the
// Agent is routed to later.
func (server *Server) reportIssued(ctx context.Context, agent string, event supervision.Event) {
	if server.supervision == nil {
		return
	}
	supervisor := Supervisor{}
	if verdict := supervisionVerdictFrom(ctx); verdict != nil {
		supervisor, event.SDI, agent = verdict.supervisor, verdict.sdi, verdict.agent
	} else if sdi, err := mintSupervisionID("d-"); err == nil {
		event.SDI = sdi
	} else {
		return
	}
	event.Agent = agent
	_ = server.queueEvent(ctx, supervisor, event)
}

// reportMission queues a mission report for the supervisor that decided the
// act, under its decision's sdi; the report of a mission no supervisor
// decided is recorded for replay, as reportIssued records a token.
func (server *Server) reportMission(ctx context.Context, agent string, report supervision.Report) {
	if server.supervision == nil {
		return
	}
	supervisor := Supervisor{}
	if verdict := supervisionVerdictFrom(ctx); verdict != nil {
		supervisor, report.SDI, agent = verdict.supervisor, verdict.sdi, verdict.agent
	} else if report.Action == supervision.ReportApproved {
		sdi, err := mintSupervisionID("d-")
		if err != nil {
			return
		}
		report.SDI = sdi
	}
	report.Agent = agent
	_ = server.queueReport(ctx, supervisor, report)
}

type supervisionVerdictKey struct{}

// withSupervisionVerdict marks the request's context with the decision the
// act proceeds under, so the code that issues a token reports it under the
// decision's sdi and applies its narrowing.
func withSupervisionVerdict(request *http.Request, verdict *supervisionVerdict) *http.Request {
	return request.WithContext(context.WithValue(request.Context(), supervisionVerdictKey{}, verdict))
}

func supervisionVerdictFrom(ctx context.Context) *supervisionVerdict {
	verdict, _ := ctx.Value(supervisionVerdictKey{}).(*supervisionVerdict)
	return verdict
}

// supervisionCompletion is the decision a completion run acts on: the
// Person Server serves the Agent's retained request again, verified as it
// was made, and the act's decision point returns this decision instead of
// consulting anyone.
type supervisionCompletion struct {
	reference  string
	verdict    supervisionVerdict
	kind       supervision.Kind
	agent      string
	verifiedAt time.Time
}

type supervisionCompletionKey struct{}

func supervisionCompletionFrom(ctx context.Context) *supervisionCompletion {
	completion, _ := ctx.Value(supervisionCompletionKey{}).(*supervisionCompletion)
	return completion
}

// supervise puts one act to the Agent's deciding supervisor. It returns nil
// and false when the Agent has none: the caller applies its own policy. It
// returns a verdict and false for an allow or a deny the caller acts on. It
// returns true when it wrote the response itself: a pending response while
// the supervisor or the person decides, or a failure.
func (server *Server) supervise(response http.ResponseWriter, request *http.Request, act supervisedAct) (*supervisionVerdict, bool) {
	ctx := request.Context()
	if completion := supervisionCompletionFrom(ctx); completion != nil {
		if completion.kind != act.request.Kind || completion.agent != act.agent.Subject {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: completion does not match the supervised act"))
			return nil, true
		}
		verdict := completion.verdict
		return &verdict, false
	}
	supervisor, routed, err := server.routeAgent(ctx, act.agent)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return nil, true
	}
	if !routed {
		return nil, false
	}
	if act.unsupported != nil {
		writeSupervisionCompositionProblem(response, act.unsupported)
		return nil, true
	}
	if err := server.followRoute(ctx, act.agent, supervisor); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return nil, true
	}
	sdi, err := mintSupervisionID("d-")
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return nil, true
	}
	now := server.clock.Now().UTC()
	act.request.SDI = sdi
	act.request.IssuedAt = now.Unix()
	act.request.Subject = supervisor.Subject
	act.request.Agent = act.agent.Subject
	// The supervisor sees every member the Agent sent, not only those the
	// act names.
	act.request.Extra = supervision.ForwardedMembers(act.proof.ExactBody())
	body, err := act.request.Encode()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("personserver: supervision request: %w", err))
		return nil, true
	}
	deadline := now.Add(server.supervision.pendingLifetime)
	for _, expiresAt := range append(act.expiresAt, time.Unix(act.agent.ExpiresAt, 0)) {
		if !expiresAt.IsZero() && expiresAt.Before(deadline) {
			deadline = expiresAt.UTC()
		}
	}
	result := server.consult(ctx, supervisor, act.request, func() (supervision.Outcome, error) {
		return server.supervision.client.Supervise(ctx, supervisor.Issuer, act.request)
	})
	if result.decision != nil && result.decision.Verdict == supervision.VerdictAllow {
		err := validateAllow(*result.decision, now)
		if err == nil && act.validate != nil {
			err = act.validate(*result.decision)
		}
		if err != nil {
			// An allow the act cannot carry out as given is a malformed
			// answer: the supervisor is unavailable for this act.
			server.logSupervision(ctx, act.request, supervisor, nil, "unavailable")
			result = consultation{unavailable: true}
		}
	}
	if decision := result.decision; decision != nil && decision.Verdict != supervision.VerdictAsk {
		return &supervisionVerdict{supervisor: supervisor, agent: act.agent.Subject, sdi: sdi, decision: *decision}, false
	}
	thumbprint, err := act.agent.Confirmation.JWK.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return nil, true
	}
	if !now.Before(deadline) {
		writeProblem(response, http.StatusRequestTimeout, "expired", errors.New("personserver: the supervised request has no time left to wait"))
		return nil, true
	}
	record := SupervisedRequest{
		SDI: sdi, Kind: act.request.Kind, Supervisor: supervisor,
		AgentProvider: act.agent.Issuer, Agent: act.agent.Subject, AgentJKT: thumbprint,
		MissionS256: act.request.MissionS256, Request: body,
		AgentRequest: SupervisedAgentRequest{
			Method: request.Method, Host: request.Host, Path: request.URL.EscapedPath(),
			Header: request.Header.Clone(), Body: act.proof.ExactBody(), VerifiedAt: act.proof.VerifiedAt().UTC(),
		},
		CreatedAt: now, ExpiresAt: deadline, Revision: 1,
	}
	record = server.applyConsultation(record, result, now)
	for attempt := 0; attempt < 3; attempt++ {
		reference, err := interaction.GeneratePendingReference(nil)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return nil, true
		}
		record.Reference = reference
		err = server.supervision.store.CreateSupervisedRequest(ctx, cloneSupervisedRequest(record))
		if errors.Is(err, ErrSupervisionConflict) {
			continue
		}
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return nil, true
		}
		writeSupervisedPending(response, record, now)
		return nil, true
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("personserver: could not allocate a supervised request reference"))
	return nil, true
}

// consultation is what one exchange with a supervisor came to. retryAt is
// set when the supervisor asked the Person Server to wait before asking
// again.
type consultation struct {
	decision    *supervision.Decision
	pending     *supervision.PendingAnswer
	retryAt     time.Time
	unavailable bool
}

// consult connects the person if needed, delivers queued events in order,
// sends the request, and reads the answer. It connects again and resends
// after unknown_sub, and replays the mission and resends after
// unknown_mission, once each. Every exchange is logged under the sdi.
func (server *Server) consult(
	ctx context.Context,
	supervisor Supervisor,
	request supervision.Request,
	send func() (supervision.Outcome, error),
) consultation {
	state := server.supervision
	if !server.ensureConnected(ctx, supervisor) {
		server.logSupervision(ctx, request, supervisor, nil, "unavailable")
		return consultation{unavailable: true}
	}
	if _, err := server.deliverNotices(ctx, supervisor); err != nil {
		server.logSupervision(ctx, request, supervisor, nil, "unavailable")
		return consultation{unavailable: true}
	}
	if state.requireSigned {
		metadata, err := state.client.Metadata(ctx, supervisor.Issuer)
		if err != nil || !metadata.Signs() {
			server.logSupervision(ctx, request, supervisor, nil, "unavailable")
			return consultation{unavailable: true}
		}
	}
	resend := func() (supervision.Outcome, error) {
		return state.client.Supervise(ctx, supervisor.Issuer, request)
	}
	recovered := map[supervision.ErrorCode]bool{}
	for {
		outcome, err := send()
		result := classifyOutcome(outcome, err, server.clock.Now())
		exchange := outcome.Exchange.Clone()
		var logged *supervision.Exchange
		if exchange.Request.Method != "" {
			logged = &exchange
		}
		server.logSupervision(ctx, request, supervisor, logged, result.label)
		if outcome.Problem == nil || recovered[outcome.Problem.Code] {
			return result.consultation
		}
		switch outcome.Problem.Code {
		case supervision.ErrorUnsupportedIss:
			server.forgetConnection(ctx, supervisor)
			return result.consultation
		case supervision.ErrorUnknownSub:
			if !server.reconnect(ctx, supervisor) {
				return consultation{unavailable: true}
			}
		case supervision.ErrorUnknownMission:
			if request.MissionS256 == "" || server.replayMission(ctx, request.Agent, request.MissionS256, supervisor) != nil {
				return consultation{unavailable: true}
			}
			if _, err := server.deliverNotices(ctx, supervisor); err != nil {
				return consultation{unavailable: true}
			}
		default:
			return result.consultation
		}
		recovered[outcome.Problem.Code] = true
		send = resend
	}
}

type classified struct {
	consultation
	label string
}

// classifyOutcome reads one answer. A transport failure, a malformed or
// unverifiable answer, and every error but rate_limited make the supervisor
// unavailable for the act (Unavailable Supervisor).
func classifyOutcome(outcome supervision.Outcome, err error, now time.Time) classified {
	switch {
	case err != nil:
		return classified{consultation{unavailable: true}, "unavailable"}
	case outcome.Decision != nil:
		decision := *outcome.Decision
		return classified{consultation{decision: &decision}, string(decision.Verdict)}
	case outcome.Pending != nil:
		pending := *outcome.Pending
		if pending.Clarification != nil {
			return classified{consultation{pending: &pending}, "clarify"}
		}
		return classified{consultation{pending: &pending}, "pending"}
	case outcome.Problem != nil && outcome.Problem.Code == supervision.ErrorRateLimited:
		return classified{consultation{retryAt: now.Add(outcome.Problem.RetryAfter)}, "rate_limited"}
	case outcome.Problem != nil:
		return classified{consultation{unavailable: true}, string(outcome.Problem.Code)}
	default:
		return classified{consultation{unavailable: true}, "unavailable"}
	}
}

func (server *Server) logSupervision(ctx context.Context, request supervision.Request, supervisor Supervisor, exchange *supervision.Exchange, outcome string) {
	_ = server.supervision.store.RecordSupervisionLog(ctx, SupervisionLogEntry{
		SDI: request.SDI, Kind: request.Kind, Agent: request.Agent, Supervisor: supervisor,
		Exchange: exchange, Outcome: outcome, RecordedAt: server.clock.Now().UTC(),
	})
}

// applyConsultation moves a supervised request to the state an answer calls
// for. A terminal allow or deny is applied by the caller, which completes the
// act.
func (server *Server) applyConsultation(record SupervisedRequest, result consultation, now time.Time) SupervisedRequest {
	record.ClaimedAt = time.Time{}
	switch {
	case result.decision != nil && result.decision.Verdict == supervision.VerdictAsk:
		ask := *result.decision
		record.State = SupervisedWaitingForPerson
		record.Ask = &ask
		record.SupervisorLocation = ""
		record.Question = nil
	case result.pending != nil && result.pending.Clarification != nil && record.Rounds < supervision.MaxClarificationRounds:
		record.State = SupervisedClarifying
		record.SupervisorLocation = result.pending.Location
		record.Question = &SupervisionQuestion{Clarification: *result.pending.Clarification, AskedAt: now}
		record.Rounds++
	case result.pending != nil && result.pending.Clarification == nil:
		record.State = SupervisedWaitingForSupervisor
		record.SupervisorLocation = result.pending.Location
		record.NextPollAt = now.Add(result.pending.RetryAfter)
		record.Question = nil
	case !result.retryAt.IsZero() && result.retryAt.Before(record.ExpiresAt):
		record.State = SupervisedWaitingForSupervisor
		record.NextPollAt = result.retryAt
	default:
		// Unavailable, a rate limit past the request's expiry, or a
		// clarification beyond the round limit: the person decides.
		record.State = SupervisedWaitingForPerson
		record.SupervisorUnavailable = true
		record.SupervisorLocation = ""
		record.Question = nil
	}
	return record
}

func writeSupervisedPending(response http.ResponseWriter, record SupervisedRequest, now time.Time) {
	header := response.Header()
	header.Set("Location", supervisionPendingPath+record.Reference)
	header.Set("Cache-Control", "no-store")
	if record.State == SupervisedClarifying && record.Question != nil {
		question := record.Question.Clarification
		header.Set("AAuth-Requirement", "requirement=clarification")
		header.Set("Retry-After", "0")
		body := struct {
			Status        string   `json:"status"`
			Clarification string   `json:"clarification"`
			Timeout       int64    `json:"timeout,omitempty"`
			Options       []string `json:"options,omitempty"`
		}{Status: "pending", Clarification: question.Question, Options: question.Options}
		if question.Timeout > 0 {
			remaining := record.Question.AskedAt.Add(question.Timeout).Sub(now)
			if record.ExpiresAt.Sub(now) < remaining {
				remaining = record.ExpiresAt.Sub(now)
			}
			body.Timeout = int64(remaining / time.Second)
			if body.Timeout < 1 {
				body.Timeout = 1
			}
		}
		writePrivateJSON(response, http.StatusAccepted, body)
		return
	}
	header.Set("AAuth-Requirement", "requirement=approval")
	header.Set("Retry-After", strconv.FormatInt(int64(supervisedRetryAfter/time.Second), 10))
	writePrivateJSON(response, http.StatusAccepted, map[string]string{"status": "pending"})
}

// --- The Agent's pending URL -------------------------------------------------

// handleSupervisedPending serves the Agent's polls, clarification answers and
// cancellation of a supervised request. Polls observe retained state; they
// do not call the supervisor.
func (server *Server) handleSupervisedPending(response http.ResponseWriter, request *http.Request) {
	var required []string
	if request.Method == http.MethodPost {
		required = []string{"content-type", "content-digest"}
	}
	_, agent, proof, err := server.verifyAgentProof(request, required)
	if err != nil {
		writeAgentTokenProblem(response, err)
		return
	}
	ctx := request.Context()
	record, err := server.supervision.store.LoadSupervisedRequest(ctx, request.PathValue("id"))
	thumbprint, thumbprintErr := agent.Confirmation.JWK.Thumbprint()
	if errors.Is(err, ErrSupervisionNotFound) || (err == nil && (thumbprintErr != nil ||
		record.Agent != agent.Subject || record.AgentProvider != agent.Issuer || record.AgentJKT != thumbprint)) {
		writeProblem(response, http.StatusNotFound, "not_found", ErrSupervisionNotFound)
		return
	}
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if record.State == SupervisedWithAccessServer {
		server.relaySupervisedFederation(response, request, agent, record)
		return
	}
	switch request.Method {
	case http.MethodGet:
		if !requestBodyIsEmpty(request) {
			writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("poll must be bodyless"))
			return
		}
		server.pollSupervised(response, request, record)
	case http.MethodPost:
		server.answerSupervised(response, request, record, proof.ExactBody())
	case http.MethodDelete:
		server.cancelSupervised(response, request, record)
	default:
		response.Header().Set("Allow", "GET, POST, DELETE")
		writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("pending URL accepts GET, POST and DELETE"))
	}
}

func (server *Server) pollSupervised(response http.ResponseWriter, request *http.Request, record SupervisedRequest) {
	ctx := request.Context()
	for attempt := 0; attempt < 3; attempt++ {
		now := server.clock.Now().UTC()
		switch record.State {
		case SupervisedGone:
			writeProblem(response, http.StatusGone, "invalid_code", errors.New("personserver: the supervised request is finished"))
			return
		case SupervisedDecided:
			after := cloneSupervisedRequest(record)
			after.State = SupervisedGone
			after.Revision++
			err := server.supervision.store.ReplaceSupervisedRequest(ctx, record, after)
			if err == nil {
				writeSupervisedResponse(response, *record.Response)
				return
			}
			if !errors.Is(err, ErrSupervisionConflict) {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
				return
			}
		default:
			if now.Before(record.ExpiresAt) {
				writeSupervisedPending(response, record, now)
				return
			}
			expired, err := server.expireSupervised(ctx, record, now)
			if err == nil {
				record = expired
				continue
			}
			if !errors.Is(err, ErrSupervisionConflict) {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
				return
			}
		}
		reloaded, err := server.supervision.store.LoadSupervisedRequest(ctx, record.Reference)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		record = reloaded
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", ErrSupervisionConflict)
}

// expireSupervised ends a request whose time ran out. A decision the
// supervisor returns afterwards is discarded. A request that was with the
// person is reported abandoned; the person was never asked about one still
// waiting on the supervisor, so nothing is reported for it.
func (server *Server) expireSupervised(ctx context.Context, record SupervisedRequest, now time.Time) (SupervisedRequest, error) {
	after := cloneSupervisedRequest(record)
	after.State = SupervisedDecided
	after.Response = problemResponse(http.StatusRequestTimeout, "expired", "The supervised request expired.")
	after.Question = nil
	after.ClaimedAt = time.Time{}
	after.Revision++
	if err := server.supervision.store.ReplaceSupervisedRequest(ctx, record, after); err != nil {
		return SupervisedRequest{}, err
	}
	withPerson := record.State == SupervisedWaitingForPerson ||
		record.State == SupervisedClarifying && record.Question != nil && record.Question.From == supervision.FromPerson
	if withPerson {
		server.reportResolved(ctx, after, supervision.AnswerAbandoned, "", "", nil, false)
	}
	return after, nil
}

// answerSupervised takes the Agent's answer to the open question. An answer
// to the supervisor is relayed to its pending URL and its reply applied; an
// answer to the person joins the transcript.
func (server *Server) answerSupervised(response http.ResponseWriter, request *http.Request, record SupervisedRequest, body []byte) {
	ctx := request.Context()
	var input struct {
		Action   string  `json:"action"`
		Response *string `json:"clarification_response"`
	}
	if err := httpapi.DecodeJSON(bytes.NewReader(body), maxRequestBytes, &input); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	switch input.Action {
	case "clarification_response":
	case "updated_request":
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: a supervised request cannot be replaced; cancel it and make a new one"))
		return
	default:
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: action must be clarification_response"))
		return
	}
	if input.Response == nil || *input.Response == "" || len(*input.Response) > supervision.MaxMarkdownBytes {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("personserver: clarification_response is required"))
		return
	}
	now := server.clock.Now().UTC()
	if record.State == SupervisedGone {
		writeProblem(response, http.StatusGone, "invalid_code", errors.New("personserver: the supervised request is finished"))
		return
	}
	if record.State != SupervisedClarifying || record.Question == nil || !now.Before(record.ExpiresAt) || !record.ClaimedAt.IsZero() {
		writeProblem(response, http.StatusConflict, "invalid_request", errors.New("personserver: no question is waiting for an answer"))
		return
	}
	answer := *input.Response
	if record.Question.From == supervision.FromPerson {
		after := cloneSupervisedRequest(record)
		after.Transcript = append(after.Transcript,
			supervision.TranscriptEntry{From: supervision.FromPerson, Text: record.Question.Clarification.Question},
			supervision.TranscriptEntry{From: supervision.FromAgent, Text: answer})
		after.Question = nil
		after.State = SupervisedWaitingForPerson
		after.Revision++
		if err := server.supervision.store.ReplaceSupervisedRequest(ctx, record, after); err != nil {
			writeSupervisedMutationProblem(response, err)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		response.WriteHeader(http.StatusNoContent)
		return
	}
	claimed, err := server.claimSupervised(ctx, record, now)
	if err != nil {
		writeSupervisedMutationProblem(response, err)
		return
	}
	decoded, err := decodeSupervisionRequest(claimed)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	location := claimed.SupervisorLocation
	result := server.consult(ctx, claimed.Supervisor, decoded, func() (supervision.Outcome, error) {
		return server.supervision.client.AnswerClarification(ctx, claimed.Supervisor.Issuer, decoded, location, answer)
	})
	if err := server.settleSupervised(ctx, claimed, result); err != nil {
		writeSupervisedMutationProblem(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

// cancelSupervised withdraws the request: the Person Server withdraws it at
// the supervisor too, and later requests to the pending URL are gone.
func (server *Server) cancelSupervised(response http.ResponseWriter, request *http.Request, record SupervisedRequest) {
	ctx := request.Context()
	if record.State == SupervisedGone || record.State == SupervisedDecided {
		writeProblem(response, http.StatusGone, "invalid_code", errors.New("personserver: the supervised request is finished"))
		return
	}
	after := cloneSupervisedRequest(record)
	after.State = SupervisedGone
	after.Question = nil
	after.ClaimedAt = time.Time{}
	after.Revision++
	if err := server.supervision.store.ReplaceSupervisedRequest(ctx, record, after); err != nil {
		writeSupervisedMutationProblem(response, err)
		return
	}
	if record.SupervisorLocation != "" {
		_, _ = server.supervision.client.Cancel(ctx, record.Supervisor.Issuer, record.SupervisorLocation)
	}
	if record.State == SupervisedWaitingForPerson || (record.State == SupervisedClarifying && record.Question != nil && record.Question.From == supervision.FromPerson) {
		server.reportResolved(ctx, after, supervision.AnswerAbandoned, "", "", nil, false)
	}
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func writeSupervisedMutationProblem(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrSupervisionConflict), errors.Is(err, ErrSupervisionNotReady):
		writeProblem(response, http.StatusConflict, "invalid_request", err)
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
	}
}

func writeSupervisedResponse(response http.ResponseWriter, retained SupervisedResponse) {
	for name, values := range retained.Header {
		response.Header()[name] = append([]string(nil), values...)
	}
	response.WriteHeader(retained.Status)
	_, _ = response.Write(retained.Body)
}

// --- Host steps --------------------------------------------------------------

// AdvanceSupervision asks the supervisor about one request waiting on it,
// once: a signed poll of its pending URL, or the original request again
// under the same sdi when the supervisor asked the Person Server to wait. A
// decision completes the act, an ask puts it to the person, and an
// unreachable supervisor puts it to the person too. It refuses a request
// that is not waiting on the supervisor, or whose next poll is not yet due.
func (server *Server) AdvanceSupervision(ctx context.Context, reference string) error {
	if server.supervision == nil {
		return errors.New("personserver: supervision is not configured")
	}
	record, err := server.supervision.store.LoadSupervisedRequest(ctx, reference)
	if err != nil {
		return err
	}
	now := server.clock.Now().UTC()
	if record.State != SupervisedWaitingForSupervisor || now.Before(record.NextPollAt) {
		return ErrSupervisionNotReady
	}
	if !now.Before(record.ExpiresAt) {
		_, err := server.expireSupervised(ctx, record, now)
		return err
	}
	claimed, err := server.claimSupervised(ctx, record, now)
	if err != nil {
		return err
	}
	decoded, err := decodeSupervisionRequest(claimed)
	if err != nil {
		return err
	}
	client := server.supervision.client
	send := func() (supervision.Outcome, error) {
		return client.Supervise(ctx, claimed.Supervisor.Issuer, decoded)
	}
	if claimed.SupervisorLocation != "" {
		location := claimed.SupervisorLocation
		send = func() (supervision.Outcome, error) {
			return client.Poll(ctx, claimed.Supervisor.Issuer, decoded, location)
		}
	}
	return server.settleSupervised(ctx, claimed, server.consult(ctx, claimed.Supervisor, decoded, send))
}

// PendingSupervision lists supervised requests waiting on the supervisor or
// the person, oldest first, for a host queue. A review confers no authority:
// the host authenticates the person before ResolveSupervision.
func (server *Server) PendingSupervision(ctx context.Context, limit int) ([]SupervisionReview, error) {
	if server.supervision == nil {
		return nil, errors.New("personserver: supervision is not configured")
	}
	if limit <= 0 {
		return nil, errors.New("personserver: limit must be positive")
	}
	records, err := server.supervision.store.PendingSupervisedRequests(ctx, limit)
	if err != nil {
		return nil, err
	}
	reviews := make([]SupervisionReview, 0, len(records))
	for _, record := range records {
		review, err := supervisionReview(record)
		if err != nil {
			return nil, err
		}
		reviews = append(reviews, review)
	}
	return reviews, nil
}

// ReviewSupervision returns one supervised request as the host presents it.
func (server *Server) ReviewSupervision(ctx context.Context, reference string) (SupervisionReview, error) {
	if server.supervision == nil {
		return SupervisionReview{}, errors.New("personserver: supervision is not configured")
	}
	record, err := server.supervision.store.LoadSupervisedRequest(ctx, reference)
	if err != nil {
		return SupervisionReview{}, err
	}
	return supervisionReview(record)
}

func supervisionReview(record SupervisedRequest) (SupervisionReview, error) {
	decoded, err := decodeSupervisionRequest(record)
	if err != nil {
		return SupervisionReview{}, err
	}
	review := SupervisionReview{
		Reference: record.Reference, SDI: record.SDI, Kind: record.Kind, Agent: record.Agent,
		MissionS256: record.MissionS256, Supervisor: record.Supervisor, State: record.State,
		Request: decoded, SupervisorUnavailable: record.SupervisorUnavailable,
		Transcript: append([]supervision.TranscriptEntry(nil), record.Transcript...),
		ExpiresAt:  record.ExpiresAt,
	}
	if record.Ask != nil {
		ask := cloneDecision(*record.Ask)
		review.Ask = &ask
		review.ApplyOptions = append([]supervision.ApplyOption(nil), record.Ask.ApplyOptions...)
	}
	if len(review.ApplyOptions) == 0 {
		review.ApplyOptions = []supervision.ApplyOption{
			{Value: supervision.ApplyOnce, Label: "This request only"},
			{Value: supervision.ApplyMission, Label: "Every request of this kind under this mission, until it ends"},
			{Value: supervision.ApplyAlways, Label: "Every request of this kind by this agent, until you change it"},
		}
		if record.MissionS256 == "" {
			review.ApplyOptions = append(review.ApplyOptions[:1], review.ApplyOptions[2])
		}
	}
	if record.Question != nil {
		question := *record.Question
		question.Clarification.Options = append([]string(nil), question.Clarification.Options...)
		review.Question = &question
	}
	return review, nil
}

// AskSupervisedAgent puts the person's question about a request waiting for
// them to the Agent, as clarification chat; the Agent's answer joins the
// transcript reported with the person's decision. The host authenticates the
// person first. Questions and answers count toward one round limit.
func (server *Server) AskSupervisedAgent(ctx context.Context, reference string, question supervision.Clarification) error {
	if server.supervision == nil {
		return errors.New("personserver: supervision is not configured")
	}
	if err := question.Validate(); err != nil {
		return err
	}
	record, err := server.supervision.store.LoadSupervisedRequest(ctx, reference)
	if err != nil {
		return err
	}
	now := server.clock.Now().UTC()
	if record.State != SupervisedWaitingForPerson || !now.Before(record.ExpiresAt) || !record.ClaimedAt.IsZero() {
		return ErrSupervisionNotReady
	}
	if record.Rounds >= supervision.MaxClarificationRounds {
		return fmt.Errorf("personserver: the clarification limit of %d rounds is reached", supervision.MaxClarificationRounds)
	}
	after := cloneSupervisedRequest(record)
	question.Options = append([]string(nil), question.Options...)
	after.Question = &SupervisionQuestion{From: supervision.FromPerson, Clarification: question, AskedAt: now}
	after.State = SupervisedClarifying
	after.Rounds++
	after.Revision++
	return server.supervision.store.ReplaceSupervisedRequest(ctx, record, after)
}

// ResolveSupervision records the person's answer to a request the Person
// Server put to them, after an ask or because the supervisor was unavailable,
// and completes the act: an allow issues what was asked, as narrowed for a
// mission by Answer.Mission, and a deny refuses it. The Agent receives the
// result at its next poll, and the supervisor receives what the person
// decided in a decision.resolved event, with the reach they gave it. The host
// authenticates the person first.
func (server *Server) ResolveSupervision(ctx context.Context, reference string, answer SupervisionAnswer) error {
	if server.supervision == nil {
		return errors.New("personserver: supervision is not configured")
	}
	if answer.Answer != supervision.AnswerAllow && answer.Answer != supervision.AnswerDeny {
		return errors.New("personserver: the person's answer is allow or deny")
	}
	if len(answer.Reason) > supervision.MaxMarkdownBytes || len(answer.Apply) > 255 {
		return errors.New("personserver: the person's answer is too long")
	}
	record, err := server.supervision.store.LoadSupervisedRequest(ctx, reference)
	if err != nil {
		return err
	}
	now := server.clock.Now().UTC()
	if record.State != SupervisedWaitingForPerson {
		return ErrSupervisionNotReady
	}
	if !now.Before(record.ExpiresAt) {
		if _, err := server.expireSupervised(ctx, record, now); err != nil {
			return err
		}
		return ErrSupervisionExpired
	}
	if answer.Apply != "" {
		review, err := supervisionReview(record)
		if err != nil {
			return err
		}
		known := false
		for _, option := range review.ApplyOptions {
			known = known || option.Value == answer.Apply
		}
		if !known {
			return errors.New("personserver: apply is not one of the reaches offered")
		}
	}
	decision := supervision.Decision{SDI: record.SDI, Verdict: supervision.VerdictDeny, Reason: answer.Reason}
	var proposed *supervision.MissionTerms
	if answer.Answer == supervision.AnswerAllow {
		decision = supervision.Decision{SDI: record.SDI, Verdict: supervision.VerdictAllow}
		if record.Kind == supervision.KindMissionProposal {
			terms, err := approvedMissionTerms(record, answer.Mission)
			if err != nil {
				return err
			}
			decision.Mission = &terms
			if err := validateSupervisedAllow(record, decision, now); err != nil {
				return err
			}
			copied := cloneMissionTerms(terms)
			proposed = &copied
		}
	} else if answer.Mission != nil {
		return errors.New("personserver: a denial carries no mission terms")
	}
	claimed, err := server.claimSupervised(ctx, record, now)
	if err != nil {
		return err
	}
	claimed.Answer = &SupervisionAnswer{Answer: answer.Answer, Apply: answer.Apply, Reason: answer.Reason, Mission: proposed}
	server.reportResolved(ctx, claimed, answer.Answer, answer.Apply, answer.Reason, proposed, claimed.SupervisorUnavailable)
	return server.decideSupervised(ctx, claimed, decision)
}

// approvedMissionTerms returns the mission terms the person approved: their
// edits, else the supervisor's proposed refinement, else the proposal as the
// Agent made it.
func approvedMissionTerms(record SupervisedRequest, edited *supervision.MissionTerms) (supervision.MissionTerms, error) {
	if edited != nil {
		if err := edited.Validate(); err != nil {
			return supervision.MissionTerms{}, err
		}
		return *edited, nil
	}
	if record.Ask != nil && record.Ask.Proposed != nil {
		return *record.Ask.Proposed, nil
	}
	decoded, err := decodeSupervisionRequest(record)
	if err != nil {
		return supervision.MissionTerms{}, err
	}
	return supervision.MissionTerms{
		Description: decoded.Description, ApprovedTools: decoded.Tools, ApprovedResources: decoded.Resources,
	}, nil
}

// reportResolved queues decision.resolved for what the person decided, or
// that they did not answer in time.
func (server *Server) reportResolved(
	ctx context.Context,
	record SupervisedRequest,
	answer supervision.Answer,
	apply, reason string,
	proposed *supervision.MissionTerms,
	unavailable bool,
) {
	event := supervision.Event{
		Name: supervision.EventDecisionResolved, SDI: record.SDI, Agent: record.Agent,
		MissionS256: record.MissionS256, Answer: answer, Apply: apply, Reason: reason, Proposed: proposed,
		Transcript: append([]supervision.TranscriptEntry(nil), record.Transcript...),
	}
	if unavailable || record.SupervisorUnavailable {
		event.Supervisor = supervision.SupervisorUnavailable
	} else if record.Ask != nil {
		event.Recommendation = record.Ask.Recommendation
	}
	if len(event.Transcript) == 0 {
		event.Transcript = nil
	}
	_ = server.queueEvent(ctx, record.Supervisor, event)
}

// claimSupervised fences a host step on a request: only one step at a time
// calls the supervisor or completes the act. A claim older than the lease is
// taken over.
func (server *Server) claimSupervised(ctx context.Context, record SupervisedRequest, now time.Time) (SupervisedRequest, error) {
	if !record.ClaimedAt.IsZero() && now.Before(record.ClaimedAt.Add(supervisionClaimLease)) {
		return SupervisedRequest{}, ErrSupervisionNotReady
	}
	after := cloneSupervisedRequest(record)
	after.ClaimedAt = now
	after.Revision++
	if err := server.supervision.store.ReplaceSupervisedRequest(ctx, record, after); err != nil {
		return SupervisedRequest{}, err
	}
	return after, nil
}

// settleSupervised applies an answer to a claimed request: a terminal
// decision completes the act; anything else records the next state.
func (server *Server) settleSupervised(ctx context.Context, claimed SupervisedRequest, result consultation) error {
	if decision := result.decision; decision != nil && decision.Verdict != supervision.VerdictAsk {
		if decision.Verdict != supervision.VerdictAllow {
			return server.decideSupervised(ctx, claimed, *decision)
		}
		if err := validateSupervisedAllow(claimed, *decision, server.clock.Now()); err == nil {
			return server.decideSupervised(ctx, claimed, *decision)
		}
		result = consultation{unavailable: true}
	}
	after := server.applyConsultation(cloneSupervisedRequest(claimed), result, server.clock.Now().UTC())
	after.Revision++
	return server.supervision.store.ReplaceSupervisedRequest(ctx, claimed, after)
}

// validateAllow refuses an allow whose exp has already passed.
func validateAllow(decision supervision.Decision, now time.Time) error {
	if decision.ExpiresAt != 0 && !time.Unix(decision.ExpiresAt, 0).After(now) {
		return errors.New("personserver: the supervisor allowed no usable lifetime")
	}
	return nil
}

// validateSupervisedAllow checks an allow that arrived after the Agent's
// request was answered with 202, against what the Agent asked. The act's own
// checks run again when it is completed.
func validateSupervisedAllow(record SupervisedRequest, decision supervision.Decision, now time.Time) error {
	if err := validateAllow(decision, now); err != nil {
		return err
	}
	request, err := decodeSupervisionRequest(record)
	if err != nil {
		return err
	}
	switch record.Kind {
	case supervision.KindMissionProposal:
		return validateSupervisedMission(missionProposalOf(request), now)(decision)
	case supervision.KindAuthToken:
		if decision.Scope == "" {
			return nil
		}
		// The resource token was verified when the Agent made the request;
		// its retained bytes name the scope it requested.
		parsed, err := jose.ParseCompact(request.ResourceToken)
		if err != nil {
			return err
		}
		var resource struct {
			Scope string `json:"scope"`
		}
		if err := json.Unmarshal(parsed.Payload(), &resource); err != nil {
			return err
		}
		requested, _ := parseScopes(resource.Scope)
		granted, err := supervision.ParseScope(decision.Scope)
		if err != nil || !scopeSubset(granted, requested) {
			return errors.New("personserver: the supervisor allowed a scope the resource token did not request")
		}
	}
	return nil
}

func missionProposalOf(request supervision.Request) aauth.MissionProposal {
	return aauth.MissionProposal{
		Description: request.Description,
		Tools:       append([]aauth.MissionTool(nil), request.Tools...),
		Resources:   append([]string(nil), request.Resources...),
	}
}

// decideSupervised completes a claimed request with a terminal decision and
// retains the response for the Agent's next poll.
func (server *Server) decideSupervised(ctx context.Context, claimed SupervisedRequest, decision supervision.Decision) error {
	retained, err := server.completeSupervised(ctx, claimed, decision)
	if err != nil {
		return err
	}
	after := cloneSupervisedRequest(claimed)
	after.State = SupervisedDecided
	decided := cloneDecision(decision)
	after.Decision = &decided
	after.Response = &retained
	if server.awaitsAccessServer(ctx, claimed, retained) {
		after.State = SupervisedWithAccessServer
		after.Response = nil
	}
	after.Question = nil
	after.SupervisorLocation = ""
	after.ClaimedAt = time.Time{}
	after.Revision++
	if err := server.supervision.store.ReplaceSupervisedRequest(ctx, claimed, after); err != nil {
		return err
	}
	_, _ = server.deliverNotices(ctx, claimed.Supervisor)
	return nil
}

// completeSupervised serves the Agent's retained request again, verified as
// it was made, with the decision in place of a consultation, and returns
// what the Agent receives. A deny ends the request with the polling error
// denied, except a permission request, whose answer is the denial itself.
func (server *Server) completeSupervised(ctx context.Context, record SupervisedRequest, decision supervision.Decision) (SupervisedResponse, error) {
	if decision.Verdict == supervision.VerdictDeny && record.Kind != supervision.KindPermission {
		detail := "The request was denied."
		if decision.Reason != "" {
			detail = decision.Reason
		}
		return *problemResponse(http.StatusForbidden, "denied", detail), nil
	}
	retained := record.AgentRequest
	target := &url.URL{Scheme: "https", Host: retained.Host, Path: retained.Path}
	if unescaped, err := url.PathUnescape(retained.Path); err == nil {
		target.Path, target.RawPath = unescaped, retained.Path
	}
	request, err := http.NewRequestWithContext(context.WithValue(ctx, supervisionCompletionKey{}, &supervisionCompletion{
		reference: record.Reference, kind: record.Kind, agent: record.Agent, verifiedAt: retained.VerifiedAt,
		verdict: supervisionVerdict{supervisor: record.Supervisor, agent: record.Agent, sdi: record.SDI, decision: decision},
	}), retained.Method, target.String(), bytes.NewReader(retained.Body))
	if err != nil {
		return SupervisedResponse{}, err
	}
	request.Host = retained.Host
	request.Header = http.Header(retained.Header).Clone()
	recorder := &supervisedRecorder{header: http.Header{}}
	switch record.Kind {
	case supervision.KindPersonToken:
		server.handlePerson(recorder, request)
	case supervision.KindAuthToken:
		server.handleToken(recorder, request)
	case supervision.KindPermission:
		server.handlePermission(recorder, request)
	case supervision.KindMissionProposal:
		server.handleMission(recorder, request)
	case supervision.KindMissionUpdate, supervision.KindMissionCompletion:
		request.SetPathValue("s256", record.MissionS256)
		server.handleMissionAction(recorder, request)
	default:
		return SupervisedResponse{}, errors.New("personserver: supervised request kind is invalid")
	}
	return recorder.result(), nil
}

// supervisedRecorder captures the response a completion run writes.
type supervisedRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (recorder *supervisedRecorder) Header() http.Header { return recorder.header }

func (recorder *supervisedRecorder) WriteHeader(status int) {
	if recorder.status == 0 {
		recorder.status = status
	}
}

func (recorder *supervisedRecorder) Write(data []byte) (int, error) {
	if recorder.status == 0 {
		recorder.status = http.StatusOK
	}
	return recorder.body.Write(data)
}

func (recorder *supervisedRecorder) result() SupervisedResponse {
	status := recorder.status
	if status == 0 {
		status = http.StatusOK
	}
	return SupervisedResponse{Status: status, Header: recorder.header.Clone(), Body: append([]byte(nil), recorder.body.Bytes()...)}
}

func problemResponse(status int, code, detail string) *SupervisedResponse {
	recorder := &supervisedRecorder{header: http.Header{}}
	recorder.header.Set("Cache-Control", "no-store")
	httpapi.WriteProblem(recorder, status, code, nil, httpapi.ProblemFields{Detail: detail})
	result := recorder.result()
	return &result
}

// supervisionVerificationClock returns the clock a completion run verifies
// the Agent's retained request with: the instant it was first verified.
func (server *Server) supervisionVerificationClock(ctx context.Context) aauth.Clock {
	if completion := supervisionCompletionFrom(ctx); completion != nil {
		at := completion.verifiedAt
		return aauth.ClockFunc(func() time.Time { return at })
	}
	return server.clock
}

// issuanceTime is when a token issued for a request is issued: the request's
// verification time, or now when a supervised request completes later.
func (server *Server) issuanceTime(ctx context.Context, verifiedAt time.Time) time.Time {
	if supervisionCompletionFrom(ctx) != nil {
		return server.clock.Now().UTC()
	}
	return verifiedAt
}

// decodeSupervisionRequest decodes the exact supervision request a record
// retains.
func decodeSupervisionRequest(record SupervisedRequest) (supervision.Request, error) {
	switch record.Kind {
	case supervision.KindMissionProposal:
		return supervision.DecodeMissionProposal(record.Request)
	case supervision.KindMissionUpdate, supervision.KindMissionCompletion:
		decoded, _, err := supervision.DecodeMissionAction(record.MissionS256, record.Request)
		if err != nil {
			return supervision.Request{}, err
		}
		if decoded == nil {
			return supervision.Request{}, errors.New("personserver: retained supervision request is a report")
		}
		return *decoded, nil
	default:
		return supervision.DecodeDecisionRequest(record.Request)
	}
}

// nonNullJSON returns an exact optional JSON member, or nil when it is absent
// or null.
func nonNullJSON(raw []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	return append([]byte(nil), raw...)
}

func cloneDecision(decision supervision.Decision) supervision.Decision {
	if decision.Mission != nil {
		terms := cloneMissionTerms(*decision.Mission)
		decision.Mission = &terms
	}
	if decision.Proposed != nil {
		terms := cloneMissionTerms(*decision.Proposed)
		decision.Proposed = &terms
	}
	decision.ApplyOptions = append([]supervision.ApplyOption(nil), decision.ApplyOptions...)
	return decision
}

func cloneMissionTerms(terms supervision.MissionTerms) supervision.MissionTerms {
	terms.ApprovedTools = append([]aauth.MissionTool(nil), terms.ApprovedTools...)
	terms.ApprovedResources = append([]string(nil), terms.ApprovedResources...)
	if terms.ExpiresAt != nil {
		value := *terms.ExpiresAt
		terms.ExpiresAt = &value
	}
	return terms
}

func cloneSupervisedRequest(record SupervisedRequest) SupervisedRequest {
	record.Request = append([]byte(nil), record.Request...)
	record.AgentRequest.Header = http.Header(record.AgentRequest.Header).Clone()
	record.AgentRequest.Body = append([]byte(nil), record.AgentRequest.Body...)
	if record.Question != nil {
		question := *record.Question
		question.Clarification.Options = append([]string(nil), question.Clarification.Options...)
		record.Question = &question
	}
	record.Transcript = append([]supervision.TranscriptEntry(nil), record.Transcript...)
	if record.Ask != nil {
		ask := cloneDecision(*record.Ask)
		record.Ask = &ask
	}
	if record.Decision != nil {
		decision := cloneDecision(*record.Decision)
		record.Decision = &decision
	}
	if record.Answer != nil {
		answer := *record.Answer
		if answer.Mission != nil {
			terms := cloneMissionTerms(*answer.Mission)
			answer.Mission = &terms
		}
		record.Answer = &answer
	}
	if record.Response != nil {
		response := *record.Response
		response.Header = http.Header(response.Header).Clone()
		response.Body = append([]byte(nil), response.Body...)
		record.Response = &response
	}
	return record
}
