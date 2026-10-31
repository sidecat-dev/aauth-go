package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// ErrPendingFinished reports a pending request that already received its
// terminal answer or was cancelled. Its pending URL must not be polled again
// (Core, Deferred Response State Machine); no request was sent.
var ErrPendingFinished = errors.New("aauth agent: pending request already finished")

// PollTooEarlyError reports a poll attempted before the interval the server
// asked for elapsed. No request was sent; poll again at NextPollAt.
type PollTooEarlyError struct {
	NextPollAt time.Time
}

func (failure *PollTooEarlyError) Error() string {
	if failure == nil {
		return "aauth agent: poll is earlier than Retry-After allows"
	}
	return "aauth agent: poll is earlier than Retry-After allows; next poll at " + failure.NextPollAt.UTC().Format(time.RFC3339)
}

// PollOptions controls one poll of a pending request.
type PollOptions struct {
	// Wait asks the server to hold the poll open for up to this long while
	// the request completes. It is sent as Prefer: wait in whole seconds,
	// rounded up (Core, Polling with GET). Zero sends no preference. The
	// server may answer sooner.
	Wait time.Duration
}

// Pending is one request that a server deferred with 202 Accepted (Core,
// Deferred Responses), and what the Agent needs to finish it: the verified
// same-origin pending URL, the polling interval, any requirement the server
// named, the credential that signed the original request, and the check the
// original request applies to its terminal answer. T is the result of that
// request.
//
// Only the methods that send the original request construct a Pending, so a
// caller can neither invent a polling target nor move the credential to
// another one. A zero Pending is refused. Each Poll, AnswerClarification and
// Cancel sends exactly one signed request and never sleeps or retries. Copies
// share one lifetime: once any copy has received a terminal answer or been
// cancelled, every copy returns ErrPendingFinished without sending anything.
type Pending[T any] struct {
	flow  *pendingFlow[T]
	state pendingState
}

// Result is the answer to a request that a server may defer: the verified
// result, or a Pending to poll.
type Result[T any] struct {
	value   T
	done    bool
	pending Pending[T]
}

// Value returns the verified result when the request completed.
func (result Result[T]) Value() (T, bool) {
	if !result.done {
		var zero T
		return zero, false
	}
	return result.value, true
}

// Pending returns the request to poll when the server has not answered yet.
func (result Result[T]) Pending() (Pending[T], bool) {
	if result.done || result.pending.flow == nil {
		return Pending[T]{}, false
	}
	return result.pending, true
}

// PendingError reports that a server deferred a request made through a
// method that returns only a completed result. The server has retained the
// request, so Pending returns it instead of dropping it: poll it, or use the
// method's Begin form, which returns a Result.
type PendingError[T any] struct {
	pending Pending[T]
}

func (failure *PendingError[T]) Error() string {
	if failure == nil || failure.pending.flow == nil {
		return "aauth agent: request is pending"
	}
	return "aauth agent: " + failure.pending.flow.name + " is pending; poll Pending or use the Begin method"
}

// Pending returns the verified pending request.
func (failure *PendingError[T]) Pending() Pending[T] {
	if failure == nil {
		return Pending[T]{}
	}
	return failure.pending
}

// Location returns the verified same-origin pending URL.
func (pending Pending[T]) Location() string { return pending.state.location }

// RetryAfter returns the current polling interval: the server's Retry-After,
// five seconds when it sent none, and the backoff after a 429 or 503.
func (pending Pending[T]) RetryAfter() time.Duration { return pending.state.retryAfter }

// NextPollAt returns the earliest time Poll sends a request.
func (pending Pending[T]) NextPollAt() time.Time { return pending.state.nextPollAt }

// Requirement returns the requirement named by the latest 202, or empty when
// the server is still working on the request without one.
func (pending Pending[T]) Requirement() aauth.Requirement { return pending.state.requirement }

// InteractionURL returns the HTTPS URL where the person can act, when the
// requirement is interaction.
func (pending Pending[T]) InteractionURL() string { return pending.state.interactionURL }

// InteractionCode returns the correlation code to show the person, when the
// requirement is interaction. It is not a credential.
func (pending Pending[T]) InteractionCode() string { return pending.state.interactionCode }

// Interacting reports that the person reached the interaction. Stop
// prompting them and keep polling.
func (pending Pending[T]) Interacting() bool { return pending.state.interacting }

// Clarification returns the question the server asked, when the requirement
// is clarification. Answer it with AnswerClarification or withdraw the request
// with Cancel.
func (pending Pending[T]) Clarification() (ClarificationQuestion, bool) {
	if pending.state.requirement != aauth.RequirementClarification ||
		pending.state.clarification.kind != clarificationQuestionValidated {
		return ClarificationQuestion{}, false
	}
	return pending.state.clarification, true
}

// Poll sends one GET to the pending URL, signed with the credential that
// signed the original request, and never resends the original body. It
// refuses to send before NextPollAt. A 202 returns the next Pending; a 429 or
// 503 returns this Pending with its interval increased as the draft requires.
// Any other answer is terminal: it is checked as the original request's
// answer would be, and an AAuth error such as denied (403), expired (408) or
// invalid_code (410) is returned as *aauth.ProblemError. A malformed or
// relocated 202 also ends the request. After a transport failure the request
// stays pending, because the server may or may not have answered.
func (pending Pending[T]) Poll(ctx context.Context, options PollOptions) (Result[T], error) {
	operation := pending.operation("poll")
	if err := pending.ready(ctx); err != nil {
		return Result[T]{}, fail(operation, err)
	}
	if options.Wait < 0 {
		return Result[T]{}, fail(operation, errors.New("poll wait must not be negative"))
	}
	if next := pending.state.nextPollAt; pending.flow.clock.Now().Before(next) {
		return Result[T]{}, fail(operation, &PollTooEarlyError{NextPollAt: next})
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.state.location, nil)
	if err != nil {
		return Result[T]{}, fail(operation, err)
	}
	if options.Wait > 0 {
		seconds := int64((options.Wait + time.Second - 1) / time.Second)
		request.Header.Set("Prefer", "wait="+strconv.FormatInt(seconds, 10))
	}
	if err := pending.flow.sign(request); err != nil {
		return Result[T]{}, fail(operation, err)
	}
	response, err := pending.flow.httpClient.Do(request)
	if err != nil {
		return Result[T]{}, fail(operation, err)
	}
	result, err := pending.accept(ctx, response)
	if err != nil {
		return Result[T]{}, fail(operation, err)
	}
	return result, nil
}

// AnswerClarification sends one signed POST with action clarification_response
// to the pending URL (Core, Agent Response to Clarification), before the
// question's deadline. The answer is Markdown the server shows as the
// Agent's. Keep polling afterwards for the outcome.
func (pending Pending[T]) AnswerClarification(ctx context.Context, markdown string) error {
	operation := pending.operation("answer clarification for")
	if err := pending.ready(ctx); err != nil {
		return fail(operation, err)
	}
	if err := answerClarification(
		ctx, pending.flow.httpClient, pending.flow.sign, pending.flow.clock, pending.state, markdown,
	); err != nil {
		return fail(operation, err)
	}
	return nil
}

// Cancel sends one signed DELETE to the pending URL, withdrawing the request
// (Core, Cancel Request). After a 2xx answer the request is finished. The
// server may also refuse; the request then stays pending.
func (pending Pending[T]) Cancel(ctx context.Context) error {
	operation := pending.operation("cancel")
	if err := pending.ready(ctx); err != nil {
		return fail(operation, err)
	}
	if err := cancelPending(ctx, pending.flow.httpClient, pending.flow.sign, pending.state); err != nil {
		return fail(operation, err)
	}
	pending.flow.finished.Store(true)
	return nil
}

func (pending Pending[T]) operation(action string) string {
	if pending.flow == nil {
		return action + " pending request"
	}
	return action + " " + pending.flow.name
}

func (pending Pending[T]) ready(ctx context.Context) error {
	if pending.flow == nil || pending.state.location == "" {
		return errors.New("verified pending request is required")
	}
	if ctx == nil {
		return errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if pending.flow.finished.Load() {
		return ErrPendingFinished
	}
	return nil
}

// accept reads one answer to a poll and closes its body.
func (pending Pending[T]) accept(ctx context.Context, response *http.Response) (Result[T], error) {
	defer response.Body.Close()
	flow := pending.flow
	now := flow.clock.Now()
	switch response.StatusCode {
	case http.StatusAccepted:
		next, err := readPendingResponse(response, &pending.state, now)
		if err != nil {
			flow.finished.Store(true)
			return Result[T]{}, err
		}
		return Result[T]{pending: Pending[T]{flow: flow, state: next}}, nil
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		interval, err := retryPollInterval(pending.state.retryAfter, response, now)
		if err != nil {
			return Result[T]{}, err
		}
		next := pending.state
		next.retryAfter, next.nextPollAt = interval, now.Add(interval)
		return Result[T]{pending: Pending[T]{flow: flow, state: next}}, nil
	}
	flow.finished.Store(true)
	value, err := flow.complete(ctx, response)
	if err != nil {
		return Result[T]{}, err
	}
	return Result[T]{value: value, done: true}, nil
}

// pendingFlow is what every copy of one Pending shares: how to sign and send
// its requests, how to check its terminal answer, and whether it finished.
type pendingFlow[T any] struct {
	name       string
	httpClient *http.Client
	clock      aauth.Clock
	sign       func(*http.Request) error
	// complete checks a terminal answer exactly as the original request's
	// immediate answer is checked, including its error statuses. The caller
	// closes the body.
	complete func(context.Context, *http.Response) (T, error)
	finished atomic.Bool
}

// newPendingFlow returns a flow whose requests are signed by this client's
// key with credential, the JWT that signed the original request.
func newPendingFlow[T any](
	client *Client,
	name string,
	credential string,
	complete func(context.Context, *http.Response) (T, error),
) *pendingFlow[T] {
	return &pendingFlow[T]{
		name: name, httpClient: client.httpClient, clock: client.clock,
		sign:     jwtRequestSigner(client.signingKey, credential, client.clock, client.maxSignedBodyBytes),
		complete: complete,
	}
}

// pendingRequestSigner signs a poll, answer or cancellation with this
// client's key and Agent token.
func (client *Client) pendingRequestSigner() func(*http.Request) error {
	return jwtRequestSigner(client.signingKey, client.agentToken, client.clock, client.maxSignedBodyBytes)
}

// jwtRequestSigner signs a poll, answer or cancellation with key and the
// exact JWT credential. Nonempty content adds content-digest and
// content-type coverage.
func jwtRequestSigner(key jose.SigningKey, credential string, clock aauth.Clock, maxBodyBytes int64) func(*http.Request) error {
	return func(request *http.Request) error {
		return signaturekey.SignJWTRequestWithOptions(
			request, key, credential, clock, signaturekey.SignOptions{MaxBodyBytes: maxBodyBytes},
		)
	}
}

// begin reads the answer to an original request and closes its body: a 202
// becomes a Pending; anything else is checked by the flow.
func (flow *pendingFlow[T]) begin(ctx context.Context, response *http.Response) (Result[T], error) {
	defer response.Body.Close()
	if response.StatusCode == http.StatusAccepted {
		state, err := readPendingResponse(response, nil, flow.clock.Now())
		if err != nil {
			return Result[T]{}, err
		}
		return Result[T]{pending: Pending[T]{flow: flow, state: state}}, nil
	}
	value, err := flow.complete(ctx, response)
	if err != nil {
		return Result[T]{}, err
	}
	return Result[T]{value: value, done: true}, nil
}

// completed returns the value of a completed result, or a PendingError that
// carries the pending request, for methods that return only a value.
func completed[T any](operation string, result Result[T]) (T, error) {
	if value, ok := result.Value(); ok {
		return value, nil
	}
	pending, _ := result.Pending()
	var zero T
	return zero, fail(operation, &PendingError[T]{pending: pending})
}

// pendingState is one verified 202 Accepted answer (Core, Pending Response).
type pendingState struct {
	location        string
	retryAfter      time.Duration
	nextPollAt      time.Time
	requirement     aauth.Requirement
	interactionURL  string
	interactionCode string
	interacting     bool
	clarification   ClarificationQuestion
}

// readPendingResponse reads one 202 Accepted answer: exactly one Location on
// the responding origin, equal to prior's when polling; a decimal
// Retry-After, or five seconds without one; Cache-Control no-store; and a JSON
// body whose status is a nonempty string. Any status other than interacting
// counts as pending, and interacting, once seen, is kept. AAuth-Requirement
// may name approval, interaction or clarification; any other requirement is
// UnsupportedRequirementError.
func readPendingResponse(response *http.Response, prior *pendingState, observedAt time.Time) (pendingState, error) {
	location, err := parsePendingLocation(response)
	if err != nil {
		return pendingState{}, err
	}
	if prior != nil && location != prior.location {
		return pendingState{}, errors.New("pending response Location changed while polling")
	}
	retryAfter, err := parseRetryAfter(response.Header.Values("Retry-After"))
	if err != nil {
		return pendingState{}, err
	}
	if !hasNoStore(response.Header.Values("Cache-Control")) {
		return pendingState{}, errors.New("pending response Cache-Control must contain no-store")
	}
	if len(response.Header.Values("Content-Type")) != 1 {
		return pendingState{}, errors.New("pending response requires exactly one Content-Type")
	}
	var encoded json.RawMessage
	if err := decodeJSONResponse(response, &encoded); err != nil {
		return pendingState{}, err
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decodePendingExchangeBody(encoded, &body); err != nil {
		return pendingState{}, err
	}
	if strings.TrimSpace(body.Status) == "" {
		return pendingState{}, errors.New("pending response status is required")
	}
	state := pendingState{
		location: location, retryAfter: retryAfter, nextPollAt: observedAt.Add(retryAfter),
		interacting: body.Status == "interacting" || (prior != nil && prior.interacting),
	}
	values := response.Header.Values("AAuth-Requirement")
	if len(values) == 0 {
		return state, nil
	}
	requirement, err := aauth.ParseRequirement(values)
	if err != nil {
		return pendingState{}, err
	}
	switch requirement {
	case aauth.RequirementApproval:
	case aauth.RequirementInteraction:
		interaction, err := aauth.ParseInteractionRequirement(values)
		if err != nil {
			return pendingState{}, err
		}
		state.interactionURL, state.interactionCode = interaction.URL, interaction.Code
	case aauth.RequirementClarification:
		state.clarification, err = parseClarification(encoded, observedAt)
		if err != nil {
			return pendingState{}, err
		}
	default:
		return pendingState{}, &UnsupportedRequirementError{Requirement: requirement}
	}
	state.requirement = requirement
	return state, nil
}

// answerClarification posts one clarification_response to a pending URL whose
// latest answer asked a question.
func answerClarification(
	ctx context.Context,
	httpClient *http.Client,
	sign func(*http.Request) error,
	clock aauth.Clock,
	state pendingState,
	markdown string,
) error {
	if state.requirement != aauth.RequirementClarification || state.clarification.kind != clarificationQuestionValidated {
		return errors.New("pending clarification is required")
	}
	if strings.TrimSpace(markdown) == "" {
		return errors.New("clarification response is required")
	}
	if len(markdown) > maxClarificationResponseBytes {
		return fmt.Errorf("clarification response exceeds %d bytes", maxClarificationResponseBytes)
	}
	if state.clarification.hasTimeout && !clock.Now().Before(state.clarification.answerBefore) {
		return errors.New("clarification answer deadline has passed")
	}
	body, err := json.Marshal(struct {
		Action                string `json:"action"`
		ClarificationResponse string `json:"clarification_response"`
	}{Action: "clarification_response", ClarificationResponse: markdown})
	if err != nil {
		return err
	}
	request, err := newJSONRequest(ctx, state.location, body)
	if err != nil {
		return err
	}
	if err := sign(request); err != nil {
		return err
	}
	return sendPendingAction(httpClient, request)
}

// cancelPending sends one bodyless DELETE to a pending URL.
func cancelPending(ctx context.Context, httpClient *http.Client, sign func(*http.Request) error, state pendingState) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, state.location, nil)
	if err != nil {
		return err
	}
	if err := sign(request); err != nil {
		return err
	}
	return sendPendingAction(httpClient, request)
}

// sendPendingAction sends an answer or cancellation; any 2xx accepts it.
func sendPendingAction(httpClient *http.Client, request *http.Request) error {
	response, err := httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return responseFailure(response)
	}
	return nil
}
