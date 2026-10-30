package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const pendingInteractionCallVerified uint8 = 1

// PendingInteractionCall is a Resource's 202 interaction answering one call
// made with Do. The Resource needs the person before it can finish the call,
// for example because a server it calls downstream as an Agent asked for an
// interaction (Core, Interaction Chaining). The Resource's pending URL is
// authoritative: poll it with PollInteractionCall until it answers with the
// call's result.
type PendingInteractionCall struct {
	kind            uint8
	resource        string
	location        string
	retryAfter      time.Duration
	interactionURL  string
	interactionCode string
	interacting     bool
}

// Resource returns the Resource the call was made to.
func (pending PendingInteractionCall) Resource() string { return pending.resource }

// Location returns the verified same-origin pending URL.
func (pending PendingInteractionCall) Location() string { return pending.location }

// RetryAfter returns the minimum interval before the next poll.
func (pending PendingInteractionCall) RetryAfter() time.Duration { return pending.retryAfter }

// InteractionURL returns the HTTPS URL where the person can act. Build the
// user-facing URL, optionally with this Agent's callback, with
// aauth.FormatInteractionVisitURL.
func (pending PendingInteractionCall) InteractionURL() string { return pending.interactionURL }

// InteractionCode returns the human-readable correlation code. It is not an
// authorization credential.
func (pending PendingInteractionCall) InteractionCode() string { return pending.interactionCode }

// Interacting reports that the person reached the interaction. The caller
// should stop prompting them while it continues polling.
func (pending PendingInteractionCall) Interacting() bool { return pending.interacting }

// InteractionCallPoll is one poll of a pending interaction call. AuthToken is
// the Auth token the call was made with.
type InteractionCallPoll struct {
	Pending   PendingInteractionCall
	AuthToken string
}

// InteractionCallPollResult is the answer to one poll: the call's final
// response, or the same pending call with its next interval when the
// Resource answered 202, 429 or 503.
type InteractionCallPollResult struct {
	response *http.Response
	pending  PendingInteractionCall
}

// Response returns the final response of the call. The caller owns its body.
func (result InteractionCallPollResult) Response() (*http.Response, bool) {
	return result.response, result.response != nil
}

// Pending returns the pending call when the Resource has not finished it.
func (result InteractionCallPollResult) Pending() (PendingInteractionCall, bool) {
	return result.pending, result.pending.kind == pendingInteractionCallVerified
}

// ReadInteractionCall reads a Resource's 202 answer to a call made with Do.
// It returns the pending call when the response carries
// AAuth-Requirement: requirement=interaction and a same-origin pending URL,
// and consumes and closes the response body. The caller directs the person to
// the interaction and polls with PollInteractionCall; it never resends the
// call.
func (client *Client) ReadInteractionCall(response *http.Response) (PendingInteractionCall, error) {
	const operation = "read interaction call"
	if client == nil {
		return PendingInteractionCall{}, fail(operation, errors.New("client is required"))
	}
	if response == nil || response.Request == nil || response.Request.URL == nil {
		return PendingInteractionCall{}, fail(operation, errors.New("response to a call is required"))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		return PendingInteractionCall{}, fail(operation, errors.New("interaction call requires a 202 response"))
	}
	requirement, err := aauth.ParseInteractionRequirement(response.Header.Values("AAuth-Requirement"))
	if err != nil {
		return PendingInteractionCall{}, fail(operation, err)
	}
	pending, err := pendingInteractionCall(response, PendingInteractionCall{})
	if err != nil {
		return PendingInteractionCall{}, fail(operation, err)
	}
	pending.interactionURL = requirement.URL
	pending.interactionCode = requirement.Code
	return pending, nil
}

// PollInteractionCall presents the call's Auth token in one signed bodyless
// GET to the pending URL. A 202 returns the pending call with its next
// interval, and so do 429 and 503 with their retry interval. Any other
// response is the call's final result, except an AAuth problem such as
// denied or expired, which is returned as a typed error. It does not sleep,
// retry, or resend the call.
func (client *Client) PollInteractionCall(ctx context.Context, input InteractionCallPoll) (InteractionCallPollResult, error) {
	const operation = "poll interaction call"
	if client == nil {
		return InteractionCallPollResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return InteractionCallPollResult{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return InteractionCallPollResult{}, fail(operation, err)
	}
	pending := input.Pending
	if pending.kind != pendingInteractionCallVerified {
		return InteractionCallPollResult{}, fail(operation, errors.New("pending interaction call is required"))
	}
	if input.AuthToken == "" {
		return InteractionCallPollResult{}, fail(operation, errors.New("auth token is required"))
	}
	claims, err := aauth.VerifyAuthToken(ctx, input.AuthToken, client.keyResolver, client.clock)
	if err == nil {
		err = client.validateAuthTokenForDirectCall(ctx, claims, pending.resource, "")
	}
	if err != nil {
		return InteractionCallPollResult{}, fail(operation, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.location, nil)
	if err != nil {
		return InteractionCallPollResult{}, fail(operation, err)
	}
	if err := signaturekey.SignJWTRequestWithOptions(
		request, client.signingKey, input.AuthToken, client.clock, signaturekey.SignOptions{},
	); err != nil {
		return InteractionCallPollResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return InteractionCallPollResult{}, fail(operation, err)
	}
	switch response.StatusCode {
	case http.StatusAccepted:
		defer response.Body.Close()
		next, err := pendingInteractionCall(response, pending)
		if err != nil {
			return InteractionCallPollResult{}, fail(operation, err)
		}
		return InteractionCallPollResult{pending: next}, nil
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		next := pending
		next.retryAfter, err = retryPollInterval(pending.retryAfter, response, client.clock.Now())
		response.Body.Close()
		if err != nil {
			return InteractionCallPollResult{}, fail(operation, err)
		}
		return InteractionCallPollResult{pending: next}, nil
	}
	if response.StatusCode == http.StatusUnauthorized && response.Header.Get("Signature-Error") != "" {
		response.Body.Close()
		return InteractionCallPollResult{}, fail(operation, authTokenResponseFailure(response))
	}
	if response.StatusCode == http.StatusNotFound {
		response.Body.Close()
		return InteractionCallPollResult{}, fail(operation, errors.New("pending interaction call is unknown to this caller"))
	}
	if isProblemResponse(response) {
		problem, isAAuth, err := inspectAAuthProblem(response)
		if err != nil {
			response.Body.Close()
			return InteractionCallPollResult{}, fail(operation, err)
		}
		if isAAuth {
			response.Body.Close()
			return InteractionCallPollResult{}, fail(operation, problem)
		}
	}
	return InteractionCallPollResult{response: response}, nil
}

// pendingInteractionCall reads the pending URL, interval and status of a 202.
// While polling, the pending URL must stay the same.
func pendingInteractionCall(response *http.Response, prior PendingInteractionCall) (PendingInteractionCall, error) {
	location, err := parsePendingLocation(response)
	if err != nil {
		return PendingInteractionCall{}, err
	}
	if prior.kind != 0 && location != prior.location {
		return PendingInteractionCall{}, errors.New("pending interaction call Location changed while polling")
	}
	resource, err := requestOrigin(response.Request.URL)
	if err != nil {
		return PendingInteractionCall{}, err
	}
	retryAfter, err := parseRetryAfter(response.Header.Values("Retry-After"))
	if err != nil {
		return PendingInteractionCall{}, err
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decodeJSONResponse(response, &body); err != nil && !errors.Is(err, io.EOF) {
		return PendingInteractionCall{}, err
	}
	next := prior
	next.kind = pendingInteractionCallVerified
	next.resource = resource
	next.location = location
	next.retryAfter = retryAfter
	next.interacting = prior.interacting || body.Status == "interacting"
	return next, nil
}
