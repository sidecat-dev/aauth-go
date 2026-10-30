package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const defaultMaxInteractionQuestionBytes = 1 << 20

// InteractionQuestionRequest selects the Person Server and supplies one
// question, optionally associated with a mission. Description and Question
// are untrusted raw Markdown.
type InteractionQuestionRequest struct {
	PersonServer string
	Description  string
	Question     string
	MissionS256  string
}
type interactionQuestionResultKind uint8
type pendingInteractionQuestionKind uint8

const (
	interactionQuestionResultAnswer interactionQuestionResultKind = iota + 1
	interactionQuestionResultPending
	interactionQuestionResultResponse
	pendingInteractionQuestionVerified pendingInteractionQuestionKind = 1
)

// InteractionQuestionResult is exactly one answer, verified continuation, or
// caller-owned 429/503 response.
type InteractionQuestionResult struct {
	kind     interactionQuestionResultKind
	answer   aauth.InteractionAnswerDocument
	pending  PendingInteractionQuestion
	response *http.Response
}

// Answer returns the exact answer when the question completed.
func (result InteractionQuestionResult) Answer() (aauth.InteractionAnswerDocument, bool) {
	if result.kind != interactionQuestionResultAnswer || len(result.answer.ExactJSON) == 0 {
		return aauth.InteractionAnswerDocument{}, false
	}
	return cloneInteractionAnswerDocument(result.answer), true
}

// Pending returns the verified continuation when the question was deferred. A
// poll answered with 429 or 503 also returns it, alongside Response, with the
// next polling interval: after a 429, five seconds more than before, or the
// 429's Retry-After when longer; after a 503, its Retry-After, or five
// seconds.
func (result InteractionQuestionResult) Pending() (PendingInteractionQuestion, bool) {
	if (result.kind != interactionQuestionResultPending && result.kind != interactionQuestionResultResponse) ||
		result.pending.kind != pendingInteractionQuestionVerified {
		return PendingInteractionQuestion{}, false
	}
	return result.pending, true
}

// Response returns an explicit retryable response. The caller owns its body.
func (result InteractionQuestionResult) Response() (*http.Response, bool) {
	if result.kind != interactionQuestionResultResponse || result.response == nil {
		return nil, false
	}
	return result.response, true
}

// PendingInteractionQuestion is a same-origin continuation bound to the
// original Agent identity and proof key.
type PendingInteractionQuestion struct {
	kind                           pendingInteractionQuestionKind
	personServer, location, origin string
	retryAfter                     time.Duration
	agentProvider, agent, agentJKT string
}

// PersonServer returns the Person Server that accepted the question.
func (pending PendingInteractionQuestion) PersonServer() string { return pending.personServer }

// Location returns the verified pending URL.
func (pending PendingInteractionQuestion) Location() string { return pending.location }

// RetryAfter returns the current polling interval hint.
func (pending PendingInteractionQuestion) RetryAfter() time.Duration { return pending.retryAfter }

// InteractionQuestionUncertainError reports an unverifiable initial result.
type InteractionQuestionUncertainError struct{ cause error }

func (failure *InteractionQuestionUncertainError) Error() string {
	if failure == nil || failure.cause == nil {
		return "aauth agent: interaction question outcome is uncertain"
	}
	return "aauth agent: interaction question outcome is uncertain: " + failure.cause.Error()
}
func (failure *InteractionQuestionUncertainError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

// AskPersonQuestion performs one signed POST. It never polls or retries.
func (client *Client) AskPersonQuestion(ctx context.Context, input InteractionQuestionRequest) (InteractionQuestionResult, error) {
	const operation = "ask person question"
	if client == nil {
		return InteractionQuestionResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return InteractionQuestionResult{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return InteractionQuestionResult{}, fail(operation, err)
	}
	document, err := aauth.EncodeInteractionQuestion(aauth.InteractionQuestion{
		Description: input.Description, Question: input.Question, MissionS256: input.MissionS256,
	})
	if err != nil {
		return InteractionQuestionResult{}, fail(operation, err)
	}
	credential, err := client.personServerRequestBinding(ctx, input.PersonServer, "", "")
	if err != nil {
		return InteractionQuestionResult{}, fail(operation, err)
	}
	maxBodyBytes := client.maxSignedBodyBytes
	if maxBodyBytes == 0 {
		maxBodyBytes = defaultMaxInteractionQuestionBytes
	}
	if int64(len(document.ExactJSON)) > maxBodyBytes {
		return InteractionQuestionResult{}, fail(operation, errors.New("interaction question exceeds maximum signed body size"))
	}
	endpoint, origin, err := client.discoverInteractionEndpoint(ctx, credential.personServer)
	if err != nil {
		return InteractionQuestionResult{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, endpoint, document.ExactJSON)
	if err != nil {
		return InteractionQuestionResult{}, fail(operation, err)
	}
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return InteractionQuestionResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return InteractionQuestionResult{}, fail(operation, &InteractionQuestionUncertainError{cause: err})
	}
	result, err := client.interactionQuestionResponse(response, credential.personServer, origin, PendingInteractionQuestion{})
	if err != nil {
		if interactionQuestionOutcomeUncertain(response.StatusCode) {
			return InteractionQuestionResult{}, fail(operation, &InteractionQuestionUncertainError{cause: err})
		}
		return InteractionQuestionResult{}, fail(operation, err)
	}
	return result, nil
}

// PollPersonQuestion performs one signed bodyless GET. It never sleeps or loops.
func (client *Client) PollPersonQuestion(ctx context.Context, pending PendingInteractionQuestion) (InteractionQuestionResult, error) {
	const operation = "poll person question"
	if client == nil {
		return InteractionQuestionResult{}, fail(operation, errors.New("client is required"))
	}
	if err := client.validatePendingInteractionQuestion(ctx, pending); err != nil {
		return InteractionQuestionResult{}, fail(operation, err)
	}
	_, origin, err := client.discoverInteractionEndpoint(ctx, pending.personServer)
	if err != nil {
		return InteractionQuestionResult{}, fail(operation, err)
	}
	if origin != pending.origin {
		return InteractionQuestionResult{}, fail(operation, errors.New("pending question origin does not match current metadata"))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.location, nil)
	if err != nil {
		return InteractionQuestionResult{}, fail(operation, err)
	}
	if err := signaturekey.SignJWTRequest(request, client.signingKey, client.agentToken, client.clock); err != nil {
		return InteractionQuestionResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return InteractionQuestionResult{}, fail(operation, err)
	}
	result, err := client.interactionQuestionResponse(response, pending.personServer, pending.origin, pending)
	if err != nil {
		return InteractionQuestionResult{}, fail(operation, err)
	}
	return result, nil
}

func (client *Client) discoverInteractionEndpoint(ctx context.Context, personServer string) (string, string, error) {
	metadata, err := client.personServerMetadata(ctx, personServer)
	if err != nil {
		return "", "", err
	}
	if metadata.InteractionEndpoint == "" {
		return "", "", errors.New("person-server metadata interaction_endpoint is required")
	}
	if err := aauth.ValidateEndpoint(metadata.InteractionEndpoint); err != nil {
		return "", "", fmt.Errorf("person-server metadata interaction_endpoint: %w", err)
	}
	target, err := url.Parse(metadata.InteractionEndpoint)
	if err != nil {
		return "", "", err
	}
	origin, err := httpOrigin(target)
	if err != nil {
		return "", "", err
	}
	return metadata.InteractionEndpoint, origin, nil
}

func (client *Client) interactionQuestionResponse(response *http.Response, personServer, origin string, prior PendingInteractionQuestion) (InteractionQuestionResult, error) {
	if response == nil {
		return InteractionQuestionResult{}, errors.New("interaction question response is required")
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
		result := InteractionQuestionResult{kind: interactionQuestionResultResponse, response: response}
		if prior.kind == pendingInteractionQuestionVerified {
			next := prior
			retryAfter, err := retryPollInterval(prior.retryAfter, response, client.clock.Now())
			if err != nil {
				response.Body.Close()
				return InteractionQuestionResult{}, err
			}
			next.retryAfter = retryAfter
			result.pending = next
		}
		return result, nil
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		answer, err := decodeInteractionAnswerResponse(response)
		if err != nil {
			return InteractionQuestionResult{}, err
		}
		return InteractionQuestionResult{kind: interactionQuestionResultAnswer, answer: answer}, nil
	case http.StatusAccepted:
		pending, err := client.pendingInteractionQuestion(response, personServer, origin, prior)
		if err != nil {
			return InteractionQuestionResult{}, err
		}
		return InteractionQuestionResult{kind: interactionQuestionResultPending, pending: pending}, nil
	default:
		return InteractionQuestionResult{}, responseFailure(response)
	}
}

func (client *Client) pendingInteractionQuestion(response *http.Response, personServer, origin string, prior PendingInteractionQuestion) (PendingInteractionQuestion, error) {
	location, err := parsePendingLocation(response)
	if err != nil {
		return PendingInteractionQuestion{}, err
	}
	if prior.kind != 0 && location != prior.location {
		return PendingInteractionQuestion{}, errors.New("pending question Location changed while polling")
	}
	target, err := url.Parse(location)
	if err != nil {
		return PendingInteractionQuestion{}, errors.New("pending question Location is invalid")
	}
	locationOrigin, err := httpOrigin(target)
	if err != nil || locationOrigin != origin {
		return PendingInteractionQuestion{}, errors.New("pending question Location does not match metadata origin")
	}
	retryAfter, err := parseRetryAfter(response.Header.Values("Retry-After"))
	if err != nil {
		return PendingInteractionQuestion{}, err
	}
	if !hasNoStore(response.Header.Values("Cache-Control")) {
		return PendingInteractionQuestion{}, errors.New("pending question response Cache-Control must contain no-store")
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decodeJSONResponse(response, &body); err != nil || body.Status == "" {
		return PendingInteractionQuestion{}, errors.New("pending question response requires status")
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return PendingInteractionQuestion{}, err
	}
	return PendingInteractionQuestion{kind: pendingInteractionQuestionVerified, personServer: personServer, location: location, origin: origin, retryAfter: retryAfter, agentProvider: client.agentClaims.Issuer, agent: client.identifier, agentJKT: thumbprint}, nil
}

func (client *Client) validatePendingInteractionQuestion(ctx context.Context, pending PendingInteractionQuestion) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := client.requireDirectPersonServerCaller(); err != nil {
		return err
	}
	if pending.kind != pendingInteractionQuestionVerified || pending.personServer == "" || pending.location == "" || pending.origin == "" || pending.agentProvider == "" || pending.agent == "" || pending.agentJKT == "" {
		return errors.New("verified pending interaction question is required")
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return err
	}
	if pending.personServer != client.agentClaims.PersonServer || pending.agentProvider != client.agentClaims.Issuer || pending.agent != client.identifier || pending.agentJKT != thumbprint {
		return errors.New("pending interaction question does not match client")
	}
	return nil
}

func decodeInteractionAnswerResponse(response *http.Response) (aauth.InteractionAnswerDocument, error) {
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return aauth.InteractionAnswerDocument{}, errors.New("interaction answer must use application/json")
	}
	exactJSON, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return aauth.InteractionAnswerDocument{}, fmt.Errorf("read interaction answer: %w", err)
	}
	if len(exactJSON) > maxResponseBytes {
		return aauth.InteractionAnswerDocument{}, errors.New("interaction answer is too large")
	}
	return aauth.DecodeInteractionAnswer(exactJSON)
}

func interactionQuestionOutcomeUncertain(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices || status >= http.StatusInternalServerError
}
func cloneInteractionAnswerDocument(document aauth.InteractionAnswerDocument) aauth.InteractionAnswerDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}
