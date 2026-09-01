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

// InteractionRelayRequest selects the Person Server and supplies one
// interaction or payment relay, optionally associated with a mission.
type InteractionRelayRequest struct {
	PersonServer string
	Relay        aauth.InteractionRelay
}

type interactionRelayResultKind uint8
type pendingInteractionRelayKind uint8

const (
	interactionRelayResultFallback interactionRelayResultKind = iota + 1
	interactionRelayResultPending
	interactionRelayResultCompletion
	interactionRelayResultResponse

	pendingInteractionRelayVerified pendingInteractionRelayKind = 1
)

// InteractionRelayResult is exactly one direct fallback, verified
// continuation, terminal relay state, or caller-owned 429/503 response.
type InteractionRelayResult struct {
	kind       interactionRelayResultKind
	fallback   aauth.InteractionRelayDocument
	pending    PendingInteractionRelay
	completion aauth.InteractionRelayCompletionDocument
	response   *http.Response
}

// Fallback returns the exact original relay after a verified
// interaction_unavailable response. The Agent application can present its URL
// and code directly to the person.
func (result InteractionRelayResult) Fallback() (aauth.InteractionRelayDocument, bool) {
	if result.kind != interactionRelayResultFallback || len(result.fallback.ExactJSON) == 0 {
		return aauth.InteractionRelayDocument{}, false
	}
	return cloneInteractionRelayDocument(result.fallback), true
}

// Pending returns the verified Person Server relay continuation.
func (result InteractionRelayResult) Pending() (PendingInteractionRelay, bool) {
	if result.kind != interactionRelayResultPending || result.pending.kind != pendingInteractionRelayVerified {
		return PendingInteractionRelay{}, false
	}
	return result.pending, true
}

// Completion returns the exact terminal relay state.
func (result InteractionRelayResult) Completion() (aauth.InteractionRelayCompletionDocument, bool) {
	if result.kind != interactionRelayResultCompletion || len(result.completion.ExactJSON) == 0 {
		return aauth.InteractionRelayCompletionDocument{}, false
	}
	return cloneInteractionRelayCompletionDocument(result.completion), true
}

// Response returns an explicit retryable response. The caller owns its body.
func (result InteractionRelayResult) Response() (*http.Response, bool) {
	if result.kind != interactionRelayResultResponse || result.response == nil {
		return nil, false
	}
	return result.response, true
}

// PendingInteractionRelay is a same-origin continuation bound to the original
// Agent identity and proof key.
type PendingInteractionRelay struct {
	kind                           pendingInteractionRelayKind
	personServer, location, origin string
	retryAfter                     time.Duration
	interacting                    bool
	agentProvider, agent, agentJKT string
}

// PersonServer returns the Person Server that accepted the relay.
func (pending PendingInteractionRelay) PersonServer() string { return pending.personServer }

// Location returns the verified relay-continuation URL.
func (pending PendingInteractionRelay) Location() string { return pending.location }

// RetryAfter returns the current polling interval hint.
func (pending PendingInteractionRelay) RetryAfter() time.Duration { return pending.retryAfter }

// Interacting reports whether the Person Server has reported that the person
// engaged with the relayed URL.
func (pending PendingInteractionRelay) Interacting() bool {
	return pending.kind == pendingInteractionRelayVerified && pending.interacting
}

// InteractionRelayUncertainError reports an unverifiable initial result after
// the relay may have reached the Person Server.
type InteractionRelayUncertainError struct{ cause error }

func (failure *InteractionRelayUncertainError) Error() string {
	if failure == nil || failure.cause == nil {
		return "aauth agent: interaction relay outcome is uncertain"
	}
	return "aauth agent: interaction relay outcome is uncertain: " + failure.cause.Error()
}

func (failure *InteractionRelayUncertainError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

// RequestInteractionRelay performs one signed POST. It never polls or retries.
func (client *Client) RequestInteractionRelay(ctx context.Context, input InteractionRelayRequest) (InteractionRelayResult, error) {
	const operation = "request interaction relay"
	if client == nil {
		return InteractionRelayResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return InteractionRelayResult{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return InteractionRelayResult{}, fail(operation, err)
	}
	document, err := aauth.EncodeInteractionRelay(input.Relay)
	if err != nil {
		return InteractionRelayResult{}, fail(operation, err)
	}
	credential, err := client.personServerRequestBinding(ctx, input.PersonServer, "", "")
	if err != nil {
		return InteractionRelayResult{}, fail(operation, err)
	}
	maxBodyBytes := client.maxSignedBodyBytes
	if maxBodyBytes == 0 {
		maxBodyBytes = defaultMaxInteractionQuestionBytes
	}
	if int64(len(document.ExactJSON)) > maxBodyBytes {
		return InteractionRelayResult{}, fail(operation, errors.New("interaction relay exceeds maximum signed body size"))
	}
	endpoint, origin, err := client.discoverInteractionEndpoint(ctx, credential.personServer)
	if err != nil {
		return InteractionRelayResult{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, endpoint, document.ExactJSON)
	if err != nil {
		return InteractionRelayResult{}, fail(operation, err)
	}
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return InteractionRelayResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return InteractionRelayResult{}, fail(operation, &InteractionRelayUncertainError{cause: err})
	}
	result, err := client.interactionRelayResponse(
		response,
		credential.personServer,
		origin,
		PendingInteractionRelay{},
		document,
	)
	if err != nil {
		if interactionQuestionOutcomeUncertain(response.StatusCode) {
			return InteractionRelayResult{}, fail(operation, &InteractionRelayUncertainError{cause: err})
		}
		return InteractionRelayResult{}, fail(operation, err)
	}
	return result, nil
}

// PollInteractionRelay performs one signed bodyless GET. It never sleeps or
// loops. A Resource-hosted pending URL remains the authority for whether the
// underlying interaction completed.
func (client *Client) PollInteractionRelay(ctx context.Context, pending PendingInteractionRelay) (InteractionRelayResult, error) {
	const operation = "poll interaction relay"
	if client == nil {
		return InteractionRelayResult{}, fail(operation, errors.New("client is required"))
	}
	if err := client.validatePendingInteractionRelay(ctx, pending); err != nil {
		return InteractionRelayResult{}, fail(operation, err)
	}
	_, origin, err := client.discoverInteractionEndpoint(ctx, pending.personServer)
	if err != nil {
		return InteractionRelayResult{}, fail(operation, err)
	}
	if origin != pending.origin {
		return InteractionRelayResult{}, fail(operation, errors.New("pending relay origin does not match current metadata"))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.location, nil)
	if err != nil {
		return InteractionRelayResult{}, fail(operation, err)
	}
	if err := signaturekey.SignJWTRequest(request, client.signingKey, client.agentToken, client.clock); err != nil {
		return InteractionRelayResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return InteractionRelayResult{}, fail(operation, err)
	}
	result, err := client.interactionRelayResponse(response, pending.personServer, pending.origin, pending, aauth.InteractionRelayDocument{})
	if err != nil {
		return InteractionRelayResult{}, fail(operation, err)
	}
	return result, nil
}

func (client *Client) interactionRelayResponse(
	response *http.Response,
	personServer string,
	origin string,
	prior PendingInteractionRelay,
	original aauth.InteractionRelayDocument,
) (InteractionRelayResult, error) {
	if response == nil {
		return InteractionRelayResult{}, errors.New("interaction relay response is required")
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
		return InteractionRelayResult{kind: interactionRelayResultResponse, response: response}, nil
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusAccepted:
		pending, err := client.pendingInteractionRelay(response, personServer, origin, prior)
		if err != nil {
			return InteractionRelayResult{}, err
		}
		return InteractionRelayResult{kind: interactionRelayResultPending, pending: pending}, nil
	case http.StatusOK:
		if prior.kind != pendingInteractionRelayVerified {
			return InteractionRelayResult{}, errors.New("interaction relay cannot complete before a verified deferred response")
		}
		if !hasNoStore(response.Header.Values("Cache-Control")) {
			return InteractionRelayResult{}, errors.New("relay completion Cache-Control must contain no-store")
		}
		completion, err := decodeInteractionRelayCompletionResponse(response)
		if err != nil {
			return InteractionRelayResult{}, err
		}
		if prior.interacting && completion.Completion.Status != aauth.InteractionRelayInteracting {
			return InteractionRelayResult{}, errors.New("relay completion regressed from interacting to pending")
		}
		return InteractionRelayResult{kind: interactionRelayResultCompletion, completion: completion}, nil
	case http.StatusFailedDependency:
		failure := responseFailure(response)
		var problem *aauth.ProblemError
		if errors.As(failure, &problem) && problem.Code == "interaction_unavailable" && len(original.ExactJSON) != 0 {
			return InteractionRelayResult{kind: interactionRelayResultFallback, fallback: cloneInteractionRelayDocument(original)}, nil
		}
		return InteractionRelayResult{}, failure
	default:
		return InteractionRelayResult{}, responseFailure(response)
	}
}

func (client *Client) pendingInteractionRelay(
	response *http.Response,
	personServer string,
	origin string,
	prior PendingInteractionRelay,
) (PendingInteractionRelay, error) {
	location, err := parsePendingLocation(response)
	if err != nil {
		return PendingInteractionRelay{}, err
	}
	if prior.kind != 0 && location != prior.location {
		return PendingInteractionRelay{}, errors.New("pending relay Location changed while polling")
	}
	target, err := url.Parse(location)
	if err != nil {
		return PendingInteractionRelay{}, errors.New("pending relay Location is invalid")
	}
	locationOrigin, err := httpOrigin(target)
	if err != nil || locationOrigin != origin {
		return PendingInteractionRelay{}, errors.New("pending relay Location does not match metadata origin")
	}
	retryAfter, err := parseRetryAfter(response.Header.Values("Retry-After"))
	if err != nil {
		return PendingInteractionRelay{}, err
	}
	if !hasNoStore(response.Header.Values("Cache-Control")) {
		return PendingInteractionRelay{}, errors.New("pending relay response Cache-Control must contain no-store")
	}
	var body struct {
		Status aauth.InteractionRelayStatus `json:"status"`
	}
	if err := decodeJSONResponse(response, &body); err != nil {
		return PendingInteractionRelay{}, err
	}
	if body.Status != aauth.InteractionRelayPending && body.Status != aauth.InteractionRelayInteracting {
		return PendingInteractionRelay{}, errors.New("pending relay response requires pending or interacting status")
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return PendingInteractionRelay{}, err
	}
	return PendingInteractionRelay{
		kind:          pendingInteractionRelayVerified,
		personServer:  personServer,
		location:      location,
		origin:        origin,
		retryAfter:    retryAfter,
		interacting:   prior.interacting || body.Status == aauth.InteractionRelayInteracting,
		agentProvider: client.agentClaims.Issuer,
		agent:         client.identifier,
		agentJKT:      thumbprint,
	}, nil
}

func (client *Client) validatePendingInteractionRelay(ctx context.Context, pending PendingInteractionRelay) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := client.requireDirectPersonServerCaller(); err != nil {
		return err
	}
	if pending.kind != pendingInteractionRelayVerified || pending.personServer == "" ||
		pending.location == "" || pending.origin == "" || pending.agentProvider == "" ||
		pending.agent == "" || pending.agentJKT == "" {
		return errors.New("verified pending interaction relay is required")
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return err
	}
	if pending.personServer != client.agentClaims.PersonServer ||
		pending.agentProvider != client.agentClaims.Issuer ||
		pending.agent != client.identifier || pending.agentJKT != thumbprint {
		return errors.New("pending interaction relay does not match client")
	}
	return nil
}

func decodeInteractionRelayCompletionResponse(response *http.Response) (aauth.InteractionRelayCompletionDocument, error) {
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return aauth.InteractionRelayCompletionDocument{}, errors.New("relay completion must use application/json")
	}
	exactJSON, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return aauth.InteractionRelayCompletionDocument{}, fmt.Errorf("read relay completion: %w", err)
	}
	if len(exactJSON) > maxResponseBytes {
		return aauth.InteractionRelayCompletionDocument{}, errors.New("relay completion is too large")
	}
	return aauth.DecodeInteractionRelayCompletion(exactJSON)
}

func cloneInteractionRelayDocument(document aauth.InteractionRelayDocument) aauth.InteractionRelayDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}

func cloneInteractionRelayCompletionDocument(document aauth.InteractionRelayCompletionDocument) aauth.InteractionRelayCompletionDocument {
	document.ExactJSON = append([]byte(nil), document.ExactJSON...)
	return document
}
