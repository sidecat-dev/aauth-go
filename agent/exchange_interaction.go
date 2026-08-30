package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	aauth "aauth-go"
	"aauth-go/internal/jsonstrict"
	"aauth-go/signaturekey"
)

type exchangeResultKind uint8

const (
	exchangeResultToken exchangeResultKind = iota + 1
	exchangeResultPending
	exchangeResultResponse
)

// ExchangeResult carries a verified auth token, a verified pending PS
// exchange, an explicit unsupported-requirement failure, or a caller-owned
// retryable response. Poll retry responses also carry updated pending state;
// an initial 503 does not.
type ExchangeResult struct {
	kind     exchangeResultKind
	token    string
	pending  PendingExchange
	response *http.Response
	failure  error
}

// UnsupportedRequirementError identifies a verified pending requirement for which this focused API has no answer method.
type UnsupportedRequirementError struct{ Requirement aauth.Requirement }

func (e *UnsupportedRequirementError) Error() string {
	return fmt.Sprintf("aauth agent: unsupported pending requirement %q", e.Requirement)
}

// Failure returns a typed unsupported-requirement result alongside Pending.
func (result ExchangeResult) Failure() error { return result.failure }

func pendingExchangeResult(p PendingExchange) ExchangeResult {
	r := ExchangeResult{kind: exchangeResultPending, pending: p}
	switch p.requirement {
	case "", aauth.RequirementApproval, aauth.RequirementInteraction:
	default:
		r.failure = &UnsupportedRequirementError{Requirement: p.requirement}
	}
	return r
}

// Token returns the verified auth token when the exchange completed.
func (result ExchangeResult) Token() (string, bool) {
	if result.kind != exchangeResultToken || result.token == "" {
		return "", false
	}
	return result.token, true
}

// Pending returns the verified continuation when the exchange is pending.
func (result ExchangeResult) Pending() (PendingExchange, bool) {
	if result.pending.kind != pendingExchangeVerified {
		return PendingExchange{}, false
	}
	return result.pending, true
}

// Response returns a caller-owned retryable 429 or 503 response. Its body
// remains unread, and the caller must close it. An initial 503 asks the caller
// to retry BeginExchange; a poll response also carries Pending.
func (result ExchangeResult) Response() (*http.Response, bool) {
	if result.kind != exchangeResultResponse || result.response == nil ||
		(result.response.StatusCode != http.StatusTooManyRequests && result.response.StatusCode != http.StatusServiceUnavailable) {
		return nil, false
	}
	return result.response, true
}

type pendingExchangeKind uint8

const pendingExchangeVerified pendingExchangeKind = 1

// PendingExchange is a verified Person Server token request awaiting a later
// result or requirement. Its private fields retain the exact original
// resource-token verification context.
type PendingExchange struct {
	kind               pendingExchangeKind
	personServer       string
	location           string
	retryAfter         time.Duration
	interactionURL     string
	interactionCode    string
	interacting        bool
	requirement        aauth.Requirement
	interactionCapable bool
	resourceToken      string
	resourceClaims     *aauth.ResourceTokenClaims
	agentProvider      string
	agent              string
	agentJKT           string
}

// PersonServer returns the Person Server that accepted the exchange.
func (pending PendingExchange) PersonServer() string {
	if pending.kind != pendingExchangeVerified {
		return ""
	}
	return pending.personServer
}

// Location returns the verified same-origin polling URL.
func (pending PendingExchange) Location() string {
	if pending.kind != pendingExchangeVerified {
		return ""
	}
	return pending.location
}

// RetryAfter returns the minimum interval the caller must respect before the
// next explicit poll.
func (pending PendingExchange) RetryAfter() time.Duration {
	if pending.kind != pendingExchangeVerified {
		return 0
	}
	return pending.retryAfter
}

// Requirement returns the current generic requirement token. An empty value
// means the server supplied no requirement.
func (pending PendingExchange) Requirement() aauth.Requirement {
	if pending.kind != pendingExchangeVerified {
		return ""
	}
	return pending.requirement
}

// InteractionURL returns the HTTPS URL where the person can act.
func (pending PendingExchange) InteractionURL() string {
	if pending.kind != pendingExchangeVerified {
		return ""
	}
	return pending.interactionURL
}

// InteractionCode returns the human-readable correlation code.
func (pending PendingExchange) InteractionCode() string {
	if pending.kind != pendingExchangeVerified {
		return ""
	}
	return pending.interactionCode
}

// Interacting reports whether the Person Server has observed the interaction.
func (pending PendingExchange) Interacting() bool {
	return pending.kind == pendingExchangeVerified && pending.interacting
}

// BeginExchange performs one signed PS token request after metadata discovery.
// It returns either an immediate verified auth token or a verified pending
// exchange and never polls, sleeps, retries, or opens an interaction URL.
// Initial payment responses and clarification answers are not implemented.
func (client *Client) BeginExchange(ctx context.Context, input ExchangeRequest) (ExchangeResult, error) {
	const operation = "begin exchange"
	if client == nil {
		return ExchangeResult{}, fail(operation, errors.New("client is required"))
	}
	response, resourceClaims, credential, err := client.exchangeRequest(ctx, input)
	if err != nil {
		return ExchangeResult{}, fail(operation, err)
	}
	switch response.StatusCode {
	case http.StatusOK:
		defer response.Body.Close()
		token, err := client.verifiedExchangeResponse(ctx, response, resourceClaims, credential)
		if err != nil {
			return ExchangeResult{}, fail(operation, err)
		}
		return ExchangeResult{kind: exchangeResultToken, token: token}, nil
	case http.StatusAccepted:
		defer response.Body.Close()
		if input.SubagentToken != "" {
			return ExchangeResult{}, fail(operation, &SubagentInteractionUnsupportedError{Operation: "auth-token exchange"})
		}
		if input.UpstreamToken != "" {
			return ExchangeResult{}, fail(operation, &CallChainingInteractionUnsupportedError{Operation: "auth-token exchange"})
		}
		pending, err := client.pendingExchangeResponse(response, input.PersonServer, input.ResourceToken, resourceClaims, PendingExchange{})
		if err != nil {
			return ExchangeResult{}, fail(operation, err)
		}
		pending.interactionCapable = slices.Contains(input.Capabilities, "interaction")
		if pending.requirement == aauth.RequirementInteraction && !pending.interactionCapable {
			return ExchangeResult{}, fail(operation, errors.New("pending interaction requires the declared interaction capability"))
		}
		return pendingExchangeResult(pending), nil
	case http.StatusServiceUnavailable:
		if _, err := parseHTTPRetryAfter(response.Header.Values("Retry-After"), client.clock.Now()); err != nil {
			response.Body.Close()
			return ExchangeResult{}, fail(operation, err)
		}
		return ExchangeResult{kind: exchangeResultResponse, response: response}, nil
	default:
		defer response.Body.Close()
		return ExchangeResult{}, fail(operation, responseFailure(response))
	}
}

// PollExchange performs exactly one bodyless Agent-token-signed GET for a
// verified pending exchange. A typed 410 invalid_code response is terminal and
// MUST NOT be retried. Clarification-answer actions are not implemented.
func (client *Client) PollExchange(ctx context.Context, pending PendingExchange) (ExchangeResult, error) {
	const operation = "poll exchange"
	if client == nil {
		return ExchangeResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return ExchangeResult{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return ExchangeResult{}, fail(operation, err)
	}
	if err := client.requireDirectPersonServerCaller(); err != nil {
		return ExchangeResult{}, fail(operation, err)
	}
	if pending.kind != pendingExchangeVerified || pending.personServer == "" ||
		pending.location == "" ||
		pending.resourceToken == "" || pending.resourceClaims == nil || pending.agentProvider == "" ||
		pending.agent == "" || pending.agentJKT == "" {
		return ExchangeResult{}, fail(operation, errors.New("verified pending exchange for this client is required"))
	}
	if pending.requirement == aauth.RequirementInteraction {
		if pending.interactionURL == "" || pending.interactionCode == "" {
			return ExchangeResult{}, fail(operation, errors.New("pending interaction URL and code are required"))
		}
	} else if pending.interactionURL != "" || pending.interactionCode != "" {
		return ExchangeResult{}, fail(operation, errors.New("non-interaction pending exchange must not carry interaction fields"))
	}
	if pending.agentProvider != client.agentClaims.Issuer || pending.personServer != client.agentClaims.PersonServer ||
		pending.agent != client.identifier {
		return ExchangeResult{}, fail(operation, errors.New("pending exchange does not match client identity"))
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return ExchangeResult{}, fail(operation, err)
	}
	if thumbprint != pending.agentJKT {
		return ExchangeResult{}, fail(operation, errors.New("pending exchange does not match client key"))
	}
	if pending.resourceClaims.PersonServer != pending.personServer || pending.resourceClaims.AgentJKT != pending.agentJKT {
		return ExchangeResult{}, fail(operation, errors.New("pending exchange resource-token context does not match client"))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.location, nil)
	if err != nil {
		return ExchangeResult{}, fail(operation, err)
	}
	if err := signaturekey.SignJWTRequest(request, client.signingKey, client.agentToken, client.clock); err != nil {
		return ExchangeResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return ExchangeResult{}, fail(operation, err)
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
		next := pending
		if response.StatusCode == http.StatusTooManyRequests {
			if next.retryAfter > time.Duration(math.MaxInt64)-5*time.Second {
				response.Body.Close()
				return ExchangeResult{}, fail(operation, errors.New("poll retry interval overflows"))
			}
			next.retryAfter += 5 * time.Second
		} else {
			retryAfter, err := parseHTTPRetryAfter(response.Header.Values("Retry-After"), client.clock.Now())
			if err != nil {
				response.Body.Close()
				return ExchangeResult{}, fail(operation, err)
			}
			next.retryAfter = retryAfter
		}
		result := pendingExchangeResult(next)
		result.kind, result.response = exchangeResultResponse, response
		return result, nil
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusAccepted:
		next, err := client.pendingExchangeResponse(
			response, pending.personServer, pending.resourceToken, *pending.resourceClaims, pending,
		)
		if err != nil {
			return ExchangeResult{}, fail(operation, err)
		}
		return pendingExchangeResult(next), nil
	case http.StatusOK:
		token, err := client.verifiedExchangeResponse(
			ctx,
			response,
			*pending.resourceClaims,
			personServerCredential{
				requestKey: client.signingKey.PublicJWK(), expiresAt: client.agentClaims.ExpiresAt,
				expirySource: "agent token",
			},
		)
		if err != nil {
			return ExchangeResult{}, fail(operation, err)
		}
		return ExchangeResult{kind: exchangeResultToken, token: token}, nil
	default:
		return ExchangeResult{}, fail(operation, responseFailure(response))
	}
}

func (client *Client) exchangeRequest(
	ctx context.Context,
	input ExchangeRequest,
) (*http.Response, aauth.ResourceTokenClaims, personServerCredential, error) {
	if ctx == nil {
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, err
	}
	if len(input.Capabilities) > 0 {
		if _, err := aauth.FormatCapabilities(input.Capabilities); err != nil {
			return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, fmt.Errorf("capabilities: %w", err)
		}
	}
	credential, err := client.personServerRequestBinding(
		ctx, input.PersonServer, input.SubagentToken, input.UpstreamToken,
	)
	if err != nil {
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, err
	}
	input.PersonServer = credential.personServer
	if input.ResourceToken == "" {
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, errors.New("resource token is required")
	}
	resourceClaims, err := aauth.VerifyResourceToken(ctx, input.ResourceToken, client.keyResolver, client.clock)
	if err != nil {
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, err
	}
	if resourceClaims.Interaction != nil {
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, errors.New("resource-token interaction requires the deferred flow")
	}
	if resourceClaims.Account != "" {
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, errors.New("resource-token account is not supported by the immediate flow")
	}
	if resourceClaims.MissionS256 != "" {
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, errors.New("mission-bound resource tokens require the mission flow")
	}
	thumbprint, err := credential.requestKey.Thumbprint()
	if err != nil {
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, err
	}
	if resourceClaims.PersonServer != input.PersonServer || resourceClaims.AgentJKT != thumbprint {
		if input.SubagentToken != "" {
			return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, errors.New("resource token does not match person server and sub-agent key")
		}
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, errors.New("resource token does not match person server and signing key")
	}
	metadata, err := client.personServerMetadata(ctx, input.PersonServer)
	if err != nil {
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, err
	}
	body, err := json.Marshal(struct {
		ResourceToken string   `json:"resource_token"`
		SubagentToken string   `json:"subagent_token,omitempty"`
		UpstreamToken string   `json:"upstream_token,omitempty"`
		Capabilities  []string `json:"capabilities,omitempty"`
	}{
		ResourceToken: input.ResourceToken, SubagentToken: input.SubagentToken,
		UpstreamToken: input.UpstreamToken, Capabilities: input.Capabilities,
	})
	if err != nil {
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, err
	}
	request, err := newJSONRequest(ctx, metadata.AuthTokenEndpoint, body)
	if err != nil {
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, err
	}
	request.Header.Set("Prefer", "wait=0")
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, aauth.ResourceTokenClaims{}, personServerCredential{}, err
	}
	return response, resourceClaims, credential, nil
}

func (client *Client) verifiedExchangeResponse(
	ctx context.Context,
	response *http.Response,
	resourceClaims aauth.ResourceTokenClaims,
	credential personServerCredential,
) (string, error) {
	var output struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}
	if err := decodeJSONResponse(response, &output); err != nil {
		return "", err
	}
	if output.AuthToken == "" {
		return "", errors.New("response did not contain an auth token")
	}
	if _, err := client.verifyAuthTokenForResourceBinding(
		ctx, output.AuthToken, resourceClaims, credential,
	); err != nil {
		return "", err
	}
	return output.AuthToken, nil
}

func (client *Client) pendingExchangeResponse(
	response *http.Response,
	personServer string,
	resourceToken string,
	resourceClaims aauth.ResourceTokenClaims,
	prior PendingExchange,
) (PendingExchange, error) {
	location, err := parsePendingLocation(response)
	if err != nil {
		return PendingExchange{}, err
	}
	retryAfter, err := parseRetryAfter(response.Header.Values("Retry-After"))
	if err != nil {
		return PendingExchange{}, err
	}
	if !hasNoStore(response.Header.Values("Cache-Control")) {
		return PendingExchange{}, errors.New("pending response Cache-Control must contain no-store")
	}
	if len(response.Header.Values("Content-Type")) != 1 {
		return PendingExchange{}, errors.New("pending response requires exactly one Content-Type")
	}
	var encodedBody json.RawMessage
	if err := decodeJSONResponse(response, &encodedBody); err != nil {
		return PendingExchange{}, err
	}
	var commonBody struct {
		Status string `json:"status"`
	}
	if err := decodePendingExchangeBody(encodedBody, &commonBody); err != nil {
		return PendingExchange{}, err
	}
	if strings.TrimSpace(commonBody.Status) == "" {
		return PendingExchange{}, errors.New("pending response status is required")
	}
	requirementValues := response.Header.Values("AAuth-Requirement")
	requirement := prior.requirement
	interactionURL := prior.interactionURL
	interactionCode := prior.interactionCode
	if len(requirementValues) > 0 {
		requirement, err = aauth.ParseRequirement(requirementValues)
		if err != nil {
			return PendingExchange{}, err
		}
		if requirement == aauth.RequirementInteraction {
			interaction, err := aauth.ParseInteractionRequirement(requirementValues)
			if err != nil {
				return PendingExchange{}, err
			}
			if prior.requirement == aauth.RequirementInteraction {
				if interaction.URL != interactionURL || !aauth.MatchInteractionCode(interactionCode, interaction.Code) {
					return PendingExchange{}, errors.New("pending exchange interaction changed while polling")
				}
			} else {
				interactionURL = interaction.URL
				interactionCode = interaction.Code
			}
		} else {
			interactionURL = ""
			interactionCode = ""
		}
	}
	if requirement == aauth.RequirementInteraction && prior.kind != 0 && !prior.interactionCapable {
		return PendingExchange{}, errors.New("pending interaction requires the declared interaction capability")
	}
	if requirement == aauth.RequirementClarification {
		var body struct {
			Clarification json.RawMessage `json:"clarification"`
			Timeout       json.RawMessage `json:"timeout"`
			Options       json.RawMessage `json:"options"`
		}
		if err := decodePendingExchangeBody(encodedBody, &body); err != nil {
			return PendingExchange{}, err
		}
		var clarification string
		if len(body.Clarification) == 0 || string(body.Clarification) == "null" ||
			json.Unmarshal(body.Clarification, &clarification) != nil || strings.TrimSpace(clarification) == "" {
			return PendingExchange{}, errors.New("pending clarification is required and must be a string")
		}
		if len(body.Timeout) > 0 {
			var timeout int64
			if string(body.Timeout) == "null" || json.Unmarshal(body.Timeout, &timeout) != nil {
				return PendingExchange{}, errors.New("pending clarification timeout must be an integer")
			}
			if timeout < 0 {
				return PendingExchange{}, errors.New("pending clarification timeout must be nonnegative")
			}
		}
		if len(body.Options) > 0 {
			var options []string
			if string(body.Options) == "null" || json.Unmarshal(body.Options, &options) != nil {
				return PendingExchange{}, errors.New("pending clarification options must be a string array")
			}
		}
	}
	if requirement == aauth.RequirementClaims {
		var body struct {
			RequiredClaims json.RawMessage `json:"required_claims"`
		}
		if err := decodePendingExchangeBody(encodedBody, &body); err != nil {
			return PendingExchange{}, err
		}
		var requiredClaims []string
		if len(body.RequiredClaims) == 0 || string(body.RequiredClaims) == "null" ||
			json.Unmarshal(body.RequiredClaims, &requiredClaims) != nil || len(requiredClaims) == 0 {
			return PendingExchange{}, errors.New("pending required_claims must not be empty")
		}
		for _, claim := range requiredClaims {
			if strings.TrimSpace(claim) == "" {
				return PendingExchange{}, errors.New("pending required_claims contains an empty value")
			}
		}
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return PendingExchange{}, err
	}
	claims := resourceClaims
	return PendingExchange{
		kind: pendingExchangeVerified, personServer: personServer,
		location: location, retryAfter: retryAfter, interactionURL: interactionURL,
		interactionCode: interactionCode, interacting: prior.interacting || commonBody.Status == "interacting",
		requirement: requirement, interactionCapable: prior.interactionCapable,
		resourceToken: resourceToken, resourceClaims: &claims,
		agentProvider: client.agentClaims.Issuer, agent: client.identifier, agentJKT: thumbprint,
	}, nil
}

func decodePendingExchangeBody(encoded json.RawMessage, destination any) error {
	if err := jsonstrict.RejectCaseVariants(encoded, destination); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if err := json.Unmarshal(encoded, destination); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
