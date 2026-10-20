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

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/internal/r3dispatch"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type exchangeResultKind uint8

type verifiedExchangeResource struct {
	claims      aauth.ResourceTokenClaims
	r3Reference *r3.Reference
	budget      *budgets.Value
}

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
	case "", aauth.RequirementApproval, aauth.RequirementInteraction, aauth.RequirementClarification:
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
	kind                 pendingExchangeKind
	personServer         string
	location             string
	origin               string
	retryAfter           time.Duration
	waitReason           string
	interactionURL       string
	interactionCode      string
	interacting          bool
	requirement          aauth.Requirement
	interactionCapable   bool
	clarification        ClarificationQuestion
	clarificationCapable bool
	resourceToken        string
	resourceClaims       *aauth.ResourceTokenClaims
	agentProvider        string
	agent                string
	agentJKT             string
	tokenKey             jose.JWK
	tokenExpiresAt       int64
	tokenExpirySource    string
	parentMediated       bool
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

// WaitReason returns the optional pending_reason display hint supplied by the
// PS: "awaiting_payment", "awaiting_approval", or empty when absent or unknown.
// This library extension is not a protocol requirement or authority to pay.
// A caller may translate it for the person; payment details remain with the PS.
func (pending PendingExchange) WaitReason() string {
	if pending.kind != pendingExchangeVerified {
		return ""
	}
	return pending.waitReason
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
// Initial payment responses are not implemented.
func (client *Client) BeginExchange(ctx context.Context, input ExchangeRequest) (ExchangeResult, error) {
	const operation = "begin exchange"
	if client == nil {
		return ExchangeResult{}, fail(operation, errors.New("client is required"))
	}
	response, verifiedResource, credential, err := client.exchangeRequest(ctx, input)
	if err != nil {
		return ExchangeResult{}, fail(operation, err)
	}
	switch response.StatusCode {
	case http.StatusOK:
		defer response.Body.Close()
		token, err := client.verifiedExchangeResponse(ctx, response, verifiedResource, credential)
		if err != nil {
			return ExchangeResult{}, fail(operation, err)
		}
		return ExchangeResult{kind: exchangeResultToken, token: token}, nil
	case http.StatusAccepted:
		defer response.Body.Close()
		if verifiedResource.r3Reference != nil {
			return ExchangeResult{}, fail(operation, errors.New("R3 exchange interaction is not implemented"))
		}
		if verifiedResource.budget != nil {
			return ExchangeResult{}, fail(operation, errors.New("Budget exchange interaction is not implemented"))
		}
		resourceClaims := verifiedResource.claims
		if input.UpstreamToken != "" {
			return ExchangeResult{}, fail(operation, &CallChainingInteractionUnsupportedError{Operation: "auth-token exchange"})
		}
		pending, err := client.pendingExchangeResponse(
			response, input.PersonServer, input.ResourceToken, resourceClaims, PendingExchange{}, credential,
		)
		if err != nil {
			return ExchangeResult{}, fail(operation, err)
		}
		missionCapabilityFallback := resourceClaims.MissionS256 != "" && input.Capabilities == nil
		pending.interactionCapable = missionCapabilityFallback || slices.Contains(input.Capabilities, "interaction")
		pending.clarificationCapable = missionCapabilityFallback || slices.Contains(input.Capabilities, "clarification")
		if err := validatePendingExchangeRequirement(pending); err != nil {
			return ExchangeResult{}, fail(operation, err)
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
// verified pending exchange. A typed 410 response is terminal and
// MUST NOT be retried.
func (client *Client) PollExchange(ctx context.Context, pending PendingExchange) (ExchangeResult, error) {
	const operation = "poll exchange"
	if client == nil {
		return ExchangeResult{}, fail(operation, errors.New("client is required"))
	}
	if err := client.validatePendingExchange(ctx, pending); err != nil {
		return ExchangeResult{}, fail(operation, err)
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
			personServerCredential{
				requestKey: pending.tokenKey, expiresAt: pending.tokenExpiresAt, expirySource: pending.tokenExpirySource,
				parentMediated: pending.parentMediated,
			},
		)
		if err != nil {
			return ExchangeResult{}, fail(operation, err)
		}
		return pendingExchangeResult(next), nil
	case http.StatusOK:
		token, err := client.verifiedExchangeResponse(
			ctx,
			response,
			verifiedExchangeResource{claims: *pending.resourceClaims},
			personServerCredential{
				requestKey: pending.tokenKey, expiresAt: pending.tokenExpiresAt,
				expirySource: pending.tokenExpirySource, parentMediated: pending.parentMediated,
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

func (client *Client) validatePendingExchange(ctx context.Context, pending PendingExchange) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := client.requireDirectPersonServerCaller(); err != nil {
		return err
	}
	if pending.kind != pendingExchangeVerified || pending.personServer == "" || pending.location == "" ||
		pending.resourceToken == "" || pending.resourceClaims == nil || pending.agentProvider == "" ||
		pending.agent == "" || pending.agentJKT == "" || pending.tokenExpiresAt <= 0 || pending.tokenExpirySource == "" {
		return errors.New("verified pending exchange for this client is required")
	}
	if err := validatePendingExchangeLocation(pending); err != nil {
		return err
	}
	if err := validatePendingExchangeRequirement(pending); err != nil {
		return err
	}
	if pending.agentProvider != client.agentClaims.Issuer || pending.personServer != client.agentClaims.PersonServer ||
		pending.agent != client.identifier {
		return errors.New("pending exchange does not match client identity")
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return err
	}
	if thumbprint != pending.agentJKT {
		return errors.New("pending exchange does not match client key")
	}
	tokenJKT, err := pending.tokenKey.Thumbprint()
	if err != nil {
		return errors.New("pending exchange credential key is invalid")
	}
	if pending.resourceClaims.PersonServer != pending.personServer || pending.resourceClaims.AgentJKT != tokenJKT {
		return errors.New("pending exchange resource-token context does not match client")
	}
	return nil
}

func (client *Client) exchangeRequest(
	ctx context.Context,
	input ExchangeRequest,
) (*http.Response, verifiedExchangeResource, personServerCredential, error) {
	if ctx == nil {
		return nil, verifiedExchangeResource{}, personServerCredential{}, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, verifiedExchangeResource{}, personServerCredential{}, err
	}
	if len(input.Capabilities) > 0 {
		if _, err := aauth.FormatCapabilities(input.Capabilities); err != nil {
			return nil, verifiedExchangeResource{}, personServerCredential{}, fmt.Errorf("capabilities: %w", err)
		}
	}
	credential, err := client.personServerRequestBinding(
		ctx, input.PersonServer, input.SubagentToken, input.UpstreamToken,
	)
	if err != nil {
		return nil, verifiedExchangeResource{}, personServerCredential{}, err
	}
	input.PersonServer = credential.personServer
	if input.ResourceToken == "" {
		return nil, verifiedExchangeResource{}, personServerCredential{}, errors.New("resource token is required")
	}
	carriesR3, err := r3dispatch.TokenCarriesClaims(input.ResourceToken)
	if err != nil {
		return nil, verifiedExchangeResource{}, personServerCredential{}, err
	}
	carriesBudget, err := budgets.TokenCarriesClaims(input.ResourceToken)
	if err != nil {
		return nil, verifiedExchangeResource{}, personServerCredential{}, err
	}
	if carriesR3 && carriesBudget {
		if client.r3 == nil {
			return nil, verifiedExchangeResource{}, personServerCredential{}, errors.New("R3 is not configured")
		}
		claims, reference, budget, _, err := r3.VerifyBudgetResourceToken(
			ctx, client.r3.Registry, input.ResourceToken, client.keyResolver, client.clock,
		)
		if err != nil {
			return nil, verifiedExchangeResource{}, personServerCredential{}, err
		}
		verifiedResource := verifiedExchangeResource{claims: claims, r3Reference: &reference, budget: &budget}
		if !slices.Contains(input.Capabilities, "budget") {
			input.Capabilities = append(append([]string(nil), input.Capabilities...), "budget")
		}
		return client.finishExchangeRequest(ctx, input, credential, verifiedResource)
	}
	verifiedResource := verifiedExchangeResource{}
	if carriesR3 {
		if client.r3 == nil {
			return nil, verifiedExchangeResource{}, personServerCredential{}, errors.New("R3 is not configured")
		}
		claims, reference, err := r3.VerifyResourceToken(ctx, input.ResourceToken, client.keyResolver, client.clock)
		if err != nil {
			return nil, verifiedExchangeResource{}, personServerCredential{}, err
		}
		verifiedResource.claims = claims
		verifiedResource.r3Reference = &reference
	} else if carriesBudget {
		claims, budget, _, err := budgets.VerifyResourceToken(ctx, input.ResourceToken, client.keyResolver, client.clock)
		if err != nil {
			return nil, verifiedExchangeResource{}, personServerCredential{}, err
		}
		verifiedResource.claims = claims
		verifiedResource.budget = &budget
		if !slices.Contains(input.Capabilities, "budget") {
			input.Capabilities = append(append([]string(nil), input.Capabilities...), "budget")
		}
		if _, err := aauth.FormatCapabilities(input.Capabilities); err != nil {
			return nil, verifiedExchangeResource{}, personServerCredential{}, fmt.Errorf("capabilities: %w", err)
		}
	} else {
		claims, err := aauth.VerifyResourceToken(ctx, input.ResourceToken, client.keyResolver, client.clock)
		if err != nil {
			return nil, verifiedExchangeResource{}, personServerCredential{}, err
		}
		verifiedResource.claims = claims
	}
	return client.finishExchangeRequest(ctx, input, credential, verifiedResource)
}

func (client *Client) finishExchangeRequest(
	ctx context.Context,
	input ExchangeRequest,
	credential personServerCredential,
	verifiedResource verifiedExchangeResource,
) (*http.Response, verifiedExchangeResource, personServerCredential, error) {
	resourceClaims := verifiedResource.claims
	if verifiedResource.budget != nil &&
		(input.SubagentToken != "" || input.UpstreamToken != "") {
		return nil, verifiedExchangeResource{}, personServerCredential{}, errors.New("delegated or call-chain Budget exchange is not implemented")
	}
	if resourceClaims.MissionS256 != "" && (input.SubagentToken != "" || input.UpstreamToken != "") {
		return nil, verifiedExchangeResource{}, personServerCredential{}, errors.New("mission-bound delegated or call-chain authorization is not supported")
	}
	if resourceClaims.Interaction != nil {
		return nil, verifiedExchangeResource{}, personServerCredential{}, errors.New("resource-token interaction requires the deferred flow")
	}
	thumbprint, err := credential.requestKey.Thumbprint()
	if err != nil {
		return nil, verifiedExchangeResource{}, personServerCredential{}, err
	}
	if resourceClaims.PersonServer != input.PersonServer || resourceClaims.AgentJKT != thumbprint {
		if input.SubagentToken != "" {
			return nil, verifiedExchangeResource{}, personServerCredential{}, errors.New("resource token does not match person server and sub-agent key")
		}
		return nil, verifiedExchangeResource{}, personServerCredential{}, errors.New("resource token does not match person server and signing key")
	}
	if input.PresentedToken == "" {
		return nil, verifiedExchangeResource{}, personServerCredential{}, errors.New("presented token is required")
	}
	if _, err := aauth.VerifyPresentedToken(
		ctx, input.PresentedToken, resourceClaims, client.keyResolver, client.clock,
	); err != nil {
		return nil, verifiedExchangeResource{}, personServerCredential{}, err
	}
	metadata, err := client.personServerMetadata(ctx, input.PersonServer)
	if err != nil {
		return nil, verifiedExchangeResource{}, personServerCredential{}, err
	}
	var capabilities *[]string
	if input.Capabilities != nil {
		values := make([]string, len(input.Capabilities))
		copy(values, input.Capabilities)
		capabilities = &values
	}
	body, err := json.Marshal(struct {
		ResourceToken  string    `json:"resource_token"`
		PresentedToken string    `json:"presented_token"`
		SubagentToken  string    `json:"subagent_token,omitempty"`
		UpstreamToken  string    `json:"upstream_token,omitempty"`
		Capabilities   *[]string `json:"capabilities,omitempty"`
	}{
		ResourceToken: input.ResourceToken, PresentedToken: input.PresentedToken,
		SubagentToken: input.SubagentToken, UpstreamToken: input.UpstreamToken, Capabilities: capabilities,
	})
	if err != nil {
		return nil, verifiedExchangeResource{}, personServerCredential{}, err
	}
	request, err := newJSONRequest(ctx, metadata.AuthTokenEndpoint, body)
	if err != nil {
		return nil, verifiedExchangeResource{}, personServerCredential{}, err
	}
	request.Header.Set("Prefer", "wait=0")
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return nil, verifiedExchangeResource{}, personServerCredential{}, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, verifiedExchangeResource{}, personServerCredential{}, err
	}
	return response, verifiedResource, credential, nil
}

func (client *Client) verifiedExchangeResponse(
	ctx context.Context,
	response *http.Response,
	resource verifiedExchangeResource,
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
	var err error
	if resource.r3Reference != nil && resource.budget != nil {
		claims, authReference, _, granted, verifyErr := r3.VerifyBudgetAuthToken(
			ctx, client.r3.Registry, output.AuthToken, client.keyResolver, client.clock,
		)
		if verifyErr != nil {
			err = verifyErr
		} else if authReference != *resource.r3Reference {
			err = errors.New("auth token changed the R3 document reference")
		} else if _, validateErr := client.validateR3AuthTokenForResourceBinding(
			claims, resource.claims, authReference, credential,
		); validateErr != nil {
			err = validateErr
		} else if narrowErr := budgets.ValidateNarrowing(*resource.budget, granted); narrowErr != nil {
			err = fmt.Errorf("auth-token Budget did not narrow the Resource offer: %w", narrowErr)
		}
	} else if resource.r3Reference != nil {
		_, err = client.verifyR3AuthTokenForResourceBinding(
			ctx, output.AuthToken, resource.claims, *resource.r3Reference, credential,
		)
	} else if resource.budget != nil {
		claims, granted, verifyErr := budgets.VerifyAuthToken(
			ctx, output.AuthToken, client.keyResolver, client.clock,
		)
		if verifyErr != nil {
			err = verifyErr
		} else if validateErr := client.validateAuthTokenForResourceBinding(
			claims, resource.claims, credential,
		); validateErr != nil {
			err = validateErr
		} else if narrowErr := budgets.ValidateNarrowing(*resource.budget, granted); narrowErr != nil {
			err = fmt.Errorf("auth-token Budget did not narrow the Resource offer: %w", narrowErr)
		}
	} else {
		_, err = client.verifyAuthTokenForResourceBinding(ctx, output.AuthToken, resource.claims, credential)
	}
	if err != nil {
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
	credential personServerCredential,
) (PendingExchange, error) {
	observedAt := client.clock.Now()
	location, err := parsePendingLocation(response)
	if err != nil {
		return PendingExchange{}, err
	}
	if prior.kind != 0 && location != prior.location {
		return PendingExchange{}, errors.New("pending exchange Location changed while polling")
	}
	origin, err := httpOrigin(response.Request.URL)
	if err != nil {
		return PendingExchange{}, errors.New("pending response request origin is invalid")
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
		Status        string `json:"status"`
		PendingReason string `json:"pending_reason"`
	}
	if err := decodePendingExchangeBody(encodedBody, &commonBody); err != nil {
		return PendingExchange{}, err
	}
	if strings.TrimSpace(commonBody.Status) == "" {
		return PendingExchange{}, errors.New("pending response status is required")
	}
	waitReason := ""
	switch commonBody.PendingReason {
	case "awaiting_payment", "awaiting_approval":
		waitReason = commonBody.PendingReason
	}
	requirementValues := response.Header.Values("AAuth-Requirement")
	var requirement aauth.Requirement
	var interactionURL string
	var interactionCode string
	var clarification ClarificationQuestion
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
			interactionURL = interaction.URL
			interactionCode = interaction.Code
		}
	}
	if requirement == aauth.RequirementInteraction && prior.kind != 0 && !prior.interactionCapable {
		return PendingExchange{}, errors.New("pending interaction requires the declared interaction capability")
	}
	if requirement == aauth.RequirementClarification && prior.kind != 0 && !prior.clarificationCapable {
		return PendingExchange{}, errors.New("pending clarification requires the declared clarification capability")
	}
	if requirement == aauth.RequirementClarification {
		clarification, err = client.parseClarification(encodedBody, observedAt)
		if err != nil {
			return PendingExchange{}, err
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
	tokenKey := credential.requestKey
	tokenExpiresAt := credential.expiresAt
	tokenExpirySource := credential.expirySource
	parentMediated := credential.parentMediated
	if prior.kind != 0 {
		tokenKey = prior.tokenKey
		tokenExpiresAt = prior.tokenExpiresAt
		tokenExpirySource = prior.tokenExpirySource
		parentMediated = prior.parentMediated
	}
	if _, err := tokenKey.PublicKey(); err != nil || tokenExpiresAt <= 0 || tokenExpirySource == "" {
		return PendingExchange{}, errors.New("pending exchange credential binding is invalid")
	}
	claims := resourceClaims
	return PendingExchange{
		kind: pendingExchangeVerified, personServer: personServer,
		location: location, origin: origin, retryAfter: retryAfter, waitReason: waitReason, interactionURL: interactionURL,
		interactionCode: interactionCode, interacting: prior.interacting || commonBody.Status == "interacting",
		requirement: requirement, interactionCapable: prior.interactionCapable,
		clarification: clarification, clarificationCapable: prior.clarificationCapable,
		resourceToken: resourceToken, resourceClaims: &claims,
		agentProvider: client.agentClaims.Issuer, agent: client.identifier, agentJKT: thumbprint,
		tokenKey: tokenKey, tokenExpiresAt: tokenExpiresAt, tokenExpirySource: tokenExpirySource,
		parentMediated: parentMediated,
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
