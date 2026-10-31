package agent

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/internal/r3dispatch"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// InitialCall supplies one exact application request and the person token
// required for an auth-token Resource's initial call.
type InitialCall struct {
	Request     *http.Request
	PersonToken string
}

// Call supplies one exact protected HTTP request and its auth token.
// UpstreamToken is local call-chain context and is never sent to the Resource.
type Call struct {
	Request       *http.Request
	AuthToken     string
	UpstreamToken string
}

// AuthTokenPoll supplies one verified held invocation and the auth token that
// completes it.
type AuthTokenPoll struct {
	Pending   PendingAuthTokenCall
	AuthToken string
}

type callResultKind uint8

type pendingAuthTokenCallKind uint8

const (
	callResultResponse callResultKind = iota + 1
	callResultAuthorizationRequired
	callResultPendingAuthToken
)

const pendingAuthTokenCallVerified pendingAuthTokenCallKind = 1

// PendingAuthTokenCall is a verified Resource-held invocation waiting for an
// auth token. Its fields are private so only Begin can construct a pollable
// value.
type PendingAuthTokenCall struct {
	kind           pendingAuthTokenCallKind
	resourceToken  string
	location       string
	retryAfter     time.Duration
	resourceClaims aauth.ResourceTokenClaims
}

// ResourceToken returns the verified resource token carried by the pending
// auth-token requirement.
func (pending PendingAuthTokenCall) ResourceToken() string {
	if pending.kind != pendingAuthTokenCallVerified {
		return ""
	}
	return pending.resourceToken
}

// Location returns the trusted same-origin URL for the held invocation.
func (pending PendingAuthTokenCall) Location() string {
	if pending.kind != pendingAuthTokenCallVerified {
		return ""
	}
	return pending.location
}

// RetryAfter returns the server's requested delay before polling.
func (pending PendingAuthTokenCall) RetryAfter() time.Duration {
	if pending.kind != pendingAuthTokenCallVerified {
		return 0
	}
	return pending.retryAfter
}

// CallResult is either one ordinary application response, one verified
// baseline auth-token requirement, or one verified pending auth-token call.
type CallResult struct {
	kind        callResultKind
	response    *http.Response
	requirement aauth.AuthTokenRequirement
	pending     PendingAuthTokenCall
}

// Response returns the ordinary application response, when that was the
// result of the call. The caller owns its body.
func (result CallResult) Response() (*http.Response, bool) {
	if result.kind != callResultResponse || result.response == nil {
		return nil, false
	}
	return result.response, true
}

// AuthorizationRequired returns the verified auth-token requirement, when
// the Resource required authorization.
func (result CallResult) AuthorizationRequired() (aauth.AuthTokenRequirement, bool) {
	if result.kind != callResultAuthorizationRequired || result.requirement.ResourceToken == "" {
		return aauth.AuthTokenRequirement{}, false
	}
	return result.requirement, true
}

// PendingAuthToken returns the verified Resource-held invocation, when that
// was the result of the call.
func (result CallResult) PendingAuthToken() (PendingAuthTokenCall, bool) {
	if result.kind != callResultPendingAuthToken || result.pending.kind != pendingAuthTokenCallVerified {
		return PendingAuthTokenCall{}, false
	}
	return result.pending, true
}

// CallAsAgent discovers the Resource's additional signature components, then
// signs and performs one application request with the configured agent token.
// It does not retry a requirement or interpret an ordinary application
// response. If the token names no Person Server and the Resource returns a
// valid person-token requirement, the method closes that unsatisfiable
// response and returns an error.
func (client *Client) CallAsAgent(ctx context.Context, original *http.Request) (*http.Response, error) {
	return client.callAsAgent(ctx, original, nil, true)
}

// CallAsAgentWithComponents signs and performs one application request using
// the exact additional signature components supplied by the caller. It does
// not fetch Resource metadata, so it also works with a metadata-less Resource.
// It applies the same unsatisfiable person-token requirement rule as
// CallAsAgent.
func (client *Client) CallAsAgentWithComponents(
	ctx context.Context,
	original *http.Request,
	additionalSignatureComponents []string,
) (*http.Response, error) {
	return client.callAsAgent(ctx, original, additionalSignatureComponents, false)
}

func (client *Client) callAsAgent(
	ctx context.Context,
	original *http.Request,
	additionalSignatureComponents []string,
	discoverComponents bool,
) (*http.Response, error) {
	const operation = "call as agent"
	if client == nil {
		return nil, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return nil, fail(operation, errors.New("context is required"))
	}
	if original == nil || original.URL == nil {
		return nil, fail(operation, errors.New("request is required"))
	}
	claims, err := aauth.VerifyAgentToken(ctx, client.agentToken, client.keyResolver, client.clock)
	if err != nil {
		return nil, fail(operation, err)
	}
	if claims.Subject != client.identifier || claims.ParentAgent != client.agentClaims.ParentAgent ||
		claims.PersonServer != client.agentClaims.PersonServer ||
		!claims.Confirmation.JWK.Equal(client.signingKey.PublicJWK()) {
		return nil, fail(operation, errors.New("configured agent-token context changed"))
	}
	resource, err := requestOrigin(original.URL)
	if err != nil {
		return nil, fail(operation, err)
	}
	components := append([]string(nil), additionalSignatureComponents...)
	if discoverComponents {
		metadata, err := client.resourceMetadata(ctx, resource)
		if err != nil {
			return nil, fail(operation, err)
		}
		components = metadata.AdditionalSignatureComponents
	}
	request, err := cloneInitialRequest(ctx, original)
	if err != nil {
		return nil, fail(operation, err)
	}
	sent := false
	if request.Body != nil && request.Body != http.NoBody {
		defer func() {
			if !sent {
				_ = request.Body.Close()
			}
		}()
	}
	if err := client.signResourceRequest(request, client.agentToken, components); err != nil {
		return nil, fail(operation, err)
	}
	sent = true
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fail(operation, err)
	}
	if response.StatusCode == http.StatusUnauthorized && response.Header.Get("Signature-Error") != "" {
		response.Body.Close()
		return nil, fail(operation, responseFailure(response))
	}
	if response.StatusCode == http.StatusUnauthorized && client.agentClaims.PersonServer == "" {
		values := response.Header.Values("AAuth-Requirement")
		if len(values) > 0 && aauth.ParsePersonTokenRequirement(values) == nil {
			response.Body.Close()
			return nil, fail(operation, errors.New(
				"resource returned an unsatisfiable person-token requirement: agent token does not name a person server",
			))
		}
	}
	if isProblemResponse(response) {
		problem, isAAuth, err := inspectAAuthProblem(response)
		if err != nil {
			response.Body.Close()
			return nil, fail(operation, err)
		}
		if isAAuth {
			response.Body.Close()
			return nil, fail(operation, problem)
		}
	}
	return response, nil
}

// Begin verifies a person token, signs one cloned application request, and
// returns an ordinary response, a baseline auth-token requirement, or a
// verified pending auth-token call.
// It does not exchange a token, retry, sleep, or poll.
func (client *Client) Begin(ctx context.Context, input InitialCall) (CallResult, error) {
	const operation = "begin"
	if client == nil {
		return CallResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return CallResult{}, fail(operation, errors.New("context is required"))
	}
	if input.Request == nil || input.Request.URL == nil {
		return CallResult{}, fail(operation, errors.New("request is required"))
	}
	if input.PersonToken == "" {
		return CallResult{}, fail(operation, errors.New("person token is required"))
	}
	resource, err := requestOrigin(input.Request.URL)
	if err != nil {
		return CallResult{}, fail(operation, err)
	}
	person, err := aauth.VerifyPersonToken(ctx, input.PersonToken, client.keyResolver, client.clock)
	if err != nil {
		return CallResult{}, fail(operation, err)
	}
	if !client.acceptsPersonServer(person.Issuer) {
		return CallResult{}, fail(operation, errors.New("person-token issuer does not match agent person server"))
	}
	if person.MissionS256 != "" {
		return CallResult{}, fail(operation, errors.New("mission-bound person tokens require the mission flow"))
	}
	if err := aauth.ValidatePersonTokenContext(person, resource, client.signingKey.PublicJWK()); err != nil {
		return CallResult{}, fail(operation, err)
	}
	if person.ExpiresAt > client.agentClaims.ExpiresAt {
		return CallResult{}, fail(operation, errors.New("person-token lifetime exceeds agent token"))
	}
	request, err := cloneInitialRequest(ctx, input.Request)
	if err != nil {
		return CallResult{}, fail(operation, err)
	}
	sent := false
	if request.Body != nil && request.Body != http.NoBody {
		defer func() {
			if !sent {
				_ = request.Body.Close()
			}
		}()
	}
	metadata, err := client.resourceMetadata(ctx, resource)
	if err != nil {
		return CallResult{}, fail(operation, err)
	}
	if err := client.signResourceRequest(request, input.PersonToken, metadata.AdditionalSignatureComponents); err != nil {
		return CallResult{}, fail(operation, err)
	}
	sent = true
	response, err := client.httpClient.Do(request)
	if err != nil {
		return CallResult{}, fail(operation, err)
	}
	if response.StatusCode == http.StatusUnauthorized && response.Header.Get("Signature-Error") != "" {
		response.Body.Close()
		return CallResult{}, fail(operation, responseFailure(response))
	}
	if response.StatusCode == http.StatusUnauthorized {
		values := response.Header.Values("AAuth-Requirement")
		if len(values) > 0 {
			requirement, err := aauth.ParseAuthTokenRequirement(values)
			if err != nil {
				response.Body.Close()
				return CallResult{}, fail(operation, err)
			}
			_, err = client.verifyResourceTokenContext(ctx, requirement.ResourceToken, resource, person, nil, nil)
			response.Body.Close()
			if err != nil {
				return CallResult{}, fail(operation, err)
			}
			return CallResult{kind: callResultAuthorizationRequired, requirement: requirement}, nil
		}
	}
	if response.StatusCode == http.StatusAccepted {
		defer response.Body.Close()
		pending, err := client.pendingAuthTokenCall(ctx, response, resource, person)
		if err != nil {
			return CallResult{}, fail(operation, err)
		}
		return CallResult{kind: callResultPendingAuthToken, pending: pending}, nil
	}
	if isProblemResponse(response) {
		problem, isAAuth, err := inspectAAuthProblem(response)
		if err != nil {
			response.Body.Close()
			return CallResult{}, fail(operation, err)
		}
		if isAAuth {
			response.Body.Close()
			return CallResult{}, fail(operation, problem)
		}
	}
	return CallResult{kind: callResultResponse, response: response}, nil
}

func (client *Client) pendingAuthTokenCall(
	ctx context.Context,
	response *http.Response,
	resource string,
	person aauth.PersonTokenClaims,
) (PendingAuthTokenCall, error) {
	location, err := parsePendingLocation(response)
	if err != nil {
		return PendingAuthTokenCall{}, err
	}
	retryAfter, err := parseRetryAfter(response.Header.Values("Retry-After"))
	if err != nil {
		return PendingAuthTokenCall{}, err
	}
	if !hasNoStore(response.Header.Values("Cache-Control")) {
		return PendingAuthTokenCall{}, errors.New("pending response Cache-Control must contain no-store")
	}
	if len(response.Header.Values("Content-Type")) != 1 {
		return PendingAuthTokenCall{}, errors.New("pending response requires exactly one Content-Type")
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decodeJSONResponse(response, &body); err != nil {
		return PendingAuthTokenCall{}, err
	}
	if body.Status == "" {
		return PendingAuthTokenCall{}, errors.New("pending response status is required")
	}
	requirementValues := response.Header.Values("AAuth-Requirement")
	if len(requirementValues) != 1 {
		return PendingAuthTokenCall{}, errors.New("pending response requires exactly one AAuth-Requirement")
	}
	requirement, err := aauth.ParseAuthTokenRequirement(requirementValues)
	if err != nil {
		return PendingAuthTokenCall{}, err
	}
	claims, err := client.verifyResourceTokenContext(ctx, requirement.ResourceToken, resource, person, nil, nil)
	if err != nil {
		return PendingAuthTokenCall{}, err
	}
	return PendingAuthTokenCall{
		kind:           pendingAuthTokenCallVerified,
		resourceToken:  requirement.ResourceToken,
		location:       location,
		retryAfter:     retryAfter,
		resourceClaims: claims,
	}, nil
}

func parsePendingLocation(response *http.Response) (string, error) {
	if response == nil || response.Request == nil || response.Request.URL == nil {
		return "", errors.New("pending response request URL is required")
	}
	values := response.Header.Values("Location")
	if len(values) != 1 || values[0] == "" {
		return "", errors.New("pending response requires exactly one Location")
	}
	reference, err := url.Parse(values[0])
	if err != nil {
		return "", errors.New("pending response Location is invalid")
	}
	if reference.User != nil || reference.Fragment != "" {
		return "", errors.New("pending response Location must not contain userinfo or a fragment")
	}
	respondingOrigin, err := httpOrigin(response.Request.URL)
	if err != nil {
		return "", errors.New("pending response request origin is invalid")
	}
	resolved := response.Request.URL.ResolveReference(reference)
	if resolved.User != nil || resolved.Fragment != "" {
		return "", errors.New("pending response Location must not contain userinfo or a fragment")
	}
	origin, err := httpOrigin(resolved)
	if err != nil || origin != respondingOrigin {
		return "", errors.New("pending response Location must be HTTPS and same-origin with the responding server")
	}
	return resolved.String(), nil
}

func httpOrigin(target *url.URL) (string, error) {
	if target == nil || !strings.EqualFold(target.Scheme, "https") || target.Hostname() == "" || target.User != nil {
		return "", errors.New("absolute HTTPS endpoint is required")
	}
	port := target.Port()
	if port == "" {
		port = "443"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("endpoint port is invalid")
	}
	return "https://" + net.JoinHostPort(strings.ToLower(target.Hostname()), strconv.Itoa(n)), nil
}

func parseHTTPRetryAfter(values []string, now time.Time) (time.Duration, error) {
	if len(values) == 0 {
		return 5 * time.Second, nil
	}
	if len(values) != 1 || values[0] == "" {
		return 0, errors.New("response requires exactly one Retry-After")
	}
	if delay, err := parseRetryAfter(values); err == nil {
		return delay, nil
	}
	date, err := http.ParseTime(values[0])
	if err != nil {
		return 0, errors.New("response Retry-After must be delay-seconds or HTTP-date")
	}
	if !date.After(now) {
		return 0, nil
	}
	return date.Sub(now), nil
}

func parseRetryAfter(values []string) (time.Duration, error) {
	if len(values) == 0 {
		return 5 * time.Second, nil
	}
	if len(values) != 1 || values[0] == "" {
		return 0, errors.New("pending response requires exactly one Retry-After")
	}
	for _, character := range values[0] {
		if character < '0' || character > '9' {
			return 0, errors.New("pending response Retry-After must be nonnegative decimal seconds")
		}
	}
	seconds, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil || seconds > uint64(math.MaxInt64/int64(time.Second)) {
		return 0, errors.New("pending response Retry-After duration overflows")
	}
	return time.Duration(seconds) * time.Second, nil
}

// retryPollInterval returns the polling interval that follows a 429 or 503
// answer to a poll. A 429 increases the current interval by five seconds, or
// to the response's Retry-After when that is longer; a Retry-After that cannot
// be read does not stop the backoff. A 503 takes the response's Retry-After,
// or the five-second default when the header is absent. An HTTP-date is
// rounded up to whole seconds, so the interval never polls sooner than the
// server asked and remains representable in a snapshot.
func retryPollInterval(current time.Duration, response *http.Response, now time.Time) (time.Duration, error) {
	values := response.Header.Values("Retry-After")
	retryAfter, err := parseHTTPRetryAfter(values, now)
	if err == nil {
		retryAfter, err = roundUpToSecond(retryAfter)
	}
	if response.StatusCode != http.StatusTooManyRequests {
		return retryAfter, err
	}
	if current > time.Duration(math.MaxInt64)-5*time.Second {
		return 0, errors.New("poll retry interval overflows")
	}
	next := current + 5*time.Second
	if len(values) == 0 || err != nil {
		return next, nil
	}
	return max(next, retryAfter), nil
}

func roundUpToSecond(interval time.Duration) (time.Duration, error) {
	fraction := interval % time.Second
	if fraction == 0 {
		return interval, nil
	}
	if interval > time.Duration(math.MaxInt64)-time.Second {
		return 0, errors.New("poll retry interval overflows")
	}
	return interval + time.Second - fraction, nil
}

func hasNoStore(values []string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
				return true
			}
		}
	}
	return false
}

func cloneInitialRequest(ctx context.Context, original *http.Request) (*http.Request, error) {
	request := original.Clone(ctx)
	request.Header = original.Header.Clone()
	if original.URL != nil {
		clonedURL := *original.URL
		request.URL = &clonedURL
	}
	if original.Body == nil || original.Body == http.NoBody {
		request.Body = original.Body
		return request, nil
	}
	if original.GetBody == nil {
		return nil, errors.New("request body must be replayable")
	}
	body, err := original.GetBody()
	if err != nil {
		return nil, fmt.Errorf("copy request body: %w", err)
	}
	if body == nil {
		return nil, errors.New("copied request body is nil")
	}
	request.Body = body
	return request, nil
}

func (client *Client) verifyResourceTokenContext(
	ctx context.Context,
	compact string,
	resource string,
	person aauth.PersonTokenClaims,
	requestedScopes []string,
	expectedAccount *string,
) (aauth.ResourceTokenClaims, error) {
	carriesR3, err := r3dispatch.TokenCarriesClaims(compact)
	if err != nil {
		return aauth.ResourceTokenClaims{}, err
	}
	carriesBudget, err := budgets.TokenCarriesClaims(compact)
	if err != nil {
		return aauth.ResourceTokenClaims{}, err
	}
	if carriesR3 {
		return aauth.ResourceTokenClaims{}, errors.New("R3 first-call resource tokens are not supported by the Core Begin flow")
	}
	var claims aauth.ResourceTokenClaims
	if carriesBudget {
		claims, _, _, err = budgets.VerifyResourceToken(ctx, compact, client.keyResolver, client.clock)
	} else {
		claims, err = aauth.VerifyResourceToken(ctx, compact, client.keyResolver, client.clock)
	}
	if err != nil {
		return aauth.ResourceTokenClaims{}, err
	}
	if err := client.validateResourceTokenContext(claims, resource, person, requestedScopes, expectedAccount); err != nil {
		return aauth.ResourceTokenClaims{}, err
	}
	return claims, nil
}

func (client *Client) validateResourceTokenContext(
	claims aauth.ResourceTokenClaims,
	resource string,
	person aauth.PersonTokenClaims,
	requestedScopes []string,
	expectedAccount *string,
) error {
	if !equalStringPointers(claims.Account, expectedAccount) {
		return errors.New("resource-token account does not match the request")
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return err
	}
	if claims.Issuer != resource {
		return errors.New("resource-token issuer does not match resource")
	}
	if claims.PersonServer != person.Issuer {
		return errors.New("resource-token person server does not match person token")
	}
	if claims.Subject != person.Subject {
		return errors.New("resource-token subject does not match person token")
	}
	if claims.PresentedJTI != person.JTI {
		return errors.New("resource-token presented_jti does not match person token")
	}
	if claims.AgentJKT != thumbprint {
		return errors.New("resource-token agent_jkt does not match signing key")
	}
	if requestedScopes != nil && !scopeSubset(strings.Fields(claims.Scope), requestedScopes) {
		return errors.New("resource-token scope is empty, duplicated, or outside the request")
	}
	if claims.MissionS256 != person.MissionS256 || claims.Tenant != person.Tenant {
		return errors.New("resource-token context does not match person token")
	}
	if claims.IssuedAt < person.IssuedAt || claims.IssuedAt >= person.ExpiresAt ||
		(person.NotBefore != 0 && claims.IssuedAt < person.NotBefore) {
		return errors.New("resource token was issued outside the person-token validity window")
	}
	// A resource token's lifetime is independent of the mission it names; the
	// Person Server checks the mission when it acts on the token.
	return nil
}

// AuthTokenPollResult is the caller-owned response to one auth-token poll.
// When the Resource still holds the invocation (202 naming the same pending
// URL), asks the agent to slow down (429), or is temporarily unavailable
// (503), Pending also returns the held invocation with its next polling
// interval.
type AuthTokenPollResult struct {
	response *http.Response
	pending  PendingAuthTokenCall
}

// Response returns the poll response. The caller owns its body.
func (result AuthTokenPollResult) Response() (*http.Response, bool) {
	return result.response, result.response != nil
}

// Pending returns the held invocation to poll again, when the response did
// not end it. Its interval is the 202's Retry-After, or five seconds when
// absent; after a 429, five seconds more than before, or the 429's
// Retry-After when longer; after a 503, its Retry-After, or five seconds.
func (result AuthTokenPollResult) Pending() (PendingAuthTokenCall, bool) {
	if result.pending.kind != pendingAuthTokenCallVerified {
		return PendingAuthTokenCall{}, false
	}
	return result.pending, true
}

// PollAuthToken presents one locally verified auth token in one signed GET to
// the trusted pending URL. It does not sleep, retry, exchange, or resend the
// original invocation.
func (client *Client) PollAuthToken(ctx context.Context, input AuthTokenPoll) (AuthTokenPollResult, error) {
	const operation = "poll auth token"
	if client == nil {
		return AuthTokenPollResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return AuthTokenPollResult{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return AuthTokenPollResult{}, fail(operation, err)
	}
	if input.Pending.kind != pendingAuthTokenCallVerified {
		return AuthTokenPollResult{}, fail(operation, errors.New("pending auth-token call is required"))
	}
	if input.AuthToken == "" {
		return AuthTokenPollResult{}, fail(operation, errors.New("auth token is required"))
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return AuthTokenPollResult{}, fail(operation, err)
	}
	if input.Pending.resourceClaims.AgentJKT != thumbprint {
		return AuthTokenPollResult{}, fail(operation, errors.New("pending resource token does not match client signing key"))
	}
	authClaims, err := client.verifyAuthTokenForResource(ctx, input.AuthToken, input.Pending.resourceClaims)
	if err != nil {
		return AuthTokenPollResult{}, fail(operation, err)
	}
	if !sameScopeSet(strings.Fields(authClaims.Scope), strings.Fields(input.Pending.resourceClaims.Scope)) {
		return AuthTokenPollResult{}, fail(operation, errors.New("auth-token scope does not exactly match held resource-token scope"))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, input.Pending.location, nil)
	if err != nil {
		return AuthTokenPollResult{}, fail(operation, err)
	}
	if err := signaturekey.SignJWTRequestWithOptions(
		request,
		client.signingKey,
		input.AuthToken,
		client.clock,
		signaturekey.SignOptions{},
	); err != nil {
		return AuthTokenPollResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return AuthTokenPollResult{}, fail(operation, err)
	}
	if response.StatusCode == http.StatusUnauthorized && response.Header.Get("Signature-Error") != "" {
		response.Body.Close()
		return AuthTokenPollResult{}, fail(operation, authTokenResponseFailure(response))
	}
	if response.StatusCode == http.StatusAccepted || response.StatusCode == http.StatusTooManyRequests ||
		response.StatusCode == http.StatusServiceUnavailable {
		next := input.Pending
		interval, held, err := nextHeldPollInterval(input.Pending.location, input.Pending.retryAfter, response, client.clock.Now())
		if err != nil {
			response.Body.Close()
			return AuthTokenPollResult{}, fail(operation, err)
		}
		if !held {
			return AuthTokenPollResult{response: response}, nil
		}
		next.retryAfter = interval
		return AuthTokenPollResult{response: response, pending: next}, nil
	}
	if isProblemResponse(response) {
		problem, isAAuth, err := inspectAAuthProblem(response)
		if err != nil {
			response.Body.Close()
			return AuthTokenPollResult{}, fail(operation, err)
		}
		if isAAuth {
			response.Body.Close()
			return AuthTokenPollResult{}, fail(operation, problem)
		}
	}
	return AuthTokenPollResult{response: response}, nil
}

// nextHeldPollInterval returns the interval before the next poll of a
// Resource-held invocation: a 202's Retry-After or the five-second default,
// or the retry interval of a 429 or 503. A 202 that names another pending URL
// is the held application's own deferred result, not this invocation still
// pending, so it reports false and the caller continues that operation.
func nextHeldPollInterval(
	location string,
	current time.Duration,
	response *http.Response,
	now time.Time,
) (time.Duration, bool, error) {
	if response.StatusCode != http.StatusAccepted {
		interval, err := retryPollInterval(current, response, now)
		return interval, err == nil, err
	}
	if next, err := parsePendingLocation(response); err != nil || next != location {
		return 0, false, nil
	}
	interval, err := parseRetryAfter(response.Header.Values("Retry-After"))
	return interval, err == nil, err
}

// Do verifies an auth token for the exact request resource, signs that request,
// and performs one HTTP call. It does not interpret ordinary application
// responses, but preserves an AAuth problem response as a typed error.
// A revoked Auth token accompanied by a person-token requirement returns
// [PersonTokenRequiredError]; the caller must obtain a Person token and retry
// the original request with it to satisfy that requirement.
func (client *Client) Do(ctx context.Context, call Call) (*http.Response, error) {
	const operation = "do"
	if client == nil {
		return nil, fail(operation, errors.New("client is required"))
	}
	if call.Request == nil || call.Request.URL == nil {
		return nil, fail(operation, errors.New("request is required"))
	}
	if call.AuthToken == "" {
		return nil, fail(operation, errors.New("auth token is required"))
	}
	resource, err := requestOrigin(call.Request.URL)
	if err != nil {
		return nil, fail(operation, err)
	}
	carriesR3, err := r3dispatch.TokenCarriesClaims(call.AuthToken)
	if err != nil {
		return nil, fail(operation, err)
	}
	carriesBudget, err := budgets.TokenCarriesClaims(call.AuthToken)
	if err != nil {
		return nil, fail(operation, err)
	}
	if carriesR3 && carriesBudget {
		return nil, fail(operation, errors.New("R3 Budget Auth tokens require BeginBudgetCall so operation enforcement, metering feedback, and uncertain outcomes are preserved"))
	}
	if carriesBudget {
		return nil, fail(operation, errors.New("Budget Auth tokens require BeginBudgetCall so metering feedback and uncertain outcomes are not discarded"))
	}
	var claims aauth.AuthTokenClaims
	if carriesR3 {
		if call.UpstreamToken != "" {
			return nil, fail(operation, errors.New("R3 call chaining is not implemented"))
		}
		claims, err = client.verifyR3AuthTokenForCall(ctx, call.AuthToken, resource)
	} else {
		claims, err = aauth.VerifyAuthToken(ctx, call.AuthToken, client.keyResolver, client.clock)
		if err == nil {
			err = client.validateAuthTokenForDirectCall(ctx, claims, resource, call.UpstreamToken)
		}
	}
	if err != nil {
		return nil, fail(operation, err)
	}
	metadata, err := client.resourceMetadata(ctx, resource)
	if err != nil {
		return nil, fail(operation, err)
	}
	request := call.Request.Clone(ctx)
	request.Header = call.Request.Header.Clone()
	if call.Request.Body != nil && call.Request.GetBody != nil {
		request.Body, err = call.Request.GetBody()
		if err != nil {
			return nil, fail(operation, err)
		}
	}
	if err := client.signResourceRequest(request, call.AuthToken, metadata.AdditionalSignatureComponents); err != nil {
		return nil, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fail(operation, err)
	}
	if response.StatusCode == http.StatusUnauthorized && response.Header.Get("Signature-Error") != "" {
		response.Body.Close()
		return nil, fail(operation, authTokenResponseFailure(response))
	}
	if isProblemResponse(response) {
		problem, isAAuth, err := inspectAAuthProblem(response)
		if err != nil {
			response.Body.Close()
			return nil, fail(operation, err)
		}
		if isAAuth {
			response.Body.Close()
			return nil, fail(operation, problem)
		}
	}
	return response, nil
}

func (client *Client) validateAuthTokenForDirectCall(
	ctx context.Context,
	claims aauth.AuthTokenClaims,
	resource string,
	upstreamToken string,
) error {
	if err := client.acceptIssuedPersonServer(
		ctx, upstreamToken, claims.PersonServer, claims.MissionS256, time.Unix(claims.IssuedAt, 0),
	); err != nil {
		return fmt.Errorf("auth-token person server: %w", err)
	}
	if claims.ExpiresAt > client.agentClaims.ExpiresAt {
		return errors.New("auth-token lifetime exceeds the agent token")
	}
	if claims.Audience != resource {
		return errors.New("auth-token audience does not match request resource")
	}
	if !claims.Confirmation.JWK.Equal(client.signingKey.PublicJWK()) {
		return errors.New("auth-token confirmation key does not match signing key")
	}
	return nil
}
