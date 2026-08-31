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

	aauth "aauth-go"
	"aauth-go/internal/r3dispatch"
	"aauth-go/signaturekey"
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
			_, err = client.verifyResourceTokenContext(ctx, requirement.ResourceToken, resource, person, nil)
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
	claims, err := client.verifyResourceTokenContext(ctx, requirement.ResourceToken, resource, person, nil)
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
) (aauth.ResourceTokenClaims, error) {
	claims, err := aauth.VerifyResourceToken(ctx, compact, client.keyResolver, client.clock)
	if err != nil {
		return aauth.ResourceTokenClaims{}, err
	}
	if claims.Interaction != nil {
		return aauth.ResourceTokenClaims{}, errors.New("resource-token interaction requires the deferred flow")
	}
	if claims.Account != nil {
		return aauth.ResourceTokenClaims{}, errors.New("resource-token account is not supported by the immediate flow")
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return aauth.ResourceTokenClaims{}, err
	}
	if claims.Issuer != resource {
		return aauth.ResourceTokenClaims{}, errors.New("resource-token issuer does not match resource")
	}
	if claims.PersonServer != person.Issuer {
		return aauth.ResourceTokenClaims{}, errors.New("resource-token person server does not match person token")
	}
	if claims.Subject != person.Subject {
		return aauth.ResourceTokenClaims{}, errors.New("resource-token subject does not match person token")
	}
	if claims.PresentedJTI != person.JTI {
		return aauth.ResourceTokenClaims{}, errors.New("resource-token presented_jti does not match person token")
	}
	if claims.AgentJKT != thumbprint {
		return aauth.ResourceTokenClaims{}, errors.New("resource-token agent_jkt does not match signing key")
	}
	if requestedScopes != nil && !scopeSubset(strings.Fields(claims.Scope), requestedScopes) {
		return aauth.ResourceTokenClaims{}, errors.New("resource-token scope is empty, duplicated, or outside the request")
	}
	if claims.MissionS256 != person.MissionS256 || claims.Tenant != person.Tenant {
		return aauth.ResourceTokenClaims{}, errors.New("resource-token context does not match person token")
	}
	if claims.IssuedAt < person.IssuedAt || claims.IssuedAt >= person.ExpiresAt ||
		(person.NotBefore != 0 && claims.IssuedAt < person.NotBefore) {
		return aauth.ResourceTokenClaims{}, errors.New("resource token was issued outside the person-token validity window")
	}
	if person.MissionS256 != "" && claims.ExpiresAt > person.ExpiresAt {
		return aauth.ResourceTokenClaims{}, errors.New("resource token outlives the mission-bound person token")
	}
	return claims, nil
}

// PollAuthToken presents one locally verified auth token in one signed GET to
// the trusted pending URL. It does not sleep, retry, exchange, or resend the
// original invocation.
func (client *Client) PollAuthToken(ctx context.Context, input AuthTokenPoll) (*http.Response, error) {
	const operation = "poll auth token"
	if client == nil {
		return nil, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return nil, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return nil, fail(operation, err)
	}
	if input.Pending.kind != pendingAuthTokenCallVerified {
		return nil, fail(operation, errors.New("pending auth-token call is required"))
	}
	if input.AuthToken == "" {
		return nil, fail(operation, errors.New("auth token is required"))
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return nil, fail(operation, err)
	}
	if input.Pending.resourceClaims.AgentJKT != thumbprint {
		return nil, fail(operation, errors.New("pending resource token does not match client signing key"))
	}
	authClaims, err := client.verifyAuthTokenForResource(ctx, input.AuthToken, input.Pending.resourceClaims)
	if err != nil {
		return nil, fail(operation, err)
	}
	if !sameScopeSet(strings.Fields(authClaims.Scope), strings.Fields(input.Pending.resourceClaims.Scope)) {
		return nil, fail(operation, errors.New("auth-token scope does not exactly match held resource-token scope"))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, input.Pending.location, nil)
	if err != nil {
		return nil, fail(operation, err)
	}
	if err := signaturekey.SignJWTRequestWithOptions(
		request,
		client.signingKey,
		input.AuthToken,
		client.clock,
		signaturekey.SignOptions{},
	); err != nil {
		return nil, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fail(operation, err)
	}
	if response.StatusCode == http.StatusUnauthorized && response.Header.Get("Signature-Error") != "" {
		response.Body.Close()
		return nil, fail(operation, responseFailure(response))
	}
	if response.StatusCode == http.StatusAccepted || response.StatusCode == http.StatusTooManyRequests ||
		response.StatusCode == http.StatusServiceUnavailable {
		return response, nil
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

// Do verifies an auth token for the exact request resource, signs that request,
// and performs one HTTP call. It does not interpret ordinary application
// responses, but preserves an AAuth problem response as a typed error.
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
	var claims aauth.AuthTokenClaims
	if carriesR3 {
		if call.UpstreamToken != "" {
			return nil, fail(operation, errors.New("R3 call chaining is not implemented"))
		}
		claims, err = client.verifyR3AuthTokenForCall(ctx, call.AuthToken, resource)
	} else {
		claims, err = aauth.VerifyAuthToken(ctx, call.AuthToken, client.keyResolver, client.clock)
		if err == nil && claims.Account != nil {
			err = errors.New("auth-token account is not supported by the immediate flow")
		}
		if err == nil && claims.MissionS256 != "" && call.UpstreamToken != "" {
			err = errors.New("mission-bound call-chain authorization is not supported")
		}
		if err == nil {
			if acceptErr := client.acceptIssuedPersonServer(
				ctx, call.UpstreamToken, claims.PersonServer, time.Unix(claims.IssuedAt, 0),
			); acceptErr != nil {
				err = fmt.Errorf("auth-token person server: %w", acceptErr)
			}
		}
		if err == nil && claims.ExpiresAt > client.agentClaims.ExpiresAt {
			err = errors.New("auth-token lifetime exceeds the agent token")
		}
		if err == nil && claims.Audience != resource {
			err = errors.New("auth-token audience does not match request resource")
		}
		if err == nil && !claims.Confirmation.JWK.Equal(client.signingKey.PublicJWK()) {
			err = errors.New("auth-token confirmation key does not match signing key")
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
	signOptions := signaturekey.SignOptions{
		AdditionalComponents: append([]string(nil), metadata.AdditionalSignatureComponents...),
	}
	if containsFold(metadata.AdditionalSignatureComponents, "content-digest") {
		signOptions.MaxBodyBytes = client.maxSignedBodyBytes
	}
	if err := signaturekey.SignJWTRequestWithOptions(
		request, client.signingKey, call.AuthToken, client.clock, signOptions,
	); err != nil {
		return nil, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fail(operation, err)
	}
	if response.StatusCode == http.StatusUnauthorized && response.Header.Get("Signature-Error") != "" {
		response.Body.Close()
		return nil, fail(operation, responseFailure(response))
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
