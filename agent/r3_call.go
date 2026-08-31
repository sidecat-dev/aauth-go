package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// R3Call supplies one exact protected HTTP call and the class Auth token
// that designated its operation for per-call authorization. Additional
// signature components are explicit so this method performs no discovery
// request before the application call.
type R3Call struct {
	Request                       *http.Request
	ClassAuthToken                string
	Operation                     r3.Operation
	AdditionalSignatureComponents []string
}

// R3Retry supplies one verified 401 continuation and the proposal Auth
// token that completes it.
type R3Retry struct {
	Authorization R3Authorization
	AuthToken     string
}

// R3Poll supplies one verified Resource-held invocation and the proposal
// Auth token that completes it.
type R3Poll struct {
	Pending   PendingR3Call
	AuthToken string
}

type r3CallResultKind uint8
type r3AuthorizationKind uint8
type pendingR3CallKind uint8

const (
	r3CallResultResponse r3CallResultKind = iota + 1
	r3CallResultAuthorizationRequired
	r3CallResultPending
)

const (
	r3AuthorizationVerified r3AuthorizationKind = 1
	pendingR3CallVerified   pendingR3CallKind   = 1
)

type r3ProposalContext struct {
	resourceToken  string
	reference      r3.Reference
	resourceClaims aauth.ResourceTokenClaims
	operation      r3.Operation
}

// R3Authorization is a verified per-call proposal requirement and an exact
// private snapshot of the request that produced it. Only BeginR3Call can
// construct a value accepted by RetryR3Call.
type R3Authorization struct {
	kind       r3AuthorizationKind
	proposal   r3ProposalContext
	request    r3RequestSnapshot
	components []string
}

// ResourceToken returns the verified proposal Resource token.
func (authorization R3Authorization) ResourceToken() string {
	if authorization.kind != r3AuthorizationVerified {
		return ""
	}
	return authorization.proposal.resourceToken
}

// Reference returns the verified proposal reference without fetching its
// content.
func (authorization R3Authorization) Reference() r3.Reference {
	if authorization.kind != r3AuthorizationVerified {
		return r3.Reference{}
	}
	return authorization.proposal.reference
}

// PendingR3Call is a verified Resource-held per-call invocation. It retains
// no application request body; PollR3Call sends only a signed GET.
type PendingR3Call struct {
	kind       pendingR3CallKind
	proposal   r3ProposalContext
	location   string
	retryAfter time.Duration
}

// ResourceToken returns the verified proposal Resource token.
func (pending PendingR3Call) ResourceToken() string {
	if pending.kind != pendingR3CallVerified {
		return ""
	}
	return pending.proposal.resourceToken
}

// Reference returns the verified proposal reference without fetching its
// content.
func (pending PendingR3Call) Reference() r3.Reference {
	if pending.kind != pendingR3CallVerified {
		return r3.Reference{}
	}
	return pending.proposal.reference
}

// Location returns the verified same-origin pending URL.
func (pending PendingR3Call) Location() string {
	if pending.kind != pendingR3CallVerified {
		return ""
	}
	return pending.location
}

// RetryAfter returns the Resource's requested delay before polling.
func (pending PendingR3Call) RetryAfter() time.Duration {
	if pending.kind != pendingR3CallVerified {
		return 0
	}
	return pending.retryAfter
}

// R3CallResult is exactly one ordinary application response, one verified
// 401 continuation, or one verified Resource-held 202 continuation.
type R3CallResult struct {
	kind          r3CallResultKind
	response      *http.Response
	authorization R3Authorization
	pending       PendingR3Call
}

// Response returns the ordinary application response, when present. The
// caller owns its body.
func (result R3CallResult) Response() (*http.Response, bool) {
	if result.kind != r3CallResultResponse || result.response == nil {
		return nil, false
	}
	return result.response, true
}

// AuthorizationRequired returns the verified 401 continuation, when present.
func (result R3CallResult) AuthorizationRequired() (R3Authorization, bool) {
	if result.kind != r3CallResultAuthorizationRequired ||
		result.authorization.kind != r3AuthorizationVerified {
		return R3Authorization{}, false
	}
	return result.authorization, true
}

// Pending returns the verified Resource-held 202 continuation, when present.
func (result R3CallResult) Pending() (PendingR3Call, bool) {
	if result.kind != r3CallResultPending || result.pending.kind != pendingR3CallVerified {
		return PendingR3Call{}, false
	}
	return result.pending, true
}

// BeginR3Call verifies one class Auth token, performs exactly one signed
// application call, and returns one closed result. It never discovers
// metadata, fetches a proposal, exchanges a token, retries, polls, or sleeps.
func (client *Client) BeginR3Call(ctx context.Context, input R3Call) (R3CallResult, error) {
	const operation = "begin R3 call"
	if client == nil {
		return R3CallResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return R3CallResult{}, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return R3CallResult{}, fail(operation, err)
	}
	if input.Request == nil || input.Request.URL == nil {
		return R3CallResult{}, fail(operation, errors.New("request is required"))
	}
	if input.ClassAuthToken == "" {
		return R3CallResult{}, fail(operation, errors.New("class auth token is required"))
	}
	if input.Operation.JSON() == nil {
		return R3CallResult{}, fail(operation, errors.New("R3 operation is required"))
	}
	if client.r3 == nil {
		return R3CallResult{}, fail(operation, errors.New("R3 is not configured"))
	}
	resource, err := requestOrigin(input.Request.URL)
	if err != nil {
		return R3CallResult{}, fail(operation, err)
	}
	classClaims, classReference, classOperations, err := r3.VerifyAuthTokenClaims(
		ctx, client.r3.Registry, input.ClassAuthToken, client.keyResolver, client.clock,
	)
	if err != nil {
		return R3CallResult{}, fail(operation, err)
	}
	if err := client.verifyR3CallAuthContext(ctx, classClaims, resource); err != nil {
		return R3CallResult{}, fail(operation, err)
	}
	contained, err := classOperations.PerCallOperations().Contains(input.Operation)
	if err != nil {
		return R3CallResult{}, fail(operation, err)
	}
	if !contained {
		return R3CallResult{}, fail(operation, errors.New("class auth token does not designate the R3 operation for per-call authorization"))
	}
	snapshot, err := snapshotR3Request(input.Request, client.maxSignedBodyBytes)
	if err != nil {
		return R3CallResult{}, fail(operation, err)
	}
	request := snapshot.request(ctx)
	components := append([]string(nil), input.AdditionalSignatureComponents...)
	if err := client.signResourceRequest(request, input.ClassAuthToken, components); err != nil {
		return R3CallResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return R3CallResult{}, fail(operation, err)
	}
	if err := validateCallResponseOrigin(response, resource); err != nil {
		closeResponse(response)
		return R3CallResult{}, fail(operation, err)
	}
	if response.StatusCode == http.StatusUnauthorized && response.Header.Get("Signature-Error") != "" {
		response.Body.Close()
		return R3CallResult{}, fail(operation, responseFailure(response))
	}
	if response.StatusCode == http.StatusUnauthorized && len(response.Header.Values("AAuth-Requirement")) > 0 {
		proposal, err := client.verifyR3ProposalRequirement(ctx, response, resource, classClaims, classReference, input.Operation)
		response.Body.Close()
		if err != nil {
			return R3CallResult{}, fail(operation, err)
		}
		return R3CallResult{
			kind: r3CallResultAuthorizationRequired,
			authorization: R3Authorization{
				kind: r3AuthorizationVerified, proposal: proposal,
				request: snapshot, components: components,
			},
		}, nil
	}
	if response.StatusCode == http.StatusAccepted {
		defer response.Body.Close()
		pending, err := client.pendingR3Call(
			ctx, response, resource, classClaims, classReference, input.Operation,
		)
		if err != nil {
			return R3CallResult{}, fail(operation, err)
		}
		return R3CallResult{kind: r3CallResultPending, pending: pending}, nil
	}
	if isProblemResponse(response) {
		problem, isAAuth, err := inspectAAuthProblem(response)
		if err != nil {
			response.Body.Close()
			return R3CallResult{}, fail(operation, err)
		}
		if isAAuth {
			response.Body.Close()
			return R3CallResult{}, fail(operation, problem)
		}
	}
	return R3CallResult{kind: r3CallResultResponse, response: response}, nil
}

// RetryR3Call verifies one proposal Auth token, regenerates only the proof
// headers on the exact retained request, and performs exactly one retry. It
// never fetches the proposal, exchanges a token, or retries again.
func (client *Client) RetryR3Call(ctx context.Context, input R3Retry) (*http.Response, error) {
	const operation = "retry R3 call"
	if client == nil {
		return nil, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return nil, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return nil, fail(operation, err)
	}
	if input.Authorization.kind != r3AuthorizationVerified {
		return nil, fail(operation, errors.New("verified R3 authorization is required"))
	}
	if input.AuthToken == "" {
		return nil, fail(operation, errors.New("auth token is required"))
	}
	if err := client.verifyR3ProposalAuthToken(ctx, input.AuthToken, input.Authorization.proposal); err != nil {
		return nil, fail(operation, err)
	}
	request := input.Authorization.request.request(ctx)
	if err := client.signResourceRequest(request, input.AuthToken, input.Authorization.components); err != nil {
		return nil, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fail(operation, err)
	}
	if err := validateCallResponseOrigin(response, input.Authorization.proposal.resourceClaims.Issuer); err != nil {
		closeResponse(response)
		return nil, fail(operation, err)
	}
	return client.finishR3Response(operation, response)
}

// PollR3Call verifies one proposal Auth token and performs exactly one
// signed GET to the trusted pending URL. It never sleeps, retries, exchanges a
// token, or resends the original application request.
func (client *Client) PollR3Call(ctx context.Context, input R3Poll) (*http.Response, error) {
	const operation = "poll R3 call"
	if client == nil {
		return nil, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return nil, fail(operation, errors.New("context is required"))
	}
	if err := ctx.Err(); err != nil {
		return nil, fail(operation, err)
	}
	if input.Pending.kind != pendingR3CallVerified {
		return nil, fail(operation, errors.New("verified pending R3 call is required"))
	}
	if input.AuthToken == "" {
		return nil, fail(operation, errors.New("auth token is required"))
	}
	if err := client.verifyR3ProposalAuthToken(ctx, input.AuthToken, input.Pending.proposal); err != nil {
		return nil, fail(operation, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, input.Pending.location, nil)
	if err != nil {
		return nil, fail(operation, err)
	}
	if err := signaturekey.SignJWTRequestWithOptions(
		request, client.signingKey, input.AuthToken, client.clock, signaturekey.SignOptions{},
	); err != nil {
		return nil, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fail(operation, err)
	}
	if err := validateCallResponseOrigin(response, input.Pending.proposal.resourceClaims.Issuer); err != nil {
		closeResponse(response)
		return nil, fail(operation, err)
	}
	return client.finishR3Response(operation, response)
}

func (client *Client) verifyR3CallAuthContext(
	ctx context.Context,
	claims aauth.AuthTokenClaims,
	resource string,
) error {
	if claims.DWK != aauth.AccessDiscoveryDocument {
		return errors.New("class auth token must be issued under the Access Server role")
	}
	if err := client.acceptIssuedPersonServer(ctx, "", claims.PersonServer, time.Unix(claims.IssuedAt, 0)); err != nil {
		return fmt.Errorf("auth-token person server: %w", err)
	}
	if claims.ExpiresAt > client.agentClaims.ExpiresAt {
		return errors.New("auth-token lifetime exceeds the agent token")
	}
	if claims.Audience != resource || !claims.Confirmation.JWK.Equal(client.signingKey.PublicJWK()) {
		return errors.New("class auth token does not match the protected call")
	}
	return nil
}

func (client *Client) verifyR3ProposalRequirement(
	ctx context.Context,
	response *http.Response,
	resource string,
	classClaims aauth.AuthTokenClaims,
	classReference r3.Reference,
	operation r3.Operation,
) (r3ProposalContext, error) {
	if !hasNoStore(response.Header.Values("Cache-Control")) {
		return r3ProposalContext{}, errors.New("R3 proposal response Cache-Control must contain no-store")
	}
	values := response.Header.Values("AAuth-Requirement")
	if len(values) != 1 {
		return r3ProposalContext{}, errors.New("R3 proposal response requires exactly one AAuth-Requirement")
	}
	requirement, err := aauth.ParseAuthTokenRequirement(values)
	if err != nil {
		return r3ProposalContext{}, err
	}
	claims, reference, err := r3.VerifyResourceToken(ctx, requirement.ResourceToken, client.keyResolver, client.clock)
	if err != nil {
		return r3ProposalContext{}, err
	}
	if reference == classReference {
		return r3ProposalContext{}, errors.New("proposal Resource token repeated the class reference")
	}
	if claims.Interaction != nil {
		return r3ProposalContext{}, errors.New("proposal Resource token must not contain an interaction")
	}
	thumbprint, err := client.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return r3ProposalContext{}, err
	}
	if claims.Issuer != resource || claims.Audience != classClaims.Issuer ||
		claims.PersonServer != classClaims.PersonServer || claims.Subject != classClaims.Subject ||
		claims.AgentJKT != thumbprint {
		return r3ProposalContext{}, errors.New("proposal Resource-token identity does not match the class authorization")
	}
	if !sameScopeSet(strings.Fields(claims.Scope), strings.Fields(classClaims.Scope)) ||
		claims.MissionS256 != classClaims.MissionS256 || claims.Tenant != classClaims.Tenant ||
		!equalStringPointers(claims.Account, classClaims.Account) {
		return r3ProposalContext{}, errors.New("proposal Resource-token context does not match the class authorization")
	}
	if claims.IssuedAt < classClaims.IssuedAt || claims.IssuedAt >= classClaims.ExpiresAt ||
		(classClaims.NotBefore != 0 && claims.IssuedAt < classClaims.NotBefore) ||
		claims.ExpiresAt > classClaims.ExpiresAt {
		return r3ProposalContext{}, errors.New("proposal Resource-token lifetime is outside the class authorization")
	}
	return r3ProposalContext{
		resourceToken: requirement.ResourceToken, reference: reference,
		resourceClaims: claims, operation: operation,
	}, nil
}

func (client *Client) pendingR3Call(
	ctx context.Context,
	response *http.Response,
	resource string,
	classClaims aauth.AuthTokenClaims,
	classReference r3.Reference,
	operation r3.Operation,
) (PendingR3Call, error) {
	location, err := parsePendingLocation(response)
	if err != nil {
		return PendingR3Call{}, err
	}
	retryAfter, err := parseRetryAfter(response.Header.Values("Retry-After"))
	if err != nil {
		return PendingR3Call{}, err
	}
	if len(response.Header.Values("Content-Type")) != 1 {
		return PendingR3Call{}, errors.New("pending R3 response requires exactly one Content-Type")
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decodeJSONResponse(response, &body); err != nil {
		return PendingR3Call{}, err
	}
	if body.Status == "" {
		return PendingR3Call{}, errors.New("pending R3 response status is required")
	}
	proposal, err := client.verifyR3ProposalRequirement(
		ctx, response, resource, classClaims, classReference, operation,
	)
	if err != nil {
		return PendingR3Call{}, err
	}
	return PendingR3Call{
		kind: pendingR3CallVerified, proposal: proposal,
		location: location, retryAfter: retryAfter,
	}, nil
}

func (client *Client) verifyR3ProposalAuthToken(
	ctx context.Context,
	compact string,
	proposal r3ProposalContext,
) error {
	claims, reference, operations, err := r3.VerifyAuthTokenClaims(
		ctx, client.r3.Registry, compact, client.keyResolver, client.clock,
	)
	if err != nil {
		return err
	}
	if reference != proposal.reference {
		return errors.New("proposal auth token changed the proposal reference")
	}
	if operations.PerCallClaimPresent() || len(operations.PerCallOperations().Operations()) != 0 {
		return errors.New("proposal auth token must not contain r3_per_call")
	}
	granted := operations.GrantedOperations().Operations()
	if len(granted) != 1 {
		return errors.New("proposal auth token does not grant exactly the requested R3 operation")
	}
	equal, err := granted[0].Equal(proposal.operation)
	if err != nil {
		return err
	}
	if !equal {
		return errors.New("proposal auth token does not grant exactly the requested R3 operation")
	}
	if claims.DWK != aauth.AccessDiscoveryDocument {
		return errors.New("proposal auth token must be issued under the Access Server role")
	}
	resource := proposal.resourceClaims
	if err := aauth.ValidateCurrentAuthTokenContext(claims, aauth.AuthTokenContext{
		Issuer: resource.Audience, DiscoveryDocument: aauth.AccessDiscoveryDocument,
		Resource: resource.Issuer, PersonServer: resource.PersonServer,
		Subject: resource.Subject, RequestKey: client.signingKey.PublicJWK(),
	}); err != nil {
		return err
	}
	if claims.Scope != "" && !scopeSubset(strings.Fields(claims.Scope), strings.Fields(resource.Scope)) ||
		claims.MissionS256 != resource.MissionS256 || claims.Tenant != resource.Tenant ||
		!equalStringPointers(claims.Account, resource.Account) {
		return errors.New("proposal auth-token context does not match the proposal Resource token")
	}
	if claims.IssuedAt < resource.IssuedAt || claims.IssuedAt >= resource.ExpiresAt ||
		(resource.NotBefore != 0 && claims.IssuedAt < resource.NotBefore) ||
		claims.ExpiresAt > client.agentClaims.ExpiresAt {
		return errors.New("proposal auth-token lifetime is outside the proposal Resource token")
	}
	return nil
}

func (client *Client) finishR3Response(operation string, response *http.Response) (*http.Response, error) {
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

func validateCallResponseOrigin(response *http.Response, resource string) error {
	if response == nil {
		return errors.New("Resource response is required")
	}
	if response.Request == nil || response.Request.URL == nil {
		return errors.New("Resource response request URL is required")
	}
	origin, err := requestOrigin(response.Request.URL)
	if err != nil || origin != resource {
		return errors.New("Resource response origin does not match the protected call")
	}
	if response.Body == nil {
		return errors.New("Resource response body is required")
	}
	return nil
}

func closeResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}

type r3RequestSnapshot struct {
	template *http.Request
	body     []byte
}

func snapshotR3Request(original *http.Request, maximum int64) (r3RequestSnapshot, error) {
	if original == nil || original.URL == nil {
		return r3RequestSnapshot{}, errors.New("request is required")
	}
	template := original.Clone(context.Background())
	template.Header = original.Header.Clone()
	clonedURL := *original.URL
	template.URL = &clonedURL
	template.Trailer = original.Trailer.Clone()
	template.Body = nil
	template.GetBody = nil

	var body []byte
	if original.Body != nil && original.Body != http.NoBody {
		if original.GetBody == nil {
			return r3RequestSnapshot{}, errors.New("request body must be replayable")
		}
		copy, err := original.GetBody()
		if err != nil {
			return r3RequestSnapshot{}, fmt.Errorf("copy request body: %w", err)
		}
		if copy == nil {
			return r3RequestSnapshot{}, errors.New("copied request body is nil")
		}
		limit := maximum
		if limit == 0 {
			limit = 1 << 20
		}
		reader := io.Reader(copy)
		if limit > 0 {
			reader = io.LimitReader(copy, limit+1)
		}
		body, err = io.ReadAll(reader)
		closeErr := copy.Close()
		if err != nil {
			return r3RequestSnapshot{}, fmt.Errorf("read copied request body: %w", err)
		}
		if closeErr != nil {
			return r3RequestSnapshot{}, fmt.Errorf("close copied request body: %w", closeErr)
		}
		if limit > 0 && int64(len(body)) > limit {
			return r3RequestSnapshot{}, fmt.Errorf("request body exceeds %d bytes", limit)
		}
	}
	template.ContentLength = int64(len(body))
	return r3RequestSnapshot{template: template, body: append([]byte(nil), body...)}, nil
}

func (snapshot r3RequestSnapshot) request(ctx context.Context) *http.Request {
	request := snapshot.template.Clone(ctx)
	request.Header = snapshot.template.Header.Clone()
	if snapshot.template.URL != nil {
		clonedURL := *snapshot.template.URL
		request.URL = &clonedURL
	}
	request.Trailer = snapshot.template.Trailer.Clone()
	if len(snapshot.body) == 0 {
		request.Body = http.NoBody
		request.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		request.ContentLength = 0
		return request
	}
	body := append([]byte(nil), snapshot.body...)
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	request.ContentLength = int64(len(body))
	return request
}
