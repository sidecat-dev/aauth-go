package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	aauth "aauth-go"
	"aauth-go/signaturekey"
)

type resourceSessionKind uint8
type pendingResourceSessionKind uint8

const (
	resourceSessionVerified        resourceSessionKind        = 1
	pendingResourceSessionVerified pendingResourceSessionKind = 1
)

// ResourceSession is one opaque Resource credential bound locally to the
// stable Agent identity that received it. Token contents are never parsed.
type ResourceSession struct {
	kind          resourceSessionKind
	resource      string
	token         string
	agentProvider string
	agent         string
	parentAgent   string
}

// ResourceSessionState is the complete caller-persisted state needed to
// restore a session without losing its local stable-Agent binding. Token
// requires confidentiality, and the complete value requires integrity.
type ResourceSessionState struct {
	Resource      string `json:"resource"`
	Token         string `json:"token"`
	AgentProvider string `json:"agent_provider"`
	Agent         string `json:"agent"`
	ParentAgent   string `json:"parent_agent,omitempty"`
}

// Resource returns the HTTPS origin that issued the session.
func (session ResourceSession) Resource() string {
	if session.kind != resourceSessionVerified {
		return ""
	}
	return session.resource
}

// Token returns the opaque token68 value. Use State when persisting a session
// so its stable-Agent binding is retained with the credential.
func (session ResourceSession) Token() string {
	if session.kind != resourceSessionVerified {
		return ""
	}
	return session.token
}

// State returns the caller-persistable projection of a verified session. A
// zero ResourceSession returns zero state.
func (session ResourceSession) State() ResourceSessionState {
	if session.kind != resourceSessionVerified {
		return ResourceSessionState{}
	}
	return ResourceSessionState{
		Resource: session.resource, Token: session.token,
		AgentProvider: session.agentProvider, Agent: session.agent, ParentAgent: session.parentAgent,
	}
}

// PendingResourceSession is a verified same-origin Resource interaction. Its
// fields are private so only a validated 202 response can make it pollable.
type PendingResourceSession struct {
	kind            pendingResourceSessionKind
	resource        string
	location        string
	retryAfter      time.Duration
	interactionURL  string
	interactionCode string
	interacting     bool
	agentProvider   string
	agent           string
	parentAgent     string
	components      []string
}

// Resource returns the responding Resource origin.
func (pending PendingResourceSession) Resource() string {
	if pending.kind != pendingResourceSessionVerified {
		return ""
	}
	return pending.resource
}

// Location returns the verified same-origin pending URL.
func (pending PendingResourceSession) Location() string {
	if pending.kind != pendingResourceSessionVerified {
		return ""
	}
	return pending.location
}

// RetryAfter returns the Resource's current polling interval.
func (pending PendingResourceSession) RetryAfter() time.Duration {
	if pending.kind != pendingResourceSessionVerified {
		return 0
	}
	return pending.retryAfter
}

// InteractionURL returns the verified Resource interaction URL.
func (pending PendingResourceSession) InteractionURL() string {
	if pending.kind != pendingResourceSessionVerified {
		return ""
	}
	return pending.interactionURL
}

// InteractionCode returns the human-readable correlation code.
func (pending PendingResourceSession) InteractionCode() string {
	if pending.kind != pendingResourceSessionVerified {
		return ""
	}
	return pending.interactionCode
}

// Interacting reports that the Resource observed the person at its UI.
func (pending PendingResourceSession) Interacting() bool {
	return pending.kind == pendingResourceSessionVerified && pending.interacting
}

// AdditionalSignatureComponents returns the exact Resource signature profile
// retained when this pending interaction was created.
func (pending PendingResourceSession) AdditionalSignatureComponents() []string {
	if pending.kind != pendingResourceSessionVerified {
		return nil
	}
	return append([]string(nil), pending.components...)
}

// ResourceSessionResult preserves one valid HTTP outcome: its caller-owned
// response, any replacement session, an optional pending interaction, and a
// recognized protocol failure. The Go error returned by a Client method is
// reserved for failures that prevented a valid outcome from being formed.
type ResourceSessionResult struct {
	response *http.Response
	session  ResourceSession
	pending  PendingResourceSession
	failure  error
}

// Response returns the ordinary or terminal response. The caller owns its
// body.
func (result ResourceSessionResult) Response() (*http.Response, bool) {
	return result.response, result.response != nil
}

// Session returns the newly issued session, when the response supplied one.
func (result ResourceSessionResult) Session() (ResourceSession, bool) {
	return result.session, result.session.kind == resourceSessionVerified
}

// Pending returns the verified interaction, when the response is still 202.
func (result ResourceSessionResult) Pending() (PendingResourceSession, bool) {
	return result.pending, result.pending.kind == pendingResourceSessionVerified
}

// Failure returns a verified Signature-Key or AAuth protocol failure carried
// by the response. A valid replacement session can accompany this failure and
// must be retained before the caller acts on it.
func (result ResourceSessionResult) Failure() error { return result.failure }

// BeginResourceSession discovers the Resource signature profile, then performs
// one Agent-token-signed application request. It preserves the caller's
// declared capabilities and never opens a browser, polls, retries, or replays
// the application request.
func (client *Client) BeginResourceSession(ctx context.Context, original *http.Request) (ResourceSessionResult, error) {
	return client.beginResourceSession(ctx, original, nil, true)
}

// BeginResourceSessionWithComponents signs and performs exactly one Resource
// request with the supplied signature profile. It does not fetch Resource
// metadata.
func (client *Client) BeginResourceSessionWithComponents(
	ctx context.Context,
	original *http.Request,
	additionalSignatureComponents []string,
) (ResourceSessionResult, error) {
	return client.beginResourceSession(ctx, original, additionalSignatureComponents, false)
}

func (client *Client) beginResourceSession(
	ctx context.Context,
	original *http.Request,
	additionalSignatureComponents []string,
	discoverComponents bool,
) (ResourceSessionResult, error) {
	const operation = "begin resource session"
	if client == nil {
		return ResourceSessionResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return ResourceSessionResult{}, fail(operation, errors.New("context is required"))
	}
	if original == nil || original.URL == nil {
		return ResourceSessionResult{}, fail(operation, errors.New("request is required"))
	}
	resource, err := requestOrigin(original.URL)
	if err != nil {
		return ResourceSessionResult{}, fail(operation, err)
	}
	capabilities, err := aauth.ParseCapabilities(original.Header.Values("AAuth-Capabilities"))
	if err != nil {
		return ResourceSessionResult{}, fail(operation, fmt.Errorf("AAuth-Capabilities: %w", err))
	}
	interactionCapable := slices.Contains(capabilities, "interaction")
	components := append([]string(nil), additionalSignatureComponents...)
	if discoverComponents {
		metadata, err := client.resourceMetadata(ctx, resource)
		if err != nil {
			return ResourceSessionResult{}, fail(operation, err)
		}
		components = metadata.AdditionalSignatureComponents
	}
	request, err := cloneInitialRequest(ctx, original)
	if err != nil {
		return ResourceSessionResult{}, fail(operation, err)
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
		return ResourceSessionResult{}, fail(operation, err)
	}
	sent = true
	response, err := client.httpClient.Do(request)
	if err != nil {
		return ResourceSessionResult{}, fail(operation, err)
	}
	if response.StatusCode == http.StatusAccepted {
		defer response.Body.Close()
		if !interactionCapable {
			return ResourceSessionResult{}, fail(operation, errors.New("Resource requested interaction the Agent did not declare"))
		}
		pending, err := client.pendingResourceSession(response, resource, PendingResourceSession{}, components)
		if err != nil {
			return ResourceSessionResult{}, fail(operation, err)
		}
		return ResourceSessionResult{pending: pending}, nil
	}
	return client.resourceSessionTerminal(operation, response, resource)
}

// PollResourceSession performs exactly one signed, bodyless GET for a verified
// pending Resource interaction whose signature profile has no additional
// fields. Use PollResourceSessionWithComponents when fresh field values are
// required.
func (client *Client) PollResourceSession(ctx context.Context, pending PendingResourceSession) (ResourceSessionResult, error) {
	return client.pollResourceSession(ctx, pending, nil, nil, false)
}

// PollResourceSessionWithComponents performs one signed pending GET with the
// exact retained component profile and fresh caller-supplied header values.
func (client *Client) PollResourceSessionWithComponents(
	ctx context.Context,
	pending PendingResourceSession,
	header http.Header,
	additionalSignatureComponents []string,
) (ResourceSessionResult, error) {
	return client.pollResourceSession(ctx, pending, header, additionalSignatureComponents, true)
}

func (client *Client) pollResourceSession(
	ctx context.Context,
	pending PendingResourceSession,
	header http.Header,
	additionalSignatureComponents []string,
	explicitComponents bool,
) (ResourceSessionResult, error) {
	const operation = "poll resource session"
	if client == nil {
		return ResourceSessionResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return ResourceSessionResult{}, fail(operation, errors.New("context is required"))
	}
	if err := client.validatePendingResourceSession(pending); err != nil {
		return ResourceSessionResult{}, fail(operation, err)
	}
	components := pending.components
	if !explicitComponents && len(components) != 0 {
		return ResourceSessionResult{}, fail(operation, errors.New(
			"pending Resource session requires PollResourceSessionWithComponents and fresh header values",
		))
	}
	if explicitComponents {
		if !slices.Equal(additionalSignatureComponents, components) {
			return ResourceSessionResult{}, fail(operation, errors.New("poll signature components do not match pending Resource session"))
		}
		for _, component := range components {
			if component == "content-digest" {
				continue
			}
			if len(header.Values(component)) == 0 {
				return ResourceSessionResult{}, fail(operation, fmt.Errorf("poll header %q is required", component))
			}
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.location, nil)
	if err != nil {
		return ResourceSessionResult{}, fail(operation, err)
	}
	request.Header = header.Clone()
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	if err := client.signResourceRequest(request, client.agentToken, components); err != nil {
		return ResourceSessionResult{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return ResourceSessionResult{}, fail(operation, err)
	}
	if response.StatusCode == http.StatusAccepted {
		defer response.Body.Close()
		next, err := client.pendingResourceSession(response, pending.resource, pending, components)
		if err != nil {
			return ResourceSessionResult{}, fail(operation, err)
		}
		return ResourceSessionResult{pending: next}, nil
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
		result := ResourceSessionResult{response: response}
		session, err := client.resourceSessionFromResponse(response, pending.resource, ResourceSession{})
		if err != nil {
			response.Body.Close()
			return ResourceSessionResult{}, fail(operation, err)
		}
		result.session = session
		return result, nil
	}
	return client.resourceSessionTerminal(operation, response, pending.resource)
}

// DoWithResourceSession discovers the Resource signature profile, performs one
// proof-bound session call, and returns its valid HTTP outcome. Result.Session
// is the session the caller must use next; the input is never mutated.
func (client *Client) DoWithResourceSession(
	ctx context.Context,
	original *http.Request,
	session ResourceSession,
) (ResourceSessionResult, error) {
	return client.doWithResourceSession(ctx, original, session, nil, true)
}

// DoWithResourceSessionWithComponents performs exactly one proof-bound
// session call with the supplied signature profile and returns its valid HTTP
// outcome. It does not fetch Resource metadata.
func (client *Client) DoWithResourceSessionWithComponents(
	ctx context.Context,
	original *http.Request,
	session ResourceSession,
	additionalSignatureComponents []string,
) (ResourceSessionResult, error) {
	return client.doWithResourceSession(ctx, original, session, additionalSignatureComponents, false)
}

func (client *Client) doWithResourceSession(
	ctx context.Context,
	original *http.Request,
	session ResourceSession,
	additionalSignatureComponents []string,
	discoverComponents bool,
) (ResourceSessionResult, error) {
	const operation = "do with resource session"
	if client == nil {
		return ResourceSessionResult{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return ResourceSessionResult{}, fail(operation, errors.New("context is required"))
	}
	if original == nil || original.URL == nil {
		return ResourceSessionResult{}, fail(operation, errors.New("request is required"))
	}
	resource, err := requestOrigin(original.URL)
	if err != nil {
		return ResourceSessionResult{}, fail(operation, err)
	}
	if err := client.validateResourceSession(session, resource); err != nil {
		return ResourceSessionResult{}, fail(operation, err)
	}
	components := append([]string(nil), additionalSignatureComponents...)
	if discoverComponents {
		metadata, err := client.resourceMetadata(ctx, resource)
		if err != nil {
			return ResourceSessionResult{}, fail(operation, err)
		}
		components = metadata.AdditionalSignatureComponents
	}
	request, err := cloneInitialRequest(ctx, original)
	if err != nil {
		return ResourceSessionResult{}, fail(operation, err)
	}
	sent := false
	if request.Body != nil && request.Body != http.NoBody {
		defer func() {
			if !sent {
				_ = request.Body.Close()
			}
		}()
	}
	authorization, err := aauth.FormatSessionAuthorization(session.token)
	if err != nil {
		return ResourceSessionResult{}, fail(operation, err)
	}
	request.Header.Set("Authorization", authorization)
	if err := client.signResourceRequest(request, client.agentToken, components); err != nil {
		return ResourceSessionResult{}, fail(operation, err)
	}
	sent = true
	response, err := client.httpClient.Do(request)
	if err != nil {
		return ResourceSessionResult{}, fail(operation, err)
	}
	next, err := client.resourceSessionFromResponse(response, resource, session)
	if err != nil {
		response.Body.Close()
		return ResourceSessionResult{}, fail(operation, err)
	}
	failure, err := client.responseProtocolFailure(response)
	if err != nil {
		response.Body.Close()
		return ResourceSessionResult{}, fail(operation, err)
	}
	if failure != nil {
		failure = fail(operation, failure)
	}
	return ResourceSessionResult{response: response, session: next, failure: failure}, nil
}

func (client *Client) pendingResourceSession(
	response *http.Response,
	resource string,
	prior PendingResourceSession,
	components []string,
) (PendingResourceSession, error) {
	location, err := parsePendingLocation(response)
	if err != nil {
		return PendingResourceSession{}, err
	}
	retryAfter, err := parseRetryAfter(response.Header.Values("Retry-After"))
	if err != nil {
		return PendingResourceSession{}, err
	}
	if !hasNoStore(response.Header.Values("Cache-Control")) {
		return PendingResourceSession{}, errors.New("pending response Cache-Control must contain no-store")
	}
	if len(response.Header.Values("Content-Type")) != 1 {
		return PendingResourceSession{}, errors.New("pending response requires exactly one Content-Type")
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decodeJSONResponse(response, &body); err != nil {
		return PendingResourceSession{}, err
	}
	if body.Status == "" {
		return PendingResourceSession{}, errors.New("pending response status is required")
	}
	interactionURL, interactionCode := prior.interactionURL, prior.interactionCode
	values := response.Header.Values("AAuth-Requirement")
	if prior.kind == 0 && len(values) == 0 {
		return PendingResourceSession{}, errors.New("initial Resource session response requires an interaction requirement")
	}
	if len(values) != 0 {
		requirement, err := aauth.ParseInteractionRequirement(values)
		if err != nil {
			return PendingResourceSession{}, err
		}
		if prior.kind != 0 && (requirement.URL != interactionURL || !aauth.MatchInteractionCode(interactionCode, requirement.Code)) {
			return PendingResourceSession{}, errors.New("Resource session interaction changed while polling")
		}
		if prior.kind == 0 {
			interactionURL, interactionCode = requirement.URL, requirement.Code
		}
	}
	return PendingResourceSession{
		kind: pendingResourceSessionVerified, resource: resource, location: location,
		retryAfter: retryAfter, interactionURL: interactionURL, interactionCode: interactionCode,
		interacting:   prior.interacting || body.Status == "interacting",
		agentProvider: client.agentClaims.Issuer, agent: client.identifier, parentAgent: client.agentClaims.ParentAgent,
		components: append([]string(nil), components...),
	}, nil
}

func (client *Client) resourceSessionTerminal(
	operation string,
	response *http.Response,
	resource string,
) (ResourceSessionResult, error) {
	result := ResourceSessionResult{response: response}
	session, err := client.resourceSessionFromResponse(response, resource, ResourceSession{})
	if err != nil {
		response.Body.Close()
		return ResourceSessionResult{}, fail(operation, err)
	}
	result.session = session
	failure, err := client.responseProtocolFailure(response)
	if err != nil {
		response.Body.Close()
		return ResourceSessionResult{}, fail(operation, err)
	}
	if failure != nil {
		result.failure = fail(operation, failure)
	}
	return result, nil
}

func (client *Client) resourceSessionFromResponse(
	response *http.Response,
	resource string,
	current ResourceSession,
) (ResourceSession, error) {
	values := response.Header.Values("AAuth-Access")
	if len(values) == 0 {
		return current, nil
	}
	token, err := aauth.ParseAAuthAccess(values)
	if err != nil {
		return ResourceSession{}, err
	}
	return client.newResourceSession(resource, token), nil
}

func (client *Client) responseProtocolFailure(response *http.Response) (error, error) {
	if response.StatusCode == http.StatusUnauthorized && response.Header.Get("Signature-Error") != "" {
		failure, err := signaturekey.DecodeErrorResponse(response)
		if err != nil {
			return nil, err
		}
		return failure, nil
	}
	if isProblemResponse(response) {
		problem, isAAuth, err := inspectAAuthProblem(response)
		if err != nil {
			return nil, err
		}
		if isAAuth {
			return problem, nil
		}
	}
	return nil, nil
}

func (client *Client) newResourceSession(resource, token string) ResourceSession {
	return ResourceSession{
		kind: resourceSessionVerified, resource: resource, token: token,
		agentProvider: client.agentClaims.Issuer, agent: client.identifier, parentAgent: client.agentClaims.ParentAgent,
	}
}

// RestoreResourceSession validates persisted session state and binds it to the
// Client's current token and proof key for the same stable Agent identity. It
// performs no network request.
func (client *Client) RestoreResourceSession(state ResourceSessionState) (ResourceSession, error) {
	const operation = "restore resource session"
	if client == nil {
		return ResourceSession{}, fail(operation, errors.New("client is required"))
	}
	if err := aauth.ValidateServerIdentifier(state.Resource); err != nil {
		return ResourceSession{}, fail(operation, fmt.Errorf("resource: %w", err))
	}
	if _, err := aauth.FormatAAuthAccess(state.Token); err != nil {
		return ResourceSession{}, fail(operation, err)
	}
	if err := aauth.ValidateServerIdentifier(state.AgentProvider); err != nil {
		return ResourceSession{}, fail(operation, fmt.Errorf("agent provider: %w", err))
	}
	if err := aauth.ValidateAgentRelationship(state.Agent, state.ParentAgent); err != nil {
		return ResourceSession{}, fail(operation, err)
	}
	if state.AgentProvider != client.agentClaims.Issuer || state.Agent != client.identifier ||
		state.ParentAgent != client.agentClaims.ParentAgent {
		return ResourceSession{}, fail(operation, errors.New("Resource session belongs to another Agent"))
	}
	return ResourceSession{
		kind: resourceSessionVerified, resource: state.Resource, token: state.Token,
		agentProvider: state.AgentProvider, agent: state.Agent, parentAgent: state.ParentAgent,
	}, nil
}

func (client *Client) validatePendingResourceSession(pending PendingResourceSession) error {
	if pending.kind != pendingResourceSessionVerified || pending.resource == "" || pending.location == "" ||
		pending.interactionURL == "" || pending.interactionCode == "" || pending.agentProvider == "" || pending.agent == "" {
		return errors.New("verified pending Resource session is required")
	}
	if pending.agentProvider != client.agentClaims.Issuer || pending.agent != client.identifier ||
		pending.parentAgent != client.agentClaims.ParentAgent {
		return errors.New("pending Resource session belongs to another Agent")
	}
	for _, component := range pending.components {
		if err := signaturekey.ValidateAdditionalComponent(component); err != nil {
			return errors.New("pending Resource session has an invalid signature profile")
		}
	}
	return nil
}

func (client *Client) validateResourceSession(session ResourceSession, resource string) error {
	if session.kind != resourceSessionVerified || session.resource == "" || session.token == "" ||
		session.agentProvider == "" || session.agent == "" {
		return errors.New("verified Resource session is required")
	}
	if session.resource != resource {
		return errors.New("Resource session belongs to another Resource")
	}
	if session.agentProvider != client.agentClaims.Issuer || session.agent != client.identifier ||
		session.parentAgent != client.agentClaims.ParentAgent {
		return errors.New("Resource session belongs to another Agent")
	}
	return nil
}
