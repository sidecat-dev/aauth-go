package reference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type AgentConfig struct {
	Identifier  string
	SigningKey  aauth.SigningKey
	AgentToken  string
	KeyResolver aauth.KeyResolver
	HTTPClient  *http.Client
	Clock       aauth.Clock
}

type Agent struct {
	identifier  string
	signingKey  aauth.SigningKey
	agentToken  string
	keyResolver aauth.KeyResolver
	httpClient  *http.Client
	clock       aauth.Clock
}

type Grant struct {
	Resource  string
	AuthToken string
	Claims    aauth.AuthTokenClaims
}

type ResourceGrant struct {
	Resource      string
	ResourceToken string
	Claims        aauth.ResourceTokenClaims
}

// AccessGrant is a resource-managed authorization result. Token is opaque to
// the agent and is only presented back to Resource with a signed request.
type AccessGrant struct {
	Resource string
	Token    string
	Scope    []string
}

// AccessAuthorization is either a usable grant or a pending continuation.
type AccessAuthorization struct {
	Grant   *AccessGrant
	Pending *PendingAccessAuthorization
}

// PendingAccessAuthorization carries the same-origin signed-poll continuation
// for a resource-managed authorization.
type PendingAccessAuthorization struct {
	ID             string
	Resource       string
	Location       string
	RetryAfter     time.Duration
	NotBefore      time.Time
	Status         string
	Requirement    *aauth.Requirement
	requestedScope []string
}

func NewAgent(config AgentConfig) (*Agent, error) {
	if err := aauth.ValidateAgentIdentifier(config.Identifier); err != nil {
		return nil, err
	}
	if config.SigningKey.ID() == "" || config.AgentToken == "" || config.KeyResolver == nil ||
		config.HTTPClient == nil || config.Clock == nil {
		return nil, errors.New("reference: agent requires key, token, resolver, HTTP client, and clock")
	}
	return &Agent{
		identifier:  config.Identifier,
		signingKey:  config.SigningKey,
		agentToken:  config.AgentToken,
		keyResolver: config.KeyResolver,
		httpClient:  config.HTTPClient,
		clock:       config.Clock,
	}, nil
}

func (agent *Agent) CreateMission(ctx context.Context, endpoint string, proposal aauth.MissionProposal) (aauth.ApprovedMission, error) {
	var approved aauth.ApprovedMission
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return approved, err
	}
	body, err := json.Marshal(proposal)
	if err != nil {
		return approved, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return approved, err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(request, agent.signingKey, agent.agentToken, agent.clock); err != nil {
		return approved, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return approved, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return approved, responseError(response)
	}
	missionBytes, err := io.ReadAll(io.LimitReader(response.Body, maxJSONBody+1))
	if err != nil {
		return approved, err
	}
	if len(missionBytes) > maxJSONBody {
		return approved, errors.New("reference: mission response is too large")
	}
	reference, err := aauth.ParseMissionHeader(response.Header.Get("AAuth-Mission"))
	if err != nil {
		return approved, err
	}
	approved = aauth.ApprovedMission{
		Reference: reference,
		Bytes:     append([]byte(nil), missionBytes...),
	}
	if err := approved.ValidateExactBytes(); err != nil {
		return approved, err
	}
	var blob struct {
		Approver string `json:"approver"`
		Agent    string `json:"agent"`
	}
	if err := json.Unmarshal(missionBytes, &blob); err != nil {
		return approved, fmt.Errorf("reference: decode approved mission: %w", err)
	}
	if blob.Approver != reference.Approver || blob.Agent != agent.identifier {
		return approved, errors.New("reference: approved mission body does not match agent or approver")
	}
	return approved, nil
}

func (agent *Agent) Authorize(
	ctx context.Context,
	resourceEndpoint string,
	personServerEndpoint string,
	scopes []string,
	mission aauth.ApprovedMission,
) (Grant, error) {
	if err := aauth.ValidateEndpoint(personServerEndpoint); err != nil {
		return Grant{}, err
	}
	personServerID, err := endpointIdentifier(personServerEndpoint)
	if err != nil {
		return Grant{}, err
	}
	if mission.Reference.Approver != personServerID {
		return Grant{}, errors.New("reference: mission approver does not match person-server endpoint")
	}
	resourceGrant, err := agent.RequestResourceToken(ctx, resourceEndpoint, scopes, mission)
	if err != nil {
		return Grant{}, err
	}
	return agent.ExchangeResourceToken(ctx, personServerEndpoint, resourceGrant)
}

func (agent *Agent) RequestResourceToken(
	ctx context.Context,
	resourceEndpoint string,
	scopes []string,
	mission aauth.ApprovedMission,
) (ResourceGrant, error) {
	if err := mission.ValidateExactBytes(); err != nil {
		return ResourceGrant{}, err
	}
	return agent.requestResourceToken(ctx, resourceEndpoint, scopes, mission.Reference)
}

// RequestResourceTokenForReference is used by an intermediary resource, which
// receives the mission reference in an upstream auth token but never receives
// or dereferences the mission body.
func (agent *Agent) RequestResourceTokenForReference(
	ctx context.Context,
	resourceEndpoint string,
	scopes []string,
	mission aauth.MissionReference,
) (ResourceGrant, error) {
	if err := mission.Validate(); err != nil {
		return ResourceGrant{}, err
	}
	return agent.requestResourceToken(ctx, resourceEndpoint, scopes, mission)
}

func (agent *Agent) requestResourceToken(
	ctx context.Context,
	resourceEndpoint string,
	scopes []string,
	mission aauth.MissionReference,
) (ResourceGrant, error) {
	var grant ResourceGrant
	if err := aauth.ValidateEndpoint(resourceEndpoint); err != nil {
		return grant, err
	}
	requestedScopes, err := parseScopes(strings.Join(scopes, " "))
	if err != nil {
		return grant, err
	}
	resourceID, err := endpointIdentifier(resourceEndpoint)
	if err != nil {
		return grant, err
	}
	resourceBody, err := json.Marshal(map[string]string{"scope": strings.Join(requestedScopes, " ")})
	if err != nil {
		return grant, err
	}
	resourceRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, resourceEndpoint, bytes.NewReader(resourceBody))
	if err != nil {
		return grant, err
	}
	resourceRequest.Header.Set("Content-Type", "application/json")
	missionHeader, err := mission.Header()
	if err != nil {
		return grant, err
	}
	resourceRequest.Header.Set("AAuth-Mission", missionHeader)
	if err := aauth.SignRequest(resourceRequest, agent.signingKey, agent.agentToken, agent.clock); err != nil {
		return grant, err
	}
	resourceResponse, err := agent.httpClient.Do(resourceRequest)
	if err != nil {
		return grant, err
	}
	defer resourceResponse.Body.Close()
	if resourceResponse.StatusCode != http.StatusOK {
		return grant, responseError(resourceResponse)
	}
	var resourceResult struct {
		ResourceToken string `json:"resource_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resourceResponse.Body, maxJSONBody)).Decode(&resourceResult); err != nil {
		return grant, err
	}
	resourceClaims, err := aauth.VerifyResourceToken(ctx, resourceResult.ResourceToken, agent.keyResolver, agent.clock)
	if err != nil {
		return grant, err
	}
	agentThumbprint, err := agent.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return grant, err
	}
	if resourceClaims.Issuer != resourceID ||
		resourceClaims.Agent != agent.identifier || resourceClaims.AgentJKT != agentThumbprint ||
		resourceClaims.Mission == nil || *resourceClaims.Mission != mission {
		return grant, errors.New("reference: resource token does not match the authorization request")
	}
	return ResourceGrant{
		Resource:      resourceID,
		ResourceToken: resourceResult.ResourceToken,
		Claims:        resourceClaims,
	}, nil
}

func (agent *Agent) ExchangeResourceToken(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
) (Grant, error) {
	agentClaims, err := aauth.VerifyAgentToken(ctx, agent.agentToken, agent.keyResolver, agent.clock)
	if err != nil {
		return Grant{}, err
	}
	if agentClaims.ParentAgent != "" {
		return Grant{}, errors.New("reference: sub-agent cannot request authorization directly")
	}
	thumbprint, err := agent.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return Grant{}, err
	}
	if resourceGrant.Claims.Agent != agent.identifier || resourceGrant.Claims.AgentJKT != thumbprint {
		return Grant{}, errors.New("reference: resource token is not bound to the requesting agent")
	}
	return agent.exchangeResourceToken(
		ctx,
		personServerEndpoint,
		resourceGrant,
		"",
		agent.identifier,
		agent.signingKey.PublicJWK(),
		nil,
		"",
	)
}

func (agent *Agent) AuthorizeSubagent(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	subagentToken string,
) (Grant, error) {
	parentClaims, err := aauth.VerifyAgentToken(ctx, agent.agentToken, agent.keyResolver, agent.clock)
	if err != nil {
		return Grant{}, err
	}
	if parentClaims.ParentAgent != "" {
		return Grant{}, errors.New("reference: sub-agent cannot mediate another sub-agent")
	}
	subagentClaims, err := aauth.VerifyAgentToken(ctx, subagentToken, agent.keyResolver, agent.clock)
	if err != nil {
		return Grant{}, err
	}
	if subagentClaims.ParentAgent != agent.identifier {
		return Grant{}, errors.New("reference: sub-agent token does not name the signing parent")
	}
	subagentThumbprint, err := subagentClaims.Confirmation.JWK.Thumbprint()
	if err != nil {
		return Grant{}, err
	}
	if resourceGrant.Claims.Agent != subagentClaims.Subject ||
		resourceGrant.Claims.AgentJKT != subagentThumbprint {
		return Grant{}, errors.New("reference: resource token is not bound to the sub-agent")
	}
	return agent.exchangeResourceToken(
		ctx,
		personServerEndpoint,
		resourceGrant,
		subagentToken,
		subagentClaims.Subject,
		subagentClaims.Confirmation.JWK,
		&aauth.Actor{Agent: agent.identifier},
		"",
	)
}

func (agent *Agent) ExchangeChainedResourceToken(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	upstreamToken string,
) (Grant, error) {
	agentClaims, err := aauth.VerifyAgentToken(ctx, agent.agentToken, agent.keyResolver, agent.clock)
	if err != nil {
		return Grant{}, err
	}
	if agentClaims.ParentAgent != "" {
		return Grant{}, errors.New("reference: sub-agent cannot perform call chaining")
	}
	upstream, err := aauth.VerifyAuthToken(ctx, upstreamToken, agent.keyResolver, agent.clock)
	if err != nil {
		return Grant{}, err
	}
	if upstream.Audience != agentClaims.Issuer {
		return Grant{}, errors.New("reference: upstream auth-token audience does not match intermediary issuer")
	}
	personServerID, err := endpointIdentifier(personServerEndpoint)
	if err != nil {
		return Grant{}, err
	}
	if upstream.Mission != nil {
		if upstream.Mission.Approver != personServerID {
			return Grant{}, errors.New("reference: upstream mission routes to a different person server")
		}
	} else if upstream.Issuer != personServerID {
		return Grant{}, errors.New("reference: upstream token without a mission routes to its issuer")
	}
	thumbprint, err := agent.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return Grant{}, err
	}
	if resourceGrant.Claims.Agent != agent.identifier || resourceGrant.Claims.AgentJKT != thumbprint {
		return Grant{}, errors.New("reference: downstream resource token is not bound to the intermediary")
	}
	return agent.exchangeResourceToken(
		ctx,
		personServerEndpoint,
		resourceGrant,
		"",
		agent.identifier,
		agent.signingKey.PublicJWK(),
		&aauth.Actor{Agent: agent.identifier, Actor: upstream.Actor},
		upstreamToken,
	)
}

func (agent *Agent) exchangeResourceToken(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	subagentToken string,
	expectedAgent string,
	expectedKey aauth.JWK,
	expectedActor *aauth.Actor,
	upstreamToken string,
) (Grant, error) {
	if err := aauth.ValidateEndpoint(personServerEndpoint); err != nil {
		return Grant{}, err
	}
	personServerID, err := endpointIdentifier(personServerEndpoint)
	if err != nil {
		return Grant{}, err
	}
	expectedIssuer := personServerID
	if resourceGrant.Claims.Audience != personServerID {
		if resourceGrant.Claims.Mission == nil ||
			resourceGrant.Claims.Mission.Approver != personServerID {
			return Grant{}, errors.New("reference: federated resource token is not governed by the person server")
		}
		expectedIssuer = resourceGrant.Claims.Audience
	}
	tokenInput := map[string]string{"resource_token": resourceGrant.ResourceToken}
	if subagentToken != "" {
		tokenInput["subagent_token"] = subagentToken
	}
	if upstreamToken != "" {
		tokenInput["upstream_token"] = upstreamToken
	}
	tokenBody, err := json.Marshal(tokenInput)
	if err != nil {
		return Grant{}, err
	}
	tokenRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, personServerEndpoint, bytes.NewReader(tokenBody))
	if err != nil {
		return Grant{}, err
	}
	tokenRequest.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(tokenRequest, agent.signingKey, agent.agentToken, agent.clock); err != nil {
		return Grant{}, err
	}
	tokenResponse, err := agent.httpClient.Do(tokenRequest)
	if err != nil {
		return Grant{}, err
	}
	defer tokenResponse.Body.Close()
	if tokenResponse.StatusCode != http.StatusOK {
		return Grant{}, responseError(tokenResponse)
	}
	var tokenResult struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(io.LimitReader(tokenResponse.Body, maxJSONBody)).Decode(&tokenResult); err != nil {
		return Grant{}, err
	}
	authClaims, err := aauth.VerifyAuthToken(ctx, tokenResult.AuthToken, agent.keyResolver, agent.clock)
	if err != nil {
		return Grant{}, err
	}
	requiredScopes, err := parseScopes(resourceGrant.Claims.Scope)
	if err != nil {
		return Grant{}, err
	}
	if authClaims.Issuer != expectedIssuer ||
		authClaims.Mission == nil ||
		resourceGrant.Claims.Mission == nil ||
		*authClaims.Mission != *resourceGrant.Claims.Mission {
		return Grant{}, errors.New("reference: auth token does not match the resource token")
	}
	if err := aauth.ValidateAuthTokenContext(
		authClaims,
		resourceGrant.Resource,
		expectedAgent,
		expectedKey,
		requiredScopes,
	); err != nil {
		return Grant{}, err
	}
	if !actorsEqual(authClaims.Actor, expectedActor) {
		return Grant{}, errors.New("reference: auth token contains an unexpected act chain")
	}
	return Grant{
		Resource:  resourceGrant.Resource,
		AuthToken: tokenResult.AuthToken,
		Claims:    authClaims,
	}, nil
}

func actorsEqual(left, right *aauth.Actor) bool {
	for left != nil && right != nil {
		if left.Agent != right.Agent {
			return false
		}
		left = left.Actor
		right = right.Actor
	}
	return left == nil && right == nil
}

func (agent *Agent) DoAuthorized(
	ctx context.Context,
	method string,
	endpoint string,
	grant Grant,
) (*http.Response, error) {
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return nil, err
	}
	resourceID, err := endpointIdentifier(endpoint)
	if err != nil {
		return nil, err
	}
	if resourceID != grant.Resource || grant.AuthToken == "" {
		return nil, errors.New("reference: grant does not apply to endpoint")
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if err := aauth.SignRequest(request, agent.signingKey, grant.AuthToken, agent.clock); err != nil {
		return nil, err
	}
	return agent.httpClient.Do(request)
}

// RequestResourceManagedAccess asks a resource to authorize immediately or
// return a deferred continuation.
func (agent *Agent) RequestResourceManagedAccess(
	ctx context.Context,
	resourceEndpoint string,
	scopes []string,
) (AccessAuthorization, error) {
	var authorization AccessAuthorization
	if err := aauth.ValidateEndpoint(resourceEndpoint); err != nil {
		return authorization, err
	}
	requestedScopes, err := parseScopes(strings.Join(scopes, " "))
	if err != nil {
		return authorization, err
	}
	body, err := json.Marshal(map[string]string{"scope": strings.Join(requestedScopes, " ")})
	if err != nil {
		return authorization, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, resourceEndpoint, bytes.NewReader(body))
	if err != nil {
		return authorization, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Prefer", "wait=0")
	if err := aauth.SignRequest(request, agent.signingKey, agent.agentToken, agent.clock); err != nil {
		return authorization, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return authorization, err
	}
	defer response.Body.Close()
	resourceID, err := endpointIdentifier(resourceEndpoint)
	if err != nil {
		return authorization, err
	}
	switch response.StatusCode {
	case http.StatusOK:
		grant, err := parseAccessGrantResponse(response, resourceID, requestedScopes)
		if err != nil {
			return authorization, err
		}
		authorization.Grant = &grant
		return authorization, nil
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			return authorization, err
		}
		pending, err := newPendingAccessAuthorization(resourceID, requestedScopes, deferred, agent.clock.Now())
		if err != nil {
			return authorization, err
		}
		authorization.Pending = &pending
		return authorization, nil
	default:
		return authorization, responseError(response)
	}
}

func parseAccessGrantResponse(
	response *http.Response,
	resourceID string,
	requestedScopes []string,
) (AccessGrant, error) {
	var grant AccessGrant
	values := response.Header.Values("AAuth-Access")
	if len(values) != 1 {
		return grant, errors.New("reference: resource did not return exactly one AAuth-Access credential")
	}
	if err := aauth.ValidateAccessToken(values[0]); err != nil {
		return grant, err
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxJSONBody+1))
	if err != nil {
		return grant, err
	}
	if len(responseBody) > maxJSONBody {
		return grant, errors.New("reference: authorization response is too large")
	}
	var result struct {
		Status string `json:"status"`
		Scope  string `json:"scope"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return grant, fmt.Errorf("reference: decode authorization response: %w", err)
	}
	grantedScopes, err := parseScopes(result.Scope)
	if err != nil {
		return grant, fmt.Errorf("reference: invalid granted scope: %w", err)
	}
	if result.Status != "authorized" || !scopesContained(grantedScopes, requestedScopes) {
		return grant, errors.New("reference: authorization response contains an invalid status or scope")
	}
	return AccessGrant{
		Resource: resourceID,
		Token:    values[0],
		Scope:    append([]string(nil), grantedScopes...),
	}, nil
}

func newPendingAccessAuthorization(
	resourceID string,
	requestedScope []string,
	deferred aauth.DeferredResponse,
	now time.Time,
) (PendingAccessAuthorization, error) {
	parsed, err := url.Parse(deferred.Location)
	if err != nil {
		return PendingAccessAuthorization{}, err
	}
	locationResource, err := endpointIdentifier(deferred.Location)
	if err != nil {
		return PendingAccessAuthorization{}, err
	}
	if locationResource != resourceID {
		return PendingAccessAuthorization{}, errors.New("reference: pending authorization moved to another resource")
	}
	return PendingAccessAuthorization{
		ID:             path.Base(parsed.Path),
		Resource:       resourceID,
		Location:       deferred.Location,
		RetryAfter:     deferred.RetryAfter,
		NotBefore:      now.Add(deferred.RetryAfter),
		Status:         deferred.Status,
		Requirement:    deferred.Requirement,
		requestedScope: append([]string(nil), requestedScope...),
	}, nil
}

// PollResourceManagedAccess makes one signed GET to a pending resource
// authorization. It returns another pending continuation or the terminal grant.
func (agent *Agent) PollResourceManagedAccess(
	ctx context.Context,
	pending *PendingAccessAuthorization,
) (AccessAuthorization, error) {
	var authorization AccessAuthorization
	if pending == nil {
		return authorization, errors.New("reference: pending access authorization is required")
	}
	if agent.clock.Now().Before(pending.NotBefore) {
		return authorization, errors.New("reference: pending authorization is not ready to poll")
	}
	if err := aauth.ValidatePollingEndpoint(pending.Location); err != nil {
		return authorization, err
	}
	resourceID, err := endpointIdentifier(pending.Location)
	if err != nil {
		return authorization, err
	}
	if resourceID != pending.Resource {
		return authorization, errors.New("reference: pending authorization does not apply to its endpoint")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.Location, nil)
	if err != nil {
		return authorization, err
	}
	request.Header.Set("Prefer", "wait=0")
	if err := aauth.SignRequest(request, agent.signingKey, agent.agentToken, agent.clock); err != nil {
		return authorization, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return authorization, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		grant, err := parseAccessGrantResponse(response, pending.Resource, pending.requestedScope)
		if err != nil {
			return authorization, err
		}
		authorization.Grant = &grant
		return authorization, nil
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			return authorization, err
		}
		next, err := newPendingAccessAuthorization(
			pending.Resource,
			pending.requestedScope,
			deferred,
			agent.clock.Now(),
		)
		if err != nil {
			return authorization, err
		}
		*pending = next
		authorization.Pending = pending
		return authorization, nil
	default:
		responseErr := responseError(response)
		var problem *aauth.ProblemError
		if response.StatusCode == http.StatusTooManyRequests &&
			errors.As(responseErr, &problem) &&
			problem.Code == aauth.PollingSlowDown {
			pending.RetryAfter += 5 * time.Second
			pending.NotBefore = agent.clock.Now().Add(pending.RetryAfter)
		}
		return authorization, responseErr
	}
}

// DoWithAccess signs and sends a request using a resource-managed grant. The
// grant is updated in place when the resource rotates AAuth-Access.
func (agent *Agent) DoWithAccess(
	ctx context.Context,
	method string,
	endpoint string,
	grant *AccessGrant,
) (*http.Response, error) {
	if grant == nil {
		return nil, errors.New("reference: access grant is required")
	}
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return nil, err
	}
	resourceID, err := endpointIdentifier(endpoint)
	if err != nil {
		return nil, err
	}
	if resourceID != grant.Resource {
		return nil, errors.New("reference: access grant does not apply to endpoint")
	}
	authorization, err := aauth.AccessAuthorization(grant.Token)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", authorization)
	if err := aauth.SignRequest(request, agent.signingKey, agent.agentToken, agent.clock); err != nil {
		return nil, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	values := response.Header.Values("AAuth-Access")
	if len(values) == 0 {
		return response, nil
	}
	if len(values) != 1 {
		response.Body.Close()
		return nil, errors.New("reference: resource returned more than one AAuth-Access credential")
	}
	if err := aauth.ValidateAccessToken(values[0]); err != nil {
		response.Body.Close()
		return nil, err
	}
	grant.Token = values[0]
	return response, nil
}

func responseError(response *http.Response) error {
	if strings.HasPrefix(
		strings.ToLower(response.Header.Get("Content-Type")),
		"application/problem+json",
	) {
		problem, err := aauth.DecodeProblemResponse(response)
		if err != nil {
			return err
		}
		return problem
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
	return fmt.Errorf("reference: server returned %s: %s", response.Status, strings.TrimSpace(string(body)))
}
