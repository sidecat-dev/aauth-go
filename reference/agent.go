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
	"strconv"
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
	requestedR3   *aauth.R3OperationSet
}

// TokenAuthorization is either an auth-token grant or a signed-poll
// continuation at a person server.
type TokenAuthorization struct {
	Grant   *Grant
	Pending *PendingTokenAuthorization
}

// PendingTokenAuthorization retains the validation context needed to verify a
// person server's eventual auth-token response.
type PendingTokenAuthorization struct {
	ID           string
	PersonServer string
	Location     string
	RetryAfter   time.Duration
	NotBefore    time.Time
	Status       string
	Requirement  *aauth.Requirement

	resourceGrant  ResourceGrant
	expectedIssuer string
	expectedAgent  string
	expectedKey    aauth.JWK
	expectedActor  *aauth.Actor
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

// PermissionAuthorization is either a terminal permission decision or a
// signed-poll continuation at the person server.
type PermissionAuthorization struct {
	Decision *aauth.PermissionResponse
	Pending  *PendingPermissionAuthorization
}

// PendingPermissionAuthorization retains a same-origin permission continuation.
type PendingPermissionAuthorization struct {
	ID           string
	PersonServer string
	Location     string
	RetryAfter   time.Duration
	NotBefore    time.Time
	Status       string
	Requirement  *aauth.Requirement
}

// InteractionAuthorization is either a terminal person-server interaction
// result or a signed-poll continuation.
type InteractionAuthorization struct {
	Completed bool
	Status    string
	Answer    string
	Pending   *PendingInteractionAuthorization
}

// PendingInteractionAuthorization retains an ownership-bound person-server
// interaction continuation, including any clarification the agent must answer.
type PendingInteractionAuthorization struct {
	ID            string
	Type          aauth.InteractionType
	PersonServer  string
	Location      string
	RetryAfter    time.Duration
	NotBefore     time.Time
	Status        string
	Requirement   *aauth.Requirement
	Clarification string
	Timeout       time.Duration
	Options       []string
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

// RequestPermission asks a person server to govern a local action. The result
// is shaped for either an immediate decision or the draft's deferred form.
func (agent *Agent) RequestPermission(
	ctx context.Context,
	endpoint string,
	input aauth.PermissionRequest,
) (PermissionAuthorization, error) {
	var authorization PermissionAuthorization
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return authorization, err
	}
	if err := input.Validate(); err != nil {
		return authorization, err
	}
	personServer, err := endpointIdentifier(endpoint)
	if err != nil {
		return authorization, err
	}
	if input.Mission != nil && input.Mission.Approver != personServer {
		return authorization, errors.New("reference: permission mission approver does not match person-server endpoint")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return authorization, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return authorization, err
	}
	request.Header.Set("Content-Type", "application/json")
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
		var decision aauth.PermissionResponse
		if err := decodeJSONBytes(io.LimitReader(response.Body, maxJSONBody+1), &decision); err != nil {
			return authorization, err
		}
		if err := decision.Validate(); err != nil {
			return authorization, err
		}
		authorization.Decision = &decision
		return authorization, nil
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			return authorization, err
		}
		pendingServer, err := endpointIdentifier(deferred.Location)
		if err != nil {
			return authorization, err
		}
		if pendingServer != personServer {
			return authorization, errors.New("reference: pending permission moved to another person server")
		}
		parsed, err := url.Parse(deferred.Location)
		if err != nil {
			return authorization, err
		}
		authorization.Pending = &PendingPermissionAuthorization{
			ID:           path.Base(parsed.Path),
			PersonServer: personServer,
			Location:     deferred.Location,
			RetryAfter:   deferred.RetryAfter,
			NotBefore:    agent.clock.Now().Add(deferred.RetryAfter),
			Status:       deferred.Status,
			Requirement:  deferred.Requirement,
		}
		return authorization, nil
	default:
		return authorization, responseError(response)
	}
}

// PollPermission makes one signed GET to a pending person-server permission
// request and returns either a refreshed continuation or a terminal decision.
func (agent *Agent) PollPermission(
	ctx context.Context,
	pending *PendingPermissionAuthorization,
) (PermissionAuthorization, error) {
	var authorization PermissionAuthorization
	if pending == nil {
		return authorization, errors.New("reference: pending permission is required")
	}
	if agent.clock.Now().Before(pending.NotBefore) {
		return authorization, errors.New("reference: pending permission is not ready to poll")
	}
	if err := aauth.ValidatePollingEndpoint(pending.Location); err != nil {
		return authorization, err
	}
	personServer, err := endpointIdentifier(pending.Location)
	if err != nil {
		return authorization, err
	}
	if personServer != pending.PersonServer {
		return authorization, errors.New("reference: pending permission does not apply to its endpoint")
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
		var decision aauth.PermissionResponse
		if err := decodeJSONBytes(io.LimitReader(response.Body, maxJSONBody+1), &decision); err != nil {
			return authorization, err
		}
		if err := decision.Validate(); err != nil {
			return authorization, err
		}
		authorization.Decision = &decision
		return authorization, nil
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			return authorization, err
		}
		next, err := newPendingPermissionAuthorization(
			pending.PersonServer,
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
		updatePollingBackoff(
			response,
			&pending.RetryAfter,
			&pending.NotBefore,
			agent.clock.Now(),
		)
		return authorization, responseErr
	}
}

func newPendingPermissionAuthorization(
	personServer string,
	deferred aauth.DeferredResponse,
	now time.Time,
) (PendingPermissionAuthorization, error) {
	locationServer, err := endpointIdentifier(deferred.Location)
	if err != nil {
		return PendingPermissionAuthorization{}, err
	}
	if locationServer != personServer {
		return PendingPermissionAuthorization{}, errors.New("reference: pending permission moved to another person server")
	}
	parsed, err := url.Parse(deferred.Location)
	if err != nil {
		return PendingPermissionAuthorization{}, err
	}
	return PendingPermissionAuthorization{
		ID:           path.Base(parsed.Path),
		PersonServer: personServer,
		Location:     deferred.Location,
		RetryAfter:   deferred.RetryAfter,
		NotBefore:    now.Add(deferred.RetryAfter),
		Status:       deferred.Status,
		Requirement:  deferred.Requirement,
	}, nil
}

// RecordAudit submits one signed mission-bound completed-action record.
func (agent *Agent) RecordAudit(
	ctx context.Context,
	endpoint string,
	input aauth.AuditRequest,
) error {
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return err
	}
	if err := input.Validate(); err != nil {
		return err
	}
	personServer, err := endpointIdentifier(endpoint)
	if err != nil {
		return err
	}
	if input.Mission.Approver != personServer {
		return errors.New("reference: audit mission approver does not match person-server endpoint")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(request, agent.signingKey, agent.agentToken, agent.clock); err != nil {
		return err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return responseError(response)
	}
	return nil
}

// ProposeMissionCompletion submits the draft's completion interaction and
// returns the person-server review continuation.
func (agent *Agent) ProposeMissionCompletion(
	ctx context.Context,
	endpoint string,
	mission aauth.MissionReference,
	summary string,
) (InteractionAuthorization, error) {
	return agent.RequestInteraction(ctx, endpoint, aauth.InteractionRequest{
		Type:    aauth.InteractionTypeCompletion,
		Summary: summary,
		Mission: &mission,
	})
}

// RequestInteraction submits a signed person-server interaction request.
func (agent *Agent) RequestInteraction(
	ctx context.Context,
	endpoint string,
	input aauth.InteractionRequest,
) (InteractionAuthorization, error) {
	var authorization InteractionAuthorization
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return authorization, err
	}
	if err := input.Validate(); err != nil {
		return authorization, err
	}
	personServer, err := endpointIdentifier(endpoint)
	if err != nil {
		return authorization, err
	}
	if input.Mission != nil && input.Mission.Approver != personServer {
		return authorization, errors.New("reference: interaction mission approver does not match person-server endpoint")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return authorization, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return authorization, err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(request, agent.signingKey, agent.agentToken, agent.clock); err != nil {
		return authorization, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return authorization, err
	}
	defer response.Body.Close()
	return decodeInteractionAuthorization(response, personServer, agent.clock.Now(), input.Type)
}

// PollInteraction makes one signed GET to a pending person-server interaction.
func (agent *Agent) PollInteraction(
	ctx context.Context,
	pending *PendingInteractionAuthorization,
) (InteractionAuthorization, error) {
	var authorization InteractionAuthorization
	if pending == nil {
		return authorization, errors.New("reference: pending interaction is required")
	}
	if agent.clock.Now().Before(pending.NotBefore) {
		return authorization, errors.New("reference: pending interaction is not ready to poll")
	}
	if err := aauth.ValidatePollingEndpoint(pending.Location); err != nil {
		return authorization, err
	}
	personServer, err := endpointIdentifier(pending.Location)
	if err != nil {
		return authorization, err
	}
	if personServer != pending.PersonServer {
		return authorization, errors.New("reference: pending interaction does not apply to its endpoint")
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
	authorization, err = decodeInteractionAuthorization(
		response,
		pending.PersonServer,
		agent.clock.Now(),
		pending.Type,
	)
	if authorization.Pending != nil {
		*pending = *authorization.Pending
		authorization.Pending = pending
	}
	return authorization, err
}

// RespondToClarification posts one signed Markdown answer to a pending
// interaction and updates the continuation returned by the person server.
func (agent *Agent) RespondToClarification(
	ctx context.Context,
	pending *PendingInteractionAuthorization,
	answer string,
) error {
	if pending == nil ||
		pending.Requirement == nil ||
		pending.Requirement.Type != aauth.RequirementClarification {
		return errors.New("reference: pending interaction is not awaiting clarification")
	}
	body, err := json.Marshal(aauth.ClarificationResponse{
		Action:                "clarification_response",
		ClarificationResponse: answer,
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		pending.Location,
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(request, agent.signingKey, agent.agentToken, agent.clock); err != nil {
		return err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	authorization, err := decodeInteractionAuthorization(
		response,
		pending.PersonServer,
		agent.clock.Now(),
		pending.Type,
	)
	if err != nil {
		return err
	}
	if authorization.Pending == nil {
		return errors.New("reference: clarification response unexpectedly terminated the interaction")
	}
	*pending = *authorization.Pending
	return nil
}

func decodeInteractionAuthorization(
	response *http.Response,
	personServer string,
	now time.Time,
	interactionType aauth.InteractionType,
) (InteractionAuthorization, error) {
	var authorization InteractionAuthorization
	switch response.StatusCode {
	case http.StatusOK:
		switch interactionType {
		case aauth.InteractionTypeCompletion:
			body, err := io.ReadAll(io.LimitReader(response.Body, maxJSONBody+1))
			if err != nil {
				return authorization, err
			}
			if len(body) > maxJSONBody {
				return authorization, errors.New("reference: interaction response is too large")
			}
			if len(bytes.TrimSpace(body)) != 0 {
				var terminal struct {
					Status string `json:"status"`
				}
				if err := decodeJSONBytes(bytes.NewReader(body), &terminal); err != nil {
					return authorization, err
				}
				if terminal.Status != "completed" {
					return authorization, errors.New("reference: completion response status is invalid")
				}
			}
			authorization.Completed = true
			authorization.Status = "completed"
		case aauth.InteractionTypeQuestion:
			var terminal struct {
				Answer *string `json:"answer"`
			}
			if err := decodeJSONBytes(io.LimitReader(response.Body, maxJSONBody+1), &terminal); err != nil {
				return authorization, err
			}
			if terminal.Answer == nil {
				return authorization, errors.New("reference: question response is missing its answer")
			}
			authorization.Answer = *terminal.Answer
			authorization.Status = "answered"
		case aauth.InteractionTypeInteraction, aauth.InteractionTypePayment:
			var terminal struct {
				Status string `json:"status"`
			}
			if err := decodeJSONBytes(io.LimitReader(response.Body, maxJSONBody+1), &terminal); err != nil {
				return authorization, err
			}
			if terminal.Status == "" {
				return authorization, errors.New("reference: relay response status is missing")
			}
			authorization.Status = terminal.Status
		default:
			return authorization, errors.New("reference: interaction type is invalid")
		}
		return authorization, nil
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			return authorization, err
		}
		pendingServer, err := endpointIdentifier(deferred.Location)
		if err != nil {
			return authorization, err
		}
		if pendingServer != personServer {
			return authorization, errors.New("reference: pending interaction moved to another person server")
		}
		parsed, err := url.Parse(deferred.Location)
		if err != nil {
			return authorization, err
		}
		authorization.Pending = &PendingInteractionAuthorization{
			ID:            path.Base(parsed.Path),
			Type:          interactionType,
			PersonServer:  personServer,
			Location:      deferred.Location,
			RetryAfter:    deferred.RetryAfter,
			NotBefore:     now.Add(deferred.RetryAfter),
			Status:        deferred.Status,
			Requirement:   deferred.Requirement,
			Clarification: deferred.Clarification,
			Timeout:       deferred.Timeout,
			Options:       append([]string(nil), deferred.Options...),
		}
		return authorization, nil
	default:
		return authorization, responseError(response)
	}
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

// AuthorizeR3 performs the ordinary four-party authorization journey while
// asking the resource for one content-addressed R3 operation set.
func (agent *Agent) AuthorizeR3(
	ctx context.Context,
	resourceEndpoint string,
	personServerEndpoint string,
	scopes []string,
	mission aauth.ApprovedMission,
	operations aauth.R3OperationSet,
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
	resourceGrant, err := agent.RequestResourceTokenR3(ctx, resourceEndpoint, scopes, mission, operations)
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
	return agent.requestResourceToken(ctx, resourceEndpoint, scopes, mission.Reference, nil)
}

// RequestResourceTokenR3 asks the resource to validate an R3 operation set and
// return a resource token that identifies the resulting exact document.
func (agent *Agent) RequestResourceTokenR3(
	ctx context.Context,
	resourceEndpoint string,
	scopes []string,
	mission aauth.ApprovedMission,
	operations aauth.R3OperationSet,
) (ResourceGrant, error) {
	if err := mission.ValidateExactBytes(); err != nil {
		return ResourceGrant{}, err
	}
	if err := operations.Validate(); err != nil {
		return ResourceGrant{}, err
	}
	cloned := operations.Clone()
	return agent.requestResourceToken(ctx, resourceEndpoint, scopes, mission.Reference, &cloned)
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
	return agent.requestResourceToken(ctx, resourceEndpoint, scopes, mission, nil)
}

func (agent *Agent) requestResourceToken(
	ctx context.Context,
	resourceEndpoint string,
	scopes []string,
	mission aauth.MissionReference,
	r3Operations *aauth.R3OperationSet,
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
	resourceInput := struct {
		Scope        string                `json:"scope"`
		R3Operations *aauth.R3OperationSet `json:"r3_operations,omitempty"`
	}{
		Scope:        strings.Join(requestedScopes, " "),
		R3Operations: r3Operations,
	}
	resourceBody, err := json.Marshal(resourceInput)
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
	if r3Operations != nil && (resourceClaims.R3URI == "" || resourceClaims.R3S256 == "") {
		return grant, errors.New("reference: resource token omitted the requested R3 reference")
	}
	var requestedR3 *aauth.R3OperationSet
	if r3Operations != nil {
		cloned := r3Operations.Clone()
		requestedR3 = &cloned
	}
	return ResourceGrant{
		Resource:      resourceID,
		ResourceToken: resourceResult.ResourceToken,
		Claims:        resourceClaims,
		requestedR3:   requestedR3,
	}, nil
}

func (agent *Agent) ExchangeResourceToken(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
) (Grant, error) {
	authorization, err := agent.RequestTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
	)
	if err != nil {
		return Grant{}, err
	}
	if authorization.Grant == nil {
		return Grant{}, errors.New("reference: authorization is pending; use RequestTokenAuthorization and PollTokenAuthorization")
	}
	return *authorization.Grant, nil
}

// RequestTokenAuthorization exchanges a resource token at a person server and
// returns either the immediate auth-token grant or a deferred continuation.
func (agent *Agent) RequestTokenAuthorization(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
) (TokenAuthorization, error) {
	agentClaims, err := aauth.VerifyAgentToken(ctx, agent.agentToken, agent.keyResolver, agent.clock)
	if err != nil {
		return TokenAuthorization{}, err
	}
	if agentClaims.ParentAgent != "" {
		return TokenAuthorization{}, errors.New("reference: sub-agent cannot request authorization directly")
	}
	thumbprint, err := agent.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return TokenAuthorization{}, err
	}
	if resourceGrant.Claims.Agent != agent.identifier || resourceGrant.Claims.AgentJKT != thumbprint {
		return TokenAuthorization{}, errors.New("reference: resource token is not bound to the requesting agent")
	}
	return agent.requestTokenAuthorization(
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
	authorization, err := agent.RequestSubagentTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		subagentToken,
	)
	if err != nil {
		return Grant{}, err
	}
	if authorization.Grant == nil {
		return Grant{}, errors.New("reference: sub-agent authorization is pending; use RequestSubagentTokenAuthorization and PollTokenAuthorization")
	}
	return *authorization.Grant, nil
}

// AuthorizeChainedSubagent lets a resource acting as a parent agent extend its
// upstream authorization to a sub-agent. The returned token is bound to the
// sub-agent and records both the parent and the upstream delegation chain.
func (agent *Agent) AuthorizeChainedSubagent(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	subagentToken string,
	upstreamToken string,
) (Grant, error) {
	authorization, err := agent.RequestChainedSubagentTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		subagentToken,
		upstreamToken,
	)
	if err != nil {
		return Grant{}, err
	}
	if authorization.Grant == nil {
		return Grant{}, errors.New("reference: chained sub-agent authorization is pending; use RequestChainedSubagentTokenAuthorization and PollTokenAuthorization")
	}
	return *authorization.Grant, nil
}

// RequestSubagentTokenAuthorization lets a parent exchange a sub-agent's
// resource token and receive either an immediate grant or a continuation the
// parent polls with its own proof.
func (agent *Agent) RequestSubagentTokenAuthorization(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	subagentToken string,
) (TokenAuthorization, error) {
	return agent.requestSubagentTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		subagentToken,
		"",
	)
}

// RequestChainedSubagentTokenAuthorization is the deferred-capable form of
// AuthorizeChainedSubagent.
func (agent *Agent) RequestChainedSubagentTokenAuthorization(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	subagentToken string,
	upstreamToken string,
) (TokenAuthorization, error) {
	if upstreamToken == "" {
		return TokenAuthorization{}, errors.New("reference: upstream auth token is required")
	}
	return agent.requestSubagentTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		subagentToken,
		upstreamToken,
	)
}

func (agent *Agent) requestSubagentTokenAuthorization(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	subagentToken string,
	upstreamToken string,
) (TokenAuthorization, error) {
	parentClaims, err := aauth.VerifyAgentToken(ctx, agent.agentToken, agent.keyResolver, agent.clock)
	if err != nil {
		return TokenAuthorization{}, err
	}
	if parentClaims.ParentAgent != "" {
		return TokenAuthorization{}, errors.New("reference: sub-agent cannot mediate another sub-agent")
	}
	subagentClaims, err := aauth.VerifyAgentToken(ctx, subagentToken, agent.keyResolver, agent.clock)
	if err != nil {
		return TokenAuthorization{}, err
	}
	if subagentClaims.ParentAgent != agent.identifier {
		return TokenAuthorization{}, errors.New("reference: sub-agent token does not name the signing parent")
	}
	subagentThumbprint, err := subagentClaims.Confirmation.JWK.Thumbprint()
	if err != nil {
		return TokenAuthorization{}, err
	}
	if resourceGrant.Claims.Agent != subagentClaims.Subject ||
		resourceGrant.Claims.AgentJKT != subagentThumbprint {
		return TokenAuthorization{}, errors.New("reference: resource token is not bound to the sub-agent")
	}
	expectedActor := &aauth.Actor{Agent: agent.identifier}
	if upstreamToken != "" {
		upstream, err := aauth.VerifyAuthToken(ctx, upstreamToken, agent.keyResolver, agent.clock)
		if err != nil {
			return TokenAuthorization{}, err
		}
		if upstream.Audience != parentClaims.Issuer {
			return TokenAuthorization{}, errors.New("reference: upstream auth-token audience does not match intermediary issuer")
		}
		personServerID, err := endpointIdentifier(personServerEndpoint)
		if err != nil {
			return TokenAuthorization{}, err
		}
		if upstream.Mission != nil {
			if upstream.Mission.Approver != personServerID {
				return TokenAuthorization{}, errors.New("reference: upstream mission routes to a different person server")
			}
		} else if upstream.Issuer != personServerID {
			return TokenAuthorization{}, errors.New("reference: upstream token without a mission routes to its issuer")
		}
		expectedActor = authorizationActor(&upstream, agent.identifier)
	}
	return agent.requestTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		subagentToken,
		subagentClaims.Subject,
		subagentClaims.Confirmation.JWK,
		expectedActor,
		upstreamToken,
	)
}

func (agent *Agent) ExchangeChainedResourceToken(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	upstreamToken string,
) (Grant, error) {
	authorization, err := agent.RequestChainedTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		upstreamToken,
	)
	if err != nil {
		return Grant{}, err
	}
	if authorization.Grant == nil {
		return Grant{}, errors.New("reference: chained authorization is pending; use RequestChainedTokenAuthorization and PollTokenAuthorization")
	}
	return *authorization.Grant, nil
}

// RequestChainedTokenAuthorization exchanges a downstream resource token using
// an upstream authorization and preserves a deferred continuation when the
// person server needs more time.
func (agent *Agent) RequestChainedTokenAuthorization(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	upstreamToken string,
) (TokenAuthorization, error) {
	agentClaims, err := aauth.VerifyAgentToken(ctx, agent.agentToken, agent.keyResolver, agent.clock)
	if err != nil {
		return TokenAuthorization{}, err
	}
	if agentClaims.ParentAgent != "" {
		return TokenAuthorization{}, errors.New("reference: sub-agent cannot perform call chaining")
	}
	upstream, err := aauth.VerifyAuthToken(ctx, upstreamToken, agent.keyResolver, agent.clock)
	if err != nil {
		return TokenAuthorization{}, err
	}
	// The upstream token remains bound to the upstream caller. The
	// intermediary resource is selected by its audience and proves its own
	// identity with the separately presented agent token and request key.
	if upstream.Audience != agentClaims.Issuer {
		return TokenAuthorization{}, errors.New("reference: upstream auth-token audience does not match intermediary issuer")
	}
	personServerID, err := endpointIdentifier(personServerEndpoint)
	if err != nil {
		return TokenAuthorization{}, err
	}
	if upstream.Mission != nil {
		if upstream.Mission.Approver != personServerID {
			return TokenAuthorization{}, errors.New("reference: upstream mission routes to a different person server")
		}
	} else if upstream.Issuer != personServerID {
		return TokenAuthorization{}, errors.New("reference: upstream token without a mission routes to its issuer")
	}
	thumbprint, err := agent.signingKey.PublicJWK().Thumbprint()
	if err != nil {
		return TokenAuthorization{}, err
	}
	if resourceGrant.Claims.Agent != agent.identifier || resourceGrant.Claims.AgentJKT != thumbprint {
		return TokenAuthorization{}, errors.New("reference: downstream resource token is not bound to the intermediary")
	}
	return agent.requestTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		"",
		agent.identifier,
		agent.signingKey.PublicJWK(),
		authorizationActor(&upstream, ""),
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
	authorization, err := agent.requestTokenAuthorization(
		ctx,
		personServerEndpoint,
		resourceGrant,
		subagentToken,
		expectedAgent,
		expectedKey,
		expectedActor,
		upstreamToken,
	)
	if err != nil {
		return Grant{}, err
	}
	if authorization.Grant == nil {
		return Grant{}, errors.New("reference: authorization is pending; use a deferred token-authorization method")
	}
	return *authorization.Grant, nil
}

func (agent *Agent) requestTokenAuthorization(
	ctx context.Context,
	personServerEndpoint string,
	resourceGrant ResourceGrant,
	subagentToken string,
	expectedAgent string,
	expectedKey aauth.JWK,
	expectedActor *aauth.Actor,
	upstreamToken string,
) (TokenAuthorization, error) {
	var authorization TokenAuthorization
	if err := aauth.ValidateEndpoint(personServerEndpoint); err != nil {
		return authorization, err
	}
	personServerID, err := endpointIdentifier(personServerEndpoint)
	if err != nil {
		return authorization, err
	}
	expectedIssuer := personServerID
	if resourceGrant.Claims.Audience != personServerID {
		if resourceGrant.Claims.Mission == nil ||
			resourceGrant.Claims.Mission.Approver != personServerID {
			return authorization, errors.New("reference: federated resource token is not governed by the person server")
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
		return authorization, err
	}
	tokenRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, personServerEndpoint, bytes.NewReader(tokenBody))
	if err != nil {
		return authorization, err
	}
	tokenRequest.Header.Set("Content-Type", "application/json")
	tokenRequest.Header.Set("Prefer", "wait=0")
	if err := aauth.SignRequest(tokenRequest, agent.signingKey, agent.agentToken, agent.clock); err != nil {
		return authorization, err
	}
	tokenResponse, err := agent.httpClient.Do(tokenRequest)
	if err != nil {
		return authorization, err
	}
	defer tokenResponse.Body.Close()
	switch tokenResponse.StatusCode {
	case http.StatusOK:
		grant, err := agent.parseTokenGrantResponse(
			ctx,
			tokenResponse,
			resourceGrant,
			expectedIssuer,
			expectedAgent,
			expectedKey,
			expectedActor,
		)
		if err != nil {
			return authorization, err
		}
		authorization.Grant = &grant
		return authorization, nil
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(tokenResponse)
		if err != nil {
			return authorization, err
		}
		pending, err := newPendingTokenAuthorization(
			personServerID,
			resourceGrant,
			expectedIssuer,
			expectedAgent,
			expectedKey,
			expectedActor,
			deferred,
			agent.clock.Now(),
		)
		if err != nil {
			return authorization, err
		}
		authorization.Pending = &pending
		return authorization, nil
	default:
		return authorization, responseError(tokenResponse)
	}
}

func (agent *Agent) parseTokenGrantResponse(
	ctx context.Context,
	tokenResponse *http.Response,
	resourceGrant ResourceGrant,
	expectedIssuer string,
	expectedAgent string,
	expectedKey aauth.JWK,
	expectedActor *aauth.Actor,
) (Grant, error) {
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
	if authClaims.R3URI != resourceGrant.Claims.R3URI ||
		authClaims.R3S256 != resourceGrant.Claims.R3S256 {
		return Grant{}, errors.New("reference: auth token R3 reference does not match the resource token")
	}
	if resourceGrant.requestedR3 != nil {
		if authClaims.R3Granted == nil ||
			!resourceGrant.requestedR3.ContainsSet(*authClaims.R3Granted) {
			return Grant{}, errors.New("reference: auth token grants R3 operations outside the agent request")
		}
		if authClaims.R3Conditional != nil &&
			!resourceGrant.requestedR3.ContainsSet(*authClaims.R3Conditional) {
			return Grant{}, errors.New("reference: auth token conditionally grants R3 operations outside the agent request")
		}
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

func newPendingTokenAuthorization(
	personServer string,
	resourceGrant ResourceGrant,
	expectedIssuer string,
	expectedAgent string,
	expectedKey aauth.JWK,
	expectedActor *aauth.Actor,
	deferred aauth.DeferredResponse,
	now time.Time,
) (PendingTokenAuthorization, error) {
	parsed, err := url.Parse(deferred.Location)
	if err != nil {
		return PendingTokenAuthorization{}, err
	}
	locationServer, err := endpointIdentifier(deferred.Location)
	if err != nil {
		return PendingTokenAuthorization{}, err
	}
	if locationServer != personServer {
		return PendingTokenAuthorization{}, errors.New("reference: pending token authorization moved to another person server")
	}
	return PendingTokenAuthorization{
		ID:             path.Base(parsed.Path),
		PersonServer:   personServer,
		Location:       deferred.Location,
		RetryAfter:     deferred.RetryAfter,
		NotBefore:      now.Add(deferred.RetryAfter),
		Status:         deferred.Status,
		Requirement:    deferred.Requirement,
		resourceGrant:  resourceGrant,
		expectedIssuer: expectedIssuer,
		expectedAgent:  expectedAgent,
		expectedKey:    expectedKey,
		expectedActor:  copyActor(expectedActor),
	}, nil
}

// PollTokenAuthorization makes one signed GET to a pending person-server token
// request. It returns a refreshed continuation or the terminal auth-token
// grant.
func (agent *Agent) PollTokenAuthorization(
	ctx context.Context,
	pending *PendingTokenAuthorization,
) (TokenAuthorization, error) {
	var authorization TokenAuthorization
	if pending == nil {
		return authorization, errors.New("reference: pending token authorization is required")
	}
	if agent.clock.Now().Before(pending.NotBefore) {
		return authorization, errors.New("reference: pending token authorization is not ready to poll")
	}
	if err := aauth.ValidatePollingEndpoint(pending.Location); err != nil {
		return authorization, err
	}
	personServer, err := endpointIdentifier(pending.Location)
	if err != nil {
		return authorization, err
	}
	if personServer != pending.PersonServer {
		return authorization, errors.New("reference: pending token authorization does not apply to its endpoint")
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
		grant, err := agent.parseTokenGrantResponse(
			ctx,
			response,
			pending.resourceGrant,
			pending.expectedIssuer,
			pending.expectedAgent,
			pending.expectedKey,
			pending.expectedActor,
		)
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
		next, err := newPendingTokenAuthorization(
			pending.PersonServer,
			pending.resourceGrant,
			pending.expectedIssuer,
			pending.expectedAgent,
			pending.expectedKey,
			pending.expectedActor,
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
		updatePollingBackoff(
			response,
			&pending.RetryAfter,
			&pending.NotBefore,
			agent.clock.Now(),
		)
		return authorization, responseErr
	}
}

func copyActor(actor *aauth.Actor) *aauth.Actor {
	if actor == nil {
		return nil
	}
	return &aauth.Actor{
		Agent: actor.Agent,
		Actor: copyActor(actor.Actor),
	}
}

// authorizationActor preserves delegation order. A parent-mediated sub-agent
// records its parent first; call-chain delegation then records the upstream
// token's agent followed by any actor links that token already carried.
func authorizationActor(upstream *aauth.AuthTokenClaims, parentAgent string) *aauth.Actor {
	if upstream != nil {
		upstreamActor := &aauth.Actor{
			Agent: upstream.Agent,
			Actor: copyActor(upstream.Actor),
		}
		if parentAgent != "" {
			return &aauth.Actor{
				Agent: parentAgent,
				Actor: upstreamActor,
			}
		}
		return upstreamActor
	}
	if parentAgent != "" {
		return &aauth.Actor{Agent: parentAgent}
	}
	return nil
}

func delegationOriginAgent(upstream aauth.AuthTokenClaims) string {
	agent := upstream.Agent
	for actor := upstream.Actor; actor != nil; actor = actor.Actor {
		agent = actor.Agent
	}
	return agent
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
		updatePollingBackoff(
			response,
			&pending.RetryAfter,
			&pending.NotBefore,
			agent.clock.Now(),
		)
		return authorization, responseErr
	}
}

func updatePollingBackoff(
	response *http.Response,
	retryAfter *time.Duration,
	notBefore *time.Time,
	now time.Time,
) {
	switch response.StatusCode {
	case http.StatusTooManyRequests:
		*retryAfter += 5 * time.Second
		*notBefore = now.Add(*retryAfter)
	case http.StatusServiceUnavailable:
		delay, err := responseRetryAfter(response.Header.Values("Retry-After"), now)
		if err != nil {
			delay = 5 * time.Second
		}
		*retryAfter = delay
		*notBefore = now.Add(delay)
	}
}

func responseRetryAfter(values []string, now time.Time) (time.Duration, error) {
	if len(values) != 1 {
		return 0, errors.New("reference: response requires exactly one Retry-After")
	}
	value := strings.TrimSpace(values[0])
	if seconds, err := strconv.ParseUint(value, 10, 31); err == nil {
		return time.Duration(seconds) * time.Second, nil
	}
	at, err := http.ParseTime(value)
	if err != nil {
		return 0, errors.New("reference: response Retry-After is invalid")
	}
	if !at.After(now) {
		return 0, nil
	}
	return at.Sub(now), nil
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
