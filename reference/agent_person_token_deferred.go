package reference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

type agentPendingPersonRecord struct {
	ID           string             `json:"id"`
	PersonServer string             `json:"person_server"`
	Resource     string             `json:"resource"`
	Location     string             `json:"location"`
	RetryAfter   time.Duration      `json:"retry_after"`
	NotBefore    time.Time          `json:"not_before"`
	Status       string             `json:"status"`
	Requirement  *aauth.Requirement `json:"requirement,omitempty"`
	MissionS256  string             `json:"mission_s256,omitempty"`
	ExpectedKey  jose.JWK           `json:"expected_key"`
	Terminal     *PersonGrant       `json:"terminal,omitempty"`
}

// RequestPersonTokenForSubagentAuthorization is the typed result form of the
// direct-parent person-token request.
func (agent *Agent) RequestPersonTokenForSubagentAuthorization(
	ctx context.Context, endpoint, resource, subagentToken string,
) (PersonTokenAuthorization, error) {
	if strings.TrimSpace(subagentToken) == "" {
		return PersonTokenAuthorization{}, errors.New("reference: sub-agent token is required")
	}
	return agent.requestPersonTokenAuthorization(ctx, endpoint, resource, nil, subagentToken, "")
}

// RequestPersonTokenForUpstreamAuthorization is the typed result form of one
// upstream-auth-token call-chain request.
func (agent *Agent) RequestPersonTokenForUpstreamAuthorization(
	ctx context.Context, endpoint, resource, upstreamToken string,
) (PersonTokenAuthorization, error) {
	if strings.TrimSpace(upstreamToken) == "" {
		return PersonTokenAuthorization{}, errors.New("reference: upstream auth token is required")
	}
	return agent.requestPersonTokenAuthorization(ctx, endpoint, resource, nil, "", upstreamToken)
}

// RequestPersonTokenForChainedSubagentAuthorization is the typed result form
// for a parent carrying both sub-agent and upstream authorization context.
func (agent *Agent) RequestPersonTokenForChainedSubagentAuthorization(
	ctx context.Context, endpoint, resource, subagentToken, upstreamToken string,
) (PersonTokenAuthorization, error) {
	if strings.TrimSpace(subagentToken) == "" {
		return PersonTokenAuthorization{}, errors.New("reference: sub-agent token is required")
	}
	if strings.TrimSpace(upstreamToken) == "" {
		return PersonTokenAuthorization{}, errors.New("reference: upstream auth token is required")
	}
	return agent.requestPersonTokenAuthorization(ctx, endpoint, resource, nil, subagentToken, upstreamToken)
}

func cloneAgentPendingPersonRecord(value agentPendingPersonRecord) agentPendingPersonRecord {
	value.Requirement = copyRequirement(value.Requirement)
	if value.Terminal != nil {
		terminal := *value.Terminal
		value.Terminal = &terminal
	}
	return value
}

func validateAgentPendingPersonRecord(value agentPendingPersonRecord) error {
	if value.ID == "" || value.PersonServer == "" || value.Resource == "" || value.Location == "" ||
		value.NotBefore.IsZero() || value.RetryAfter < 0 ||
		(value.Status != "pending" && value.Status != "interacting") ||
		aauth.ValidatePollingEndpoint(value.Location) != nil || aauth.ValidateServerIdentifier(value.Resource) != nil {
		return ErrAuthorizationStateIntegrity
	}
	server, err := endpointIdentifier(value.Location)
	if err != nil || server != value.PersonServer || path.Base(mustParseURLPath(value.Location)) != value.ID {
		return ErrAuthorizationStateIntegrity
	}
	if _, err := value.ExpectedKey.PublicKey(); err != nil {
		return ErrAuthorizationStateIntegrity
	}
	if value.Terminal != nil && (value.Terminal.Resource != value.Resource || value.Terminal.PersonToken == "") {
		return ErrAuthorizationStateIntegrity
	}
	return nil
}

// RequestPersonTokenAuthorization starts a direct current person-token request
// and returns either the grant or the PS's signed-poll continuation.
func (agent *Agent) RequestPersonTokenAuthorization(
	ctx context.Context,
	endpoint string,
	resource string,
	mission *aauth.ApprovedMission,
) (PersonTokenAuthorization, error) {
	return agent.requestPersonTokenAuthorization(ctx, endpoint, resource, mission, "", "")
}

func (agent *Agent) requestPersonTokenAuthorization(
	ctx context.Context,
	endpoint string,
	resource string,
	mission *aauth.ApprovedMission,
	subagentToken string,
	upstreamToken string,
) (PersonTokenAuthorization, error) {
	var authorization PersonTokenAuthorization
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return authorization, err
	}
	if err := aauth.ValidateServerIdentifier(resource); err != nil {
		return authorization, err
	}
	personServer, err := endpointIdentifier(endpoint)
	if err != nil {
		return authorization, err
	}
	input := struct {
		Resource      string `json:"resource"`
		MissionS256   string `json:"mission_s256,omitempty"`
		SubagentToken string `json:"subagent_token,omitempty"`
		UpstreamToken string `json:"upstream_token,omitempty"`
	}{Resource: resource, SubagentToken: subagentToken, UpstreamToken: upstreamToken}
	if mission != nil {
		if err := mission.ValidateExactBytes(); err != nil {
			return authorization, err
		}
		if mission.Reference.Approver != personServer {
			return authorization, errors.New("reference: person-token mission approver does not match endpoint")
		}
		input.MissionS256 = mission.Reference.S256
	}
	expectedKey := agent.signingKey.PublicJWK()
	if subagentToken != "" {
		parentEvidence, err := aauth.VerifyAgentToken(ctx, agent.agentToken, agent.keyResolver, agent.clock)
		if err != nil {
			return authorization, err
		}
		parentClaims, err := claimsWithoutAuthorization(parentEvidence)
		if err != nil {
			return authorization, err
		}
		if parentClaims.ParentAgent != "" {
			return authorization, errors.New("reference: sub-agent cannot mediate another sub-agent")
		}
		subagentEvidence, err := aauth.VerifyAgentToken(ctx, subagentToken, agent.keyResolver, agent.clock)
		if err != nil {
			return authorization, err
		}
		subagentClaims, err := claimsWithoutAuthorization(subagentEvidence)
		if err != nil {
			return authorization, err
		}
		if subagentClaims.ParentAgent != agent.identifier ||
			(upstreamToken == "" && subagentClaims.PersonServer != personServer) {
			return authorization, errors.New("reference: sub-agent token does not name this parent and person server")
		}
		expectedKey = subagentClaims.Confirmation.JWK
	}
	if upstreamToken != "" {
		agentEvidence, err := aauth.VerifyAgentToken(ctx, agent.agentToken, agent.keyResolver, agent.clock)
		if err != nil {
			return authorization, err
		}
		agentClaims, err := claimsWithoutAuthorization(agentEvidence)
		if err != nil {
			return authorization, err
		}
		if agentClaims.ParentAgent != "" {
			return authorization, errors.New("reference: sub-agent cannot perform call chaining")
		}
		upstreamEvidence, err := aauth.VerifyAuthToken(ctx, upstreamToken, agent.keyResolver, agent.clock)
		if err != nil {
			return authorization, err
		}
		upstream, err := claimsWithoutAuthorization(upstreamEvidence)
		if err != nil {
			return authorization, err
		}
		if upstream.Audience != agentClaims.Issuer || upstream.PersonServer != personServer ||
			!upstream.Confirmation.JWK.Equal(agent.signingKey.PublicJWK()) {
			return authorization, errors.New("reference: upstream auth token does not route this intermediary to the person server and signing key")
		}
		input.MissionS256 = upstream.MissionS256
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
	request.Header.Set("Prefer", "wait=0")
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return authorization, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return authorization, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		grant, err := agent.parsePersonGrantResponse(ctx, response, personServer, resource, input.MissionS256, expectedKey)
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
		pending, err := newPendingPersonTokenAuthorization(personServer, resource, input.MissionS256, expectedKey, deferred, agent.clock.Now())
		if err != nil {
			return authorization, err
		}
		if err := agent.retainPendingPersonToken(ctx, pending, nil); err != nil {
			return authorization, err
		}
		authorization.Pending = &pending
		return authorization, nil
	default:
		return authorization, responseError(response)
	}
}

// PollPersonTokenAuthorization makes one signed poll and returns either the
// refreshed continuation or the terminal person token.
func (agent *Agent) PollPersonTokenAuthorization(
	ctx context.Context,
	pending *PendingPersonTokenAuthorization,
) (PersonTokenAuthorization, error) {
	var authorization PersonTokenAuthorization
	if pending == nil {
		return authorization, errors.New("reference: pending person-token authorization is required")
	}
	terminal, err := agent.restorePendingPersonToken(ctx, pending)
	if err != nil {
		return authorization, err
	}
	if terminal != nil {
		authorization.Grant = terminal
		return authorization, nil
	}
	if agent.clock.Now().Before(pending.NotBefore) {
		return authorization, errors.New("reference: pending person-token authorization is not ready to poll")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.Location, nil)
	if err != nil {
		return authorization, err
	}
	request.Header.Set("Prefer", "wait=0")
	if err := agent.signRequest(request, agent.agentToken); err != nil {
		return authorization, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return authorization, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		grant, err := agent.parsePersonGrantResponse(ctx, response, pending.PersonServer, pending.Resource, pending.missionS256, pending.expectedKey)
		if err != nil {
			return authorization, err
		}
		if err := agent.retainPendingPersonToken(ctx, *pending, &grant); err != nil {
			return authorization, err
		}
		authorization.Grant = &grant
		return authorization, nil
	case http.StatusAccepted:
		deferred, err := aauth.ParseDeferredResponse(response)
		if err != nil {
			return authorization, err
		}
		next, err := newPendingPersonTokenAuthorization(pending.PersonServer, pending.Resource, pending.missionS256, pending.expectedKey, deferred, agent.clock.Now())
		if err != nil {
			return authorization, err
		}
		*pending = next
		if err := agent.retainPendingPersonToken(ctx, *pending, nil); err != nil {
			return authorization, err
		}
		authorization.Pending = pending
		return authorization, nil
	default:
		return authorization, responseError(response)
	}
}

func (agent *Agent) retainPendingPersonToken(ctx context.Context, pending PendingPersonTokenAuthorization, terminal *PersonGrant) error {
	record := agentPendingPersonRecord{
		ID: pending.ID, PersonServer: pending.PersonServer, Resource: pending.Resource, Location: pending.Location,
		RetryAfter: pending.RetryAfter, NotBefore: pending.NotBefore, Status: pending.Status,
		Requirement: copyRequirement(pending.Requirement), MissionS256: pending.missionS256,
		ExpectedKey: pending.expectedKey, Terminal: terminal,
	}
	agent.authorizationMu.Lock()
	defer agent.authorizationMu.Unlock()
	agent.pendingPersons[pending.ID] = cloneAgentPendingPersonRecord(record)
	return agent.persistAuthorizationStateLocked(ctx)
}

func (agent *Agent) restorePendingPersonToken(ctx context.Context, pending *PendingPersonTokenAuthorization) (*PersonGrant, error) {
	agent.authorizationMu.Lock()
	defer agent.authorizationMu.Unlock()
	if err := agent.settleAuthorizationStateLocked(ctx); err != nil {
		return nil, err
	}
	record, ok := agent.pendingPersons[pending.ID]
	if !ok {
		return nil, errors.New("reference: pending person-token authorization is unavailable from retained state")
	}
	pending.PersonServer, pending.Resource, pending.Location = record.PersonServer, record.Resource, record.Location
	pending.RetryAfter, pending.NotBefore, pending.Status = record.RetryAfter, record.NotBefore, record.Status
	pending.Requirement, pending.missionS256, pending.expectedKey = copyRequirement(record.Requirement), record.MissionS256, record.ExpectedKey
	if record.Terminal == nil {
		return nil, nil
	}
	terminal := *record.Terminal
	evidence, err := aauth.VerifyPersonToken(ctx, terminal.PersonToken, agent.keyResolver, agent.clock)
	if err != nil {
		return nil, ErrAuthorizationStateIntegrity
	}
	claims, err := claimsWithoutAuthorization(evidence)
	if err != nil || claims != terminal.Claims {
		return nil, ErrAuthorizationStateIntegrity
	}
	return &terminal, nil
}

func newPendingPersonTokenAuthorization(
	personServer string,
	resource string,
	missionS256 string,
	expectedKey jose.JWK,
	deferred aauth.DeferredResponse,
	now time.Time,
) (PendingPersonTokenAuthorization, error) {
	locationServer, err := endpointIdentifier(deferred.Location)
	if err != nil || locationServer != personServer {
		return PendingPersonTokenAuthorization{}, errors.New("reference: person-token continuation is outside its person server")
	}
	id, err := pendingIDFromLocation(deferred.Location)
	if err != nil {
		return PendingPersonTokenAuthorization{}, err
	}
	return PendingPersonTokenAuthorization{
		ID: id, PersonServer: personServer, Resource: resource, Location: deferred.Location,
		RetryAfter: deferred.RetryAfter, NotBefore: now.Add(deferred.RetryAfter), Status: deferred.Status,
		Requirement: copyRequirement(deferred.Requirement), missionS256: missionS256, expectedKey: expectedKey,
	}, nil
}

func (agent *Agent) parsePersonGrantResponse(
	ctx context.Context,
	response *http.Response,
	personServer string,
	resource string,
	missionS256 string,
	expectedKey jose.JWK,
) (PersonGrant, error) {
	var result struct {
		PersonToken string `json:"person_token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxJSONBody)).Decode(&result); err != nil {
		return PersonGrant{}, err
	}
	evidence, err := aauth.VerifyPersonToken(ctx, result.PersonToken, agent.keyResolver, agent.clock)
	if err != nil {
		return PersonGrant{}, err
	}
	claims, err := claimsWithoutAuthorization(evidence)
	if err != nil {
		return PersonGrant{}, err
	}
	if claims.Issuer != personServer || claims.Audience != resource || claims.MissionS256 != missionS256 ||
		!claims.Confirmation.JWK.Equal(expectedKey) {
		return PersonGrant{}, errors.New("reference: person token does not match its request")
	}
	return PersonGrant{Resource: resource, PersonToken: result.PersonToken, Claims: claims}, nil
}
