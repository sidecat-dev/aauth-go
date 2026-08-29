package reference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// Do sends one exact call with the agent token and follows the current
// person-token and auth-token requirement chain through the person server named
// by that verified token. Other responses are returned unchanged for the caller
// to handle.
func (agent *Agent) Do(ctx context.Context, call AuthorizedCall) (*http.Response, error) {
	resource, err := endpointIdentifier(call.Endpoint)
	if err != nil {
		return nil, err
	}
	agentClaims, err := agent.currentAgentClaims(ctx)
	if err != nil {
		return nil, err
	}
	if grant, ok := agent.cachedAuthGrant(resource, agentClaims); ok {
		response, err := agent.DoAuthorizedRequest(ctx, call, grant)
		if err != nil {
			return nil, err
		}
		challenge, present, challengeErr := parseAuthTokenChallenge(response)
		if challengeErr != nil {
			response.Body.Close()
			return nil, challengeErr
		}
		if !present {
			return response, nil
		}
		response.Body.Close()
		endpoints, endpointErr := agent.resolvePersonServerEndpoints(ctx, grant.Claims.PersonServer)
		if endpointErr != nil {
			return nil, endpointErr
		}
		upgradedResponse, upgraded, stepUpErr := agent.finishAuthTokenStepUp(
			ctx, call, resource, endpoints.AuthToken, grant, challenge,
		)
		if stepUpErr != nil {
			return nil, stepUpErr
		}
		agent.rememberAuthGrant(upgraded)
		return upgradedResponse, nil
	}
	if person, ok := agent.cachedPersonGrant(resource, agentClaims); ok {
		response, err := agent.DoWithPersonToken(ctx, call, person.PersonToken)
		if err != nil {
			return nil, err
		}
		return agent.followAuthTokenRequirement(ctx, call, resource, agentClaims.PersonServer, "", person, response)
	}

	request, err := agent.newAuthorizedCallRequest(ctx, call, agent.agentToken)
	if err != nil {
		return nil, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	requirement, present, err := responseRequirement(response)
	if err != nil {
		response.Body.Close()
		return nil, err
	}
	if !present || requirement.Type != aauth.RequirementPersonToken {
		return response, nil
	}
	response.Body.Close()

	if agentClaims.PersonServer == "" {
		return nil, errors.New("reference: agent has no person server and cannot satisfy person-token requirement")
	}
	endpoints, err := agent.resolvePersonServerEndpoints(ctx, agentClaims.PersonServer)
	if err != nil {
		return nil, err
	}
	person, err := agent.RequestPersonToken(ctx, endpoints.PersonToken, resource, nil)
	if err != nil {
		return nil, err
	}
	agent.rememberPersonGrant(person)
	response, err = agent.DoWithPersonToken(ctx, call, person.PersonToken)
	if err != nil {
		return nil, err
	}
	return agent.followAuthTokenRequirement(ctx, call, resource, agentClaims.PersonServer, endpoints.AuthToken, person, response)
}

func (agent *Agent) followAuthTokenRequirement(
	ctx context.Context,
	call AuthorizedCall,
	resource string,
	personServer string,
	authTokenEndpoint string,
	person PersonGrant,
	response *http.Response,
) (*http.Response, error) {
	requirement, present, err := responseRequirement(response)
	if err != nil {
		response.Body.Close()
		return nil, err
	}
	if !present || requirement.Type != aauth.RequirementAuthToken {
		return response, nil
	}
	response.Body.Close()
	if authTokenEndpoint == "" {
		endpoints, err := agent.resolvePersonServerEndpoints(ctx, personServer)
		if err != nil {
			return nil, err
		}
		authTokenEndpoint = endpoints.AuthToken
	}
	resourceGrant, err := agent.resourceGrantFromChallenge(ctx, resource, person.Claims, requirement.ResourceToken)
	if err != nil {
		return nil, err
	}
	grant, err := agent.ExchangeResourceToken(ctx, authTokenEndpoint, resourceGrant)
	if err != nil {
		return nil, err
	}
	agent.rememberAuthGrant(grant)
	return agent.DoAuthorizedRequest(ctx, call, grant)
}

func (agent *Agent) currentAgentClaims(ctx context.Context) (aauth.AgentTokenClaims, error) {
	evidence, err := aauth.VerifyAgentToken(ctx, agent.agentToken, agent.keyResolver, agent.clock)
	if err != nil {
		return aauth.AgentTokenClaims{}, err
	}
	claims, err := claimsWithoutAuthorization(evidence)
	if err != nil {
		return aauth.AgentTokenClaims{}, err
	}
	if claims.Subject != agent.identifier || !claims.Confirmation.JWK.Equal(agent.signingKey.PublicJWK()) {
		return aauth.AgentTokenClaims{}, errors.New("reference: agent token does not identify this agent and signing key")
	}
	return claims, nil
}

func (agent *Agent) cachedPersonGrant(resource string, current aauth.AgentTokenClaims) (PersonGrant, bool) {
	agent.personMu.Lock()
	defer agent.personMu.Unlock()
	grant, ok := agent.personGrants[resource]
	if !ok || grant.PersonToken == "" || grant.Resource != resource || grant.Claims.Audience != resource ||
		grant.Claims.Issuer != current.PersonServer || grant.Claims.MissionS256 != "" ||
		grant.Claims.ExpiresAt <= agent.clock.Now().Unix() ||
		!grant.Claims.Confirmation.JWK.Equal(agent.signingKey.PublicJWK()) {
		delete(agent.personGrants, resource)
		return PersonGrant{}, false
	}
	return grant, true
}

func (agent *Agent) rememberPersonGrant(grant PersonGrant) {
	agent.personMu.Lock()
	defer agent.personMu.Unlock()
	agent.personGrants[grant.Resource] = grant
}

func (agent *Agent) cachedAuthGrant(resource string, current aauth.AgentTokenClaims) (Grant, bool) {
	agent.authMu.Lock()
	defer agent.authMu.Unlock()
	grant, ok := agent.authGrants[resource]
	if !ok || grant.AuthToken == "" || grant.Resource != resource || grant.Claims.Audience != resource ||
		grant.Claims.PersonServer != current.PersonServer || grant.Claims.MissionS256 != "" ||
		grant.Claims.ExpiresAt <= agent.clock.Now().Unix() || grant.R3 != nil || grant.Budget != nil ||
		!grant.Claims.Confirmation.JWK.Equal(agent.signingKey.PublicJWK()) {
		delete(agent.authGrants, resource)
		return Grant{}, false
	}
	return grant, true
}

func (agent *Agent) rememberAuthGrant(grant Grant) {
	if grant.R3 != nil || grant.Budget != nil || grant.Claims.MissionS256 != "" {
		return
	}
	agent.authMu.Lock()
	defer agent.authMu.Unlock()
	agent.authGrants[grant.Resource] = grant
}

type personServerEndpoints struct {
	PersonToken string
	AuthToken   string
}

func responseRequirement(response *http.Response) (aauth.Requirement, bool, error) {
	var zero aauth.Requirement
	if response.StatusCode != http.StatusUnauthorized || len(response.Header.Values("AAuth-Requirement")) == 0 {
		return zero, false, nil
	}
	requirementValues := response.Header.Values("AAuth-Requirement")
	if len(requirementValues) != 1 {
		return zero, false, errors.New("reference: response carries more than one AAuth-Requirement")
	}
	requirement, err := aauth.ParseRequirementHeader(requirementValues[0])
	if err != nil {
		return zero, false, fmt.Errorf("reference: parse AAuth requirement: %w", err)
	}
	return requirement, true, nil
}

func (agent *Agent) resolvePersonServerEndpoints(ctx context.Context, personServer string) (personServerEndpoints, error) {
	var endpoints personServerEndpoints
	if err := aauth.ValidateServerIdentifier(personServer); err != nil {
		return endpoints, fmt.Errorf("reference: agent person server: %w", err)
	}
	metadataEndpoint := personServer + "/.well-known/" + aauth.PersonDiscoveryDocument
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataEndpoint, nil)
	if err != nil {
		return endpoints, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return endpoints, fmt.Errorf("reference: fetch person-server metadata: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return endpoints, responseError(response)
	}
	var metadata map[string]json.RawMessage
	if err := decodeJSONBytes(response.Body, &metadata); err != nil {
		return endpoints, fmt.Errorf("reference: decode person-server metadata: %w", err)
	}
	var issuer string
	if err := json.Unmarshal(metadata["issuer"], &issuer); err != nil || issuer != personServer {
		return endpoints, errors.New("reference: person-server metadata issuer does not match the requested server")
	}
	if err := json.Unmarshal(metadata["person_token_endpoint"], &endpoints.PersonToken); err != nil {
		return endpoints, errors.New("reference: person-server metadata person_token_endpoint is required")
	}
	if err := aauth.ValidateEndpoint(endpoints.PersonToken); err != nil {
		return endpoints, fmt.Errorf("reference: person-server metadata person_token_endpoint: %w", err)
	}
	if err := json.Unmarshal(metadata["auth_token_endpoint"], &endpoints.AuthToken); err != nil {
		return endpoints, errors.New("reference: person-server metadata auth_token_endpoint is required")
	}
	if err := aauth.ValidateEndpoint(endpoints.AuthToken); err != nil {
		return endpoints, fmt.Errorf("reference: person-server metadata auth_token_endpoint: %w", err)
	}
	return endpoints, nil
}
