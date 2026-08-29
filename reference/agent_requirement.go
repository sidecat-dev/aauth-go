package reference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// Do sends one exact call with the agent token and follows a runtime
// person-token requirement through the person server named by that verified
// token. Other responses are returned unchanged for the caller to handle.
func (agent *Agent) Do(ctx context.Context, call AuthorizedCall) (*http.Response, error) {
	request, err := agent.newAuthorizedCallRequest(ctx, call, agent.agentToken)
	if err != nil {
		return nil, err
	}
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusUnauthorized || len(response.Header.Values("AAuth-Requirement")) == 0 {
		return response, nil
	}
	requirementValues := response.Header.Values("AAuth-Requirement")
	if len(requirementValues) != 1 {
		response.Body.Close()
		return nil, errors.New("reference: response carries more than one AAuth-Requirement")
	}
	requirement, err := aauth.ParseRequirementHeader(requirementValues[0])
	if err != nil {
		response.Body.Close()
		return nil, fmt.Errorf("reference: parse AAuth requirement: %w", err)
	}
	if requirement.Type != aauth.RequirementPersonToken {
		return response, nil
	}
	response.Body.Close()

	agentEvidence, err := aauth.VerifyAgentToken(ctx, agent.agentToken, agent.keyResolver, agent.clock)
	if err != nil {
		return nil, err
	}
	agentClaims, err := claimsWithoutAuthorization(agentEvidence)
	if err != nil {
		return nil, err
	}
	if agentClaims.Subject != agent.identifier || !agentClaims.Confirmation.JWK.Equal(agent.signingKey.PublicJWK()) {
		return nil, errors.New("reference: agent token does not identify this agent and signing key")
	}
	if agentClaims.PersonServer == "" {
		return nil, errors.New("reference: agent has no person server and cannot satisfy person-token requirement")
	}
	resource, err := endpointIdentifier(call.Endpoint)
	if err != nil {
		return nil, err
	}
	personTokenEndpoint, err := agent.resolvePersonTokenEndpoint(ctx, agentClaims.PersonServer)
	if err != nil {
		return nil, err
	}
	person, err := agent.RequestPersonToken(ctx, personTokenEndpoint, resource, nil)
	if err != nil {
		return nil, err
	}
	return agent.DoWithPersonToken(ctx, call, person.PersonToken)
}

func (agent *Agent) resolvePersonTokenEndpoint(ctx context.Context, personServer string) (string, error) {
	if err := aauth.ValidateServerIdentifier(personServer); err != nil {
		return "", fmt.Errorf("reference: agent person server: %w", err)
	}
	metadataEndpoint := personServer + "/.well-known/" + aauth.PersonDiscoveryDocument
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataEndpoint, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/json")
	response, err := agent.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("reference: fetch person-server metadata: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", responseError(response)
	}
	var metadata map[string]json.RawMessage
	if err := decodeJSONBytes(response.Body, &metadata); err != nil {
		return "", fmt.Errorf("reference: decode person-server metadata: %w", err)
	}
	var issuer string
	if err := json.Unmarshal(metadata["issuer"], &issuer); err != nil || issuer != personServer {
		return "", errors.New("reference: person-server metadata issuer does not match the requested server")
	}
	var endpoint string
	if err := json.Unmarshal(metadata["person_token_endpoint"], &endpoint); err != nil {
		return "", errors.New("reference: person-server metadata person_token_endpoint is required")
	}
	if err := aauth.ValidateEndpoint(endpoint); err != nil {
		return "", fmt.Errorf("reference: person-server metadata person_token_endpoint: %w", err)
	}
	return endpoint, nil
}
