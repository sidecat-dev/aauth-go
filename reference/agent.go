package reference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

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
	var grant Grant
	if err := aauth.ValidateEndpoint(resourceEndpoint); err != nil {
		return grant, err
	}
	if err := aauth.ValidateEndpoint(personServerEndpoint); err != nil {
		return grant, err
	}
	if err := mission.ValidateExactBytes(); err != nil {
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
	personServerID, err := endpointIdentifier(personServerEndpoint)
	if err != nil {
		return grant, err
	}
	if mission.Reference.Approver != personServerID {
		return grant, errors.New("reference: mission approver does not match person-server endpoint")
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
	missionHeader, err := mission.Reference.Header()
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
	if resourceClaims.Issuer != resourceID || resourceClaims.Audience != personServerID ||
		resourceClaims.Agent != agent.identifier || resourceClaims.AgentJKT != agentThumbprint ||
		resourceClaims.Mission == nil || *resourceClaims.Mission != mission.Reference {
		return grant, errors.New("reference: resource token does not match the authorization request")
	}

	tokenBody, err := json.Marshal(map[string]string{"resource_token": resourceResult.ResourceToken})
	if err != nil {
		return grant, err
	}
	tokenRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, personServerEndpoint, bytes.NewReader(tokenBody))
	if err != nil {
		return grant, err
	}
	tokenRequest.Header.Set("Content-Type", "application/json")
	if err := aauth.SignRequest(tokenRequest, agent.signingKey, agent.agentToken, agent.clock); err != nil {
		return grant, err
	}
	tokenResponse, err := agent.httpClient.Do(tokenRequest)
	if err != nil {
		return grant, err
	}
	defer tokenResponse.Body.Close()
	if tokenResponse.StatusCode != http.StatusOK {
		return grant, responseError(tokenResponse)
	}
	var tokenResult struct {
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(io.LimitReader(tokenResponse.Body, maxJSONBody)).Decode(&tokenResult); err != nil {
		return grant, err
	}
	authClaims, err := aauth.VerifyAuthToken(ctx, tokenResult.AuthToken, agent.keyResolver, agent.clock)
	if err != nil {
		return grant, err
	}
	if authClaims.Issuer != personServerID || authClaims.Audience != resourceID ||
		authClaims.Agent != agent.identifier || !authClaims.Confirmation.JWK.Equal(agent.signingKey.PublicJWK()) ||
		authClaims.Mission == nil || *authClaims.Mission != mission.Reference {
		return grant, errors.New("reference: auth token does not match the authorization request")
	}
	return Grant{
		Resource:  resourceID,
		AuthToken: tokenResult.AuthToken,
		Claims:    authClaims,
	}, nil
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

func responseError(response *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
	return fmt.Errorf("reference: server returned %s: %s", response.Status, strings.TrimSpace(string(body)))
}
