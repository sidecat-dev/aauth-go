package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// SubagentTokenRequest asks this Agent's own Agent Provider for a sub-agent
// token through the provider's documented hosted endpoint (Bootstrap,
// Sub-Agents Under a Hosted AP). Endpoint must be on that provider's origin:
// no other provider can issue the child. PublicKey is the sub-agent's key;
// its private key stays with the sub-agent. Discriminator is an optional
// suggestion the provider may replace.
type SubagentTokenRequest struct {
	Endpoint      string
	PublicKey     jose.JWK
	Discriminator string
}

// RequestSubagentToken sends one parent-signed JSON POST with members "jwk"
// and "discriminator", the shape agentprovider.SubagentHandler serves, and
// returns the issued token only after verifying it is a one-level child of
// this Agent bound to PublicKey. It never retries.
func (client *Client) RequestSubagentToken(ctx context.Context, input SubagentTokenRequest) (string, error) {
	const operation = "request sub-agent token"
	if client == nil {
		return "", fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return "", fail(operation, errors.New("context is required"))
	}
	if client.agentClaims.ParentAgent != "" {
		return "", fail(operation, errors.New("a sub-agent cannot request sub-agents"))
	}
	if err := aauth.ValidateEndpoint(input.Endpoint); err != nil {
		return "", fail(operation, err)
	}
	endpoint, err := url.Parse(input.Endpoint)
	if err != nil || endpoint.Scheme+"://"+endpoint.Host != client.agentClaims.Issuer {
		return "", fail(operation, errors.New("endpoint is not on this Agent's own Agent Provider origin"))
	}
	if _, err := input.PublicKey.PublicKey(); err != nil {
		return "", fail(operation, fmt.Errorf("sub-agent key: %w", err))
	}
	body, err := json.Marshal(struct {
		JWK           jose.JWK `json:"jwk"`
		Discriminator string   `json:"discriminator,omitempty"`
	}{JWK: input.PublicKey, Discriminator: input.Discriminator})
	if err != nil {
		return "", fail(operation, err)
	}
	request, err := newJSONRequest(ctx, input.Endpoint, body)
	if err != nil {
		return "", fail(operation, err)
	}
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return "", fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return "", fail(operation, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fail(operation, responseFailure(response))
	}
	var output struct {
		AgentToken string `json:"agent_token"`
	}
	if err := decodeJSONResponse(response, &output); err != nil {
		return "", fail(operation, err)
	}
	child, err := aauth.VerifySubagentToken(ctx, output.AgentToken, client.agentClaims, client.keyResolver, client.clock)
	if err != nil {
		return "", fail(operation, err)
	}
	if !child.Confirmation.JWK.Equal(input.PublicKey) {
		return "", fail(operation, errors.New("issued sub-agent token is bound to another key"))
	}
	return output.AgentToken, nil
}
