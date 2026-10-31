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
// this Agent bound to PublicKey. It never retries. When the Agent Provider
// defers issuance, the error is a *PendingError[string] that carries the
// pending request; BeginSubagentToken returns it as a Result.
func (client *Client) RequestSubagentToken(ctx context.Context, input SubagentTokenRequest) (string, error) {
	const operation = "request sub-agent token"
	result, err := client.beginSubagentToken(ctx, input, operation)
	if err != nil {
		return "", err
	}
	return completed(operation, result)
}

// BeginSubagentToken sends the same single POST as RequestSubagentToken and
// returns the verified sub-agent token, or the pending request when the Agent
// Provider answers 202, for example while its policy waits on an approval.
// Polls are signed by the parent, and the token they finally deliver is
// verified exactly as an immediate one.
func (client *Client) BeginSubagentToken(ctx context.Context, input SubagentTokenRequest) (Result[string], error) {
	return client.beginSubagentToken(ctx, input, "begin sub-agent token")
}

func (client *Client) beginSubagentToken(ctx context.Context, input SubagentTokenRequest, operation string) (Result[string], error) {
	if client == nil {
		return Result[string]{}, fail(operation, errors.New("client is required"))
	}
	if ctx == nil {
		return Result[string]{}, fail(operation, errors.New("context is required"))
	}
	if client.agentClaims.ParentAgent != "" {
		return Result[string]{}, fail(operation, errors.New("a sub-agent cannot request sub-agents"))
	}
	if err := aauth.ValidateEndpoint(input.Endpoint); err != nil {
		return Result[string]{}, fail(operation, err)
	}
	endpoint, err := url.Parse(input.Endpoint)
	if err != nil || endpoint.Scheme+"://"+endpoint.Host != client.agentClaims.Issuer {
		return Result[string]{}, fail(operation, errors.New("endpoint is not on this Agent's own Agent Provider origin"))
	}
	if _, err := input.PublicKey.PublicKey(); err != nil {
		return Result[string]{}, fail(operation, fmt.Errorf("sub-agent key: %w", err))
	}
	body, err := json.Marshal(struct {
		JWK           jose.JWK `json:"jwk"`
		Discriminator string   `json:"discriminator,omitempty"`
	}{JWK: input.PublicKey, Discriminator: input.Discriminator})
	if err != nil {
		return Result[string]{}, fail(operation, err)
	}
	request, err := newJSONRequest(ctx, input.Endpoint, body)
	if err != nil {
		return Result[string]{}, fail(operation, err)
	}
	if err := client.signJSONRequest(request, client.agentToken); err != nil {
		return Result[string]{}, fail(operation, err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Result[string]{}, fail(operation, err)
	}
	publicKey := input.PublicKey
	flow := newPendingFlow(client, "sub-agent token", client.agentToken,
		func(ctx context.Context, response *http.Response) (string, error) {
			return client.readSubagentToken(ctx, response, publicKey)
		})
	result, err := flow.begin(ctx, response)
	if err != nil {
		return Result[string]{}, fail(operation, err)
	}
	return result, nil
}

func (client *Client) readSubagentToken(ctx context.Context, response *http.Response, publicKey jose.JWK) (string, error) {
	if response.StatusCode != http.StatusOK {
		return "", responseFailure(response)
	}
	var output struct {
		AgentToken string `json:"agent_token"`
	}
	if err := decodeJSONResponse(response, &output); err != nil {
		return "", err
	}
	child, err := aauth.VerifySubagentToken(ctx, output.AgentToken, client.agentClaims, client.keyResolver, client.clock)
	if err != nil {
		return "", err
	}
	if !child.Confirmation.JWK.Equal(publicKey) {
		return "", errors.New("issued sub-agent token is bound to another key")
	}
	return output.AgentToken, nil
}
