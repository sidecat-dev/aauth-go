package agentprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// SelfHostedAgentConfig supplies the one issuer, Agent identity, and key used
// by Bootstrap's self-hosted profile.
type SelfHostedAgentConfig struct {
	Issuer     string
	Agent      string
	SigningKey jose.SigningKey
	Clock      aauth.Clock
	NewID      func() string
}

// SelfHostedAgentTokenRequest supplies the claims that may change when the
// self-hosted Agent issues its next token.
type SelfHostedAgentTokenRequest struct {
	PersonServer     string
	Lifetime         time.Duration
	AdditionalClaims map[string]json.RawMessage
}

// SelfHostedAgent composes ordinary Agent Provider discovery and issuance
// while fixing the Agent-token confirmation key to the provider signing key.
type SelfHostedAgent struct {
	provider *Server
	agent    string
	key      jose.SigningKey
}

// NewSelfHostedAgent constructs Bootstrap's single-key self-hosted profile.
func NewSelfHostedAgent(config SelfHostedAgentConfig) (*SelfHostedAgent, error) {
	if err := aauth.ValidateAgentIdentifier(config.Agent); err != nil {
		return nil, fmt.Errorf("aauth: self-hosted Agent: %w", err)
	}
	if err := aauth.ValidateAgentRelationship(config.Agent, ""); err != nil {
		return nil, fmt.Errorf("aauth: self-hosted Agent: %w", err)
	}
	if err := aauth.ValidateAgentIssuer(config.Agent, config.Issuer); err != nil {
		return nil, fmt.Errorf("aauth: self-hosted Agent issuer: %w", err)
	}
	provider, err := New(Config{
		Issuer:     config.Issuer,
		SigningKey: config.SigningKey,
		Clock:      config.Clock,
		NewID:      config.NewID,
	})
	if err != nil {
		return nil, err
	}
	return &SelfHostedAgent{provider: provider, agent: config.Agent, key: config.SigningKey}, nil
}

// Issue creates the next ordinary current Agent token. Self-hosted Agents have
// no separate refresh ceremony; callers issue a fresh short-lived token when
// needed.
func (selfHosted *SelfHostedAgent) Issue(request SelfHostedAgentTokenRequest) (string, error) {
	if selfHosted == nil || selfHosted.provider == nil || selfHosted.key.ID() == "" {
		return "", errors.New("aauth: self-hosted Agent is required")
	}
	return selfHosted.provider.Issue(aauth.AgentTokenRequest{
		Agent:            selfHosted.agent,
		PersonServer:     request.PersonServer,
		PublicKey:        selfHosted.key.PublicJWK(),
		Lifetime:         request.Lifetime,
		AdditionalClaims: request.AdditionalClaims,
	})
}

// Handler serves the ordinary Agent Provider metadata and JWKS documents.
func (selfHosted *SelfHostedAgent) Handler() http.Handler {
	if selfHosted == nil || selfHosted.provider == nil {
		return http.NotFoundHandler()
	}
	return selfHosted.provider.Handler()
}
