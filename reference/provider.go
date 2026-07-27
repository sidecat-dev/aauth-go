package reference

import (
	"errors"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type AgentProviderConfig struct {
	Identifier string
	SigningKey aauth.SigningKey
	Clock      aauth.Clock
	NewID      func() string
}

// AgentProvider implements the platform-independent issuance result. How an
// agent authenticates to its provider remains deployment-specific in AAuth.
type AgentProvider struct {
	identifier string
	signingKey aauth.SigningKey
	clock      aauth.Clock
	newID      func() string
}

func NewAgentProvider(config AgentProviderConfig) (*AgentProvider, error) {
	if err := aauth.ValidateServerIdentifier(config.Identifier); err != nil {
		return nil, err
	}
	if config.SigningKey.ID() == "" {
		return nil, errors.New("reference: agent provider signing key is required")
	}
	if config.Clock == nil {
		return nil, errors.New("reference: agent provider clock is required")
	}
	if config.NewID == nil {
		return nil, errors.New("reference: agent provider identifier source is required")
	}
	return &AgentProvider{
		identifier: config.Identifier,
		signingKey: config.SigningKey,
		clock:      config.Clock,
		newID:      config.NewID,
	}, nil
}

func (provider *AgentProvider) IssueAgentToken(request aauth.AgentTokenRequest) (string, error) {
	return aauth.MintAgentToken(
		provider.identifier,
		provider.signingKey,
		request,
		provider.clock.Now(),
		provider.newID(),
	)
}
