package reference

import (
	"errors"
	"net/http"

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

func (provider *AgentProvider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/aauth-agent.json", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]any{
			"issuer":   provider.identifier,
			"jwks_uri": provider.identifier + "/jwks",
		})
	})
	mux.HandleFunc("GET /jwks", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]any{
			"keys": []aauth.JWK{provider.signingKey.PublicJWK()},
		})
	})
	return mux
}
