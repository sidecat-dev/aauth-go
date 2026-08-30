// Package agentprovider provides the minimal Agent Provider role needed to
// issue current AAuth agent tokens and publish their verification key.
package agentprovider

import (
	"errors"
	"net/http"

	aauth "github.com/aauth-dev/auth-go"
	"github.com/aauth-dev/auth-go/internal/httpapi"
	"github.com/aauth-dev/auth-go/jose"
)

// Config supplies the protocol identity and issuer dependencies of a Server.
type Config struct {
	Issuer     string
	SigningKey jose.SigningKey
	Clock      aauth.Clock
	NewID      func() string
}

// Server issues agent tokens and publishes Agent Provider discovery data.
type Server struct {
	issuer     string
	signingKey jose.SigningKey
	clock      aauth.Clock
	newID      func() string
	handler    http.Handler
}

// New constructs an Agent Provider server.
func New(config Config) (*Server, error) {
	if err := aauth.ValidateServerIdentifier(config.Issuer); err != nil {
		return nil, err
	}
	if config.SigningKey.ID() == "" {
		return nil, errors.New("aauth: agent provider signing key is required")
	}
	if _, err := config.SigningKey.PublicJWK().PublicKey(); err != nil {
		return nil, errors.New("aauth: agent provider signing key is invalid")
	}
	if config.Clock == nil {
		return nil, errors.New("aauth: agent provider clock is required")
	}
	if config.NewID == nil {
		return nil, errors.New("aauth: agent provider token ID source is required")
	}

	server := &Server{
		issuer:     config.Issuer,
		signingKey: config.SigningKey,
		clock:      config.Clock,
		newID:      config.NewID,
	}
	server.handler = server.newHandler()
	return server, nil
}

// Issue creates a current agent token for one validated request.
func (server *Server) Issue(request aauth.AgentTokenRequest) (string, error) {
	if server == nil {
		return "", errors.New("aauth: agent provider is required")
	}
	if request.ParentAgent != "" {
		return "", errors.New("aauth: this Agent Provider implements top-level agent tokens only")
	}
	return aauth.MintAgentToken(
		server.issuer,
		server.signingKey,
		request,
		server.clock.Now(),
		server.newID(),
	)
}

// Handler serves the Agent Provider metadata and JWKS documents.
func (server *Server) Handler() http.Handler {
	if server == nil || server.handler == nil {
		return http.NotFoundHandler()
	}
	return server.handler
}

func (server *Server) newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/aauth-agent.json", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}{
			Issuer:  server.issuer,
			JWKSURI: server.issuer + "/.well-known/jwks.json",
		})
	})
	mux.HandleFunc("GET /.well-known/jwks.json", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, struct {
			Keys []jose.JWK `json:"keys"`
		}{Keys: []jose.JWK{server.signingKey.PublicJWK()}})
	})
	return mux
}

func writeJSON(response http.ResponseWriter, value any) {
	httpapi.WriteJSON(response, http.StatusOK, value)
}
