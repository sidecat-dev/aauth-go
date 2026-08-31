// Package agentprovider issues current AAuth Agent tokens, publishes Agent
// Provider discovery, and composes one explicit two-key enrollment profile
// and the public Events inbox through host policy and storage interfaces.
package agentprovider

import (
	"errors"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// Config supplies the protocol identity and issuer dependencies of a Server.
type Config struct {
	Issuer     string
	SigningKey jose.SigningKey
	Clock      aauth.Clock
	NewID      func() string
	// Events enables public subscribe-token issuance and the Resource-to-AP inbox.
	Events *EventsConfig
}

// Server issues agent tokens and publishes Agent Provider discovery data.
type Server struct {
	issuer     string
	signingKey jose.SigningKey
	clock      aauth.Clock
	newID      func() string
	events     *eventsServerConfig
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

	eventsConfig, err := normalizeEventsConfig(config.Issuer, config.Events)
	if err != nil {
		return nil, err
	}
	server := &Server{
		issuer:     config.Issuer,
		signingKey: config.SigningKey,
		clock:      config.Clock,
		newID:      config.NewID,
		events:     eventsConfig,
	}
	server.handler = server.newHandler()
	return server, nil
}

// Issue creates a current agent token for one validated request.
func (server *Server) Issue(request aauth.AgentTokenRequest) (string, error) {
	if server == nil {
		return "", errors.New("aauth: agent provider is required")
	}
	compact, _, err := server.issueAt(request, server.clock.Now())
	return compact, err
}

func (server *Server) issueAt(request aauth.AgentTokenRequest, issuedAt time.Time) (string, time.Time, error) {
	if server == nil {
		return "", time.Time{}, errors.New("aauth: agent provider is required")
	}
	if request.ParentAgent != "" {
		return "", time.Time{}, errors.New("aauth: this Agent Provider implements top-level agent tokens only")
	}
	issuedAt = issuedAt.UTC().Truncate(time.Second)
	compact, err := aauth.MintAgentToken(
		server.issuer,
		server.signingKey,
		request,
		issuedAt,
		server.newID(),
	)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Unix(issuedAt.Add(request.Lifetime).Unix(), 0).UTC()
	return compact, expiresAt, nil
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
			Issuer        string `json:"issuer"`
			JWKSURI       string `json:"jwks_uri"`
			EventEndpoint string `json:"event_endpoint,omitempty"`
		}{
			Issuer:        server.issuer,
			JWKSURI:       server.issuer + "/.well-known/jwks.json",
			EventEndpoint: eventEndpoint(server),
		})
	})
	mux.HandleFunc("GET /.well-known/jwks.json", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, struct {
			Keys []jose.JWK `json:"keys"`
		}{Keys: []jose.JWK{server.signingKey.PublicJWK()}})
	})
	if server.events != nil {
		mux.HandleFunc("POST "+server.events.path, server.handleEvent)
	}
	return mux
}

func writeJSON(response http.ResponseWriter, value any) {
	httpapi.WriteJSON(response, http.StatusOK, value)
}
