// Package supervisionserver implements the supervision server (SS) role of
// AAuth Supervision: the server a person connects to their Person Server,
// which the Person Server consults for every supervision decision about the
// Agents routed to it.
//
// The SS answers; it never calls the Person Server. A Server verifies every
// Person Server request as a jwks_uri HTTP Message Signature, accepts only
// connected (iss, sub) pairs, and hands each act to host policy, which allows,
// denies or asks the person, asks the Agent a clarifying question, or defers
// the decision for the host to resolve later. Events and mission reports are
// recorded once per (iss, id) and shown to an optional host observer. With a
// signing key the Server publishes jwks_uri and signs every terminal answer to
// a supervision request, and repeats it byte for byte.
//
// The supervision package owns every body this package reads or writes. Hosts
// authenticate people and operators; this package records what they decide.
package supervisionserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
)

// Endpoint paths below the issuer. Pending URLs are {PendingPath}/{id} and
// {ConnectPendingPath}/{id}.
const (
	ConnectPath        = "/connect"
	ConnectPendingPath = "/connect/pending"
	MissionPath        = "/mission"
	DecisionPath       = "/decision"
	EventPath          = "/event"
	PendingPath        = "/pending"
	JWKSPath           = "/.well-known/jwks.json"
)

const (
	// DefaultDecisionRetention is how long a decided or cancelled record is
	// kept when Config.DecisionRetention is zero.
	DefaultDecisionRetention = 24 * time.Hour
	// DefaultPendingLifetime bounds a connect interaction that names no
	// lifetime.
	DefaultPendingLifetime = 10 * time.Minute
	// DefaultDecisionLifetime bounds a deferral and a clarification that name
	// none. A pending URL past it answers unknown_pending.
	DefaultDecisionLifetime = time.Hour
	// MaximumPendingLifetime is the longest a request may stay pending.
	MaximumPendingLifetime = 24 * time.Hour
	// DefaultRetryAfter is the polling interval of a deferral or connect
	// interaction that names none.
	DefaultRetryAfter = 5 * time.Second
	// MaximumConnectCodeAttempts is how many wrong codes end a connect
	// interaction.
	MaximumConnectCodeAttempts = 3

	maximumRetryAfter         = time.Hour
	maximumRetainedResponses  = 8
	maximumTransitionAttempts = 4
)

// ErrUnsupportedIss is returned by Config.TrustPersonServer to refuse a
// Person Server entirely. The SS answers 403 unsupported_iss.
var ErrUnsupportedIss = errors.New("supervisionserver: the person server is not accepted")

// Config supplies a supervision server's identity, keys, policy and state.
type Config struct {
	// Issuer is the SS's server identifier. Every endpoint is on its origin.
	Issuer string
	// Name is an optional display name published in the metadata.
	Name string
	// SigningKey, when set, makes the SS publish jwks_uri and sign the
	// terminal response to every supervision request. Without it the SS is a
	// plain JSON responder.
	SigningKey *jose.SigningKey
	// KeyResolver resolves Person Server keys named by jwks_uri signatures.
	KeyResolver signaturekey.KeyResolver
	Clock       aauth.Clock
	Store       Store
	// TrustPersonServer optionally refuses a Person Server before anything
	// else; wrap ErrUnsupportedIss to refuse. Nil admits every Person Server
	// whose signature verifies, and Connect still decides per person.
	TrustPersonServer func(ctx context.Context, personServer string) error
	// Connect decides a connect for a pair not yet connected.
	Connect func(ctx context.Context, request ConnectRequest) (ConnectResult, error)
	// Decide answers each supervision request, and again after each
	// clarification answer.
	Decide func(ctx context.Context, request DecisionRequest) (DecisionResult, error)
	// Observe optionally sees each event and mission report before the SS
	// acknowledges it. An error answers server_error and records nothing, so
	// the Person Server delivers it again; Observe may therefore see one
	// delivery more than once, and never misses one the SS acknowledged.
	Observe func(ctx context.Context, observation Observation) error
	// DecisionRetention is the least time a decision is kept after it is
	// given. Zero selects DefaultDecisionRetention. It should be no shorter
	// than the longest token lifetime the Person Server issues; a decision
	// that bounds exp is kept at least until that exp.
	DecisionRetention time.Duration
}

// Server is a supervision server.
type Server struct {
	issuer            string
	name              string
	signingKey        *jose.SigningKey
	keyResolver       signaturekey.KeyResolver
	clock             aauth.Clock
	store             Store
	trustPersonServer func(context.Context, string) error
	connect           func(context.Context, ConnectRequest) (ConnectResult, error)
	decide            func(context.Context, DecisionRequest) (DecisionResult, error)
	observe           func(context.Context, Observation) error
	retention         time.Duration
}

// New validates config and returns a Server.
func New(config Config) (*Server, error) {
	if err := aauth.ValidateServerIdentifier(config.Issuer); err != nil {
		return nil, fmt.Errorf("supervisionserver: issuer: %w", err)
	}
	var signingKey *jose.SigningKey
	if config.SigningKey != nil {
		if _, err := config.SigningKey.PublicJWK().PublicKey(); err != nil {
			return nil, fmt.Errorf("supervisionserver: signing key: %w", err)
		}
		key := *config.SigningKey
		signingKey = &key
	}
	if config.KeyResolver == nil {
		return nil, errors.New("supervisionserver: key resolver is required")
	}
	if config.Clock == nil {
		return nil, errors.New("supervisionserver: clock is required")
	}
	if config.Store == nil {
		return nil, errors.New("supervisionserver: store is required")
	}
	if config.Connect == nil {
		return nil, errors.New("supervisionserver: connect policy is required")
	}
	if config.Decide == nil {
		return nil, errors.New("supervisionserver: decision policy is required")
	}
	if config.DecisionRetention < 0 {
		return nil, errors.New("supervisionserver: decision retention must not be negative")
	}
	retention := config.DecisionRetention
	if retention == 0 {
		retention = DefaultDecisionRetention
	}
	return &Server{
		issuer: config.Issuer, name: config.Name, signingKey: signingKey,
		keyResolver: config.KeyResolver, clock: config.Clock, store: config.Store,
		trustPersonServer: config.TrustPersonServer, connect: config.Connect,
		decide: config.Decide, observe: config.Observe, retention: retention,
	}, nil
}

// Metadata returns the metadata document the Server publishes.
func (server *Server) Metadata() supervision.Metadata {
	metadata := supervision.Metadata{
		Issuer: server.issuer, Name: server.name,
		ConnectEndpoint:  server.issuer + ConnectPath,
		MissionEndpoint:  server.issuer + MissionPath,
		DecisionEndpoint: server.issuer + DecisionPath,
		EventEndpoint:    server.issuer + EventPath,
	}
	if server.signingKey != nil {
		metadata.JWKSURI = server.issuer + JWKSPath
	}
	return metadata
}

// Handler serves the metadata document and, with a signing key, the JWKS;
// POST to the connect, mission, {mission}/{s256}, decision and event
// endpoints; signed GET polls of {ConnectPendingPath}/{id}; and signed GET,
// POST (a clarification answer) and DELETE (a cancellation) of
// {PendingPath}/{id}. A policy answers at once, so Prefer: wait never holds a
// request open: a deferral answers 202 immediately.
func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/"+supervision.DiscoveryDocument, server.handleMetadata)
	if server.signingKey != nil {
		mux.HandleFunc("GET "+JWKSPath, server.handleJWKS)
	}
	mux.HandleFunc("POST "+ConnectPath, server.handleConnect)
	mux.HandleFunc("GET "+ConnectPendingPath+"/{id}", server.handleConnectPoll)
	mux.HandleFunc("POST "+MissionPath, server.handleMissionProposal)
	mux.HandleFunc("POST "+MissionPath+"/{s256}", server.handleMissionAction)
	mux.HandleFunc("POST "+DecisionPath, server.handleDecision)
	mux.HandleFunc("POST "+EventPath, server.handleEvent)
	mux.HandleFunc("GET "+PendingPath+"/{id}", server.handlePoll)
	mux.HandleFunc("POST "+PendingPath+"/{id}", server.handleClarificationAnswer)
	mux.HandleFunc("DELETE "+PendingPath+"/{id}", server.handleCancel)
	return mux
}

func (server *Server) handleMetadata(response http.ResponseWriter, _ *http.Request) {
	httpapi.WriteJSON(response, http.StatusOK, server.Metadata())
}

func (server *Server) handleJWKS(response http.ResponseWriter, _ *http.Request) {
	httpapi.WriteJSON(response, http.StatusOK, map[string]any{"keys": []jose.JWK{server.signingKey.PublicJWK()}})
}

// authenticate verifies the request as a jwks_uri signature by a Person
// Server under its person-server metadata document, and applies
// TrustPersonServer. A request with a body must cover content-type and
// content-digest and carry JSON; its exact body is returned. A request
// without one must be bodyless. On failure the response is written.
func (server *Server) authenticate(response http.ResponseWriter, request *http.Request, withBody bool) (string, signaturekey.VerifiedRequest, []byte, bool) {
	options := signaturekey.VerifyOptions{
		AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
		MaxBodyBytes:    supervision.MaxBodyBytes,
	}
	if withBody {
		options.RequiredComponents = []string{"content-type", "content-digest"}
	}
	prepared, err := signaturekey.PrepareRequest(request, server.clock, options)
	if err != nil {
		writeSignatureProblem(response, err)
		return "", signaturekey.VerifiedRequest{}, nil, false
	}
	personServer, document, _, ok := prepared.Credential().JWKSURI()
	if !ok || document != aauth.PersonDiscoveryDocument {
		writeSignatureProblem(response, errors.New("supervisionserver: a person server signature is required"))
		return "", signaturekey.VerifiedRequest{}, nil, false
	}
	proof, err := prepared.VerifyJWKSURI(request.Context(), server.keyResolver)
	if err == nil && proof.Signer() != personServer {
		err = errors.New("supervisionserver: signer is not the named person server")
	}
	if err != nil {
		writeSignatureProblem(response, err)
		return "", signaturekey.VerifiedRequest{}, nil, false
	}
	if server.trustPersonServer != nil {
		if err := server.trustPersonServer(request.Context(), personServer); err != nil {
			if errors.Is(err, ErrUnsupportedIss) {
				writeProblem(response, supervision.ErrorUnsupportedIss, err)
			} else {
				writeProblem(response, supervision.ErrorServerError, err)
			}
			return "", signaturekey.VerifiedRequest{}, nil, false
		}
	}
	if !withBody {
		if request.Body != nil {
			if extra, err := io.ReadAll(io.LimitReader(request.Body, 1)); err != nil || len(extra) != 0 {
				writeProblem(response, supervision.ErrorInvalidRequest, errors.New("supervisionserver: the request must be bodyless"))
				return "", signaturekey.VerifiedRequest{}, nil, false
			}
		}
		return personServer, proof, nil, true
	}
	media, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeProblem(response, supervision.ErrorInvalidRequest, errors.New("supervisionserver: the body must be application/json"))
		return "", signaturekey.VerifiedRequest{}, nil, false
	}
	body := proof.ExactBody()
	if len(body) == 0 {
		writeProblem(response, supervision.ErrorInvalidRequest, errors.New("supervisionserver: the body is required"))
		return "", signaturekey.VerifiedRequest{}, nil, false
	}
	return personServer, proof, body, true
}

// requireConnection answers unknown_sub unless (personServer, subject) is
// connected.
func (server *Server) requireConnection(response http.ResponseWriter, request *http.Request, personServer, subject string) (Connection, bool) {
	connection, err := server.store.LoadConnection(request.Context(), personServer, subject)
	if errors.Is(err, ErrNotFound) {
		writeProblem(response, supervision.ErrorUnknownSub, err)
		return Connection{}, false
	}
	if err != nil {
		writeProblem(response, supervision.ErrorServerError, err)
		return Connection{}, false
	}
	return connection, true
}

// writeProblem writes a supervision error with the status the draft assigns.
func writeProblem(response http.ResponseWriter, code supervision.ErrorCode, cause error) {
	writeStatusProblem(response, code.Status(), string(code), cause)
}

// writeStatusProblem writes an error the supervision table does not name:
// the Core polling codes of a pending URL.
func writeStatusProblem(response http.ResponseWriter, status int, code string, cause error) {
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteProblem(response, status, code, cause)
}

// writeSignatureProblem answers 401 with Signature-Error.
func writeSignatureProblem(response http.ResponseWriter, cause error) {
	writeStatusProblem(response, http.StatusUnauthorized, "invalid_signature", cause)
}

func validWholeSeconds(value time.Duration, maximum time.Duration) bool {
	return value >= 0 && value <= maximum && value%time.Second == 0
}

func retryAfterValue(value time.Duration) string {
	return fmt.Sprint(int64(value / time.Second))
}

func pendingLocation(base, id string) string {
	return strings.TrimRight(base, "/") + "/" + id
}
