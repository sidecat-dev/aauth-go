package personserver

import (
	"context"
	"errors"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// ErrAgentTokenRevoked reports an Agent token revoked by its issuing Agent
// Provider. A Person Server returns invalid_agent_token for later use.
var ErrAgentTokenRevoked = errors.New("personserver: Agent token revoked")

// AgentTokenRevocationStore retains Agent-token references revoked by their
// issuer. Revoke must be idempotent. IsRevoked and Revoke for one reference
// must be linearizable. A non-sentinel Revoke error may be indeterminate, so an
// exact retry must be safe. A marker is retained through the request's
// ExpiresAt, and a repeat with a later ExpiresAt extends it; a repeat with an
// earlier ExpiresAt must not shorten it. The recipient owns clock skew and
// removal; removal before the maximum ExpiresAt seen, plus its skew, lets the
// revoked token be used again.
type AgentTokenRevocationStore interface {
	Revoke(context.Context, aauth.RevocationRequest) error
	IsRevoked(context.Context, aauth.TokenReference) (bool, error)
}

func (server *Server) handleAgentTokenRevocation(response http.ResponseWriter, request *http.Request) {
	prepared, err := signaturekey.PrepareRequest(request, server.clock, signaturekey.VerifyOptions{
		RequiredComponents: []string{"content-type", "content-digest"},
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
		MaxBodyBytes:       maxRequestBytes,
	})
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", err)
		return
	}
	issuer, document, _, ok := prepared.Credential().JWKSURI()
	if !ok || document != aauth.AgentDiscoveryDocument {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", errors.New("agent provider proof is required"))
		return
	}
	proof, err := prepared.VerifyJWKSURI(request.Context(), server.keyResolver)
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", err)
		return
	}
	if proof.Signer() != issuer {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", errors.New("agent provider proof signer does not match its issuer"))
		return
	}
	input, err := aauth.DecodeRevocationRequest(request.Body, maxRequestBytes, issuer)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := server.agentTokenRevocations.Revoke(request.Context(), input); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.WriteHeader(http.StatusOK)
}
