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
// exact retry must be safe. Because the wire request does not carry token
// expiry, a host retains a marker until it can independently prove no matching
// Agent token can remain valid.
type AgentTokenRevocationStore interface {
	Revoke(context.Context, aauth.TokenReference) error
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
	var reference aauth.TokenReference
	if err := decodeJSON(request.Body, &reference); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if err := aauth.ValidateTokenReference(reference); err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if reference.Issuer != issuer {
		writeProblem(response, http.StatusForbidden, "access_denied", errors.New("revocation caller is not the token issuer"))
		return
	}
	if err := server.agentTokenRevocations.Revoke(request.Context(), reference); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.WriteHeader(http.StatusOK)
}
