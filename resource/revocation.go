package resource

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// ErrAuthTokenRevoked reports that an observed auth token was revoked.
var ErrAuthTokenRevoked = errors.New("resource: auth token revoked")

// ErrAuthTokenConflict reports reuse of one issuer/JTI pair for different auth
// token bytes.
var ErrAuthTokenConflict = errors.New("resource: auth token identity conflict")

// ErrAgentTokenRevoked reports an Agent token revoked by its issuing Agent
// Provider.
var ErrAgentTokenRevoked = errors.New("resource: Agent token revoked")

// AgentTokenRevocationStore retains Agent-token references revoked by their
// issuer. Revoke must be idempotent. IsRevoked and Revoke for one reference
// must be linearizable. A non-sentinel Revoke error may be indeterminate, so an
// exact retry must be safe. A marker is retained through the request's
// ExpiresAt, and a repeat with a later ExpiresAt extends it; it may be removed
// afterward.
type AgentTokenRevocationStore interface {
	Revoke(context.Context, aauth.RevocationRequest) error
	IsRevoked(context.Context, aauth.TokenReference) (bool, error)
}

// ObservedAuthToken is the minimum status record a Resource needs to enforce
// later revocation without retaining the compact credential.
type ObservedAuthToken struct {
	Reference     aauth.TokenReference
	CompactSHA256 [32]byte
	ExpiresAt     time.Time
}

// AuthTokenStatusStore atomically observes and revokes auth tokens. Observe
// returns nil for a first observation or an exact active repeat,
// ErrAuthTokenRevoked for a revoked exact repeat or for a reference revoked
// before it was first observed, and ErrAuthTokenConflict when the issuer/JTI
// pair is already bound to different token bytes. Revoke returns nil for an
// active, already-revoked, or never-observed token; a never-observed token is
// recorded as revoked so a later Observe of the same reference is refused.
// Observe and Revoke for one reference must be linearizable. Active and revoked
// records remain retained through ExpiresAt (an observed token's own
// ExpiresAt, otherwise the request's, extended by a later repeat); once
// revoked, a reference cannot be recreated by Observe. A record may be removed
// after expiry.
//
// A non-sentinel store error may be indeterminate: the mutation may already be
// committed. Callers may repeat the exact Observe or Revoke; while the record
// remains retained, repeats resolve from that retained state and remain
// consequence-safe.
type AuthTokenStatusStore interface {
	Observe(context.Context, ObservedAuthToken) error
	Revoke(context.Context, aauth.RevocationRequest) error
}

func (server *Server) observeAuthToken(ctx context.Context, compact string, claims aauth.AuthTokenClaims) error {
	if server.authTokenStatuses == nil {
		return nil
	}
	return server.authTokenStatuses.Observe(ctx, ObservedAuthToken{
		Reference:     aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI},
		CompactSHA256: sha256.Sum256([]byte(compact)),
		ExpiresAt:     time.Unix(claims.ExpiresAt, 0).UTC(),
	})
}

func (server *Server) serveRevocation(response http.ResponseWriter, request *http.Request) {
	prepared, err := signaturekey.PrepareRequest(request, server.clock, signaturekey.VerifyOptions{
		RequiredComponents: authorizationSignatureComponents(server.additionalSignatureComponents),
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
		MaxBodyBytes:       server.maxSignedBodyBytes,
	})
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", err)
		return
	}
	issuer, document, _, ok := prepared.Credential().JWKSURI()
	if !ok || (document != aauth.PersonDiscoveryDocument && document != aauth.AgentDiscoveryDocument) {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", errors.New("token issuer proof is required"))
		return
	}
	proof, err := prepared.VerifyJWKSURI(request.Context(), server.keyResolver)
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", err)
		return
	}
	if proof.Signer() != issuer {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", errors.New("token issuer proof signer does not match its issuer"))
		return
	}
	input, err := aauth.DecodeRevocationRequest(request.Body, maximumAuthorizationRequestBytes, issuer)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	switch document {
	case aauth.PersonDiscoveryDocument:
		if server.authTokenStatuses == nil {
			writeProblem(response, http.StatusForbidden, "unsupported_iss", errors.New("Auth-token revocation is not configured"))
			return
		}
		err = server.authTokenStatuses.Revoke(request.Context(), input)
	case aauth.AgentDiscoveryDocument:
		if server.agentTokenRevocations == nil {
			writeProblem(response, http.StatusForbidden, "unsupported_iss", errors.New("Agent-token revocation is not configured"))
			return
		}
		err = server.agentTokenRevocations.Revoke(request.Context(), input)
	}
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.WriteHeader(http.StatusOK)
}
