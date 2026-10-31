package resource

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/revocation"
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
// ExpiresAt, and a repeat with a later ExpiresAt extends it; a repeat with an
// earlier ExpiresAt must not shorten it. The recipient owns clock skew and
// removal; removal before the maximum ExpiresAt seen, plus its skew, lets the
// revoked token be used again.
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

// serveRevocation records a revocation from the server that issued the token.
// A Resource has nothing downstream of one, so it answers at once with an
// empty 200 and never 202. A Person Server revokes person tokens and, in
// three-party access, the auth tokens it issued; the configured Access Server
// revokes the auth tokens it issued; an Agent Provider revokes Agent tokens.
func (server *Server) serveRevocation(response http.ResponseWriter, request *http.Request) {
	caller, err := revocation.VerifyCaller(request, server.clock, server.keyResolver,
		authorizationSignatureComponents(server.additionalSignatureComponents), server.maxSignedBodyBytes)
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", err)
		return
	}
	stores := server.revocationStores(caller)
	if len(stores) == 0 {
		writeProblem(response, http.StatusForbidden, "unsupported_iss", errors.New("this Resource accepts no revocations from this caller"))
		return
	}
	now := server.clock.Now().UTC()
	if delay, ok := server.revocationLimiter.Allow(caller.Issuer, now); !ok {
		revocation.WriteRateLimited(response, delay, errors.New("revocation rate exceeded"))
		return
	}
	input, err := revocation.DecodeRequest(request, caller.Issuer, maximumAuthorizationRequestBytes, now, server.revocationLimits)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	for _, record := range stores {
		if err := record(request.Context(), input); err != nil {
			if errors.Is(err, aauth.ErrRevocationLimitReached) {
				revocation.WriteRateLimited(response, server.revocationLimits.Window, err)
				return
			}
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
	}
	revocation.WriteReport(response, nil)
}

// revocationStores selects where a verified caller's revocation is recorded.
// A Person Server's jti may name a person token or, in three-party access, an
// auth token, so both records are kept.
func (server *Server) revocationStores(caller revocation.Caller) []func(context.Context, aauth.RevocationRequest) error {
	var stores []func(context.Context, aauth.RevocationRequest) error
	switch caller.Document {
	case aauth.PersonDiscoveryDocument:
		if server.personTokenRevocations != nil {
			stores = append(stores, server.personTokenRevocations.Revoke)
		}
		if server.authTokenStatuses != nil && server.authorizationTopology == authorizationTopologyPersonServer {
			stores = append(stores, server.authTokenStatuses.Revoke)
		}
	case aauth.AccessDiscoveryDocument:
		if server.authTokenStatuses != nil && server.authorizationTopology == authorizationTopologyFederated &&
			caller.Issuer == server.accessServer {
			stores = append(stores, server.authTokenStatuses.Revoke)
		}
	case aauth.AgentDiscoveryDocument:
		if server.agentTokenRevocations != nil {
			stores = append(stores, server.agentTokenRevocations.Revoke)
		}
	}
	return stores
}

func (server *Server) acceptsRevocations() bool {
	return server.authTokenStatuses != nil || server.agentTokenRevocations != nil || server.personTokenRevocations != nil
}
