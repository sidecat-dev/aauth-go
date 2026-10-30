package personserver

import (
	"context"
	"errors"

	aauth "gitlab.com/sidecat-dev/aauth-go"
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
