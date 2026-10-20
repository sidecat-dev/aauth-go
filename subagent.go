package aauth

import (
	"context"
	"errors"
	"fmt"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

var (
	// ErrInvalidSubagentToken maps to invalid_subagent_token: the sub-agent
	// token is malformed or unverifiable, is not a sub-agent token, does not
	// name the signing parent in parent_agent, has another issuer, or reuses
	// the parent's key.
	ErrInvalidSubagentToken = errors.New("aauth: sub-agent token is invalid")
	// ErrExpiredSubagentToken maps to expired_subagent_token.
	ErrExpiredSubagentToken = errors.New("aauth: sub-agent token is expired")
)

// VerifySubagentToken verifies a sub-agent's Agent token carried as a request
// parameter for parent-mediated authorization (Protocol -11, Sub-Agents).
// Parent must be the verified claims of the top-level Agent that signed the
// request. The child token is verified on its own terms; then its
// authoritative parent_agent must name that parent, both tokens must share one
// issuer, and the child must hold a distinct confirmation key. A grandchild
// fails because its parent is itself a sub-agent.
//
// A failure wraps ErrExpiredSubagentToken or ErrInvalidSubagentToken. The
// caller still applies its request-window iat check, any Agent-token
// revocation state and its policy.
func VerifySubagentToken(
	ctx context.Context,
	compact string,
	parent AgentTokenClaims,
	resolver signaturekey.KeyResolver,
	clock Clock,
) (AgentTokenClaims, error) {
	if parent.ParentAgent != "" {
		return AgentTokenClaims{}, fmt.Errorf("%w: the requesting Agent is itself a sub-agent", ErrInvalidSubagentToken)
	}
	child, err := VerifyAgentToken(ctx, compact, resolver, clock)
	if err != nil {
		var validation *TokenValidationError
		if errors.As(err, &validation) && validation.Code == TokenValidationExpired {
			return AgentTokenClaims{}, fmt.Errorf("%w: %w", ErrExpiredSubagentToken, err)
		}
		return AgentTokenClaims{}, fmt.Errorf("%w: %w", ErrInvalidSubagentToken, err)
	}
	switch {
	case child.ParentAgent == "":
		return AgentTokenClaims{}, fmt.Errorf("%w: the token does not identify a sub-agent", ErrInvalidSubagentToken)
	case child.ParentAgent != parent.Subject:
		return AgentTokenClaims{}, fmt.Errorf("%w: parent_agent does not name the requesting Agent", ErrInvalidSubagentToken)
	case child.Issuer != parent.Issuer:
		return AgentTokenClaims{}, fmt.Errorf("%w: the issuer differs from the requesting Agent's", ErrInvalidSubagentToken)
	case child.Confirmation.JWK.Equal(parent.Confirmation.JWK):
		return AgentTokenClaims{}, fmt.Errorf("%w: the sub-agent must hold a key distinct from its parent", ErrInvalidSubagentToken)
	}
	return child, nil
}
