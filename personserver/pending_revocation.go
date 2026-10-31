package personserver

import (
	"context"
	"errors"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
)

// agentBindingRevokedDetail is the public explanation of every refusal a
// revoked Agent-person binding causes, so a caller can tell it from a denial.
const agentBindingRevokedDetail = "The Agent-person binding that authorized this request was revoked."

// revokedPendingTokenError reports that a token a pending request depends on
// has been revoked. Detail is public and names the token. It matches
// ErrAgentTokenRevoked, or ErrResourceTokenRevoked for a withdrawn resource
// token, for a host decision refused on that ground.
type revokedPendingTokenError struct {
	detail string
	reason error
}

func (failure *revokedPendingTokenError) Error() string { return "personserver: " + failure.detail }
func (failure *revokedPendingTokenError) Unwrap() error {
	if failure.reason != nil {
		return failure.reason
	}
	return ErrAgentTokenRevoked
}

// checkPendingRevocations applies the Agent Provider's revocations to the
// Agent token that started a pending request and, for a parent-mediated
// request, its sub-agent token, then the binding of the top-level Agent. Both
// tokens were issued by provider. createdAt is when the wait began.
func (server *Server) checkPendingRevocations(
	ctx context.Context,
	provider, agent, agentJTI, subagentJTI string,
	createdAt time.Time,
) error {
	if err := server.checkPendingAgentTokens(ctx, provider, agentJTI, subagentJTI); err != nil {
		return err
	}
	return server.checkAgentBinding(ctx, AgentBinding{AgentProvider: provider, Agent: agent}, createdAt)
}

// checkPendingAgentTokens applies the Agent Provider's revocations to the
// Agent token that started a pending request and to its sub-agent token.
func (server *Server) checkPendingAgentTokens(ctx context.Context, provider, agentJTI, subagentJTI string) error {
	if server.agentTokenRevocations == nil {
		return nil
	}
	for _, token := range []struct{ jti, detail string }{
		{agentJTI, "The Agent token that started this request was revoked."},
		{subagentJTI, "The sub-agent token of this request was revoked."},
	} {
		if token.jti == "" {
			continue
		}
		revoked, err := server.agentTokenRevocations.IsRevoked(ctx, aauth.TokenReference{Issuer: provider, JTI: token.jti})
		if err != nil {
			return &agentTokenRevocationStoreError{cause: err}
		}
		if revoked {
			return &revokedPendingTokenError{detail: token.detail}
		}
	}
	return nil
}

// pendingRevoked reports whether err ends a pending request rather than
// reporting a store failure.
func pendingRevoked(err error) bool {
	var revoked *revokedPendingTokenError
	return errors.As(err, &revoked) || errors.Is(err, ErrAgentBindingRevoked)
}

// writePendingRevocationProblem answers a pending request whose Agent token
// was revoked with the polling error revoked, and a revoked binding as the
// synchronous request would be answered.
func writePendingRevocationProblem(response http.ResponseWriter, err error, bindingStatus int, bindingCode string) {
	var revoked *revokedPendingTokenError
	if errors.As(err, &revoked) {
		response.Header().Set("Cache-Control", "no-store")
		httpapi.WriteProblem(response, http.StatusForbidden, "revoked", err, httpapi.ProblemFields{Detail: revoked.detail})
		return
	}
	writeAgentBindingProblem(response, err, bindingStatus, bindingCode)
}
