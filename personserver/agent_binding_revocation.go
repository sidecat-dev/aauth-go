package personserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// ErrAgentBindingRevoked reports that the host revoked the Agent-person binding
// an issuance, delivery, or host decision depends on.
var ErrAgentBindingRevoked = errors.New("personserver: Agent-person binding revoked")

// AgentBinding names one Agent-person binding in this Person Server's
// namespace by its top-level Agent (Protocol -11, Agent-Person Binding). A
// parent-mediated request is authorized by its parent's binding; a sub-agent
// has none of its own. The binding behind a call chain is that of the Agent
// the upstream token was issued to, or that Agent's parent.
type AgentBinding struct {
	AgentProvider string
	Agent         string
}

// AgentBindingRevocationStore retains the Agent-person bindings the host has
// revoked. RevokeAgentBinding must be idempotent, and RevokeAgentBinding and
// IsAgentBindingRevoked for one binding must be linearizable. A non-sentinel
// RevokeAgentBinding error may be indeterminate, so an exact retry must be safe.
//
// A revocation applies to every credential the binding authorized: Person
// tokens issued to the Agent or a sub-agent it mediated, Auth tokens presented
// on a step-up, and pending requests waiting on them. Removing an entry
// re-admits those credentials while they are unexpired. A host establishing a
// replacement binding for the same Agent removes the entry no sooner than one
// hour after it revoked the binding, the longest Person, Auth, or pending
// lifetime this library issues or retains, plus its clock skew.
type AgentBindingRevocationStore interface {
	RevokeAgentBinding(context.Context, AgentBinding) error
	IsAgentBindingRevoked(context.Context, AgentBinding) (bool, error)
}

// RevokeAgentBinding records a host-authenticated revocation of one top-level
// Agent's binding. It requires AgentBindingRevocations. It does not revoke
// issued tokens at Resources or Access Servers; delivered Auth tokens expire
// normally.
func (server *Server) RevokeAgentBinding(ctx context.Context, binding AgentBinding) error {
	if server == nil || server.agentBindingRevocations == nil {
		return errors.New("personserver: Agent binding revocation is not configured")
	}
	if ctx == nil {
		return errors.New("personserver: context is required")
	}
	if err := validateAgentBinding(binding); err != nil {
		return err
	}
	return server.agentBindingRevocations.RevokeAgentBinding(ctx, binding)
}

func validateAgentBinding(binding AgentBinding) error {
	if err := aauth.ValidateServerIdentifier(binding.AgentProvider); err != nil {
		return fmt.Errorf("personserver: Agent binding provider: %w", err)
	}
	if err := aauth.ValidateAgentIssuer(binding.Agent, binding.AgentProvider); err != nil {
		return fmt.Errorf("personserver: Agent binding agent: %w", err)
	}
	// Bindings belong to top-level Agents. ValidateAgentRelationship applies
	// the reserved delimiter rule to the host's input, not to a request.
	if err := aauth.ValidateAgentRelationship(binding.Agent, ""); err != nil {
		return fmt.Errorf("personserver: Agent binding names a sub-agent: %w", err)
	}
	return nil
}

func agentBinding(agent aauth.AgentTokenClaims) AgentBinding {
	return AgentBinding{AgentProvider: agent.Issuer, Agent: agent.Subject}
}

// checkAgentBinding returns ErrAgentBindingRevoked for a revoked binding and a
// store failure otherwise. Without a configured store no binding is revoked.
func (server *Server) checkAgentBinding(ctx context.Context, binding AgentBinding) error {
	if server.agentBindingRevocations == nil {
		return nil
	}
	revoked, err := server.agentBindingRevocations.IsAgentBindingRevoked(ctx, binding)
	if err != nil {
		return &agentBindingStoreError{cause: err}
	}
	if revoked {
		return ErrAgentBindingRevoked
	}
	return nil
}

type agentBindingStoreError struct{ cause error }

func (failure *agentBindingStoreError) Error() string { return failure.cause.Error() }
func (failure *agentBindingStoreError) Unwrap() error { return failure.cause }

// writeAgentBindingProblem writes the refusal a revoked binding receives at
// one endpoint, or server_error when the store could not answer.
func writeAgentBindingProblem(response http.ResponseWriter, err error, status int, code string) {
	if errors.Is(err, ErrAgentBindingRevoked) {
		writeProblem(response, status, code, err)
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", err)
}
