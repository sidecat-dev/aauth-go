package personserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
)

var (
	// ErrAgentBindingRevoked reports that the host revoked the Agent-person
	// binding an issuance, delivery, or host decision depends on, or that the
	// request or credential predates the binding that replaced it.
	ErrAgentBindingRevoked = errors.New("personserver: Agent-person binding revoked")
	// ErrAgentBindingNotRevoked reports a replacement for a binding the host
	// has not revoked.
	ErrAgentBindingNotRevoked = errors.New("personserver: Agent-person binding is not revoked")
)

// AgentBinding names one Agent-person binding in this Person Server's
// namespace by its top-level Agent (Protocol -11, Agent-Person Binding). A
// parent-mediated request is authorized by its parent's binding; a sub-agent
// has none of its own. The binding behind a call chain is that of the Agent
// the upstream token was issued to, or that Agent's parent.
type AgentBinding struct {
	AgentProvider string
	Agent         string
}

// AgentBindingRevocation is the retained revocation state of one binding.
// RevokedAt is the latest revocation. ReestablishedAt is when the host then
// established a replacement binding; it is zero while the revocation is in
// force. Both are zero for a binding that was never revoked.
type AgentBindingRevocation struct {
	RevokedAt       time.Time
	ReestablishedAt time.Time
}

// AgentBindingRevocationStore retains the host's revocations of Agent-person
// bindings.
//
// RevokeAgentBinding records a revocation in force: it keeps the later of the
// recorded and supplied instants and clears any replacement.
// ReestablishAgentBinding records a replacement at the later of the supplied
// instant and RevokedAt; it returns ErrAgentBindingNotRevoked when no
// revocation is recorded and keeps the first instant when the revocation was
// already replaced. LoadAgentBindingRevocation returns the zero value for a
// binding never revoked. Operations for one binding must be linearizable. A
// non-sentinel error may be indeterminate, so an exact retry must be safe.
//
// An entry outlives its replacement because it is the fence that keeps the
// revoked binding's credentials out: while a revocation is in force nothing
// is admitted, and after a replacement only requests created, and presented
// tokens issued, after ReestablishedAt are. Deleting an entry re-admits
// whatever the revoked binding authorized that is still unexpired, so a host
// keeps entries rather than removing them.
type AgentBindingRevocationStore interface {
	RevokeAgentBinding(context.Context, AgentBinding, time.Time) error
	ReestablishAgentBinding(context.Context, AgentBinding, time.Time) error
	LoadAgentBindingRevocation(context.Context, AgentBinding) (AgentBindingRevocation, error)
}

// RevokeAgentBinding records a host-authenticated revocation of one top-level
// Agent's binding at the Server's current time. It requires
// AgentBindingRevocations. It does not revoke issued tokens at Resources or
// Access Servers; delivered Auth tokens expire normally.
func (server *Server) RevokeAgentBinding(ctx context.Context, binding AgentBinding) error {
	if err := server.validateAgentBindingCall(ctx, binding); err != nil {
		return err
	}
	return server.agentBindingRevocations.RevokeAgentBinding(ctx, binding, server.clock.Now().UTC())
}

// ReestablishAgentBinding records that the host has established a replacement
// binding for a revoked Agent, at the Server's current time. Requests made
// after it are admitted again under the host's BindPerson policy, while every
// pending request created and every token issued under the revoked binding
// stays refused. It returns ErrAgentBindingNotRevoked for a binding that is not
// revoked. Hosts running several instances keep their clocks within the
// interval between a revocation and its replacement.
func (server *Server) ReestablishAgentBinding(ctx context.Context, binding AgentBinding) error {
	if err := server.validateAgentBindingCall(ctx, binding); err != nil {
		return err
	}
	return server.agentBindingRevocations.ReestablishAgentBinding(ctx, binding, server.clock.Now().UTC())
}

func (server *Server) validateAgentBindingCall(ctx context.Context, binding AgentBinding) error {
	if server == nil || server.agentBindingRevocations == nil {
		return errors.New("personserver: Agent binding revocation is not configured")
	}
	if ctx == nil {
		return errors.New("personserver: context is required")
	}
	return validateAgentBinding(binding)
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

// checkAgentBinding returns ErrAgentBindingRevoked when the binding is revoked,
// or when since, the instant a pending request was created or a presented
// credential was issued, is not after the binding's replacement. A store
// failure or inconsistent state is a store error. Without a configured store no
// binding is revoked.
func (server *Server) checkAgentBinding(ctx context.Context, binding AgentBinding, since time.Time) error {
	if server.agentBindingRevocations == nil {
		return nil
	}
	state, err := server.agentBindingRevocations.LoadAgentBindingRevocation(ctx, binding)
	if err != nil {
		return &agentBindingStoreError{cause: err}
	}
	inconsistent := &agentBindingStoreError{cause: errors.New("personserver: Agent binding revocation state is inconsistent")}
	switch {
	case state.RevokedAt.IsZero():
		if !state.ReestablishedAt.IsZero() {
			return inconsistent
		}
		return nil
	case state.ReestablishedAt.IsZero():
		return ErrAgentBindingRevoked
	case state.ReestablishedAt.Before(state.RevokedAt):
		return inconsistent
	case !since.After(state.ReestablishedAt):
		return ErrAgentBindingRevoked
	}
	return nil
}

type agentBindingStoreError struct{ cause error }

func (failure *agentBindingStoreError) Error() string { return failure.cause.Error() }
func (failure *agentBindingStoreError) Unwrap() error { return failure.cause }

// writeAgentBindingProblem writes the refusal a revoked binding receives at
// one endpoint, with a public detail naming the binding, or server_error when
// the store could not answer.
func writeAgentBindingProblem(response http.ResponseWriter, err error, status int, code string) {
	if errors.Is(err, ErrAgentBindingRevoked) {
		response.Header().Set("Cache-Control", "no-store")
		httpapi.WriteProblem(response, status, code, err, httpapi.ProblemFields{Detail: agentBindingRevokedDetail})
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", err)
}
