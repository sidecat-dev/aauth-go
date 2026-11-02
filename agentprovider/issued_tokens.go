package agentprovider

import (
	"context"
	"errors"
	"fmt"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// ErrAgentTokenNamesNoPersonServer reports an issued Agent token without a ps
// claim. Core gives such a token no revocation path: a Resource that accepts
// it directly is bounded by its lifetime alone (Core, Who Revokes What).
var ErrAgentTokenNamesNoPersonServer = errors.New("aauth: the Agent token names no Person Server to revoke it at")

// IssuedAgentToken is what an Agent Provider retains of one Agent token it
// issued, so that revoking the Agent reaches the Person Server the token
// names (Core, Revocation Cascade: the parties that cascade retain what they
// issued). PersonServer is the token's ps claim, empty when it has none, and
// ParentAgent the parent of a sub-agent token.
type IssuedAgentToken struct {
	JTI          string
	Agent        string
	ParentAgent  string
	PersonServer string
	ExpiresAt    time.Time
}

// IssuedAgentTokenStore retains a record of every Agent token the provider
// issues. RecordIssuedAgentToken retains one record durably before the
// provider returns the token; a failure withholds the token. A record with
// the JTI of a retained one is a conflict unless it is identical.
// LoadIssuedAgentTokens returns every retained record whose Agent is agent
// and whose ExpiresAt is after at, in any order. A store may discard a record
// once at is past its ExpiresAt plus clock skew. A hosted refresh may mint a
// candidate token that loses to a concurrent exact refresh; its record stays,
// and revoking a token no one holds is harmless.
type IssuedAgentTokenStore interface {
	RecordIssuedAgentToken(ctx context.Context, token IssuedAgentToken) error
	LoadIssuedAgentTokens(ctx context.Context, agent string, at time.Time) ([]IssuedAgentToken, error)
}

// ErrIssuedAgentTokenConflict reports a record whose JTI names a different
// retained record.
var ErrIssuedAgentTokenConflict = errors.New("aauth: issued Agent token conflicts with a retained record")

// AgentTokenRevocation is the outcome for one Agent token in RevokeAgent.
// Err is nil when the Person Server recorded the revocation and its cascade
// is terminal. A *RevocationPendingError means it recorded the revocation and
// its cascade continues; repeat RevokeAgent after RetryAfter.
// ErrAgentTokenNamesNoPersonServer marks a token with no ps. Any other error
// is the Person Server's refusal or an unreachable one, as from
// RevokeAgentToken.
type AgentTokenRevocation struct {
	Token IssuedAgentToken
	Err   error
}

// RevokeAgent revokes every unexpired Agent token this provider issued to
// agent at the Person Server its ps claim names (Core, Revocation Cascade:
// the agent provider calls the PS's revocation endpoint). It reads the
// provider's IssuedAgentTokenStore, so the host names the Agent and not each
// Person Server. Each token is revoked by its own (iss, jti) and exp; a
// sub-agent is a different Agent and is revoked by its own identifier.
// Repeating the call is safe: a Person Server records nothing new for a
// revocation it holds and re-attempts its cascade.
//
// The error is for a failure before any revocation was sent, such as an
// unconfigured store; each token's outcome is in its AgentTokenRevocation.
func (client *RevocationClient) RevokeAgent(ctx context.Context, agent string) ([]AgentTokenRevocation, error) {
	if client == nil || client.provider == nil {
		return nil, errors.New("aauth: Agent-token revocation client is required")
	}
	if ctx == nil {
		return nil, errors.New("aauth: Agent-token revocation context is required")
	}
	if client.provider.issuedTokens == nil {
		return nil, errors.New("aauth: RevokeAgent requires the provider's IssuedTokens store")
	}
	if err := aauth.ValidateAgentIdentifier(agent); err != nil {
		return nil, fmt.Errorf("aauth: Agent to revoke: %w", err)
	}
	tokens, err := client.provider.issuedTokens.LoadIssuedAgentTokens(ctx, agent, client.provider.clock.Now())
	if err != nil {
		return nil, fmt.Errorf("aauth: load issued Agent tokens: %w", err)
	}
	outcomes := make([]AgentTokenRevocation, 0, len(tokens))
	for _, token := range tokens {
		if token.Agent != agent {
			return nil, errors.New("aauth: issued Agent token store returned another Agent's token")
		}
		outcome := AgentTokenRevocation{Token: token}
		if token.PersonServer == "" {
			outcome.Err = ErrAgentTokenNamesNoPersonServer
		} else {
			outcome.Err = client.RevokeAgentToken(ctx, token.PersonServer, aauth.RevocationRequest{
				Reference: aauth.TokenReference{Issuer: client.provider.issuer, JTI: token.JTI},
				ExpiresAt: token.ExpiresAt,
			})
		}
		outcomes = append(outcomes, outcome)
	}
	return outcomes, nil
}

// recordIssued retains token in the provider's store, when it has one, before
// the token is returned.
func (server *Server) recordIssued(ctx context.Context, token IssuedAgentToken) error {
	if server.issuedTokens == nil {
		return nil
	}
	if err := server.issuedTokens.RecordIssuedAgentToken(ctx, token); err != nil {
		return fmt.Errorf("aauth: record issued Agent token: %w", err)
	}
	return nil
}
