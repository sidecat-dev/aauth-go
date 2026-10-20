package agentprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

var (
	// ErrInvalidSubagentParent reports a parent token that is not a current
	// top-level Agent token signed by this Agent Provider's key.
	ErrInvalidSubagentParent = errors.New("aauth: sub-agent parent is not a current top-level Agent of this provider")
	// ErrInvalidSubagentRequest reports a sub-agent request this provider
	// cannot issue: a malformed discriminator, missing or reused key, or no
	// usable lifetime.
	ErrInvalidSubagentRequest = errors.New("aauth: invalid sub-agent token request")
)

// SubagentTokenRequest is one host-approved sub-agent issuance. The host owns
// enrollment policy: how many sub-agents a parent may have, their lifetime,
// and a Discriminator unique among the parent's sub-agents for as long as any
// party might hold a token naming it. PublicKey is the sub-agent's own key;
// its private key stays with the sub-agent.
type SubagentTokenRequest struct {
	Discriminator    string
	PublicKey        jose.JWK
	Lifetime         time.Duration
	AdditionalClaims map[string]json.RawMessage
}

// IssueSubagent issues a one-level sub-agent token (Bootstrap, Sub-Agent
// Tokens) after verifying parentToken as a current top-level Agent token
// signed by this provider's own key. The child keeps this issuer, names the
// parent in parent_agent, copies the parent's ps, takes the parent's local part
// plus "+" and Discriminator, and expires no later than the parent's token.
//
// The host authenticates the request that carries parentToken, for example
// the parent's signed HTTP request, before calling IssueSubagent.
func (server *Server) IssueSubagent(ctx context.Context, parentToken string, request SubagentTokenRequest) (string, error) {
	if server == nil {
		return "", errors.New("aauth: agent provider is required")
	}
	if ctx == nil {
		return "", errors.New("aauth: context is required")
	}
	// Only this provider's own key can authenticate a parent here; a
	// sub-agent token's iss must equal its parent's.
	own := signaturekey.StaticKeyResolver{
		{Issuer: server.issuer, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: server.signingKey.ID()}: server.signingKey.PublicJWK(),
	}
	parent, err := aauth.VerifyAgentToken(ctx, parentToken, own, server.clock)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidSubagentParent, err)
	}
	if parent.Issuer != server.issuer || parent.ParentAgent != "" {
		return "", fmt.Errorf("%w: a sub-agent cannot have sub-agents", ErrInvalidSubagentParent)
	}
	if request.Discriminator == "" || strings.Contains(request.Discriminator, "+") {
		return "", fmt.Errorf("%w: the discriminator must be one nonempty segment without +", ErrInvalidSubagentRequest)
	}
	if _, err := request.PublicKey.PublicKey(); err != nil {
		return "", fmt.Errorf("%w: sub-agent key: %w", ErrInvalidSubagentRequest, err)
	}
	if request.PublicKey.Equal(parent.Confirmation.JWK) {
		return "", fmt.Errorf("%w: the sub-agent must hold a key distinct from its parent", ErrInvalidSubagentRequest)
	}
	if request.Lifetime <= 0 {
		return "", fmt.Errorf("%w: lifetime must be positive", ErrInvalidSubagentRequest)
	}
	local, domain, _ := strings.Cut(strings.TrimPrefix(parent.Subject, "aauth:"), "@")
	child := "aauth:" + local + "+" + request.Discriminator + "@" + domain
	issuedAt := server.clock.Now().UTC().Truncate(time.Second)
	lifetime := request.Lifetime
	if parentExpiresAt := time.Unix(parent.ExpiresAt, 0); issuedAt.Add(lifetime).After(parentExpiresAt) {
		lifetime = parentExpiresAt.Sub(issuedAt)
	}
	compact, err := aauth.MintAgentToken(server.issuer, server.signingKey, aauth.AgentTokenRequest{
		Agent: child, ParentAgent: parent.Subject, PersonServer: parent.PersonServer,
		PublicKey: request.PublicKey, Lifetime: lifetime, AdditionalClaims: request.AdditionalClaims,
	}, issuedAt, server.newID())
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidSubagentRequest, err)
	}
	// Return only a token the protocol verifier accepts for this parent.
	if _, err := aauth.VerifySubagentToken(ctx, compact, parent, own, server.clock); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidSubagentRequest, err)
	}
	return compact, nil
}
