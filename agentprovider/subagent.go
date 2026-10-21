package agentprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
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
	own := server.ownKeys()
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

// ErrSubagentDenied is returned by host sub-agent policy to refuse a hosted
// request. SubagentHandler answers it, and a request from a parent that is
// itself a sub-agent, with 403 subagent_denied.
var ErrSubagentDenied = errors.New("aauth: sub-agent issuance denied")

// SubagentRequest is a verified hosted sub-agent request. Parent holds the
// verified claims of the requesting top-level Agent; PublicKey is the
// sub-agent's key and Discriminator the parent's optional suggestion.
type SubagentRequest struct {
	Parent        aauth.AgentTokenClaims
	PublicKey     jose.JWK
	Discriminator string
}

// SubagentDecision is host policy's approval: the final discriminator, unique
// among the parent's live sub-agents, the requested lifetime (still capped at
// the parent's exp) and any additional claims.
type SubagentDecision struct {
	Discriminator    string
	Lifetime         time.Duration
	AdditionalClaims map[string]json.RawMessage
}

// SubagentHandler serves the hosted sub-agent request of Bootstrap, Sub-Agents
// Under a Hosted AP. The parent signs a JSON POST with its own key under the
// jwt scheme, covering content-type and content-digest, presenting its agent
// token issued by this provider. The body is {"jwk": <sub-agent public JWK>,
// "discriminator": <optional>}; the response is {"agent_token": <compact>}.
// Bootstrap defines no route or member names; these follow its example, and
// the host chooses where to mount the handler. Policy decides whether this
// parent may spawn, how many live sub-agents it may have and their lifetime.
func (server *Server) SubagentHandler(policy func(context.Context, SubagentRequest) (SubagentDecision, error)) http.Handler {
	if server == nil || policy == nil {
		return http.NotFoundHandler()
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		server.serveSubagent(response, request, policy)
	})
}

func (server *Server) serveSubagent(response http.ResponseWriter, request *http.Request, policy func(context.Context, SubagentRequest) (SubagentDecision, error)) {
	if !acceptJSONPost(response, request) {
		return
	}
	prepared, err := signaturekey.PrepareRequest(request, server.clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJWT},
		RequiredComponents: []string{"content-type", "content-digest"},
		MaxBodyBytes:       httpapi.DefaultMaxBodyBytes,
	})
	if err != nil {
		writeSignatureProblem(response, err)
		return
	}
	compact, ok := prepared.Credential().JWT()
	if !ok {
		writeSignatureProblem(response, signaturekey.NewError(signaturekey.ErrorInvalidRequest, errors.New("agentprovider: the parent's agent token is required")))
		return
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return prepared.VerifiedAt() })
	parent, err := aauth.VerifyAgentToken(request.Context(), compact, server.ownKeys(), verificationClock)
	if err != nil {
		var validation *aauth.TokenValidationError
		if errors.As(err, &validation) {
			writeSignatureProblem(response, validation.SignatureKeyError())
			return
		}
		writeSignatureProblem(response, signaturekey.NewError(signaturekey.ErrorInvalidJWT, err))
		return
	}
	proof, err := prepared.Verify(parent.Confirmation.JWK)
	if err == nil {
		err = proof.CheckIssuedAt(time.Unix(parent.IssuedAt, 0))
	}
	if err == nil && proof.Authority() != strings.TrimPrefix(server.issuer, "https://") {
		err = signaturekey.NewError(signaturekey.ErrorInvalidRequest, errors.New("agentprovider: signed authority does not match the Agent Provider"))
	}
	if err != nil {
		writeSignatureProblem(response, err)
		return
	}
	if parent.ParentAgent != "" {
		httpapi.WriteProblem(response, http.StatusForbidden, "subagent_denied", fmt.Errorf("%w: a sub-agent cannot have sub-agents", ErrSubagentDenied))
		return
	}
	var input struct {
		JWK           jose.JWK `json:"jwk"`
		Discriminator string   `json:"discriminator"`
	}
	if err := httpapi.DecodeJSON(bytes.NewReader(proof.ExactBody()), httpapi.DefaultMaxBodyBytes, &input); err != nil {
		httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if _, err := input.JWK.PublicKey(); err != nil {
		httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", fmt.Errorf("agentprovider: sub-agent jwk: %w", err))
		return
	}
	decision, err := policy(request.Context(), SubagentRequest{Parent: parent, PublicKey: input.JWK, Discriminator: input.Discriminator})
	if err != nil {
		if errors.Is(err, ErrSubagentDenied) {
			httpapi.WriteProblem(response, http.StatusForbidden, "subagent_denied", err)
			return
		}
		httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	child, err := server.IssueSubagent(request.Context(), compact, SubagentTokenRequest{
		Discriminator: decision.Discriminator, PublicKey: input.JWK,
		Lifetime: decision.Lifetime, AdditionalClaims: decision.AdditionalClaims,
	})
	if err != nil {
		if errors.Is(err, ErrInvalidSubagentRequest) {
			httpapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", err)
			return
		}
		httpapi.WriteProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(response, http.StatusOK, struct {
		AgentToken string `json:"agent_token"`
	}{AgentToken: child})
}

// ownKeys trusts only this provider's own signing key: a sub-agent token's
// issuer must equal its parent's.
func (server *Server) ownKeys() signaturekey.StaticKeyResolver {
	return signaturekey.StaticKeyResolver{
		{Issuer: server.issuer, DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: server.signingKey.ID()}: server.signingKey.PublicJWK(),
	}
}
