// Package accessserver implements four-party AAuth Core authorization and
// immediate R3 class and per-call authorization.
package accessserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/internal/httpapi"
	"gitlab.com/sidecat-dev/aauth-go/internal/interaction"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const maxRequestBytes = 1 << 20

// ErrAccessDenied distinguishes an intentional trust or authorization policy
// refusal from an operational callback failure. Policy callbacks wrap this
// error only when they mean to refuse an otherwise valid request.
var ErrAccessDenied = errors.New("accessserver: access denied")

// Config supplies the protocol and deployment choices owned by an Access
// Server. R3 explicitly enables vocabulary-neutral class-document and per-call
// proposal authorization.
type Config struct {
	Issuer            string
	SigningKey        jose.SigningKey
	KeyResolver       signaturekey.KeyResolver
	Clock             aauth.Clock
	NewID             func() string
	TrustPersonServer func(context.Context, string) error
	Authorize         func(context.Context, AuthorizationRequest) (Decision, error)
	Budget            *BudgetConfig
	R3                *R3Config
	// Deferred enables retained Core approval, payment, claims and
	// interaction continuations.
	Deferred *DeferredConfig
	// Revocation enables the revocation endpoint and refusal of revoked
	// person and resource tokens.
	Revocation *RevocationConfig
}

// Agent is the verified agent identity presented to authorization policy.
type Agent struct {
	Identifier       string
	Confirmation     jose.JWK
	ExpiresAt        time.Time
	AdditionalClaims map[string]json.RawMessage
}

// AuthorizationRequest is verified Core context presented to Access Server
// policy. It contains ordinary values, not transport or verification objects.
// MissionS256 is opaque correlation context from the verified Resource token;
// mission content and Person Server history are not exposed.
type AuthorizationRequest struct {
	PersonServer string
	Resource     string
	Subject      string
	Tenant       string
	Account      *string
	MissionS256  string
	Scopes       []string
	Agent        Agent
	// Subagent is present only for a parent-mediated request. Agent remains
	// the top-level parent whose grant the policy evaluates.
	Subagent *Agent
	// Budget is the Person Server ceiling when the PS-to-AS request carried one.
	// It is nil when that request omitted budget, including when the Resource
	// token offered a budget. Omission is not a grant.
	Budget *budgets.Value
	// BudgetConsumed is the resource token's consumption record when the
	// Resource reported spend on the presented auth token. It is not a grant.
	BudgetConsumed *budgets.ConsumptionRecord
	// Claims are values the Person Server posted for a requirement=claims wait.
	// Keys are claim names. sub is never present.
	Claims map[string]json.RawMessage
	// InteractionCode is the code this Access Server drew for the request's
	// wait when Deferred is configured: a PendingDecision with an
	// InteractionURL is answered with it, and every poll of that wait carries
	// the same code. It correlates the person's visit to the interaction page
	// and authorizes nothing.
	InteractionCode string
	// Upstream or UpstreamPerson is set when an intermediary chains this
	// request: the verified auth token or person token the calling Agent
	// presented to it. It names the person the intermediary acts for and
	// grants nothing by itself; Agent is then the intermediary, whose own
	// Agent token need not name this Person Server. The issued auth token
	// expires no later than it, and its sub is Subject, never the upstream
	// token's.
	Upstream       *aauth.AuthTokenClaims
	UpstreamPerson *aauth.PersonTokenClaims
}

// Decision is the requested Core-scope subset and lifetime granted by Core
// policy. R3 policy decisions are returned through R3Config callbacks.
type Decision struct {
	// Pending defers Core authorization instead of granting scopes.
	Pending  *PendingDecision
	Scopes   []string
	Lifetime time.Duration
	// Budget is required when AuthorizationRequest.Budget is present and may
	// only lower its amount without changing unit or decimals.
	Budget *budgets.Value
}

// Server is an AAuth Access Server.
type Server struct {
	issuer            string
	signingKey        jose.SigningKey
	keyResolver       signaturekey.KeyResolver
	clock             aauth.Clock
	newID             func() string
	trustPersonServer func(context.Context, string) error
	authorize         func(context.Context, AuthorizationRequest) (Decision, error)
	budget            *budgetConfig
	r3                *r3Config
	deferred          *DeferredConfig
	revocation        *revocationState
}

// New constructs an Access Server.
func New(config Config) (*Server, error) {
	if err := aauth.ValidateServerIdentifier(config.Issuer); err != nil {
		return nil, fmt.Errorf("accessserver: issuer: %w", err)
	}
	if _, err := config.SigningKey.PublicJWK().PublicKey(); err != nil {
		return nil, fmt.Errorf("accessserver: signing key: %w", err)
	}
	if config.KeyResolver == nil {
		return nil, errors.New("accessserver: key resolver is required")
	}
	if config.Clock == nil {
		return nil, errors.New("accessserver: clock is required")
	}
	if config.NewID == nil {
		return nil, errors.New("accessserver: token ID source is required")
	}
	if config.TrustPersonServer == nil {
		return nil, errors.New("accessserver: Person Server trust policy is required")
	}
	if config.Authorize == nil {
		return nil, errors.New("accessserver: authorization policy is required")
	}
	r3Configuration, err := newR3Config(config.R3, config.SigningKey, config.Issuer, config.Clock)
	if err != nil {
		return nil, err
	}
	budgetConfiguration, err := newBudgetConfig(config.Budget)
	if err != nil {
		return nil, err
	}
	if err := validateDeferredConfig(config.Deferred); err != nil {
		return nil, err
	}
	server := &Server{
		issuer: config.Issuer, signingKey: config.SigningKey,
		keyResolver: config.KeyResolver, clock: config.Clock, newID: config.NewID,
		trustPersonServer: config.TrustPersonServer, authorize: config.Authorize,
		budget: budgetConfiguration, r3: r3Configuration, deferred: cloneDeferredConfig(config.Deferred),
	}
	if err := server.configureRevocation(config.Revocation); err != nil {
		return nil, err
	}
	return server, nil
}

// Handler serves POST /token, the metadata and JWKS documents, and with
// Deferred the pending URLs GET, POST, and DELETE /token/pending/{id}, where id
// is the PendingAuthorizationRecord ID. POST delivers claims. With Revocation
// it also serves POST /revoke and its pending URLs GET /revoke/pending/{id}.
func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", server.handleToken)
	if server.deferred != nil {
		mux.HandleFunc("GET /token/pending/{id}", server.handlePendingToken)
		mux.HandleFunc("POST /token/pending/{id}", server.handlePendingClaims)
		mux.HandleFunc("DELETE /token/pending/{id}", server.handlePendingCancellation)
	}
	server.handleRevocationRoutes(mux)
	mux.HandleFunc("GET /.well-known/aauth-access.json", server.handleMetadata)
	mux.HandleFunc("GET /.well-known/jwks.json", server.handleJWKS)
	return mux
}

func (server *Server) handleToken(response http.ResponseWriter, request *http.Request) {
	prepared, err := signaturekey.PrepareRequest(request, server.clock, signaturekey.VerifyOptions{
		RequiredComponents: []string{"content-type", "content-digest"},
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJWKSURI},
		MaxBodyBytes:       maxRequestBytes,
	})
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", err)
		return
	}
	personServer, discovery, _, ok := prepared.Credential().JWKSURI()
	if !ok || discovery != aauth.PersonDiscoveryDocument {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", errors.New("person server proof is required"))
		return
	}
	proof, err := prepared.VerifyJWKSURI(request.Context(), server.keyResolver)
	if err != nil || proof.Signer() != personServer {
		writeProblem(response, http.StatusUnauthorized, "invalid_request", err)
		return
	}
	if err := server.trustPersonServer(request.Context(), personServer); err != nil {
		writeAccessPolicyProblem(response, err)
		return
	}

	server.authorizeToken(response, request, personServer, proof, nil)
}

func (server *Server) authorizeToken(response http.ResponseWriter, request *http.Request, personServer string, proof signaturekey.VerifiedRequest, pending *PendingAuthorizationRecord) {
	encoded, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBytes+1))
	if err != nil || len(encoded) > maxRequestBytes {
		writeProblem(response, 400, "invalid_request", err)
		return
	}

	var input struct {
		ResourceToken  string          `json:"resource_token"`
		AgentToken     string          `json:"agent_token"`
		PresentedToken string          `json:"presented_token"`
		SubagentToken  json.RawMessage `json:"subagent_token"`
		UpstreamToken  json.RawMessage `json:"upstream_token"`
		Budget         json.RawMessage `json:"budget"`
	}
	if err := decodeJSON(bytes.NewReader(encoded), &input); err != nil || input.ResourceToken == "" || input.AgentToken == "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if input.PresentedToken == "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("accessserver: presented_token is required"))
		return
	}
	if input.UpstreamToken != nil && input.SubagentToken != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("accessserver: sub-agent and call-chain authorization cannot be combined"))
		return
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return proof.VerifiedAt() })
	agentClaims, err := aauth.VerifyAgentToken(request.Context(), input.AgentToken, server.keyResolver, verificationClock)
	if err == nil {
		err = proof.CheckIssuedAt(time.Unix(agentClaims.IssuedAt, 0))
	}
	if err != nil {
		writeTokenProblem(response, err, "invalid_agent_token", "expired_agent_token")
		return
	}
	resourceClaims, r3Context, budgetOffer, budgetConsumed, err := server.verifyResourceTokenForAuthorization(
		request.Context(), input.ResourceToken, verificationClock,
	)
	if err == nil {
		err = proof.CheckIssuedAt(time.Unix(resourceClaims.IssuedAt, 0))
	}
	if err != nil {
		if server.refuseRevokedParameter(response, request.Context(), input.ResourceToken, nil, err, "revoked_resource_token", pending != nil) {
			return
		}
		if budgets.IsTokenClaimError(err) {
			writeProblem(response, http.StatusBadRequest, "invalid_budget", err)
		} else {
			writeTokenProblem(response, err, "invalid_resource_token", "expired_resource_token")
		}
		return
	}
	resourceReference := aauth.TokenReference{Issuer: resourceClaims.Issuer, JTI: resourceClaims.JTI}
	if server.refuseRevokedParameter(response, request.Context(), input.ResourceToken, &resourceReference, nil, "revoked_resource_token", pending != nil) {
		return
	}
	// An intermediary's own ps, if any, names its own Person Server, not the
	// person's; a chained request is tied to the signing Person Server by the
	// upstream token instead.
	if agentClaims.ParentAgent != "" || input.UpstreamToken == nil && agentClaims.PersonServer != personServer {
		writeProblem(response, http.StatusBadRequest, "invalid_agent_token", errors.New("agent token context does not match the person server"))
		return
	}
	confirmation := agentClaims.Confirmation.JWK
	credentialExpiresAt := time.Unix(agentClaims.ExpiresAt, 0).UTC()
	var upstream *verifiedUpstream
	if input.UpstreamToken != nil {
		upstream, err = verifyUpstreamToken(request.Context(), input.UpstreamToken, agentClaims, personServer, server.keyResolver, proof)
		if err != nil {
			writeUpstreamTokenProblem(response, err)
			return
		}
		upstreamReference := upstream.reference()
		if server.refuseRevokedParameter(response, request.Context(), "", &upstreamReference, nil, "revoked_upstream_token", pending != nil) {
			return
		}
		// Downstream access does not outlive the upstream token, and neither
		// does a wait for it.
		if expiresAt := upstream.expiresAt(); expiresAt.Before(credentialExpiresAt) {
			credentialExpiresAt = expiresAt
		}
	}
	var subagentClaims *aauth.AgentTokenClaims
	if input.SubagentToken != nil {
		var compact string
		if err := json.Unmarshal(input.SubagentToken, &compact); err != nil || compact == "" {
			writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("accessserver: subagent_token must be a non-empty compact token string"))
			return
		}
		// The AS verifies the relationship itself rather than trusting the PS:
		// the child names this parent, shares its issuer and holds its own key.
		verified, err := aauth.VerifySubagentToken(request.Context(), compact, agentClaims, server.keyResolver, verificationClock)
		if err == nil {
			err = proof.CheckIssuedAt(time.Unix(verified.IssuedAt, 0))
		}
		if err != nil {
			writeSubagentTokenProblem(response, err)
			return
		}
		confirmation = verified.Confirmation.JWK
		if expiresAt := time.Unix(verified.ExpiresAt, 0).UTC(); expiresAt.Before(credentialExpiresAt) {
			credentialExpiresAt = expiresAt
		}
		subagentClaims = &verified
	}
	if resourceClaims.Audience != server.issuer || resourceClaims.PersonServer != personServer ||
		resourceClaims.Subject == "" || resourceClaims.PresentedJTI == "" {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token context does not match the person server or access server"))
		return
	}
	if resourceClaims.Interaction != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource-token interaction requires the deferred flow"))
		return
	}
	agentJKT, err := confirmation.Thumbprint()
	if err != nil || agentJKT != resourceClaims.AgentJKT {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token does not name the authorized agent key"))
		return
	}
	// The resource token names the token the agent presented by jti alone. The
	// Access Server verifies that token itself: its signature, its binding to
	// the resource token, and its expiry, which bounds the token issued here.
	presented, err := aauth.VerifyPresentedToken(
		request.Context(), input.PresentedToken, resourceClaims, server.keyResolver, verificationClock,
	)
	if err == nil {
		err = proof.CheckIssuedAt(presentedTokenIssuedAt(presented))
	}
	if err != nil {
		if server.refuseRevokedParameter(response, request.Context(), input.PresentedToken, nil, err, "revoked_presented_token", pending != nil) {
			return
		}
		writePresentedTokenProblem(response, err)
		return
	}
	presentedReference := aauth.TokenReference{Issuer: presented.Issuer, JTI: presented.JTI}
	if server.refuseRevokedParameter(response, request.Context(), input.PresentedToken, &presentedReference, nil, "revoked_presented_token", pending != nil) {
		return
	}
	var budgetCeiling *budgets.Value
	if budgetOffer != nil {
		if err := server.budget.validateOffer(request.Context(), resourceClaims.Issuer, *budgetOffer); err != nil {
			var resolutionFailure *budgetMetadataResolutionError
			if errors.As(err, &resolutionFailure) {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
			} else {
				writeProblem(response, http.StatusBadRequest, "invalid_budget", err)
			}
			return
		}
	}
	personBudgetCeiling, err := decodeBudgetCeiling(input.Budget)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_budget", err)
		return
	}
	budgetCeiling, err = selectBudgetCeiling(budgetOffer, personBudgetCeiling)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_budget", err)
		return
	}
	var requestedScopes []string
	if resourceClaims.Scope != "" {
		requestedScopes, err = aauth.ParseScope(resourceClaims.Scope)
		if err != nil {
			writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
			return
		}
	} else if r3Context == nil {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token has no authorization claim"))
		return
	}
	policyRequest := AuthorizationRequest{
		PersonServer: personServer,
		Resource:     resourceClaims.Issuer,
		Subject:      resourceClaims.Subject,
		Tenant:       resourceClaims.Tenant,
		Account:      cloneStringPointer(resourceClaims.Account),
		MissionS256:  resourceClaims.MissionS256,
		Scopes:       append([]string(nil), requestedScopes...),
		Agent: Agent{
			Identifier: agentClaims.Subject, Confirmation: agentClaims.Confirmation.JWK,
			ExpiresAt:        time.Unix(agentClaims.ExpiresAt, 0).UTC(),
			AdditionalClaims: cloneClaims(agentClaims.AdditionalClaims),
		},
		Budget:         cloneBudgetValue(budgetCeiling),
		BudgetConsumed: cloneConsumptionRecord(budgetConsumed),
		Claims:         cloneClaims(pendingClaims(pending)),
	}
	if server.deferred != nil {
		if pending != nil {
			policyRequest.InteractionCode = pending.InteractionCode
		} else if policyRequest.InteractionCode, err = interaction.GenerateCode(nil); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
	}
	policyRequest.Upstream, policyRequest.UpstreamPerson = upstream.policyClaims()
	if subagentClaims != nil {
		policyRequest.Subagent = &Agent{
			Identifier: subagentClaims.Subject, Confirmation: subagentClaims.Confirmation.JWK,
			ExpiresAt:        time.Unix(subagentClaims.ExpiresAt, 0).UTC(),
			AdditionalClaims: cloneClaims(subagentClaims.AdditionalClaims),
		}
	}
	if r3Context != nil {
		if err := server.fetchR3Artifact(request.Context(), r3Context, resourceClaims.Account); err != nil {
			if isInvalidR3Artifact(err) {
				writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
			} else {
				writeProblem(response, http.StatusInternalServerError, "server_error", err)
			}
			return
		}
	}
	var decision Decision
	var r3Authorization *r3.Authorization
	switch {
	case r3Context == nil:
		decision, err = server.authorize(request.Context(), policyRequest)
	case r3Context.kind == r3.ArtifactDocument:
		documentDecision, documentErr := server.r3.authorizeDocument(
			request.Context(), policyRequest, r3Context.reference, r3Context.document,
		)
		decision = Decision{
			Scopes:   append([]string(nil), documentDecision.Scopes...),
			Lifetime: documentDecision.Lifetime,
			Budget:   cloneBudgetValue(documentDecision.Budget),
		}
		r3Authorization = documentDecision.Authorization
		err = documentErr
	case r3Context.kind == r3.ArtifactProposal:
		if server.r3.authorizeProposal == nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("accessserver: R3 proposal authorization policy is required"))
			return
		}
		proposalDecision, proposalErr := server.r3.authorizeProposal(
			request.Context(), policyRequest, r3Context.reference, r3Context.proposal,
		)
		decision = Decision{
			Scopes:   append([]string(nil), proposalDecision.Scopes...),
			Lifetime: proposalDecision.Lifetime,
			Budget:   cloneBudgetValue(proposalDecision.Budget),
		}
		err = proposalErr
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("accessserver: R3 artifact is unclassified"))
		return
	}
	if err != nil {
		if pending != nil && errors.Is(err, ErrAccessDenied) {
			writeProblem(response, 403, "denied", err)
		} else {
			writeAccessPolicyProblem(response, err)
		}
		return
	}
	if decision.Pending != nil {
		if r3Context != nil || budgetOffer != nil {
			writeProblem(response, 500, "server_error", errors.New("accessserver: deferred authorization supports Core requests without R3 or Budget only"))
			return
		}
		server.deferAuthorization(response, request, personServer, encoded, resourceClaims, credentialExpiresAt, presented, decision, pending, policyRequest.InteractionCode)
		return
	}
	if err := validateDecision(decision, requestedScopes, r3Context != nil); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	grantedBudget, err := validateBudgetDecision(budgetCeiling, decision.Budget)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if r3Context != nil && r3Context.kind == r3.ArtifactDocument {
		if r3Authorization == nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("accessserver: R3 document policy returned no class authorization"))
			return
		}
		proven, err := r3.NewAuthorization(
			r3Authorization.GrantedOperations(),
			r3Authorization.PerCallOperations(),
			r3Context.document,
		)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		r3Authorization = &proven
		if grantedBudget != nil && len(proven.PerCallOperations().Operations()) != 0 {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("accessserver: fixed Budget cannot grant per-call R3 operations"))
			return
		}
	}
	expiresAt := proof.VerifiedAt().Add(decision.Lifetime)
	if credentialExpiresAt.Before(expiresAt) {
		expiresAt = credentialExpiresAt
	}
	// The Person Server owns mission validation and does not disclose mission
	// content to the Access Server. It caps the person token at the mission's
	// expires_at, so the presented token carries that bound here; a Resource
	// token's lifetime is independent of the mission.
	if presented.ExpiresAt.Before(expiresAt) {
		expiresAt = presented.ExpiresAt
	}
	claims := aauth.AuthTokenClaims{
		Issuer: server.issuer, DWK: aauth.AccessDiscoveryDocument,
		Audience: resourceClaims.Issuer, JTI: server.newID(),
		Confirmation: aauth.Confirmation{JWK: confirmation},
		IssuedAt:     proof.VerifiedAt().Unix(), ExpiresAt: expiresAt.Unix(),
		Subject: resourceClaims.Subject, Scope: strings.Join(decision.Scopes, " "),
		PersonServer: personServer, Account: resourceClaims.Account,
		MissionS256: resourceClaims.MissionS256, Tenant: resourceClaims.Tenant,
	}
	var authToken string
	if r3Context != nil {
		switch r3Context.kind {
		case r3.ArtifactDocument:
			if grantedBudget == nil {
				authToken, err = r3.MintAuthToken(
					server.r3.registry, server.signingKey, claims,
					r3Context.reference, r3Context.exact, *r3Authorization,
				)
			} else {
				var operationGrant r3.Grant
				operationGrant, err = r3.NewGrant(r3Authorization.GrantedOperations(), r3Context.document)
				if err == nil {
					authToken, err = r3.MintBudgetAuthToken(
						server.r3.registry, server.signingKey, claims,
						r3Context.reference, r3Context.exact, operationGrant, *grantedBudget,
					)
				}
			}
		case r3.ArtifactProposal:
			if grantedBudget == nil {
				authToken, err = r3.MintPerCallAuthToken(
					server.r3.registry, server.signingKey, claims,
					r3Context.reference, r3Context.exact,
				)
			} else {
				authToken, err = r3.MintBudgetPerCallAuthToken(
					server.r3.registry, server.signingKey, claims,
					r3Context.reference, r3Context.exact, *grantedBudget,
				)
			}
		default:
			err = errors.New("accessserver: R3 artifact is unclassified")
		}
	} else if grantedBudget != nil {
		authToken, err = budgets.MintAuthToken(server.signingKey, claims, *grantedBudget)
	} else {
		authToken, err = aauth.MintAuthToken(server.signingKey, claims)
	}
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if r3Context != nil {
		auditAgent := agentClaims.Subject
		parentAgent := ""
		if subagentClaims != nil {
			auditAgent = subagentClaims.Subject
			parentAgent = agentClaims.Subject
		}
		if err := server.commitR3Issuance(
			request.Context(), claims, resourceClaims, r3Context, auditAgent, parentAgent,
		); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
	}
	if err := server.commitIssuedAuthToken(request.Context(), claims, presented); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writePrivateJSON(response, http.StatusOK, struct {
		AuthToken string `json:"auth_token"`
		ExpiresIn int64  `json:"expires_in"`
	}{AuthToken: authToken, ExpiresIn: claims.ExpiresAt - claims.IssuedAt})
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func writeAccessPolicyProblem(response http.ResponseWriter, err error) {
	if errors.Is(err, ErrAccessDenied) {
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	writeProblem(response, http.StatusInternalServerError, "server_error", err)
}

func pendingClaims(pending *PendingAuthorizationRecord) map[string]json.RawMessage {
	if pending == nil {
		return nil
	}
	return pending.Claims
}

func cloneClaims(claims map[string]json.RawMessage) map[string]json.RawMessage {
	if len(claims) == 0 {
		return nil
	}
	cloned := make(map[string]json.RawMessage, len(claims))
	for name, value := range claims {
		cloned[name] = append(json.RawMessage(nil), value...)
	}
	return cloned
}

func validateDecision(decision Decision, requested []string, hasR3 bool) error {
	if decision.Lifetime <= 0 || decision.Lifetime > time.Hour {
		return errors.New("accessserver: authorization policy returned an invalid decision")
	}
	if len(requested) == 0 {
		if !hasR3 || len(decision.Scopes) != 0 {
			return errors.New("accessserver: authorization policy returned an invalid scope decision")
		}
		return nil
	}
	if len(decision.Scopes) == 0 {
		return errors.New("accessserver: authorization policy returned an invalid decision")
	}
	seen := make(map[string]struct{}, len(decision.Scopes))
	for _, scope := range decision.Scopes {
		if scope == "" || !slices.Contains(requested, scope) {
			return errors.New("accessserver: authorization policy granted an unrequested scope")
		}
		if _, duplicate := seen[scope]; duplicate {
			return errors.New("accessserver: authorization policy returned duplicate scopes")
		}
		seen[scope] = struct{}{}
	}
	return nil
}

func (server *Server) handleMetadata(response http.ResponseWriter, _ *http.Request) {
	metadata := map[string]string{
		"issuer":              server.issuer,
		"auth_token_endpoint": strings.TrimRight(server.issuer, "/") + "/token",
		"jwks_uri":            strings.TrimRight(server.issuer, "/") + "/.well-known/jwks.json",
	}
	if endpoint := server.revocationEndpoint(); endpoint != "" {
		metadata["revocation_endpoint"] = endpoint
	}
	httpapi.WriteJSON(response, http.StatusOK, metadata)
}

func (server *Server) handleJWKS(response http.ResponseWriter, _ *http.Request) {
	httpapi.WriteJSON(response, http.StatusOK, map[string]any{"keys": []jose.JWK{server.signingKey.PublicJWK()}})
}

func decodeJSON(reader io.Reader, destination any) error {
	return httpapi.DecodeJSON(reader, maxRequestBytes, destination)
}

func writePrivateJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(response, status, value)
}

func writeProblem(response http.ResponseWriter, status int, code string, cause error) {
	response.Header().Set("Cache-Control", "no-store")
	httpapi.WriteProblem(response, status, code, cause)
}

// writeTokenProblem reports request-parameter token failures. A parameter
// token issued beyond the request's signature window is HTTP 400 clock_skew;
// it never uses the 401 Signature-Error path.
func presentedTokenIssuedAt(presented aauth.PresentedToken) time.Time {
	switch {
	case presented.Auth != nil:
		return time.Unix(presented.Auth.IssuedAt, 0)
	case presented.Person != nil:
		return time.Unix(presented.Person.IssuedAt, 0)
	}
	return time.Time{}
}

func writePresentedTokenProblem(response http.ResponseWriter, err error) {
	var skew *signaturekey.Error
	if errors.As(err, &skew) && skew.Code == signaturekey.ErrorClockSkew {
		writeProblem(response, http.StatusBadRequest, string(signaturekey.ErrorClockSkew), err)
		return
	}
	switch {
	case errors.Is(err, aauth.ErrExpiredPresentedToken):
		writeProblem(response, http.StatusBadRequest, "expired_presented_token", err)
	case errors.Is(err, aauth.ErrPresentedTokenMismatch):
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", err)
	default:
		writeProblem(response, http.StatusBadRequest, "invalid_presented_token", err)
	}
}

// writeSubagentTokenProblem maps a subagent_token failure to Protocol -11's
// <invalid|expired>_subagent_token codes, keeping parameter clock_skew.
func writeSubagentTokenProblem(response http.ResponseWriter, err error) {
	var skew *signaturekey.Error
	switch {
	case errors.As(err, &skew) && skew.Code == signaturekey.ErrorClockSkew:
		writeProblem(response, http.StatusBadRequest, string(signaturekey.ErrorClockSkew), err)
	case errors.Is(err, aauth.ErrExpiredSubagentToken):
		writeProblem(response, http.StatusBadRequest, "expired_subagent_token", err)
	default:
		writeProblem(response, http.StatusBadRequest, "invalid_subagent_token", err)
	}
}

func writeTokenProblem(response http.ResponseWriter, err error, invalidCode, expiredCode string) {
	var skew *signaturekey.Error
	if errors.As(err, &skew) && skew.Code == signaturekey.ErrorClockSkew {
		writeProblem(response, http.StatusBadRequest, string(signaturekey.ErrorClockSkew), err)
		return
	}
	var tokenFailure *aauth.TokenValidationError
	if errors.As(err, &tokenFailure) && tokenFailure.Code == aauth.TokenValidationExpired {
		writeProblem(response, http.StatusBadRequest, expiredCode, err)
		return
	}
	writeProblem(response, http.StatusBadRequest, invalidCode, err)
}
