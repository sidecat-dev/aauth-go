// Package accessserver implements the Access Server role for immediate
// four-party AAuth Core and R3 class and per-call authorization.
package accessserver

import (
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
	// Budget is the verified Resource offer narrowed by the Person Server. When
	// the signed request omits a ceiling, it is the Resource offer itself.
	Budget *budgets.Value
}

// Decision is the requested Core-scope subset and lifetime granted by Core
// policy. R3 policy decisions are returned through R3Config callbacks.
type Decision struct {
	Scopes   []string
	Lifetime time.Duration
	// Budget is required when AuthorizationRequest.Budget is present and may
	// only lower its amount without changing unit or decimals.
	Budget *budgets.Value
}

// Server is an immediate AAuth Access Server.
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
}

// New constructs an immediate Access Server.
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
	return &Server{
		issuer: config.Issuer, signingKey: config.SigningKey,
		keyResolver: config.KeyResolver, clock: config.Clock, newID: config.NewID,
		trustPersonServer: config.TrustPersonServer, authorize: config.Authorize,
		budget: budgetConfiguration, r3: r3Configuration,
	}, nil
}

// Handler serves the token, metadata, and JWKS endpoints.
func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", server.handleToken)
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

	var input struct {
		ResourceToken string          `json:"resource_token"`
		AgentToken    string          `json:"agent_token"`
		SubagentToken json.RawMessage `json:"subagent_token"`
		UpstreamToken json.RawMessage `json:"upstream_token"`
		Budget        json.RawMessage `json:"budget"`
	}
	if err := decodeJSON(request.Body, &input); err != nil || input.ResourceToken == "" || input.AgentToken == "" {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	if input.UpstreamToken != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("accessserver: request member \"upstream_token\" is not supported by the immediate flow"))
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
	resourceClaims, r3Context, budgetOffer, err := server.verifyResourceTokenForAuthorization(
		request.Context(), input.ResourceToken, verificationClock,
	)
	if err == nil {
		err = proof.CheckIssuedAt(time.Unix(resourceClaims.IssuedAt, 0))
	}
	if err != nil {
		if budgets.IsTokenClaimError(err) {
			writeProblem(response, http.StatusBadRequest, "invalid_budget", err)
		} else {
			writeTokenProblem(response, err, "invalid_resource_token", "expired_resource_token")
		}
		return
	}
	if agentClaims.ParentAgent != "" || agentClaims.PersonServer != personServer {
		writeProblem(response, http.StatusBadRequest, "invalid_agent_token", errors.New("agent token context does not match the person server"))
		return
	}
	confirmation := agentClaims.Confirmation.JWK
	credentialExpiresAt := time.Unix(agentClaims.ExpiresAt, 0).UTC()
	var subagentClaims *aauth.AgentTokenClaims
	if input.SubagentToken != nil {
		var compact string
		if err := json.Unmarshal(input.SubagentToken, &compact); err != nil || compact == "" {
			writeProblem(response, http.StatusBadRequest, "invalid_request", errors.New("accessserver: subagent_token must be a non-empty compact token string"))
			return
		}
		verified, err := aauth.VerifyAgentToken(request.Context(), compact, server.keyResolver, verificationClock)
		if err == nil {
			err = proof.CheckIssuedAt(time.Unix(verified.IssuedAt, 0))
		}
		if err != nil {
			writeTokenProblem(response, err, "invalid_agent_token", "expired_agent_token")
			return
		}
		if verified.ParentAgent != agentClaims.Subject {
			writeProblem(response, http.StatusBadRequest, "invalid_agent_token", errors.New("sub-agent token does not name the requesting parent"))
			return
		}
		if verified.Confirmation.JWK.Equal(agentClaims.Confirmation.JWK) {
			writeProblem(response, http.StatusBadRequest, "invalid_agent_token", errors.New("sub-agent token must use a key distinct from the parent"))
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
	agentJKT, err := confirmation.Thumbprint()
	if err != nil || agentJKT != resourceClaims.AgentJKT {
		writeProblem(response, http.StatusBadRequest, "invalid_resource_token", errors.New("resource token does not name the authorized agent key"))
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
		Budget: cloneBudgetValue(budgetCeiling),
	}
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
		}
		err = proposalErr
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("accessserver: R3 artifact is unclassified"))
		return
	}
	if err != nil {
		writeAccessPolicyProblem(response, err)
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
	// content or its accepted-update history to the Access Server. Core requires
	// the Resource token to fit within the mission lifetime, so its expiry is the
	// AS's verifiable ceiling for a mission-bound Auth token.
	if resourceClaims.MissionS256 != "" {
		resourceExpiresAt := time.Unix(resourceClaims.ExpiresAt, 0).UTC()
		if resourceExpiresAt.Before(expiresAt) {
			expiresAt = resourceExpiresAt
		}
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
			authToken, err = r3.MintPerCallAuthToken(
				server.r3.registry, server.signingKey, claims,
				r3Context.reference, r3Context.exact,
			)
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
	httpapi.WriteJSON(response, http.StatusOK, map[string]string{
		"issuer":              server.issuer,
		"auth_token_endpoint": strings.TrimRight(server.issuer, "/") + "/token",
		"jwks_uri":            strings.TrimRight(server.issuer, "/") + "/.well-known/jwks.json",
	})
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
