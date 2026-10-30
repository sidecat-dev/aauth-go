package resource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/internal/r3dispatch"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func (server *Server) serveProtected(response http.ResponseWriter, request *http.Request) {
	if !hasAAuthRequestProof(request) {
		server.writeCredentialRequirement(response)
		return
	}
	prepared, compact, err := server.prepareProtectedRequest(request)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	if compact == "" {
		server.serveFurtherScheme(response, request, prepared)
		return
	}
	// The header is untrusted dispatch input only. Each branch below runs the
	// exact token verifier before using any token claim or proof key.
	header, err := jose.PeekHeader(compact)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", &requestTokenError{cause: err})
		return
	}
	switch server.accessMode {
	case aauth.AccessModeAgentToken:
		if header.Type == aauth.AgentTokenType {
			server.serveAgentTokenProtected(response, request, prepared, compact)
			return
		}
		server.writeCredentialRequirement(response)
		return
	case aauth.AccessModePersonToken:
		if header.Type == aauth.PersonTokenType {
			server.servePersonTokenProtected(response, request, prepared, compact)
			return
		}
		server.writeCredentialRequirement(response)
		return
	case aauth.AccessModeAuthToken:
		switch header.Type {
		case aauth.AuthTokenType:
			server.serveAuthTokenProtected(response, request, prepared, compact)
			return
		case aauth.AgentTokenType:
			server.serveAgentTokenPersonChallenge(response, request, prepared, compact)
			return
		case aauth.PersonTokenType:
			server.servePersonTokenChallenge(response, request, prepared, compact)
			return
		}
	}
	writeCredentialProblem(response, "invalid_token", &requestTokenError{
		cause: fmt.Errorf("aauth: protected request token typ %q is not valid for %s access", header.Type, server.accessMode),
	})
}

func (server *Server) serveAgentTokenPersonChallenge(
	response http.ResponseWriter,
	request *http.Request,
	prepared signaturekey.PreparedRequest,
	compact string,
) {
	_, claims, err := server.verifyPreparedAgentRequest(request, prepared, compact)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	if server.agentTokenRevocations != nil {
		revoked, err := server.agentTokenRevocations.IsRevoked(request.Context(), aauth.TokenReference{
			Issuer: claims.Issuer,
			JTI:    claims.JTI,
		})
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("check Agent-token revocation: %w", err))
			return
		}
		if revoked {
			writeCredentialProblem(response, "invalid_token", &requestTokenError{cause: ErrAgentTokenRevoked})
			return
		}
	}
	server.writeCredentialRequirement(response)
}

func hasAAuthRequestProof(request *http.Request) bool {
	return len(request.Header.Values("Signature-Key")) != 0 ||
		len(request.Header.Values("Signature-Input")) != 0 ||
		len(request.Header.Values("Signature")) != 0
}

func (server *Server) writeCredentialRequirement(response http.ResponseWriter) {
	server.writeAcceptedSchemes(response)
	switch server.accessMode {
	case aauth.AccessModeAgentToken:
		response.Header().Set("AAuth-Requirement", aauth.FormatAgentTokenRequirement())
	case aauth.AccessModePersonToken, aauth.AccessModeAuthToken:
		response.Header().Set("AAuth-Requirement", aauth.FormatPersonTokenRequirement())
	default:
		writeCredentialProblem(response, "invalid_token", &requestTokenError{
			cause: fmt.Errorf("aauth: unsupported Resource access mode %q", server.accessMode),
		})
		return
	}
	response.WriteHeader(http.StatusUnauthorized)
}

func (server *Server) serveAgentTokenProtected(
	response http.ResponseWriter,
	request *http.Request,
	prepared signaturekey.PreparedRequest,
	compact string,
) {
	proof, claims, err := server.verifyPreparedAgentRequest(request, prepared, compact)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	if !claims.Confirmation.JWK.Equal(proof.PublicKey()) {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", errors.New("request key does not match agent token"))
		return
	}
	if server.agentTokenRevocations != nil {
		revoked, err := server.agentTokenRevocations.IsRevoked(request.Context(), aauth.TokenReference{
			Issuer: claims.Issuer,
			JTI:    claims.JTI,
		})
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("check Agent-token revocation: %w", err))
			return
		}
		if revoked {
			writeCredentialProblem(response, "invalid_token", &requestTokenError{cause: ErrAgentTokenRevoked})
			return
		}
	}
	principal := AgentPrincipal{
		AgentProvider: claims.Issuer, Agent: claims.Subject, ParentAgent: claims.ParentAgent,
		PersonServer: claims.PersonServer, Confirmation: claims.Confirmation.JWK,
		AdditionalClaims: cloneAdditionalClaims(claims.AdditionalClaims),
	}
	server.protected.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), agentPrincipalContextKey{}, principal)))
}

func (server *Server) servePersonTokenProtected(
	response http.ResponseWriter,
	request *http.Request,
	prepared signaturekey.PreparedRequest,
	compact string,
) {
	proof, claims, err := server.verifyPreparedPersonRequest(request, prepared, compact)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	if err := aauth.ValidatePersonTokenContext(claims, server.issuer, proof.PublicKey()); err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_token", err)
		return
	}
	if claims.MissionS256 != "" {
		writeProblem(response, http.StatusUnauthorized, "invalid_token", errors.New("mission-bound person tokens require mission verification"))
		return
	}
	if err := server.resolvePerson(
		request.Context(),
		PersonIdentity{Issuer: claims.Issuer, Subject: claims.Subject},
		PersonContext{Tenant: claims.Tenant},
	); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("resolve person: %w", err))
		return
	}
	principal := PersonPrincipal{
		PersonServer: claims.Issuer, Subject: claims.Subject, Tenant: claims.Tenant,
		Confirmation: claims.Confirmation.JWK,
	}
	server.protected.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), personPrincipalContextKey{}, principal)))
}

func (server *Server) serveAuthTokenProtected(
	response http.ResponseWriter,
	request *http.Request,
	prepared signaturekey.PreparedRequest,
	compact string,
) {
	var (
		proof         signaturekey.VerifiedRequest
		claims        aauth.AuthTokenClaims
		authorization *r3ProtectedAuthorization
		budgetGrant   *budgets.Value
	)
	carriesR3, err := r3dispatch.TokenCarriesClaims(compact)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", &requestTokenError{cause: err})
		return
	}
	carriesBudget, err := budgets.TokenCarriesClaims(compact)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", &requestTokenError{cause: err})
		return
	}
	if carriesR3 && carriesBudget {
		if server.r3 == nil || server.budget == nil {
			writeCredentialProblem(response, "invalid_token", &requestTokenError{
				cause: errors.New("aauth: combined R3 and Budget auth token requires both Resource profiles"),
			})
			return
		}
		var reference r3.Reference
		var operations r3.AuthTokenOperations
		var grant budgets.Value
		proof, claims, reference, operations, grant, err = server.verifyPreparedR3BudgetAuthRequest(request, prepared, compact)
		authorization = &r3ProtectedAuthorization{reference: reference, operations: operations}
		budgetGrant = &grant
	} else if server.budget != nil && carriesBudget {
		var grant budgets.Value
		proof, claims, grant, err = server.verifyPreparedBudgetAuthRequest(request, prepared, compact)
		budgetGrant = &grant
	} else if server.r3 != nil && carriesR3 {
		var reference r3.Reference
		var operations r3.AuthTokenOperations
		proof, claims, reference, operations, err = server.verifyPreparedR3AuthRequest(request, prepared, compact)
		authorization = &r3ProtectedAuthorization{reference: reference, operations: operations}
	} else {
		proof, claims, err = server.verifyPreparedAuthRequest(request, prepared, compact)
	}
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	expectedDocument := aauth.AccessDiscoveryDocument
	expectedIssuer := server.accessServer
	if server.authorizationTopology == authorizationTopologyPersonServer {
		expectedDocument = aauth.PersonDiscoveryDocument
		expectedIssuer = claims.PersonServer
	}
	if claims.DWK != expectedDocument || claims.Issuer != expectedIssuer {
		writeProblem(response, http.StatusUnauthorized, "invalid_token", errors.New("auth token issuer role is invalid"))
		return
	}
	if claims.Audience != server.issuer || aauth.ValidateServerIdentifier(claims.PersonServer) != nil || claims.Subject == "" {
		writeProblem(response, http.StatusForbidden, "access_denied", errors.New("auth token context does not match resource"))
		return
	}
	if err := server.authTokenMatchesAsk(request, claims); err != nil {
		writeAuthorizationAskProblem(response, err)
		return
	}
	if !claims.Confirmation.JWK.Equal(proof.PublicKey()) {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", errors.New("request key does not match auth token"))
		return
	}
	if claims.Account != nil && server.validateAccount == nil {
		writeProblem(response, http.StatusForbidden, "access_denied", errors.New("account is not supported by the immediate resource flow"))
		return
	}
	var scopes []string
	if claims.Scope != "" {
		validated, err := server.validateScopes(claims.Scope)
		if err != nil {
			writeProblem(response, http.StatusForbidden, "access_denied", err)
			return
		}
		scopes = validated
	} else if authorization == nil {
		writeProblem(response, http.StatusForbidden, "access_denied", errors.New("auth token has no authorization claim"))
		return
	}
	metered := server.budget != nil
	if metered && server.budget.metered != nil {
		policyRequest, finish, err := cloneScopePolicyRequest(request)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		metered = server.budget.metered(policyRequest)
		if err := finish(); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
	}
	if metered && budgetGrant == nil {
		writeProblem(response, http.StatusForbidden, "access_denied", errors.New("metered route requires a signed Budget grant"))
		return
	}
	if err := server.observeAuthToken(request.Context(), compact, claims); err != nil {
		switch {
		case errors.Is(err, ErrAuthTokenRevoked):
			response.Header().Set("AAuth-Requirement", aauth.FormatPersonTokenRequirement())
			writeProblem(response, http.StatusUnauthorized, "invalid_token", signaturekey.NewError(signaturekey.ErrorRevokedJWT, err))
		case errors.Is(err, ErrAuthTokenConflict):
			writeProblem(response, http.StatusForbidden, "access_denied", err)
		default:
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	// Balance observation requires a structurally valid, non-revoked credential.
	// Route authorization can still refuse it without charging the request.
	applicationResponse := response
	var budgetResponse *budgetResponseWriter
	if budgetGrant != nil {
		budgetResponse = newBudgetResponseWriter(response, request.Context(), server.budget.store, claims, *budgetGrant, server.clock.Now())
		response = budgetResponse
	}
	requiredScopes, err := server.authorizeScopes(request, scopes, authorization != nil)
	if err != nil {
		var policyFailure *scopePolicyError
		if errors.As(err, &policyFailure) {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	operation, mapped, err := server.r3OperationForRequest(request)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if authorization == nil {
		if mapped {
			writeProblem(response, http.StatusForbidden, "access_denied", errors.New("R3 authorization is required for this route"))
			return
		}
	} else {
		if !mapped {
			writeProblem(response, http.StatusForbidden, "access_denied", errors.New("R3 operation is not granted"))
			return
		}
		referenceKind, err := server.validateR3ProtectedReference(*authorization, claims)
		if err != nil {
			writeProblem(response, http.StatusForbidden, "access_denied", err)
			return
		}
		access, err := authorization.operations.AccessFor(operation)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if referenceKind == r3ClassReference && access == r3.OperationAccessGranted {
			// The AS-signed class grant is directly enforceable without a
			// document lookup.
		} else if referenceKind == r3ClassReference && access == r3.OperationAccessPerCall {
			server.serveR3PerCallChallenge(
				response, request, proof, claims, *authorization, operation, requiredScopes, compact,
			)
			return
		} else if referenceKind == r3ProposalReference && access == r3.OperationAccessGranted {
			server.serveR3RetryCompletion(
				response, request, proof, claims, *authorization, operation, scopes, compact,
			)
			return
		} else {
			writeProblem(response, http.StatusForbidden, "access_denied", errors.New("R3 operation is not granted"))
			return
		}
	}
	if err := server.resolvePerson(
		request.Context(),
		PersonIdentity{Issuer: claims.PersonServer, Subject: claims.Subject},
		PersonContext{MissionS256: claims.MissionS256, Tenant: claims.Tenant, AdditionalClaims: cloneAdditionalClaims(claims.AdditionalClaims)},
	); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("resolve person: %w", err))
		return
	}
	principal := AuthPrincipal{
		PersonServer:     claims.PersonServer,
		Subject:          claims.Subject,
		MissionS256:      claims.MissionS256,
		Tenant:           claims.Tenant,
		Account:          cloneAuthorizationAccount(claims.Account),
		Scope:            append([]string(nil), scopes...),
		Confirmation:     claims.Confirmation.JWK,
		AdditionalClaims: cloneAdditionalClaims(claims.AdditionalClaims),
	}
	protectedContext := context.WithValue(request.Context(), authPrincipalContextKey{}, principal)
	protectedContext = context.WithValue(protectedContext, authTokenContextKey{}, compact)
	handlerWriter := applicationResponse
	if metered {
		var reference *r3.Reference
		if authorization != nil {
			value := authorization.reference
			reference = &value
		}
		if server.budget.maximum != nil {
			settlement, ok := server.beginReservedBudget(budgetResponse, request, claims, principal, *budgetGrant, reference, requiredScopes)
			if !ok {
				return
			}
			defer settlement.finish()
			protectedContext = context.WithValue(protectedContext, budgetSettlementKey{}, settlement)
			handlerWriter = settlement.writer
		} else if !server.enforceFixedBudget(budgetResponse, request, claims, principal, *budgetGrant, reference, requiredScopes) {
			return
		}
	} else if budgetResponse != nil {
		// Sending Rules permits omitted feedback when the meter fails. This
		// route needs no charge, so the application can still serve it.
		_ = budgetResponse.setUnchargedFeedback()
	}
	server.protected.ServeHTTP(handlerWriter, request.WithContext(protectedContext))
}

func (server *Server) verifyPreparedR3BudgetAuthRequest(
	request *http.Request,
	prepared signaturekey.PreparedRequest,
	compact string,
) (signaturekey.VerifiedRequest, aauth.AuthTokenClaims, r3.Reference, r3.AuthTokenOperations, budgets.Value, error) {
	verificationClock := aauth.ClockFunc(func() time.Time { return prepared.VerifiedAt() })
	claims, reference, operations, grant, err := r3.VerifyBudgetAuthToken(
		request.Context(), server.r3.registry, compact, server.keyResolver, verificationClock,
	)
	if err != nil {
		return signaturekey.VerifiedRequest{}, aauth.AuthTokenClaims{}, r3.Reference{}, r3.AuthTokenOperations{}, budgets.Value{}, &requestTokenError{cause: err}
	}
	verifiedProof, err := prepared.Verify(claims.Confirmation.JWK)
	if err == nil {
		err = verifiedProof.CheckIssuedAt(time.Unix(claims.IssuedAt, 0))
	}
	return verifiedProof, claims, reference, operations, grant, err
}

func (server *Server) verifyPreparedBudgetAuthRequest(
	request *http.Request,
	prepared signaturekey.PreparedRequest,
	compact string,
) (signaturekey.VerifiedRequest, aauth.AuthTokenClaims, budgets.Value, error) {
	verificationClock := aauth.ClockFunc(func() time.Time { return prepared.VerifiedAt() })
	claims, grant, err := budgets.VerifyAuthToken(request.Context(), compact, server.keyResolver, verificationClock)
	if err != nil {
		return signaturekey.VerifiedRequest{}, aauth.AuthTokenClaims{}, budgets.Value{}, &requestTokenError{cause: err}
	}
	verifiedProof, err := prepared.Verify(claims.Confirmation.JWK)
	if err == nil {
		err = verifiedProof.CheckIssuedAt(time.Unix(claims.IssuedAt, 0))
	}
	return verifiedProof, claims, grant, err
}

func (server *Server) enforceFixedBudget(
	response *budgetResponseWriter,
	request *http.Request,
	claims aauth.AuthTokenClaims,
	principal AuthPrincipal,
	grant budgets.Value,
	r3Reference *r3.Reference,
	requiredScopes []string,
) bool {
	// Pricing is part of metering. A pricing failure must not trigger a
	// fallback balance observation or establish a ledger binding.
	response.observationBlocked = true
	policyRequest, finish, err := cloneScopePolicyRequest(request)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("prepare Resource Budget cost request: %w", err))
		return false
	}
	cost, policyErr := server.budget.cost(request.Context(), BudgetCostRequest{
		Request: policyRequest, Principal: cloneBudgetPrincipal(principal), Grant: grant,
	})
	finishErr := finish()
	if policyErr != nil || finishErr != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("Resource Budget cost policy: %w", errors.Join(policyErr, finishErr)))
		return false
	}
	if _, err := budgets.NewValue(cost, grant.Unit()); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("Resource Budget cost policy: %w", err))
		return false
	}
	charge := response.charge
	charge.Cost = cost
	result, err := server.budget.store.Charge(request.Context(), charge)
	if err == nil {
		if result.Cost != cost || result.Remaining < 0 || result.Remaining > grant.Amount() ||
			result.Cost+result.Remaining > grant.Amount() {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("Resource Budget store returned an invalid charge result"))
			return false
		}
		feedback, err := budgets.NewSuccessFeedback(grant, result.Cost, result.Remaining)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return false
		}
		formatted, err := budgets.FormatFeedback(feedback)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return false
		}
		response.Header().Set("AAuth-Budget", formatted)
		return true
	}
	return server.refuseBudget(response, request, claims, principal, grant, r3Reference, requiredScopes, cost, result, err)
}

func (server *Server) refuseBudget(
	response *budgetResponseWriter,
	request *http.Request,
	claims aauth.AuthTokenClaims,
	principal AuthPrincipal,
	grant budgets.Value,
	r3Reference *r3.Reference,
	requiredScopes []string,
	cost int64,
	result BudgetChargeResult,
	err error,
) bool {
	if !errors.Is(err, ErrBudgetInsufficient) && !errors.Is(err, ErrBudgetExhausted) {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return false
	}
	if result.Cost != 0 || result.Remaining < 0 || result.Remaining > grant.Amount() {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("Resource Budget store returned an invalid refusal result"))
		return false
	}
	reason := budgets.ReasonInsufficientBudget
	var required *int64
	switch {
	case errors.Is(err, ErrBudgetExhausted):
		if result.Remaining != 0 {
			writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("Resource Budget store reported exhaustion with a nonzero remainder"))
			return false
		}
		reason = budgets.ReasonBudgetExhausted
	case result.Remaining == 0 || cost <= result.Remaining:
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("Resource Budget store reported inconsistent insufficiency"))
		return false
	default:
		value := cost
		required = &value
	}
	response.remaining = &result.Remaining
	response.observationBlocked = false
	feedback, err := budgets.NewRefusalFeedback(grant, result.Remaining, required)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return false
	}
	formattedFeedback, err := budgets.FormatFeedback(feedback)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return false
	}
	challengeToken, err := server.budget.challenge(request.Context(), BudgetChallengeRequest{
		Token:     aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI},
		Principal: cloneBudgetPrincipal(principal), Grant: grant,
		Remaining: result.Remaining, Consumed: result.Consumed, Required: cost, Reason: reason,
		R3Reference: cloneR3Reference(r3Reference),
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("Resource Budget challenge: %w", err))
		return false
	}
	if err := server.validateBudgetChallenge(
		request.Context(), challengeToken, claims.JTI, principal, r3Reference,
		result.Consumed, grant.Unit(),
	); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("Resource Budget challenge: %w", err))
		return false
	}
	formattedRequirement, err := budgets.FormatAuthTokenRequirement(
		aauth.AuthTokenRequirement{ResourceToken: challengeToken}, reason,
	)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return false
	}
	store, hold, err := server.heldBudgetStore(request, r3Reference != nil)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return false
	}
	if hold {
		server.holdBudgetRefusal(
			response, request, store, claims, challengeToken, requiredScopes, formattedRequirement, formattedFeedback,
		)
		return false
	}
	response.Header().Set("AAuth-Budget", formattedFeedback)
	response.Header().Set("AAuth-Requirement", formattedRequirement)
	response.WriteHeader(http.StatusUnauthorized)
	return false
}

func (server *Server) validateBudgetChallenge(
	ctx context.Context,
	compact string,
	presentedJTI string,
	principal AuthPrincipal,
	expectedR3Reference *r3.Reference,
	metered int64,
	meteredUnit budgets.Unit,
) error {
	var claims aauth.ResourceTokenClaims
	var offer budgets.Value
	var consumed *budgets.ConsumptionRecord
	if expectedR3Reference == nil {
		var err error
		claims, offer, consumed, err = budgets.VerifyResourceToken(ctx, compact, server.keyResolver, server.clock)
		if err != nil {
			return err
		}
	} else {
		var reference r3.Reference
		var err error
		claims, reference, offer, consumed, err = r3.VerifyBudgetResourceToken(
			ctx, server.r3.registry, compact, server.keyResolver, server.clock,
		)
		if err != nil {
			return err
		}
		if reference != *expectedR3Reference {
			return errors.New("fresh Resource token changed the protected R3 reference")
		}
	}
	if consumed != nil {
		if !offer.Unit().Equal(meteredUnit) {
			return errors.New("fresh Resource token states consumption in a different scale than the metered grant")
		}
		if consumed.Consumed() != metered {
			return errors.New("fresh Resource token consumption record does not match metered spend")
		}
	}
	thumbprint, err := principal.Confirmation.Thumbprint()
	if err != nil {
		return err
	}
	expectedAudience := principal.PersonServer
	if server.authorizationTopology == authorizationTopologyFederated {
		expectedAudience = server.accessServer
	}
	if claims.Issuer != server.issuer || claims.DWK != aauth.ResourceDiscoveryDocument ||
		claims.Audience != expectedAudience || claims.PersonServer != principal.PersonServer ||
		claims.Subject != principal.Subject || claims.AgentJKT != thumbprint || claims.PresentedJTI != presentedJTI ||
		claims.MissionS256 != principal.MissionS256 || claims.Tenant != principal.Tenant ||
		!sameBudgetAccount(claims.Account, principal.Account) {
		return errors.New("fresh Resource token does not preserve the protected Budget context")
	}
	if claims.Scope == "" && len(principal.Scope) == 0 && expectedR3Reference != nil {
		// The R3 grant supplies operation authority; Budget does not require a
		// duplicate Core scope in the combined profile.
	} else {
		scopes, err := server.validateScopes(claims.Scope)
		if err != nil || !sameScopeSet(scopes, principal.Scope) {
			return errors.New("fresh Resource token does not preserve the protected scopes")
		}
	}
	if !server.budget.declared(offer) {
		return errors.New("fresh Resource token carries an undeclared Budget offer")
	}
	return nil
}

func cloneR3Reference(reference *r3.Reference) *r3.Reference {
	if reference == nil {
		return nil
	}
	value := *reference
	return &value
}

func cloneBudgetPrincipal(principal AuthPrincipal) AuthPrincipal {
	principal.Scope = append([]string(nil), principal.Scope...)
	principal.Account = cloneBudgetAccount(principal.Account)
	principal.AdditionalClaims = cloneAdditionalClaims(principal.AdditionalClaims)
	return principal
}

func (server *Server) servePersonTokenChallenge(
	response http.ResponseWriter,
	request *http.Request,
	prepared signaturekey.PreparedRequest,
	compact string,
) {
	proof, claims, err := server.verifyPreparedPersonRequest(request, prepared, compact)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	if err := aauth.ValidatePersonTokenContext(claims, server.issuer, proof.PublicKey()); err != nil {
		writeProblem(response, http.StatusUnauthorized, "invalid_token", err)
		return
	}
	if claims.MissionS256 != "" {
		writeProblem(response, http.StatusUnauthorized, "invalid_token", errors.New("mission-bound person tokens require mission verification"))
		return
	}
	scopes, err := server.requiredRouteScopes(request, false)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	hold, err := server.shouldHoldAuthTokenRequest(request)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	var budgetOffer *budgets.Value
	if !hold && server.budget != nil {
		offer, present, err := server.budget.initialOfferFor(request.Context(), request, claims, scopes)
		if err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		if present {
			budgetOffer = &offer
		}
	}
	ask, err := server.checkedAuthorizationAsk(request, claims)
	if err != nil {
		writeAuthorizationAskProblem(response, err)
		return
	}
	loginHint := ""
	var askAccount *string
	if ask != nil {
		loginHint = ask.LoginHint
		askAccount = cloneAuthorizationAccount(ask.Account)
	}
	if hold {
		server.serveHeldChallenge(response, request, proof, claims, scopes, loginHint)
		return
	}
	resourceToken, err := server.issueAuthorizationResourceToken(
		request, proof.VerifiedAt(), proof.PublicKey(), claims, scopes, askAccount, nil, budgetOffer, loginHint,
	)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	requirement, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: resourceToken})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.Header().Set("AAuth-Requirement", requirement)
	response.WriteHeader(http.StatusUnauthorized)
}

// shouldHoldAuthTokenRequest selects held delivery for a person-token or R3
// per-call challenge. A Resource with a Budget profile holds only Budget
// refusals, whose completion is metered against the completing token; any
// other held completion would run a metered route unmetered.
func (server *Server) shouldHoldAuthTokenRequest(request *http.Request) (bool, error) {
	if server.budget != nil {
		return false, nil
	}
	return server.holdPolicy(request)
}

// holdPolicy applies the host's HoldAuthTokenRequest policy.
func (server *Server) holdPolicy(request *http.Request) (bool, error) {
	if server.heldInvocations == nil {
		return false, nil
	}
	if server.holdAuthTokenRequest == nil {
		return true, nil
	}
	policyRequest, finish, err := cloneScopePolicyRequest(request)
	if err != nil {
		return false, fmt.Errorf("aauth: prepare held-delivery policy request: %w", err)
	}
	policyRequest.Header = heldApplicationHeaders(policyRequest.Header)
	hold := server.holdAuthTokenRequest(policyRequest)
	if err := finish(); err != nil {
		return false, fmt.Errorf("aauth: finish held-delivery policy request: %w", err)
	}
	return hold, nil
}

func (server *Server) verifyPreparedPersonRequest(
	request *http.Request,
	prepared signaturekey.PreparedRequest,
	compact string,
) (signaturekey.VerifiedRequest, aauth.PersonTokenClaims, error) {
	verificationClock := aauth.ClockFunc(func() time.Time { return prepared.VerifiedAt() })
	claims, err := aauth.VerifyPersonToken(request.Context(), compact, server.keyResolver, verificationClock)
	if err != nil {
		return signaturekey.VerifiedRequest{}, aauth.PersonTokenClaims{}, &requestTokenError{cause: err}
	}
	verifiedProof, err := prepared.Verify(claims.Confirmation.JWK)
	if err == nil {
		err = verifiedProof.CheckIssuedAt(time.Unix(claims.IssuedAt, 0))
	}
	return verifiedProof, claims, err
}

func (server *Server) verifyPreparedAgentRequest(
	request *http.Request,
	prepared signaturekey.PreparedRequest,
	compact string,
) (signaturekey.VerifiedRequest, aauth.AgentTokenClaims, error) {
	verificationClock := aauth.ClockFunc(func() time.Time { return prepared.VerifiedAt() })
	claims, err := aauth.VerifyAgentToken(request.Context(), compact, server.keyResolver, verificationClock)
	if err != nil {
		return signaturekey.VerifiedRequest{}, aauth.AgentTokenClaims{}, &requestTokenError{cause: err}
	}
	verifiedProof, err := prepared.Verify(claims.Confirmation.JWK)
	if err == nil {
		err = verifiedProof.CheckIssuedAt(time.Unix(claims.IssuedAt, 0))
	}
	return verifiedProof, claims, err
}

func (server *Server) verifyPreparedAuthRequest(
	request *http.Request,
	prepared signaturekey.PreparedRequest,
	compact string,
) (signaturekey.VerifiedRequest, aauth.AuthTokenClaims, error) {
	verificationClock := aauth.ClockFunc(func() time.Time { return prepared.VerifiedAt() })
	claims, err := aauth.VerifyAuthToken(request.Context(), compact, server.keyResolver, verificationClock)
	if err != nil {
		return signaturekey.VerifiedRequest{}, aauth.AuthTokenClaims{}, &requestTokenError{cause: err}
	}
	verifiedProof, err := prepared.Verify(claims.Confirmation.JWK)
	if err == nil {
		err = verifiedProof.CheckIssuedAt(time.Unix(claims.IssuedAt, 0))
	}
	return verifiedProof, claims, err
}

func (server *Server) prepareJWTRequest(
	request *http.Request,
	required []string,
) (signaturekey.PreparedRequest, string, error) {
	prepared, err := signaturekey.PrepareRequest(request, server.clock, signaturekey.VerifyOptions{
		RequiredComponents: required,
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJWT},
		MaxBodyBytes:       server.maxSignedBodyBytes,
	})
	if err != nil {
		return signaturekey.PreparedRequest{}, "", err
	}
	compact, ok := prepared.Credential().JWT()
	if !ok {
		return signaturekey.PreparedRequest{}, "", errors.New("aauth: resource requires a JWT credential")
	}
	return prepared, compact, nil
}

func cloneAdditionalClaims(claims map[string]json.RawMessage) map[string]json.RawMessage {
	if len(claims) == 0 {
		return nil
	}
	cloned := make(map[string]json.RawMessage, len(claims))
	for name, value := range claims {
		cloned[name] = append(json.RawMessage(nil), value...)
	}
	return cloned
}

func (server *Server) requiredRouteScopes(request *http.Request, allowEmpty bool) ([]string, error) {
	policyRequest, finish, err := cloneScopePolicyRequest(request)
	if err != nil {
		return nil, &scopePolicyError{cause: fmt.Errorf("aauth: prepare protected route scope policy request: %w", err)}
	}
	required := server.requiredScopes(policyRequest)
	if err := finish(); err != nil {
		return nil, &scopePolicyError{cause: fmt.Errorf("aauth: finish protected route scope policy request: %w", err)}
	}
	if len(required) == 0 {
		if allowEmpty {
			return nil, nil
		}
		return nil, &scopePolicyError{cause: errors.New("aauth: protected route has no required scope")}
	}
	validated := make([]string, len(required))
	seen := make(map[string]struct{}, len(required))
	for index, scope := range required {
		if scope == "" {
			return nil, &scopePolicyError{cause: errors.New("aauth: protected route returned an empty required scope")}
		}
		if err := aauth.ValidateScopeValue(scope); err != nil {
			return nil, &scopePolicyError{cause: fmt.Errorf("aauth: protected route scope: %w", err)}
		}
		if _, declared := server.scopeDescriptions[scope]; !declared {
			return nil, &scopePolicyError{cause: fmt.Errorf("aauth: protected route requires undeclared scope %q", scope)}
		}
		if _, duplicate := seen[scope]; duplicate {
			return nil, &scopePolicyError{cause: fmt.Errorf("aauth: protected route repeats required scope %q", scope)}
		}
		seen[scope] = struct{}{}
		validated[index] = scope
	}
	return validated, nil
}

func cloneScopePolicyRequest(request *http.Request) (*http.Request, func() error, error) {
	if request == nil {
		return nil, nil, errors.New("aauth: protected request is required")
	}
	policyRequest := request.Clone(request.Context())
	policyRequest.Header = request.Header.Clone()
	if request.URL != nil {
		clonedURL := *request.URL
		policyRequest.URL = &clonedURL
	}
	finish := func() error { return nil }
	if request.GetBody != nil {
		body, err := request.GetBody()
		if err != nil {
			return nil, nil, fmt.Errorf("copy request body: %w", err)
		}
		if body == nil {
			return nil, nil, errors.New("aauth: copied request body is nil")
		}
		independent := &scopePolicyIndependentBody{body: body}
		policyRequest.Body = independent
		return policyRequest, independent.finish, nil
	}
	if request.Body == nil || request.Body == http.NoBody {
		policyRequest.Body = request.Body
		return policyRequest, finish, nil
	}

	original := request.Body
	recorded := &scopePolicyRecordingReader{source: original}
	policyRequest.Body = scopePolicyNoCloseBody{Reader: recorded}
	finish = func() error {
		readPrefix := append([]byte(nil), recorded.prefix.Bytes()...)
		request.Body = &recoveredApplicationBody{
			Reader:   io.MultiReader(bytes.NewReader(readPrefix), original),
			original: original,
		}
		return recorded.firstErr
	}
	return policyRequest, finish, nil
}

type scopePolicyRecordingReader struct {
	source   io.Reader
	prefix   bytes.Buffer
	firstErr error
}

func (reader *scopePolicyRecordingReader) Read(buffer []byte) (int, error) {
	read, err := reader.source.Read(buffer)
	if read > 0 {
		_, _ = reader.prefix.Write(buffer[:read])
	}
	if err != nil && !errors.Is(err, io.EOF) && reader.firstErr == nil {
		reader.firstErr = err
	}
	return read, err
}

type scopePolicyIndependentBody struct {
	body     io.ReadCloser
	closed   bool
	firstErr error
	closeErr error
}

func (body *scopePolicyIndependentBody) Read(buffer []byte) (int, error) {
	read, err := body.body.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) && body.firstErr == nil {
		body.firstErr = err
	}
	return read, err
}

func (body *scopePolicyIndependentBody) Close() error {
	if body.closed {
		return body.closeErr
	}
	body.closed = true
	body.closeErr = body.body.Close()
	return body.closeErr
}

func (body *scopePolicyIndependentBody) finish() error {
	return errors.Join(body.firstErr, body.Close())
}

type scopePolicyNoCloseBody struct{ io.Reader }

func (scopePolicyNoCloseBody) Close() error { return nil }

type recoveredApplicationBody struct {
	io.Reader
	original io.Closer
	closed   bool
}

func (body *recoveredApplicationBody) Close() error {
	if body.closed {
		return nil
	}
	body.closed = true
	return body.original.Close()
}

func (server *Server) authorizeScopes(request *http.Request, granted []string, allowEmpty bool) ([]string, error) {
	required, err := server.requiredRouteScopes(request, allowEmpty)
	if err != nil {
		return nil, err
	}
	grants := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		grants[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, allowed := grants[scope]; !allowed {
			return nil, fmt.Errorf("aauth: protected route requires scope %q", scope)
		}
	}
	return required, nil
}

type scopePolicyError struct{ cause error }

func (failure *scopePolicyError) Error() string { return failure.cause.Error() }
func (failure *scopePolicyError) Unwrap() error { return failure.cause }
