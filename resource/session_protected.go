package resource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func (server *ResourceManagedServer) serveResourceManaged(response http.ResponseWriter, request *http.Request) {
	if !hasAAuthRequestProof(request) {
		if len(request.Header.Values("Authorization")) != 0 {
			writeCredentialProblem(response, "invalid_signature", &requestTokenError{cause: &signaturekey.Error{
				Code:  signaturekey.ErrorInvalidRequest,
				Cause: errors.New("session Authorization requires Signature, Signature-Input, and Signature-Key"),
			}})
			return
		}
		response.Header().Set("AAuth-Requirement", aauth.FormatAgentTokenRequirement())
		response.WriteHeader(http.StatusUnauthorized)
		return
	}
	proof, claims, err := server.verifyResourceManagedAgentRequest(request, server.additionalSignatureComponents)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	if !claims.Confirmation.JWK.Equal(proof.PublicKey()) {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", errors.New("request key does not match agent token"))
		return
	}
	principal := AgentPrincipal{
		AgentProvider: claims.Issuer, Agent: claims.Subject, ParentAgent: claims.ParentAgent,
		PersonServer: claims.PersonServer, Confirmation: proof.PublicKey(),
		AdditionalClaims: cloneAdditionalClaims(claims.AdditionalClaims),
	}
	if len(request.Header.Values("Authorization")) != 0 {
		server.serveSessionAuthorized(response, request, proof, principal)
		return
	}
	scopes, err := server.requiredManagedRouteScopes(request)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	authorization := SessionAuthorizationRequest{
		AgentPrincipal: principal, Method: request.Method, Path: request.URL.EscapedPath(),
		RequiredScopes: scopes,
	}
	if authorization.Path == "" {
		authorization.Path = "/"
	}
	if server.authorizeImmediately != nil {
		grant, authorized, err := server.authorizeImmediately(request.Context(), cloneSessionAuthorizationRequest(authorization))
		if err != nil {
			writeProblem(response, http.StatusForbidden, "access_denied", err)
			return
		}
		if authorized {
			server.serveImmediateSession(response, request, proof, principal, scopes, grant)
			return
		}
	}
	if server.deferredSessions == nil {
		writeProblem(response, http.StatusForbidden, "interaction_unavailable", errors.New("Resource interaction is not configured"))
		return
	}
	server.beginSessionInteraction(response, request, authorization)
}

func (server *ResourceManagedServer) serveImmediateSession(
	response http.ResponseWriter,
	request *http.Request,
	proof signaturekey.VerifiedRequest,
	principal AgentPrincipal,
	required []string,
	grant SessionGrant,
) {
	if err := server.validateSessionGrant(grant, required); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	record, err := server.sessionRecord(principal, grant, proof.VerifiedAt())
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	approval, err := server.sessions.Create(request.Context(), record)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := server.validateCreatedSessionApproval(approval, record, proof.VerifiedAt()); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.Header().Set("AAuth-Access", approval.Token)
	sessionPrincipal := sessionPrincipalFromRecord(record, principal, proof.PublicKey())
	server.protected.ServeHTTP(response, request.WithContext(context.WithValue(
		request.Context(), sessionPrincipalContextKey{}, sessionPrincipal,
	)))
}

func (server *ResourceManagedServer) serveSessionAuthorized(
	response http.ResponseWriter,
	request *http.Request,
	proof signaturekey.VerifiedRequest,
	principal AgentPrincipal,
) {
	token, err := aauth.ParseSessionAuthorization(request.Header.Values("Authorization"))
	if err != nil {
		writeProblem(response, http.StatusForbidden, "invalid_session", err)
		return
	}
	record, err := server.sessions.Load(request.Context(), token, proof.VerifiedAt())
	if err != nil {
		switch {
		case errors.Is(err, ErrSessionNotFound), errors.Is(err, ErrSessionExpired):
			writeProblem(response, http.StatusForbidden, "invalid_session", err)
		default:
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	required, err := server.requiredManagedRouteScopes(request)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := server.validateSessionRecordForUse(record, principal, required, proof.VerifiedAt()); err != nil {
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	sessionPrincipal := sessionPrincipalFromRecord(record, principal, proof.PublicKey())
	server.protected.ServeHTTP(response, request.WithContext(context.WithValue(
		request.Context(), sessionPrincipalContextKey{}, sessionPrincipal,
	)))
}

func (server *ResourceManagedServer) verifyResourceManagedAgentRequest(
	request *http.Request,
	required []string,
) (signaturekey.VerifiedRequest, aauth.AgentTokenClaims, error) {
	prepared, err := signaturekey.PrepareRequest(request, server.clock, signaturekey.VerifyOptions{
		RequiredComponents: required,
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeJWT},
		MaxBodyBytes:       server.maxSignedBodyBytes,
	})
	if err != nil {
		return signaturekey.VerifiedRequest{}, aauth.AgentTokenClaims{}, &requestTokenError{cause: err}
	}
	compact, ok := prepared.Credential().JWT()
	if !ok {
		return signaturekey.VerifiedRequest{}, aauth.AgentTokenClaims{}, &requestTokenError{
			cause: errors.New("aauth: resource-managed requests require a JWT credential"),
		}
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return prepared.VerifiedAt() })
	claims, err := aauth.VerifyAgentToken(request.Context(), compact, server.keyResolver, verificationClock)
	if err != nil {
		return signaturekey.VerifiedRequest{}, aauth.AgentTokenClaims{}, &requestTokenError{cause: err}
	}
	proof, err := prepared.Verify(claims.Confirmation.JWK)
	if err != nil {
		return signaturekey.VerifiedRequest{}, aauth.AgentTokenClaims{}, &requestTokenError{cause: err}
	}
	return proof, claims, nil
}

func (server *ResourceManagedServer) requiredManagedRouteScopes(request *http.Request) ([]string, error) {
	policyRequest, finish, err := cloneScopePolicyRequest(request)
	if err != nil {
		return nil, fmt.Errorf("resource: prepare Resource-managed scope policy request: %w", err)
	}
	values := server.requiredScopes(policyRequest)
	if err := finish(); err != nil {
		return nil, fmt.Errorf("resource: finish Resource-managed scope policy request: %w", err)
	}
	return server.validateManagedScopes(values)
}

func (server *ResourceManagedServer) validateSessionRecordForUse(
	record SessionRecord,
	principal AgentPrincipal,
	required []string,
	now time.Time,
) error {
	if record.Resource != server.issuer || record.AgentProvider != principal.AgentProvider ||
		record.Agent != principal.Agent || record.ParentAgent != principal.ParentAgent {
		return errors.New("resource: session does not belong to this Resource and Agent")
	}
	if record.Subject == "" || strings.TrimSpace(record.Subject) != record.Subject || record.CreatedAt.IsZero() ||
		record.CreatedAt.After(now) || !record.ExpiresAt.After(now) {
		return errors.New("resource: session record is invalid or expired")
	}
	scopes, err := server.validateManagedScopes(record.Scope)
	if err != nil || !scopeSetContains(scopes, required) {
		return errors.New("resource: session does not cover the required scopes")
	}
	return nil
}

func sessionPrincipalFromRecord(
	record SessionRecord,
	agent AgentPrincipal,
	proofKey jose.JWK,
) SessionPrincipal {
	return SessionPrincipal{
		Resource: record.Resource, AgentProvider: record.AgentProvider, Agent: record.Agent,
		ParentAgent: record.ParentAgent, Subject: record.Subject, Scope: append([]string(nil), record.Scope...),
		Confirmation: proofKey, AdditionalClaims: cloneAdditionalClaims(agent.AdditionalClaims),
	}
}
