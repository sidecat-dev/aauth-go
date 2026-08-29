package reference

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func (resource *Resource) handleDeferredProtectedCall(response http.ResponseWriter, request *http.Request) {
	if resource.deferredProtectedStore == nil {
		writeProblem(response, http.StatusNotFound, "deferred_call_not_found", ErrDeferredProtectedNotFound)
		return
	}
	record, err := resource.deferredProtectedStore.Load(request.Context(), request.PathValue("id"))
	if err != nil {
		writeProblem(response, http.StatusNotFound, "deferred_call_not_found", err)
		return
	}
	if !record.ExpiresAt.After(resource.clock.Now()) {
		writeProblem(response, http.StatusGone, "deferred_call_expired", errors.New("deferred protected call expired"))
		return
	}
	verified, err := aauth.VerifyRequest(
		request.Context(), request, resource.keyResolver, resource.clock,
		aauth.VerifyRequestOptions{
			RequireExactComponents: true,
			AllowedCredentialTypes: []string{aauth.AuthTokenType},
		},
	)
	if err != nil {
		writeSignatureFailure(response, err)
		return
	}
	if err := verified.AuthToken.RequireNoAuthorizationMembers(); err != nil {
		writeTokenVerificationFailure(response, http.StatusForbidden, "invalid_token", err)
		return
	}
	claims, err := verified.AuthClaims()
	if err != nil || claims.Issuer != resource.tokenAudience || claims.DWK != resource.authTokenDiscoveryDocument {
		writeTokenVerificationFailure(response, http.StatusForbidden, "invalid_token", errors.New("auth token issuer does not match deferred resource configuration"))
		return
	}
	resourceEvidence, err := aauth.VerifyResourceToken(
		request.Context(), record.ResourceToken,
		signaturekey.StaticKeyResolver{resource.identifier: {resource.signingKey.ID(): resource.signingKey.PublicJWK()}},
		resource.clock,
	)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "deferred_custody_invalid", err)
		return
	}
	resourceClaims, err := claimsWithoutAuthorization(resourceEvidence)
	if err != nil || resourceClaims.Issuer != resource.identifier || resourceClaims.Audience != claims.Issuer ||
		resourceClaims.PersonServer != claims.PersonServer || resourceClaims.Subject != claims.Subject ||
		resourceClaims.MissionS256 != claims.MissionS256 || resourceClaims.Tenant != claims.Tenant ||
		resourceClaims.Account != claims.Account || claims.ExpiresAt > resourceClaims.ExpiresAt ||
		aauth.ValidateCurrentAuthTokenContext(
			claims, resource.identifier, resourceClaims.PersonServer, resourceClaims.Subject,
			verified.PublicKey, record.RequiredScopes,
		) != nil {
		writeTokenVerificationFailure(response, http.StatusForbidden, "invalid_token", errors.New("auth token does not satisfy the held invocation"))
		return
	}
	if !resource.consumeProof(response, request, verified) {
		return
	}
	record, acquired, err := resource.deferredProtectedStore.Claim(request.Context(), record.ID, claims.Issuer, claims.JTI)
	if err != nil {
		writeProblem(response, http.StatusConflict, "deferred_call_conflict", err)
		return
	}
	if record.State == DeferredProtectedComplete {
		writeDeferredProtectedResult(response, *record.Result)
		return
	}
	if !acquired {
		response.Header().Set("Retry-After", "1")
		writeProblem(response, http.StatusConflict, "deferred_call_in_progress", errors.New("deferred protected call is executing"))
		return
	}
	defer resource.deferredProtectedStore.Release(record.ID)
	parsedTarget, err := url.ParseRequestURI(record.Target)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "deferred_custody_invalid", err)
		return
	}
	rawAuthToken, err := verified.AuthToken.Compact()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	authorized := aauth.AuthorizedRequest{
		PersonServer: claims.PersonServer, Subject: claims.Subject,
		AuthTokenIssuer: claims.Issuer, AuthTokenDWK: claims.DWK, AuthTokenID: claims.JTI,
		AuthTokenIssuedAt: time.Unix(claims.IssuedAt, 0).UTC(), AuthTokenExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
		ConfirmationKey: verified.PublicKey, Scope: append([]string(nil), record.RequiredScopes...),
		MissionS256: claims.MissionS256, Tenant: claims.Tenant, Account: claims.Account,
		ProofReplayKey: verified.ReplayKey, ProofCreatedAt: verified.Created.UTC(),
		AuthToken: rawAuthToken, Method: record.Method, Path: parsedTarget.Path, Target: record.Target,
		Body: append([]byte(nil), record.Body...), ContentType: record.ContentType,
	}
	if err := resource.protectedAuthorizationPolicy(request.Context(), copyAuthorizedRequest(authorized)); err != nil {
		writeProblem(response, http.StatusForbidden, "invalid_token", errors.New("protected request was denied by resource policy"))
		return
	}
	value, err := resource.deferredProtectedOperation(request.Context(), authorized, record.ID)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "operation_failed", err)
		return
	}
	body, err := json.Marshal(value)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "operation_failed", err)
		return
	}
	body = append(body, '\n')
	complete, err := resource.deferredProtectedStore.Complete(request.Context(), record.ID, DeferredProtectedResult{
		Status: http.StatusOK, ContentType: "application/json", Body: body,
	})
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "deferred_custody_unavailable", err)
		return
	}
	writeDeferredProtectedResult(response, *complete.Result)
}
