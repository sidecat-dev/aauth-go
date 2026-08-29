package reference

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func (resource *Resource) mintAndRetainResourceToken(
	ctx context.Context,
	claims aauth.ResourceTokenClaims,
	reference r3.DocumentReference,
	budget *budgets.Budget,
	now time.Time,
) (string, error) {
	draft, err := aauth.NewResourceTokenDraft(claims)
	if err != nil {
		return "", err
	}
	if reference.Valid() {
		draft, err = r3.BindResourceToken(draft, reference)
	}
	if err == nil && budget != nil {
		draft, err = budgets.BindResourceToken(draft, *budget, nil)
	}
	if err != nil {
		return "", err
	}
	compact, err := draft.Mint(resource.signingKey)
	if err != nil || resource.resourceTokenLineageStore == nil {
		return compact, err
	}
	record, err := NewResourceTokenLineageRecord(compact, claims)
	if err != nil {
		return "", err
	}
	if existing, loadErr := resource.resourceTokenLineageStore.Load(ctx, record.ContextKey); loadErr == nil {
		if !existing.Active(now) {
			return "", ErrResourceTokenLineageConflict
		}
		return existing.ResourceToken, nil
	} else if !errors.Is(loadErr, ErrResourceTokenLineageNotFound) {
		return "", loadErr
	}
	if err := resource.resourceTokenLineageStore.Commit(ctx, record); err != nil {
		if !errors.Is(err, ErrResourceTokenLineageConflict) {
			return "", err
		}
		winner, loadErr := resource.resourceTokenLineageStore.Load(ctx, record.ContextKey)
		if loadErr != nil || !winner.Active(now) {
			return "", errors.Join(err, loadErr)
		}
		return winner.ResourceToken, nil
	}
	return compact, nil
}

func (resource *Resource) challengeR3PerCall(
	response http.ResponseWriter,
	request *http.Request,
	body []byte,
	verified aauth.VerifiedRequest,
	claims aauth.AuthTokenClaims,
	initial r3.TokenResult,
	operation r3.OperationSet,
) {
	if resource.resourceTokenLineageStore == nil || resource.r3ProposalForRequest == nil ||
		resource.r3ParametersForRequest == nil || resource.r3PerCallStore == nil ||
		resource.r3PerCallOperation == nil {
		writeProblem(response, http.StatusNotImplemented, "r3_per_call_not_implemented", errors.New("resource does not implement R3 per-call authorization"))
		return
	}
	thumbprint, err := verified.PublicKey.Thumbprint()
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "r3_lineage_failed", err)
		return
	}
	lineageKey, err := ResourceAuthorizationLineageKey(
		resource.identifier, claims.Issuer, claims.PersonServer, claims.Subject,
		thumbprint, claims.MissionS256, claims.Tenant, claims.Account,
		initial.URI(), initial.Digest(),
	)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "r3_lineage_failed", err)
		return
	}
	lineage, err := resource.resourceTokenLineageStore.Resolve(request.Context(), lineageKey, claims.IssuedAt)
	if err != nil || !lineage.Active(time.Unix(claims.IssuedAt, 0)) ||
		lineage.PersonServer != claims.PersonServer || lineage.Subject != claims.Subject ||
		lineage.AgentJKT != thumbprint || !scopeStringContains(lineage.Scope, claims.Scope) {
		writeProblem(response, http.StatusForbidden, "r3_lineage_not_found", errors.New("current auth token cannot be linked to the person token retained for its R3 authorization"))
		return
	}
	if !resource.consumeProof(response, request, verified) {
		return
	}
	exact, err := resource.r3ProposalForRequest(request.Context(), request, append([]byte(nil), body...))
	if err != nil {
		writeHostPolicyRefusal(response, "r3_per_call_denied", "resource could not construct a per-call proposal")
		return
	}
	proposal, err := r3.ParsePerCallProposal(exact)
	proposalOperation, operationErr := proposal.Operation()
	if err != nil || operationErr != nil || !proposalOperation.Equal(operation) {
		writeProblem(response, http.StatusInternalServerError, "invalid_r3_per_call_proposal", errors.Join(err, operationErr))
		return
	}
	digest := r3.S256(exact)
	reference, err := r3.NewDocumentReference(resource.identifier+"/r3/per-call/"+digest, exact)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "invalid_r3_per_call_proposal", err)
		return
	}
	now := verified.VerifiedAt.UTC()
	expiresAt := now.Add(5 * time.Minute)
	if tokenExpiry := time.Unix(claims.ExpiresAt, 0); tokenExpiry.Before(expiresAt) {
		expiresAt = tokenExpiry
	}
	readers := []string{claims.Issuer, claims.PersonServer}
	if claims.Issuer == claims.PersonServer {
		readers = readers[:1]
	}
	if err := resource.r3DocumentStore.RetainAuthorized(request.Context(), digest, reference.ExactBytes(), readers, expiresAt); err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "r3_custody_unavailable", err)
		return
	}
	resourceClaims := aauth.ResourceTokenClaims{
		Issuer: resource.identifier, DWK: aauth.ResourceDiscoveryDocument,
		Audience: claims.Issuer, JTI: resource.newID(), AgentJKT: thumbprint,
		IssuedAt: now.Unix(), ExpiresAt: expiresAt.Unix(), Scope: claims.Scope,
		PersonServer: claims.PersonServer, Subject: claims.Subject,
		PresentedJTI: lineage.PresentedJTI, MissionS256: claims.MissionS256,
		Tenant: claims.Tenant, Account: claims.Account,
	}
	compact, err := resource.mintAndRetainResourceToken(request.Context(), resourceClaims, reference, nil, now)
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "r3_custody_unavailable", err)
		return
	}
	requirement, err := aauth.FormatRequirementHeader(aauth.Requirement{Type: aauth.RequirementAuthToken, ResourceToken: compact})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "invalid_r3_per_call_challenge", err)
		return
	}
	response.Header().Set("AAuth-Requirement", requirement)
	writeProblem(response, http.StatusUnauthorized, "authorization_required", errors.New("R3 per-call approval is required"))
}

func (resource *Resource) completeR3PerCall(
	response http.ResponseWriter,
	request *http.Request,
	body []byte,
	verified aauth.VerifiedRequest,
	claims aauth.AuthTokenClaims,
	token r3.TokenResult,
	operation r3.OperationSet,
) {
	if !resource.isR3PerCallReference(token) {
		writeProblem(response, http.StatusForbidden, "invalid_r3_per_call_grant", errors.New("R3 per-call token does not name its exact resource proposal"))
		return
	}
	exact, err := resource.r3DocumentStore.Load(request.Context(), token.Digest())
	if err != nil {
		writeProblem(response, http.StatusForbidden, "r3_per_call_proposal_not_found", err)
		return
	}
	proposal, err := r3.ParsePerCallProposal(exact)
	proposalOperation, operationErr := proposal.Operation()
	if err != nil || operationErr != nil || !proposalOperation.Equal(operation) {
		writeProblem(response, http.StatusForbidden, "invalid_r3_per_call_grant", errors.Join(err, operationErr))
		return
	}
	presented, err := resource.r3ParametersForRequest(request.Context(), request, append([]byte(nil), body...))
	if err != nil || proposal.Match(presented) != nil {
		writeProblem(response, http.StatusForbidden, "r3_per_call_parameters_mismatch", errors.New("call parameters do not match the approved R3 proposal"))
		return
	}
	if !resource.consumeProof(response, request, verified) {
		return
	}
	operationJSON, err := json.Marshal(operation)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "r3_per_call_failed", err)
		return
	}
	execution, err := NewR3PerCallExecution(claims.Issuer, claims.JTI, token.Digest(), operationJSON, claims.ExpiresAt)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "r3_per_call_failed", err)
		return
	}
	record, acquired, err := resource.r3PerCallStore.Claim(request.Context(), execution)
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "r3_per_call_custody_unavailable", err)
		return
	}
	if record.State == "complete" {
		writeR3PerCallResult(response, *record.Result)
		return
	}
	if !acquired {
		response.Header().Set("Retry-After", "1")
		writeProblem(response, http.StatusConflict, "r3_per_call_in_progress", errors.New("the approved R3 call is already executing"))
		return
	}
	defer resource.r3PerCallStore.Release(execution.Key)
	granted, err := parseScopes(claims.Scope)
	if err != nil {
		writeProblem(response, http.StatusForbidden, "invalid_token", err)
		return
	}
	authorized := aauth.AuthorizedRequest{
		Agent: claims.Agent, PersonServer: claims.PersonServer, Subject: claims.Subject,
		AuthTokenIssuer: claims.Issuer, AuthTokenDWK: claims.DWK, AuthTokenID: claims.JTI,
		AuthTokenIssuedAt: time.Unix(claims.IssuedAt, 0).UTC(), AuthTokenExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
		ConfirmationKey: verified.PublicKey, ProofReplayKey: verified.ReplayKey,
		ProofCreatedAt: verified.Created.UTC(), Scope: granted,
		Mission: claims.Mission, MissionS256: claims.MissionS256, Tenant: claims.Tenant,
		Account: claims.Account, Actor: claims.Actor, AuthToken: verified.RawCredential,
		Method: request.Method, Path: request.URL.Path, Body: append([]byte(nil), body...),
		ContentType: request.Header.Get("Content-Type"),
	}
	if err := resource.protectedAuthorizationPolicy(request.Context(), copyAuthorizedRequest(authorized)); err != nil {
		writeProblem(response, http.StatusForbidden, "invalid_token", errors.New("protected request was denied by resource policy"))
		return
	}
	output, err := resource.r3PerCallOperation(request.Context(), authorized, execution.Key)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "operation_failed", err)
		return
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "operation_failed", err)
		return
	}
	completed, err := resource.r3PerCallStore.Complete(request.Context(), execution.Key, R3PerCallResult{
		Status: http.StatusOK, ContentType: "application/json", Body: encoded,
	})
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "r3_per_call_custody_unavailable", err)
		return
	}
	writeR3PerCallResult(response, *completed.Result)
}

func (resource *Resource) isR3PerCallReference(token r3.TokenResult) bool {
	return token.Valid() && token.URI() == resource.identifier+"/r3/per-call/"+token.Digest()
}

func writeR3PerCallResult(response http.ResponseWriter, result R3PerCallResult) {
	response.Header().Set("Content-Type", result.ContentType)
	response.WriteHeader(result.Status)
	_, _ = response.Write(result.Body)
}

func scopeStringContains(available, requested string) bool {
	availableScopes, availableErr := parseScopes(available)
	requestedScopes, requestedErr := parseScopes(requested)
	return availableErr == nil && requestedErr == nil && scopesContained(requestedScopes, availableScopes)
}
