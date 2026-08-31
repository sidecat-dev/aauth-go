package resource

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"time"

	aauth "aauth-go"
	"aauth-go/jose"
	"aauth-go/r3"
	"aauth-go/signaturekey"
)

func (server *Server) serveMCPR3PerCallChallenge(
	response http.ResponseWriter,
	request *http.Request,
	proof signaturekey.VerifiedRequest,
	claims aauth.AuthTokenClaims,
	authorization mcpR3ProtectedAuthorization,
	operation r3.MCPOperation,
	requiredScopes []string,
) {
	if server.mcpR3 == nil || server.mcpR3.perCall == nil {
		writeProblem(response, http.StatusForbidden, "access_denied", errors.New("MCP R3 per-call authorization is not configured"))
		return
	}
	classRecord, err := server.mcpR3.documents.Load(request.Context(), authorization.reference.URI())
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("load MCP R3 class context: %w", err))
		return
	}
	_, classResourceClaims, err := server.validateMCPR3ClassLineage(
		request.Context(), classRecord, proof, claims, authorization, operation,
	)
	if err != nil {
		writeMCPR3ValidationFailure(response, err)
		return
	}
	presented, err := server.presentMCPR3Call(request, operation, claims.Account)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	description, err := server.describeMCPR3Call(request, operation, claims.Account)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if matches, err := description.Parameters.Matches(presented); err != nil || !matches {
		if err == nil {
			err = errors.New("proposal parameters do not match the concrete call")
		}
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("describe MCP R3 call: %w", err))
		return
	}
	proposal, err := r3.NewMCPProposal(operation, description.Parameters, r3.ProposalOptions{
		Account: cloneAuthorizationAccount(claims.Account), Display: description.Display,
	})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("construct MCP R3 proposal: %w", err))
		return
	}
	exactJSON, err := json.Marshal(proposal)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("serialize MCP R3 proposal: %w", err))
		return
	}

	verifiedAt := proof.VerifiedAt()
	proposalClaims, expiresAt, err := server.mcpR3ProposalClaims(classResourceClaims, claims, proof, verifiedAt)
	if err != nil {
		writeMCPR3ValidationFailure(response, err)
		return
	}
	proposalURI := mcpR3ProposalURI(
		server.issuer, exactJSON, proposalClaims.PersonServer, proposalClaims.Audience, proposalClaims.JTI,
	)
	compact, reference, err := r3.MintMCPProposalResourceToken(
		server.signingKey, proposalClaims, proposalURI, exactJSON,
	)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	proposalRecord := R3ProposalRecord{
		Reference: reference, ExactJSON: append([]byte(nil), exactJSON...),
		PersonServer: proposalClaims.PersonServer, AccessServer: proposalClaims.Audience,
		ResourceTokenJTI: proposalClaims.JTI, ClassReference: classRecord.Reference,
		RetainUntil: expiresAt,
	}
	if err := server.mcpR3.perCall.proposals.Commit(request.Context(), proposalRecord); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("retain MCP R3 proposal: %w", err))
		return
	}
	hold, err := server.shouldHoldAuthTokenRequest(request)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if hold {
		server.serveHeldMCPR3Challenge(
			response, request, compact, reference, authorization.reference,
			operation, exactJSON, requiredScopes, verifiedAt, expiresAt,
		)
		return
	}
	retry := R3RetryInvocation{
		Reference: reference, ClassReference: authorization.reference, Operation: operation,
		ResourceToken: compact, ExactProposal: append([]byte(nil), exactJSON...),
		RequiredScopes: append([]string(nil), requiredScopes...),
		PreparedAt:     verifiedAt, ExpiresAt: expiresAt,
		CompletionUntil: expiresAt.Add(maximumDerivativeAuthTokenLifetime),
	}
	if err := server.mcpR3.perCall.retries.Prepare(request.Context(), retry); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("retain MCP R3 retry: %w", err))
		return
	}
	requirement, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: compact})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.Header().Set("AAuth-Requirement", requirement)
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusUnauthorized)
}

func (server *Server) serveHeldMCPR3Challenge(
	response http.ResponseWriter,
	request *http.Request,
	resourceToken string,
	reference r3.Reference,
	classReference r3.Reference,
	operation r3.MCPOperation,
	exactProposal []byte,
	scopes []string,
	issuedAt time.Time,
	expiresAt time.Time,
) {
	snapshot, err := snapshotHeldRequest(request, server.maxRetainedRequestBodyBytes)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := validateHeldRequestHeaderLimit(snapshot.header, server.maxRetainedHeaderBytes); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	requirement, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: resourceToken})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	invocation := snapshot.heldInvocation(resourceToken, scopes, issuedAt, expiresAt)
	invocation.R3PerCall = &HeldR3PerCall{
		Reference: reference, ClassReference: classReference, Operation: operation,
		ExactProposal: append([]byte(nil), exactProposal...),
	}
	pendingID, err := server.heldInvocations.Create(request.Context(), invocation)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := validateHeldPendingID(pendingID); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	response.Header().Set("Location", server.issuer+"/pending/"+pendingID)
	response.Header().Set("Retry-After", fmt.Sprintf("%.0f", heldPollRetryAfter.Seconds()))
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("AAuth-Requirement", requirement)
	writeJSON(response, http.StatusAccepted, struct {
		Status string `json:"status"`
	}{Status: "pending"})
}

func (server *Server) serveMCPR3RetryCompletion(
	response http.ResponseWriter,
	request *http.Request,
	proof signaturekey.VerifiedRequest,
	claims aauth.AuthTokenClaims,
	authorization mcpR3ProtectedAuthorization,
	operation r3.MCPOperation,
	scopes []string,
	compact string,
) {
	if server.mcpR3 == nil || server.mcpR3.perCall == nil {
		writeProblem(response, http.StatusForbidden, "access_denied", errors.New("MCP R3 per-call authorization is not configured"))
		return
	}
	retry, err := server.mcpR3.perCall.retries.Load(request.Context(), authorization.reference)
	if err != nil {
		server.writeR3RetryFailure(response, err)
		return
	}
	proposal, _, err := server.validateMCPR3Retry(
		request.Context(), retry, proof, claims, authorization, operation, scopes,
	)
	if err != nil {
		writeMCPR3ValidationFailure(response, err)
		return
	}
	presented, err := server.presentMCPR3Call(request, operation, claims.Account)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if matches, err := proposal.Parameters().Matches(presented); err != nil || !matches {
		if err == nil {
			err = errors.New("retry parameters do not match the approved proposal")
		}
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	snapshot, err := snapshotHeldRequest(request, server.maxRetainedRequestBodyBytes)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, "invalid_request", err)
		return
	}
	claim, err := server.mcpR3.perCall.retries.Claim(context.Background(), authorization.reference, R3RetryAuthToken{
		SHA256: sha256.Sum256([]byte(compact)), PresentedAt: proof.VerifiedAt(),
		RetainUntil: time.Unix(claims.ExpiresAt, 0),
	})
	if err != nil {
		server.writeR3RetryFailure(response, err)
		return
	}
	if replay, ok := claim.Replay(); ok {
		if err := server.writeHeldResponse(response, replay); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	execution, ok := claim.Execution()
	if !ok || execution.InvocationID != authorization.reference.URI() || execution.Fence == "" {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("R3 retry store returned an invalid claim"))
		return
	}
	result := server.executeMCPR3Retry(snapshot, compact, claims, proof.PublicKey(), proof.VerifiedAt(), scopes)
	retained, err := server.mcpR3.perCall.retries.Retain(context.Background(), execution, result)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := server.writeHeldResponse(response, retained); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
	}
}

func (server *Server) validateMCPR3Retry(
	ctx context.Context,
	retry R3RetryInvocation,
	proof signaturekey.VerifiedRequest,
	claims aauth.AuthTokenClaims,
	authorization mcpR3ProtectedAuthorization,
	operation r3.MCPOperation,
	scopes []string,
) (r3.MCPProposal, aauth.ResourceTokenClaims, error) {
	if retry.ResourceToken == "" || len(retry.ExactProposal) == 0 || retry.PreparedAt.IsZero() || retry.ExpiresAt.IsZero() ||
		retry.CompletionUntil.IsZero() || !retry.PreparedAt.Before(retry.ExpiresAt) ||
		!retry.CompletionUntil.Equal(retry.ExpiresAt.Add(maximumDerivativeAuthTokenLifetime)) {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			errors.New("MCP R3 retry authorization context is incomplete"),
		)
	}
	proposal, err := r3.ParseReferencedProposal(retry.Reference, retry.ExactProposal)
	if err != nil {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			fmt.Errorf("parse retained MCP R3 proposal: %w", err),
		)
	}
	if err := r3.ValidateProposalAccount(proposal, claims.Account); err != nil {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, err
	}
	if retry.Reference != authorization.reference || retry.Operation != proposal.Operation() {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			errors.New("retained MCP R3 retry changed its proposal identity"),
		)
	}
	granted := authorization.operations.GrantedOperations().Operations()
	if len(granted) != 1 || granted[0] != operation || proposal.Operation() != operation ||
		authorization.operations.PerCallClaimPresent() ||
		len(authorization.operations.PerCallOperations().Operations()) != 0 {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, errors.New("MCP R3 completion token does not grant exactly the retained proposal operation")
	}
	verificationClock := aauth.ClockFunc(func() time.Time { return retry.PreparedAt })
	retained, reference, err := r3.VerifyMCPResourceToken(
		ctx, retry.ResourceToken, server.keyResolver, verificationClock,
	)
	if err != nil {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			fmt.Errorf("verify retained MCP R3 proposal token: %w", err),
		)
	}
	if reference != retry.Reference || retained.JTI == "" ||
		retained.Issuer != server.issuer || retained.DWK != aauth.ResourceDiscoveryDocument ||
		retained.IssuedAt != retry.PreparedAt.Unix() || retained.ExpiresAt != retry.ExpiresAt.Unix() {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			errors.New("retained MCP R3 retry context does not match its proposal token"),
		)
	}
	if mcpR3ProposalURIFromDigest(
		server.issuer, retry.Reference.Digest(), retained.PersonServer, retained.Audience, retained.JTI,
	) != retry.Reference.URI() {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			errors.New("retained MCP R3 proposal reference is invalid"),
		)
	}
	if retained.Audience != claims.Issuer || retained.PersonServer != claims.PersonServer ||
		retained.Subject != claims.Subject || retained.Tenant != claims.Tenant ||
		retained.MissionS256 != claims.MissionS256 || !equalOptionalString(retained.Account, claims.Account) {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, errors.New("MCP R3 completion token changed the retained proposal context")
	}
	classRecord, err := server.mcpR3.documents.Load(ctx, retry.ClassReference.URI())
	if err != nil {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			fmt.Errorf("load retained MCP R3 class context: %w", err),
		)
	}
	if classRecord.Reference != retry.ClassReference {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			errors.New("retained MCP R3 class context changed its reference"),
		)
	}
	classClaims, err := server.verifyMCPR3ClassContext(ctx, classRecord)
	if err != nil {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(err)
	}
	if retained.PresentedJTI != classClaims.PresentedJTI ||
		retained.PersonServer != classClaims.PersonServer || retained.Subject != classClaims.Subject ||
		retained.AgentJKT != classClaims.AgentJKT || retained.Tenant != classClaims.Tenant ||
		retained.MissionS256 != classClaims.MissionS256 || !equalOptionalString(retained.Account, classClaims.Account) {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			errors.New("MCP R3 proposal token changed retained class lineage"),
		)
	}
	requestedScopes, err := server.validateMCPR3Scopes(retained.Scope)
	if err != nil {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			errors.New("retained MCP R3 proposal scopes are invalid"),
		)
	}
	if !scopeSetContainsAll(requestedScopes, scopes) || !scopeSetContainsAll(scopes, retry.RequiredScopes) {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, errors.New("MCP R3 retry scopes exceed the proposal or omit a required route scope")
	}
	classRequestedScopes, err := server.validateMCPR3Scopes(classClaims.Scope)
	if err != nil || !scopeSetContainsAll(classRequestedScopes, requestedScopes) {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			errors.New("MCP R3 proposal scopes exceed retained class authorization"),
		)
	}
	fingerprint, err := proof.PublicKey().Thumbprint()
	if err != nil {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, err
	}
	if retained.AgentJKT != fingerprint {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, errors.New("MCP R3 retry key is invalid")
	}
	if claims.IssuedAt < retained.IssuedAt || claims.IssuedAt >= retained.ExpiresAt {
		return r3.MCPProposal{}, aauth.ResourceTokenClaims{}, errors.New("MCP R3 completion token lifetime is outside the retained proposal authorization")
	}
	return proposal, retained, nil
}

type mcpR3RetainedStateError struct {
	cause error
}

func (err *mcpR3RetainedStateError) Error() string { return err.cause.Error() }
func (err *mcpR3RetainedStateError) Unwrap() error { return err.cause }

func retainedMCPR3State(err error) error {
	var retained *mcpR3RetainedStateError
	if errors.As(err, &retained) {
		return err
	}
	return &mcpR3RetainedStateError{cause: err}
}

func writeMCPR3ValidationFailure(response http.ResponseWriter, err error) {
	var retained *mcpR3RetainedStateError
	if errors.As(err, &retained) {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	writeProblem(response, http.StatusForbidden, "access_denied", err)
}

func (server *Server) executeMCPR3Retry(
	snapshot heldRequestSnapshot,
	compact string,
	claims aauth.AuthTokenClaims,
	requestKey jose.JWK,
	verifiedAt time.Time,
	scopes []string,
) (result HeldResponse) {
	defer func() {
		if recover() != nil {
			result = server.heldInternalFailure()
		}
	}()
	remainingLifetime := time.Unix(claims.ExpiresAt, 0).Sub(time.Unix(verifiedAt.Unix(), 0))
	if remainingLifetime <= 0 {
		return server.heldInternalFailure()
	}
	executionContext, cancel := context.WithTimeout(context.Background(), remainingLifetime)
	defer cancel()
	if err := server.resolvePerson(
		executionContext,
		PersonIdentity{Issuer: claims.PersonServer, Subject: claims.Subject},
		PersonContext{MissionS256: claims.MissionS256, Tenant: claims.Tenant, AdditionalClaims: cloneAdditionalClaims(claims.AdditionalClaims)},
	); err != nil {
		return server.heldInternalFailure()
	}
	principal := AuthPrincipal{
		PersonServer: claims.PersonServer, Subject: claims.Subject,
		MissionS256: claims.MissionS256, Tenant: claims.Tenant,
		Account: cloneAuthorizationAccount(claims.Account), Scope: append([]string(nil), scopes...),
		Confirmation: requestKey, AdditionalClaims: cloneAdditionalClaims(claims.AdditionalClaims),
	}
	executionContext = context.WithValue(executionContext, authTokenContextKey{}, compact)
	applicationRequest, err := snapshot.request(executionContext, principal)
	if err != nil {
		return server.heldInternalFailure()
	}
	if applicationRequest.Body != nil {
		defer applicationRequest.Body.Close()
	}
	writer, err := newHeldResponseWriter(server.maxRetainedResponseBodyBytes, server.maxRetainedHeaderBytes)
	if err != nil {
		return server.heldInternalFailure()
	}
	server.protected.ServeHTTP(writer, applicationRequest)
	captured, err := writer.snapshot()
	if err != nil {
		return server.heldInternalFailure()
	}
	result = HeldResponse{
		StatusCode: captured.statusCode, Header: captured.header.Clone(),
		Body: append([]byte(nil), captured.body...), Trailer: captured.trailer.Clone(),
	}
	if result.StatusCode == http.StatusAccepted {
		if err := server.validateApplicationPendingResponse(result); err != nil {
			return server.heldInternalFailure()
		}
	}
	return result
}

func (server *Server) writeR3RetryFailure(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrR3RetryExpired):
		writeProblem(response, http.StatusRequestTimeout, "expired", err)
	case errors.Is(err, ErrR3RetryNotFound), errors.Is(err, ErrR3ProposalNotFound):
		writeProblem(response, http.StatusGone, "gone", err)
	case errors.Is(err, ErrR3RetryTokenMismatch):
		writeProblem(response, http.StatusForbidden, "access_denied", err)
	case errors.Is(err, ErrR3RetryConflict):
		response.Header().Set("Retry-After", "1")
		writeProblem(response, http.StatusServiceUnavailable, "temporarily_unavailable", err)
	case errors.Is(err, ErrR3RetryUnresolved), errors.Is(err, ErrR3RetryCompletionStale):
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
	}
}

func (server *Server) describeMCPR3Call(
	request *http.Request,
	operation r3.MCPOperation,
	account *string,
) (MCPR3CallDescription, error) {
	policyRequest, finish, err := cloneScopePolicyRequest(request)
	if err != nil {
		return MCPR3CallDescription{}, fmt.Errorf("prepare MCP R3 proposal request: %w", err)
	}
	description, describeErr := server.mcpR3.perCall.describeCall(
		request.Context(), policyRequest, operation, cloneAuthorizationAccount(account),
	)
	if err := errors.Join(describeErr, finish()); err != nil {
		return MCPR3CallDescription{}, fmt.Errorf("MCP R3 proposal adapter: %w", err)
	}
	return description, nil
}

func (server *Server) presentMCPR3Call(
	request *http.Request,
	operation r3.MCPOperation,
	account *string,
) (map[string]r3.PresentedMCPParameter, error) {
	policyRequest, finish, err := cloneScopePolicyRequest(request)
	if err != nil {
		return nil, fmt.Errorf("prepare MCP R3 presented request: %w", err)
	}
	presented, presentErr := server.mcpR3.perCall.presentCall(
		request.Context(), policyRequest, operation, cloneAuthorizationAccount(account),
	)
	if err := errors.Join(presentErr, finish()); err != nil {
		return nil, fmt.Errorf("MCP R3 parameter adapter: %w", err)
	}
	return presented, nil
}

func (server *Server) validateMCPR3ClassLineage(
	ctx context.Context,
	record R3DocumentRecord,
	proof signaturekey.VerifiedRequest,
	claims aauth.AuthTokenClaims,
	authorization mcpR3ProtectedAuthorization,
	operation r3.MCPOperation,
) (r3.Document, aauth.ResourceTokenClaims, error) {
	if record.Reference != authorization.reference {
		return r3.Document{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			errors.New("retained MCP R3 class context changed its reference"),
		)
	}
	retained, err := server.verifyMCPR3ClassContext(ctx, record)
	if err != nil {
		return r3.Document{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(err)
	}
	document, err := r3.ParseReferencedDocument(record.Reference, record.ExactJSON)
	if err != nil {
		return r3.Document{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			fmt.Errorf("retained MCP R3 class document: %w", err),
		)
	}
	if err := r3.ValidateDocumentAccount(document, retained.Account); err != nil {
		return r3.Document{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			fmt.Errorf("retained MCP R3 class account: %w", err),
		)
	}
	if _, err := r3.NewAuthorization(
		authorization.operations.GrantedOperations(), authorization.operations.PerCallOperations(), document,
	); err != nil {
		return r3.Document{}, aauth.ResourceTokenClaims{}, fmt.Errorf("MCP R3 class authorization: %w", err)
	}
	if !authorization.operations.PerCallOperations().Contains(operation) {
		return r3.Document{}, aauth.ResourceTokenClaims{}, errors.New("MCP operation is not in the class per-call set")
	}
	fingerprint, err := proof.PublicKey().Thumbprint()
	if err != nil {
		return r3.Document{}, aauth.ResourceTokenClaims{}, err
	}
	if claims.Issuer != retained.Audience || claims.Audience != retained.Issuer ||
		claims.PersonServer != retained.PersonServer || claims.Subject != retained.Subject ||
		claims.Tenant != retained.Tenant || claims.MissionS256 != retained.MissionS256 ||
		!equalOptionalString(claims.Account, retained.Account) || fingerprint != retained.AgentJKT {
		return r3.Document{}, aauth.ResourceTokenClaims{}, errors.New("MCP R3 class authorization changed retained lineage")
	}
	if claims.IssuedAt < retained.IssuedAt || claims.IssuedAt >= retained.ExpiresAt {
		return r3.Document{}, aauth.ResourceTokenClaims{}, errors.New("MCP R3 class Auth token was issued outside the class Resource-token lifetime")
	}
	requestedScopes, err := server.validateMCPR3Scopes(retained.Scope)
	if err != nil {
		return r3.Document{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			errors.New("MCP R3 class Resource-token scopes are invalid"),
		)
	}
	classScopes, err := server.validateMCPR3Scopes(claims.Scope)
	if err != nil || !scopeSetContainsAll(requestedScopes, classScopes) {
		return r3.Document{}, aauth.ResourceTokenClaims{}, errors.New("MCP R3 class Auth-token scopes exceed the retained Resource token")
	}
	lineageAt := retained.IssuedAt
	if lineageAt < record.ClassContext.PersonTokenIssuedAt ||
		record.ClassContext.PersonTokenNotBefore != 0 && lineageAt < record.ClassContext.PersonTokenNotBefore ||
		lineageAt >= record.ClassContext.PersonTokenExpiresAt {
		return r3.Document{}, aauth.ResourceTokenClaims{}, retainedMCPR3State(
			errors.New("MCP R3 class Resource token was issued outside its Person-token lineage"),
		)
	}
	return document, retained, nil
}

func (server *Server) mcpR3ProposalClaims(
	retained aauth.ResourceTokenClaims,
	classClaims aauth.AuthTokenClaims,
	proof signaturekey.VerifiedRequest,
	verifiedAt time.Time,
) (aauth.ResourceTokenClaims, time.Time, error) {
	identifier := server.newID()
	if identifier == "" {
		return aauth.ResourceTokenClaims{}, time.Time{}, retainedMCPR3State(
			errors.New("MCP R3 proposal Resource-token identifier is required"),
		)
	}
	expiresAt := verifiedAt.Add(5 * time.Minute)
	for _, ceiling := range []time.Time{time.Unix(classClaims.ExpiresAt, 0)} {
		if ceiling.Before(expiresAt) {
			expiresAt = ceiling
		}
	}
	if !verifiedAt.Before(expiresAt) {
		return aauth.ResourceTokenClaims{}, time.Time{}, errors.New("MCP R3 proposal authorization has no remaining lifetime")
	}
	fingerprint, err := proof.PublicKey().Thumbprint()
	if err != nil {
		return aauth.ResourceTokenClaims{}, time.Time{}, err
	}
	return aauth.ResourceTokenClaims{
		Issuer: server.issuer, DWK: aauth.ResourceDiscoveryDocument,
		Audience: classClaims.Issuer, JTI: identifier,
		AgentJKT: fingerprint, IssuedAt: verifiedAt.Unix(), ExpiresAt: expiresAt.Unix(),
		Scope: classClaims.Scope, Account: cloneAuthorizationAccount(classClaims.Account),
		PersonServer: retained.PersonServer, Subject: retained.Subject,
		PresentedJTI: retained.PresentedJTI, MissionS256: classClaims.MissionS256,
		Tenant: classClaims.Tenant,
	}, expiresAt, nil
}

func (server *Server) verifyMCPR3ClassContext(
	ctx context.Context,
	record R3DocumentRecord,
) (aauth.ResourceTokenClaims, error) {
	if !validR3ClassContext(record) || record.ClassContext.ExactResourceToken == "" {
		return aauth.ResourceTokenClaims{}, errors.New("retained MCP R3 class context is invalid")
	}
	verificationClock := aauth.ClockFunc(func() time.Time {
		return time.Unix(record.ClassContext.ResourceToken.IssuedAt, 0)
	})
	claims, reference, err := r3.VerifyMCPResourceToken(
		ctx, record.ClassContext.ExactResourceToken, server.keyResolver, verificationClock,
	)
	if err != nil {
		return aauth.ResourceTokenClaims{}, fmt.Errorf("verify retained MCP R3 class Resource token: %w", err)
	}
	if reference != record.Reference || !reflect.DeepEqual(claims, record.ClassContext.ResourceToken) ||
		claims.Issuer != server.issuer || claims.DWK != aauth.ResourceDiscoveryDocument ||
		claims.PersonServer != record.PersonServer || claims.Audience != record.AccessServer ||
		mcpR3DocumentURIFromDigest(
			server.issuer, record.Reference.Digest(), record.PersonServer, record.AccessServer, claims.JTI,
		) != record.Reference.URI() {
		return aauth.ResourceTokenClaims{}, errors.New("retained MCP R3 class Resource token does not match its context")
	}
	return claims, nil
}

func equalOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func scopeSetContainsAll(granted, required []string) bool {
	for _, value := range required {
		if !slices.Contains(granted, value) {
			return false
		}
	}
	return true
}
