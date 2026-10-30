package resource

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/internal/r3dispatch"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	heldPollRetryAfter                 = 5 * time.Second
	maximumDerivativeAuthTokenLifetime = aauth.MaximumAuthTokenLifetime
)

func (server *Server) serveHeldChallenge(
	response http.ResponseWriter,
	request *http.Request,
	proof signaturekey.VerifiedRequest,
	person aauth.PersonTokenClaims,
	scopes []string,
	loginHint string,
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
	resourceToken, err := server.issueResourceToken(proof.VerifiedAt(), proof.PublicKey(), person, scopes, loginHint)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	requirement, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: resourceToken})
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	resourceTokenIssuedAt := time.Unix(proof.VerifiedAt().Unix(), 0)
	invocation := snapshot.heldInvocation(
		resourceToken,
		scopes,
		resourceTokenIssuedAt,
		resourceTokenIssuedAt.Add(5*time.Minute),
	)
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

func (server *Server) serveHeldPoll(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		server.writeHeldMethodNotAllowed(response)
		return
	}
	pendingID := request.PathValue("id")
	if err := validateHeldPendingID(pendingID); err != nil {
		writeProblem(response, http.StatusGone, "gone", ErrHeldInvocationNotFound)
		return
	}
	invocation, err := server.heldInvocations.Load(request.Context(), pendingID)
	if err != nil {
		server.writeHeldStoreFailure(response, pendingID, err)
		return
	}
	snapshot, err := heldRequestSnapshotFromInvocation(invocation, server.maxRetainedRequestBodyBytes, server.maxRetainedHeaderBytes)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if invocation.Budget != nil {
		server.serveHeldBudgetPoll(response, request, pendingID, invocation, snapshot)
		return
	}
	resourceToken, resourceReference, resourceCarriesR3, err := server.verifyHeldRetainedResourceToken(
		request.Context(), invocation,
	)
	if err != nil {
		writeR3ValidationFailure(response, err)
		return
	}
	if resourceCarriesR3 != (invocation.R3PerCall != nil) {
		writeProblem(
			response, http.StatusInternalServerError, "server_error",
			retainedR3State(errors.New("held invocation authorization kind does not match its Resource token")),
		)
		return
	}
	prepared, compact, err := server.prepareJWTRequest(request, nil)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	var (
		proof           signaturekey.VerifiedRequest
		authToken       aauth.AuthTokenClaims
		executionScopes = append([]string(nil), invocation.RequiredScopes...)
	)
	if !resourceCarriesR3 {
		proof, authToken, err = server.verifyPreparedAuthRequest(request, prepared, compact)
		if err != nil {
			writeCredentialProblem(response, "invalid_token", err)
			return
		}
		err = server.verifyHeldCompletion(proof, authToken, resourceToken, invocation)
	} else {
		var reference r3.Reference
		var operations r3.AuthTokenOperations
		proof, authToken, reference, operations, err = server.verifyPreparedR3AuthRequest(request, prepared, compact)
		if err != nil {
			writeCredentialProblem(response, "invalid_token", err)
			return
		}
		executionScopes, err = server.verifyHeldR3Completion(
			request.Context(), proof, authToken,
			r3ProtectedAuthorization{reference: reference, operations: operations},
			resourceReference, invocation,
		)
	}
	if err != nil {
		writeR3ValidationFailure(response, err)
		return
	}
	released, releaseFirst, err := server.heldRelease(invocation)
	if err != nil {
		writeR3ValidationFailure(response, err)
		return
	}
	credential := HeldAuthToken{
		SHA256:      sha256.Sum256([]byte(compact)),
		PresentedAt: time.Unix(proof.VerifiedAt().Unix(), 0),
		RetainUntil: time.Unix(authToken.ExpiresAt, 0),
	}
	claim, err := server.heldInvocations.Claim(context.Background(), pendingID, credential)
	if err != nil {
		server.writeHeldStoreFailure(response, pendingID, err)
		return
	}
	if retained, replay := claim.Replay(); replay {
		if err := server.writeHeldResponse(response, retained); err != nil {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	execution, execute := claim.Execution()
	if !execute || execution.InvocationID != pendingID || execution.Fence == "" {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("held invocation store returned an invalid execution claim"))
		return
	}
	// A release-gated call already ran before approval: completion releases
	// the response it produced and never runs it again.
	applicationResponse := released
	if !releaseFirst {
		applicationResponse = server.executeHeldInvocation(
			snapshot, compact, authToken, proof.PublicKey(), proof.VerifiedAt(), executionScopes,
		)
	}
	retained, err := server.heldInvocations.Retain(context.Background(), execution, applicationResponse)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := server.writeHeldResponse(response, retained); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
}

func (server *Server) serveHeldNamespace(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		server.writeHeldMethodNotAllowed(response)
		return
	}
	writeProblem(response, http.StatusGone, "gone", ErrHeldInvocationNotFound)
}

func (*Server) writeHeldMethodNotAllowed(response http.ResponseWriter) {
	response.Header().Set("Allow", http.MethodGet)
	writeProblem(response, http.StatusMethodNotAllowed, "method_not_allowed", errors.New("held invocation polling requires GET"))
}

func (server *Server) verifyHeldCompletion(
	proof signaturekey.VerifiedRequest,
	authToken aauth.AuthTokenClaims,
	resourceToken aauth.ResourceTokenClaims,
	invocation HeldInvocation,
) error {
	if resourceToken.Account != nil || resourceToken.MissionS256 != "" || resourceToken.Interaction != nil {
		return retainedR3State(errors.New("held resource token uses an unsupported authorization branch"))
	}
	if resourceToken.Tenant != authToken.Tenant {
		return errors.New("held Auth token changed the retained tenant")
	}
	if authToken.IssuedAt < resourceToken.IssuedAt || authToken.IssuedAt >= resourceToken.ExpiresAt {
		return errors.New("held Auth token was issued outside the Resource-token lifetime")
	}
	requestJKT, err := proof.PublicKey().Thumbprint()
	if err != nil {
		return err
	}
	if resourceToken.AgentJKT != requestJKT {
		return errors.New("held resource token does not match poll signing key")
	}
	resourceScopes, err := server.validateScopes(resourceToken.Scope)
	if err != nil || !slices.Equal(resourceScopes, invocation.RequiredScopes) {
		return retainedR3State(errors.New("held resource-token scopes do not match retained route scopes"))
	}
	if authToken.Account != nil || authToken.MissionS256 != "" {
		return errors.New("held auth token uses an unsupported authorization branch")
	}
	authScopes, err := server.validateScopes(authToken.Scope)
	if err != nil || !sameScopeSet(authScopes, invocation.RequiredScopes) {
		return errors.New("held auth-token scopes do not exactly match retained route scopes")
	}
	if err := aauth.ValidateCurrentAuthTokenContext(authToken, aauth.AuthTokenContext{
		Issuer:            server.accessServer,
		DiscoveryDocument: aauth.AccessDiscoveryDocument,
		Resource:          server.issuer,
		PersonServer:      resourceToken.PersonServer,
		Subject:           resourceToken.Subject,
		RequestKey:        proof.PublicKey(),
		RequiredScopes:    invocation.RequiredScopes,
	}); err != nil {
		return err
	}
	return nil
}

func (server *Server) verifyHeldR3Completion(
	ctx context.Context,
	proof signaturekey.VerifiedRequest,
	authToken aauth.AuthTokenClaims,
	authorization r3ProtectedAuthorization,
	resourceReference r3.Reference,
	invocation HeldInvocation,
) ([]string, error) {
	if server.r3 == nil || invocation.R3PerCall == nil {
		return nil, errors.New("held R3 per-call authorization is not configured")
	}
	if authToken.Issuer != server.accessServer || authToken.DWK != aauth.AccessDiscoveryDocument ||
		authToken.Audience != server.issuer {
		return nil, errors.New("held R3 Auth token does not match the Access Server and Resource")
	}
	held := invocation.R3PerCall
	if held.Reference != resourceReference {
		return nil, retainedR3State(errors.New("held R3 proposal reference does not match its Resource token"))
	}
	if held.Reference != authorization.reference {
		return nil, errors.New("held R3 Auth token changed the proposal reference")
	}
	kind, err := server.validateR3ProtectedReference(authorization, authToken)
	if err != nil || kind != r3ProposalReference {
		return nil, errors.New("held R3 Auth token does not reference a proposal")
	}
	authScopes, err := server.validateR3Scopes(authToken.Scope)
	if err != nil {
		return nil, errors.New("held R3 Auth-token scopes are invalid")
	}
	proposal, err := server.r3.registry.ParseReferencedProposal(held.Reference, held.ExactProposal)
	if err != nil {
		return nil, retainedR3State(fmt.Errorf("parse held R3 proposal: %w", err))
	}
	if _, _, err := server.validateR3Retry(ctx, R3RetryInvocation{
		Reference: held.Reference, ClassReference: held.ClassReference,
		ResourceToken: invocation.ResourceToken, ExactProposal: append([]byte(nil), held.ExactProposal...),
		RequiredScopes: append([]string(nil), invocation.RequiredScopes...),
		PreparedAt:     invocation.ResourceTokenIssuedAt, ExpiresAt: invocation.ExpiresAt,
		CompletionUntil: invocation.CompletionUntil,
	}, proof, authToken, authorization, proposal.Operation(), authScopes); err != nil {
		return nil, err
	}
	return authScopes, nil
}

func (server *Server) verifyHeldRetainedResourceToken(
	ctx context.Context,
	invocation HeldInvocation,
) (aauth.ResourceTokenClaims, r3.Reference, bool, error) {
	verificationClock := aauth.ClockFunc(func() time.Time { return invocation.ResourceTokenIssuedAt })
	carriesR3, err := r3dispatch.TokenCarriesClaims(invocation.ResourceToken)
	if err != nil {
		return aauth.ResourceTokenClaims{}, r3.Reference{}, false, retainedR3State(
			fmt.Errorf("inspect held Resource token: %w", err),
		)
	}
	var (
		claims    aauth.ResourceTokenClaims
		reference r3.Reference
	)
	if carriesR3 {
		if server.r3 == nil {
			return aauth.ResourceTokenClaims{}, r3.Reference{}, false, retainedR3State(
				errors.New("held R3 Resource token is not configured"),
			)
		}
		claims, reference, err = r3.VerifyResourceToken(
			ctx, invocation.ResourceToken, server.keyResolver, verificationClock,
		)
	} else {
		claims, err = aauth.VerifyResourceToken(
			ctx, invocation.ResourceToken, server.keyResolver, verificationClock,
		)
	}
	if err != nil {
		return aauth.ResourceTokenClaims{}, r3.Reference{}, false, retainedR3State(
			fmt.Errorf("verify held Resource token: %w", err),
		)
	}
	if claims.Issuer != server.issuer || claims.Audience != server.accessServer ||
		claims.DWK != aauth.ResourceDiscoveryDocument ||
		claims.IssuedAt != invocation.ResourceTokenIssuedAt.Unix() ||
		claims.ExpiresAt != invocation.ExpiresAt.Unix() ||
		!invocation.CompletionUntil.Equal(invocation.ExpiresAt.Add(maximumDerivativeAuthTokenLifetime)) {
		return aauth.ResourceTokenClaims{}, r3.Reference{}, false, retainedR3State(
			errors.New("held Resource token does not match its retained invocation"),
		)
	}
	return claims, reference, carriesR3, nil
}

func (server *Server) validateR3Scopes(scope string) ([]string, error) {
	if scope == "" {
		return nil, nil
	}
	return server.validateScopes(scope)
}

func (server *Server) executeHeldInvocation(
	snapshot heldRequestSnapshot,
	compact string,
	claims aauth.AuthTokenClaims,
	requestKey jose.JWK,
	verifiedAt time.Time,
	scopes []string,
) HeldResponse {
	return server.executeHeldInvocationSettled(snapshot, compact, claims, requestKey, verifiedAt, scopes, nil)
}

// executeHeldInvocationSettled runs a held invocation. A non-nil settlement
// is the Budget reservation the handler may settle with SettleBudget.
func (server *Server) executeHeldInvocationSettled(
	snapshot heldRequestSnapshot,
	compact string,
	claims aauth.AuthTokenClaims,
	requestKey jose.JWK,
	verifiedAt time.Time,
	scopes []string,
	settlement *budgetSettlement,
) (result HeldResponse) {
	defer func() {
		if recover() != nil {
			result = server.heldInternalFailure()
		}
	}()
	remainingLifetime := time.Unix(claims.ExpiresAt, 0).Sub(time.Unix(verifiedAt.Unix(), 0))
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
		PersonServer: claims.PersonServer, Subject: claims.Subject, Tenant: claims.Tenant,
		MissionS256: claims.MissionS256, Account: cloneAuthorizationAccount(claims.Account),
		Scope: append([]string(nil), scopes...), Confirmation: requestKey,
		AdditionalClaims: cloneAdditionalClaims(claims.AdditionalClaims),
	}
	executionContext = context.WithValue(executionContext, authTokenContextKey{}, compact)
	if settlement != nil {
		executionContext = context.WithValue(executionContext, budgetSettlementKey{}, settlement)
	}
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
		StatusCode: captured.statusCode,
		Header:     captured.header.Clone(), Body: append([]byte(nil), captured.body...), Trailer: captured.trailer.Clone(),
	}
	if result.StatusCode == http.StatusAccepted {
		if err := server.validateApplicationPendingResponse(result); err != nil {
			return server.heldInternalFailure()
		}
	}
	return result
}

func sameScopeSet(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for _, scope := range first {
		if !slices.Contains(second, scope) {
			return false
		}
	}
	return true
}

func (server *Server) validateApplicationPendingResponse(response HeldResponse) error {
	locations := response.Header.Values("Location")
	if len(locations) != 1 || locations[0] == "" {
		return errors.New("held application 202 requires exactly one Location")
	}
	reference, err := url.Parse(locations[0])
	if err != nil || reference.User != nil || reference.Fragment != "" || reference.Opaque != "" {
		return errors.New("held application 202 Location is invalid")
	}
	base, err := url.Parse(server.issuer + "/")
	if err != nil {
		return errors.New("held application 202 Resource origin is invalid")
	}
	resolved := base.ResolveReference(reference)
	if resolved.Scheme != base.Scheme || resolved.Host != base.Host || resolved.User != nil || resolved.Fragment != "" {
		return errors.New("held application 202 Location must be same-origin with the Resource")
	}
	retryAfter := response.Header.Values("Retry-After")
	if len(retryAfter) != 1 || retryAfter[0] == "" {
		return errors.New("held application 202 requires exactly one Retry-After")
	}
	for _, character := range retryAfter[0] {
		if character < '0' || character > '9' {
			return errors.New("held application 202 Retry-After must be nonnegative decimal seconds")
		}
	}
	seconds, err := strconv.ParseUint(retryAfter[0], 10, 64)
	if err != nil || seconds > uint64(math.MaxInt64/int64(time.Second)) {
		return errors.New("held application 202 Retry-After duration overflows")
	}
	if !heldResponseHasNoStore(response.Header.Values("Cache-Control")) {
		return errors.New("held application 202 Cache-Control must contain no-store")
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return errors.New("held application 202 requires exactly one Content-Type")
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		return errors.New("held application 202 Content-Type must be application/json")
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := jsonstrict.RejectCaseVariants(response.Body, &body); err != nil {
		return errors.New("held application 202 JSON status is ambiguous")
	}
	if err := json.Unmarshal(response.Body, &body); err != nil || body.Status == "" {
		return errors.New("held application 202 requires a JSON status")
	}
	return nil
}

func heldResponseHasNoStore(values []string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
				return true
			}
		}
	}
	return false
}

func (server *Server) heldInternalFailure() HeldResponse {
	body, _ := json.Marshal(struct {
		Status int    `json:"status"`
		Code   string `json:"error"`
		Detail string `json:"detail"`
	}{Status: http.StatusInternalServerError, Code: "server_error", Detail: http.StatusText(http.StatusInternalServerError)})
	return HeldResponse{
		StatusCode: http.StatusInternalServerError,
		Header:     http.Header{"Content-Type": []string{"application/problem+json"}},
		Body:       body,
	}
}

func (server *Server) writeHeldResponse(response http.ResponseWriter, retained HeldResponse) error {
	validated, err := server.validateRetainedHeldResponse(retained)
	if err != nil {
		return err
	}
	for name, values := range validated.Header {
		for _, value := range values {
			response.Header().Add(name, value)
		}
	}
	for name := range validated.Trailer {
		response.Header().Add("Trailer", name)
	}
	response.WriteHeader(validated.StatusCode)
	if len(validated.Body) != 0 {
		_, _ = response.Write(validated.Body)
	}
	for name, values := range validated.Trailer {
		response.Header()[name] = append([]string(nil), values...)
	}
	return nil
}

func (server *Server) validateRetainedHeldResponse(retained HeldResponse) (HeldResponse, error) {
	if err := validateHeldResponseStatus(retained.StatusCode); err != nil {
		return HeldResponse{}, err
	}
	if int64(len(retained.Body)) > server.maxRetainedResponseBodyBytes {
		return HeldResponse{}, fmt.Errorf("retained held response exceeds %d bytes", server.maxRetainedResponseBodyBytes)
	}
	if !heldResponseBodyAllowed(retained.StatusCode) && (len(retained.Body) != 0 || len(retained.Trailer) != 0) {
		return HeldResponse{}, fmt.Errorf("retained held response status %d does not permit content or trailers", retained.StatusCode)
	}
	header, declaredTrailer, contentLength, err := captureHeldResponseHeader(retained.Header, server.maxRetainedHeaderBytes)
	if err != nil {
		return HeldResponse{}, err
	}
	if len(declaredTrailer) != 0 {
		return HeldResponse{}, errors.New("retained held response must carry trailers separately from its headers")
	}
	if header.Get("Content-Type") == "" && header.Get("Content-Encoding") == "" && len(retained.Body) != 0 {
		header.Set("Content-Type", http.DetectContentType(retained.Body))
	}
	if contentLength >= 0 && contentLength != int64(len(retained.Body)) {
		return HeldResponse{}, errors.New("retained held response Content-Length does not match its body")
	}
	trailer := make(http.Header, len(retained.Trailer))
	seenTrailer := make(map[string]string, len(retained.Trailer))
	for _, name := range sortedHeldResponseHeaderKeys(retained.Trailer) {
		canonical, err := validateHeldResponseTrailerName(name)
		if err != nil {
			return HeldResponse{}, err
		}
		if previous, duplicate := seenTrailer[canonical]; duplicate {
			return HeldResponse{}, fmt.Errorf("retained held response trailer %q repeats with spelling %q", canonical, previous)
		}
		seenTrailer[canonical] = name
		values := retained.Trailer[name]
		if err := validateHeldResponseHeaderValues(canonical, values); err != nil {
			return HeldResponse{}, err
		}
		trailer[canonical] = append([]string(nil), values...)
	}
	if err := validateHeldResponseHeaderLimit(header, trailer, server.maxRetainedHeaderBytes); err != nil {
		return HeldResponse{}, err
	}
	validated := HeldResponse{
		StatusCode: retained.StatusCode,
		Header:     header,
		Body:       append([]byte(nil), retained.Body...),
		Trailer:    trailer,
	}
	if validated.StatusCode == http.StatusAccepted {
		if err := server.validateApplicationPendingResponse(validated); err != nil {
			return HeldResponse{}, err
		}
	}
	return validated, nil
}

func (server *Server) writeHeldStoreFailure(response http.ResponseWriter, pendingID string, err error) {
	switch {
	case errors.Is(err, ErrHeldInvocationExpired):
		writeProblem(response, http.StatusRequestTimeout, "expired", err)
	case errors.Is(err, ErrHeldInvocationNotFound):
		writeProblem(response, http.StatusGone, "gone", err)
	case errors.Is(err, ErrHeldAuthTokenMismatch):
		writeProblem(response, http.StatusForbidden, "access_denied", err)
	case errors.Is(err, ErrHeldInvocationConflict):
		response.Header().Set("Location", server.issuer+"/pending/"+pendingID)
		response.Header().Set("Retry-After", fmt.Sprintf("%.0f", heldPollRetryAfter.Seconds()))
		response.Header().Set("Cache-Control", "no-store")
		writeJSON(response, http.StatusAccepted, struct {
			Status string `json:"status"`
		}{Status: "pending"})
	case errors.Is(err, ErrHeldExecutionUnresolved), errors.Is(err, ErrHeldCompletionStale):
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
	default:
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
	}
}

func (snapshot heldRequestSnapshot) heldInvocation(
	resourceToken string,
	scopes []string,
	resourceTokenIssuedAt time.Time,
	expiresAt time.Time,
) HeldInvocation {
	return HeldInvocation{
		Method: snapshot.method, Scheme: snapshot.scheme, URLHost: snapshot.urlHost, Host: snapshot.host,
		EscapedPath: snapshot.escapedPath, RawPath: snapshot.rawPath, RawQuery: snapshot.rawQuery,
		ForceQuery: snapshot.forceQuery, RequestURI: snapshot.requestURI, Header: snapshot.header.Clone(),
		Body: append([]byte(nil), snapshot.body...), BodyKind: exportHeldRequestBodyKind(snapshot.bodyKind),
		HasGetBody: snapshot.hadGetBody, ContentLength: snapshot.contentLength,
		Proto: snapshot.proto, ProtoMajor: snapshot.protoMajor, ProtoMinor: snapshot.protoMinor,
		ResourceToken: resourceToken, ResourceTokenIssuedAt: resourceTokenIssuedAt,
		RequiredScopes: append([]string(nil), scopes...), ExpiresAt: expiresAt,
		CompletionUntil: expiresAt.Add(maximumDerivativeAuthTokenLifetime),
	}
}

func heldRequestSnapshotFromInvocation(invocation HeldInvocation, maxBodyBytes, maxHeaderBytes int64) (heldRequestSnapshot, error) {
	if invocation.ResourceToken == "" || invocation.ResourceTokenIssuedAt.IsZero() || invocation.ExpiresAt.IsZero() ||
		invocation.CompletionUntil.IsZero() ||
		!invocation.ResourceTokenIssuedAt.Before(invocation.ExpiresAt) ||
		!invocation.CompletionUntil.Equal(invocation.ExpiresAt.Add(maximumDerivativeAuthTokenLifetime)) ||
		len(invocation.RequiredScopes) == 0 && invocation.R3PerCall == nil {
		return heldRequestSnapshot{}, errors.New("held invocation authorization context is incomplete")
	}
	if int64(len(invocation.Body)) > maxBodyBytes {
		return heldRequestSnapshot{}, fmt.Errorf("held invocation body exceeds %d bytes", maxBodyBytes)
	}
	if err := validateHeldRequestHeaderLimit(invocation.Header, maxHeaderBytes); err != nil {
		return heldRequestSnapshot{}, err
	}
	bodyKind, err := importHeldRequestBodyKind(invocation.BodyKind)
	if err != nil {
		return heldRequestSnapshot{}, err
	}
	if (bodyKind == heldRequestBodyNil || bodyKind == heldRequestBodyNoBody) && len(invocation.Body) != 0 {
		return heldRequestSnapshot{}, errors.New("held invocation empty-body representation contains bytes")
	}
	if bodyKind == heldRequestBodyNil && invocation.HasGetBody {
		return heldRequestSnapshot{}, errors.New("held invocation nil body must not define GetBody")
	}
	seenHeader := make(map[string]string, len(invocation.Header))
	for name, values := range invocation.Header {
		if !validHeldResponseHeaderName(name) {
			return heldRequestSnapshot{}, fmt.Errorf("held invocation header name %q is invalid", name)
		}
		canonical := http.CanonicalHeaderKey(name)
		if previous, duplicate := seenHeader[canonical]; duplicate {
			return heldRequestSnapshot{}, fmt.Errorf("held invocation header %q repeats with spelling %q", canonical, previous)
		}
		seenHeader[canonical] = name
		if err := validateHeldResponseHeaderValues(canonical, values); err != nil {
			return heldRequestSnapshot{}, err
		}
		if strings.EqualFold(name, "Signature-Key") || strings.EqualFold(name, "Signature-Input") || strings.EqualFold(name, "Signature") {
			return heldRequestSnapshot{}, errors.New("held invocation contains stale request proof headers")
		}
	}
	snapshot := heldRequestSnapshot{
		method: invocation.Method, scheme: invocation.Scheme, urlHost: invocation.URLHost, host: invocation.Host,
		escapedPath: invocation.EscapedPath, rawPath: invocation.RawPath, rawQuery: invocation.RawQuery,
		forceQuery: invocation.ForceQuery, requestURI: invocation.RequestURI, header: invocation.Header.Clone(),
		body: append([]byte(nil), invocation.Body...), bodyKind: bodyKind, hadGetBody: invocation.HasGetBody,
		contentLength: invocation.ContentLength, proto: invocation.Proto, protoMajor: invocation.ProtoMajor, protoMinor: invocation.ProtoMinor,
	}
	probe, err := snapshot.request(context.Background(), AuthPrincipal{})
	if err != nil {
		return heldRequestSnapshot{}, err
	}
	if err := validateHeldRequestFeatures(probe); err != nil {
		return heldRequestSnapshot{}, err
	}
	if _, err := validateHeldRequestTarget(probe); err != nil {
		return heldRequestSnapshot{}, err
	}
	return snapshot, nil
}

func exportHeldRequestBodyKind(kind heldRequestBodyKind) HeldRequestBodyKind {
	switch kind {
	case heldRequestBodyNil:
		return HeldRequestBodyNil
	case heldRequestBodyNoBody:
		return HeldRequestBodyNoBody
	case heldRequestBodyBytes:
		return HeldRequestBodyBytes
	default:
		return ""
	}
}

func importHeldRequestBodyKind(kind HeldRequestBodyKind) (heldRequestBodyKind, error) {
	switch kind {
	case HeldRequestBodyNil:
		return heldRequestBodyNil, nil
	case HeldRequestBodyNoBody:
		return heldRequestBodyNoBody, nil
	case HeldRequestBodyBytes:
		return heldRequestBodyBytes, nil
	default:
		return 0, fmt.Errorf("held invocation body kind %q is invalid", kind)
	}
}

func validateHeldPendingID(id string) error {
	if len(id) < 16 || len(id) > 128 {
		return errors.New("held invocation store returned an invalid pending identifier length")
	}
	for _, character := range id {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return errors.New("held invocation store returned a pending identifier that is not URL-safe")
	}
	if url.PathEscape(id) != id {
		return errors.New("held invocation store returned a pending identifier that changes under path escaping")
	}
	return nil
}
