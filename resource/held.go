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

	aauth "aauth-go"
	"aauth-go/internal/jsonstrict"
	"aauth-go/jose"
	"aauth-go/signaturekey"
)

const heldPollRetryAfter = 5 * time.Second

func (server *Server) serveHeldChallenge(
	response http.ResponseWriter,
	request *http.Request,
	proof signaturekey.VerifiedRequest,
	person aauth.PersonTokenClaims,
	scopes []string,
) {
	snapshot, err := snapshotHeldRequest(request, server.maxHeldRequestBodyBytes)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if err := validateHeldRequestHeaderLimit(snapshot.header, server.maxHeldHeaderBytes); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	resourceToken, err := server.issueResourceToken(proof.VerifiedAt(), proof.PublicKey(), person, scopes)
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
	snapshot, err := heldRequestSnapshotFromInvocation(invocation, server.maxHeldRequestBodyBytes, server.maxHeldHeaderBytes)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	prepared, compact, err := server.prepareJWTRequest(request, nil)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	proof, authToken, err := server.verifyPreparedAuthRequest(request, prepared, compact)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
		return
	}
	if err := server.verifyHeldCompletion(request.Context(), proof, authToken, invocation); err != nil {
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	credential := HeldAuthToken{
		SHA256:      sha256.Sum256([]byte(compact)),
		PresentedAt: time.Unix(proof.VerifiedAt().Unix(), 0),
		RetainUntil: time.Unix(authToken.ExpiresAt, 0),
	}
	claim, err := server.heldInvocations.Claim(request.Context(), pendingID, credential)
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
	applicationResponse := server.executeHeldInvocation(snapshot, compact, authToken, proof.PublicKey(), proof.VerifiedAt())
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
	ctx context.Context,
	proof signaturekey.VerifiedRequest,
	authToken aauth.AuthTokenClaims,
	invocation HeldInvocation,
) error {
	verificationClock := aauth.ClockFunc(func() time.Time { return invocation.ResourceTokenIssuedAt })
	resourceToken, err := aauth.VerifyResourceToken(ctx, invocation.ResourceToken, server.keyResolver, verificationClock)
	if err != nil {
		return err
	}
	if resourceToken.Issuer != server.issuer || resourceToken.Audience != server.accessServer ||
		resourceToken.DWK != aauth.ResourceDiscoveryDocument {
		return errors.New("held resource token does not match Resource and Access Server")
	}
	if resourceToken.Account != nil || resourceToken.MissionS256 != "" || resourceToken.Interaction != nil {
		return errors.New("held resource token uses an unsupported authorization branch")
	}
	if resourceToken.IssuedAt != invocation.ResourceTokenIssuedAt.Unix() ||
		resourceToken.ExpiresAt != invocation.ExpiresAt.Unix() || resourceToken.Tenant != authToken.Tenant {
		return errors.New("held token context does not match retained invocation")
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
		return errors.New("held resource-token scopes do not match retained route scopes")
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

func (server *Server) executeHeldInvocation(
	snapshot heldRequestSnapshot,
	compact string,
	claims aauth.AuthTokenClaims,
	requestKey jose.JWK,
	verifiedAt time.Time,
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
		PersonContext{Tenant: claims.Tenant, AdditionalClaims: cloneAdditionalClaims(claims.AdditionalClaims)},
	); err != nil {
		return server.heldInternalFailure()
	}
	scopes, err := server.validateScopes(claims.Scope)
	if err != nil {
		return server.heldInternalFailure()
	}
	principal := AuthPrincipal{
		PersonServer: claims.PersonServer, Subject: claims.Subject, Tenant: claims.Tenant,
		Scope: scopes, Confirmation: requestKey, AdditionalClaims: cloneAdditionalClaims(claims.AdditionalClaims),
	}
	executionContext = context.WithValue(executionContext, authTokenContextKey{}, compact)
	applicationRequest, err := snapshot.request(executionContext, principal)
	if err != nil {
		return server.heldInternalFailure()
	}
	if applicationRequest.Body != nil {
		defer applicationRequest.Body.Close()
	}
	writer, err := newHeldResponseWriter(server.maxHeldResponseBodyBytes, server.maxHeldHeaderBytes)
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
	if int64(len(retained.Body)) > server.maxHeldResponseBodyBytes {
		return HeldResponse{}, fmt.Errorf("retained held response exceeds %d bytes", server.maxHeldResponseBodyBytes)
	}
	if !heldResponseBodyAllowed(retained.StatusCode) && (len(retained.Body) != 0 || len(retained.Trailer) != 0) {
		return HeldResponse{}, fmt.Errorf("retained held response status %d does not permit content or trailers", retained.StatusCode)
	}
	header, declaredTrailer, contentLength, err := captureHeldResponseHeader(retained.Header, server.maxHeldHeaderBytes)
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
	if err := validateHeldResponseHeaderLimit(header, trailer, server.maxHeldHeaderBytes); err != nil {
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
	}
}

func heldRequestSnapshotFromInvocation(invocation HeldInvocation, maxBodyBytes, maxHeaderBytes int64) (heldRequestSnapshot, error) {
	if invocation.ResourceToken == "" || invocation.ResourceTokenIssuedAt.IsZero() || invocation.ExpiresAt.IsZero() ||
		!invocation.ResourceTokenIssuedAt.Before(invocation.ExpiresAt) || len(invocation.RequiredScopes) == 0 {
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
