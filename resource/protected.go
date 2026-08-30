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

	aauth "github.com/aauth-dev/auth-go"
	"github.com/aauth-dev/auth-go/jose"
	"github.com/aauth-dev/auth-go/signaturekey"
)

func (server *Server) serveProtected(response http.ResponseWriter, request *http.Request) {
	if !hasAAuthRequestProof(request) {
		server.writeCredentialRequirement(response)
		return
	}
	prepared, compact, err := server.prepareJWTRequest(request, server.additionalSignatureComponents)
	if err != nil {
		writeCredentialProblem(response, "invalid_token", err)
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
		case aauth.PersonTokenType:
			server.servePersonTokenChallenge(response, request, prepared, compact)
			return
		}
	}
	writeCredentialProblem(response, "invalid_token", &requestTokenError{
		cause: fmt.Errorf("aauth: protected request token typ %q is not valid for %s access", header.Type, server.accessMode),
	})
}

func hasAAuthRequestProof(request *http.Request) bool {
	return len(request.Header.Values("Signature-Key")) != 0 ||
		len(request.Header.Values("Signature-Input")) != 0 ||
		len(request.Header.Values("Signature")) != 0
}

func (server *Server) writeCredentialRequirement(response http.ResponseWriter) {
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
	proof, claims, err := server.verifyPreparedAuthRequest(request, prepared, compact)
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
	if claims.Account != "" {
		writeProblem(response, http.StatusForbidden, "access_denied", errors.New("account is not supported by the immediate resource flow"))
		return
	}
	if claims.MissionS256 != "" {
		writeProblem(response, http.StatusForbidden, "access_denied", errors.New("mission-bound auth tokens require mission verification"))
		return
	}
	if !claims.Confirmation.JWK.Equal(proof.PublicKey()) {
		writeProblem(response, http.StatusUnauthorized, "invalid_signature", errors.New("request key does not match auth token"))
		return
	}
	scopes, err := server.validateScopes(claims.Scope)
	if err != nil {
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	if err := server.observeAuthToken(request.Context(), compact, claims); err != nil {
		switch {
		case errors.Is(err, ErrAuthTokenRevoked), errors.Is(err, ErrAuthTokenConflict):
			writeProblem(response, http.StatusForbidden, "access_denied", err)
		default:
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
		}
		return
	}
	if err := server.authorizeScopes(request, scopes); err != nil {
		var policyFailure *scopePolicyError
		if errors.As(err, &policyFailure) {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return
		}
		writeProblem(response, http.StatusForbidden, "access_denied", err)
		return
	}
	if err := server.resolvePerson(
		request.Context(),
		PersonIdentity{Issuer: claims.PersonServer, Subject: claims.Subject},
		PersonContext{Tenant: claims.Tenant, AdditionalClaims: cloneAdditionalClaims(claims.AdditionalClaims)},
	); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("resolve person: %w", err))
		return
	}
	principal := AuthPrincipal{
		PersonServer:     claims.PersonServer,
		Subject:          claims.Subject,
		Tenant:           claims.Tenant,
		Scope:            append([]string(nil), scopes...),
		Confirmation:     claims.Confirmation.JWK,
		AdditionalClaims: cloneAdditionalClaims(claims.AdditionalClaims),
	}
	server.protected.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), authPrincipalContextKey{}, principal)))
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
	scopes, err := server.requiredRouteScopes(request)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	hold, err := server.shouldHoldAuthTokenRequest(request)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return
	}
	if hold {
		server.serveHeldChallenge(response, request, proof, claims, scopes)
		return
	}
	resourceToken, err := server.issueResourceToken(proof.VerifiedAt(), proof.PublicKey(), claims, scopes)
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

func (server *Server) shouldHoldAuthTokenRequest(request *http.Request) (bool, error) {
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

func (server *Server) requiredRouteScopes(request *http.Request) ([]string, error) {
	policyRequest, finish, err := cloneScopePolicyRequest(request)
	if err != nil {
		return nil, &scopePolicyError{cause: fmt.Errorf("aauth: prepare protected route scope policy request: %w", err)}
	}
	required := server.requiredScopes(policyRequest)
	if err := finish(); err != nil {
		return nil, &scopePolicyError{cause: fmt.Errorf("aauth: finish protected route scope policy request: %w", err)}
	}
	if len(required) == 0 {
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

func (server *Server) authorizeScopes(request *http.Request, granted []string) error {
	required, err := server.requiredRouteScopes(request)
	if err != nil {
		return err
	}
	grants := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		grants[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, allowed := grants[scope]; !allowed {
			return fmt.Errorf("aauth: protected route requires scope %q", scope)
		}
	}
	return nil
}

type scopePolicyError struct{ cause error }

func (failure *scopePolicyError) Error() string { return failure.cause.Error() }
func (failure *scopePolicyError) Unwrap() error { return failure.cause }
