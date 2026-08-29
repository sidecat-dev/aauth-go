// Package reference provides small, deployable AAuth role handlers and an
// agent client built exclusively on the public aauth package.
package reference

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

const maxJSONBody = 1 << 20

func claimsWithoutAuthorization[T aauth.TokenClaims](verified aauth.VerifiedToken[T]) (T, error) {
	var zero T
	if err := verified.RequireNoAuthorizationMembers(); err != nil {
		return zero, err
	}
	return verified.Claims()
}

type retainedAuthorizationTokenKeys struct {
	Resource jose.JWK  `json:"resource"`
	Agent    jose.JWK  `json:"agent"`
	Subagent *jose.JWK `json:"subagent,omitempty"`
	Upstream *jose.JWK `json:"upstream,omitempty"`
}

func copyRetainedAuthorizationTokenKeys(value retainedAuthorizationTokenKeys) retainedAuthorizationTokenKeys {
	value.Subagent = copyJWK(value.Subagent)
	value.Upstream = copyJWK(value.Upstream)
	return value
}

func decodeJSON(response http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(response, request.Body, maxJSONBody)
	return decodeJSONBytes(request.Body, destination)
}

func decodeJSONBytes(reader io.Reader, destination any) error {
	return decodeJSONBytesWithLimit(reader, destination, maxJSONBody)
}

func decodeJSONBytesWithLimit(reader io.Reader, destination any, limit int64) error {
	encoded, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	if int64(len(encoded)) > limit {
		return errors.New("decode JSON: input is too large")
	}
	if err := jsonstrict.RejectAmbiguousNames(encoded); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("decode JSON: multiple values")
		}
		return fmt.Errorf("decode JSON trailing data: %w", err)
	}
	return nil
}

func readBoundedRequestBody(request *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(request.Body, maxJSONBody+1))
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	if len(body) > maxJSONBody {
		return nil, errors.New("request body is too large")
	}
	request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return body, nil
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeProblem(response http.ResponseWriter, status int, code string, err error) {
	writeProblemBody(response, status, problemBody(status, code, err, nil))
}

func writeHostPolicyRefusal(response http.ResponseWriter, code string, publicDetail string) {
	writeProblem(response, http.StatusForbidden, code, errors.New(publicDetail))
}

// writeSignatureFailure emits the AAuth HTTP-signature profile's 401 response.
// Authentication failure is distinct from policy denial: callers use this only
// before an endpoint has successfully authenticated the request.
func writeSignatureFailure(response http.ResponseWriter, err error) {
	if writeOperationalResolutionFailure(response, err) {
		return
	}
	var signatureError *signaturekey.Error
	if !errors.As(err, &signatureError) {
		signatureError = &signaturekey.Error{
			Code:  signaturekey.ErrorInvalidSignature,
			Cause: err,
		}
	}
	header, formatErr := signaturekey.FormatError(*signatureError)
	if formatErr != nil {
		signatureError = &signaturekey.Error{
			Code:  signaturekey.ErrorInvalidSignature,
			Cause: formatErr,
		}
		header, _ = signaturekey.FormatError(*signatureError)
	}
	response.Header().Set("Signature-Error", header)
	if len(signatureError.AcceptedAlgorithms) > 0 {
		if value, err := signaturekey.FormatAcceptAlgorithms(signatureError.AcceptedAlgorithms); err == nil {
			response.Header().Set("Accept-Signature-Alg", value)
		}
	}
	if len(signatureError.AcceptedSchemes) > 0 {
		if value, err := signaturekey.FormatAcceptSchemes(signatureError.AcceptedSchemes); err == nil {
			response.Header().Set("Accept-Signature-Scheme", value)
		}
	}
	extensions := make(map[string]any)
	if len(signatureError.RequiredInput) > 0 {
		extensions["required_input"] = signatureError.RequiredInput
	}
	// Causes can contain admitted endpoints, trust configuration, and
	// transport diagnostics. They remain available to the local caller but
	// are never copied into a remote Problem Details response. PublicDetail is
	// set only by the verifier for diagnostics it has classified as safe.
	var publicDetail error
	if signatureError.PublicDetail() != "" {
		publicDetail = errors.New(signatureError.PublicDetail())
	}
	body := problemBody(http.StatusUnauthorized, string(signatureError.Code), publicDetail, extensions)
	var problem map[string]any
	if err := json.Unmarshal(body, &problem); err == nil {
		problem["type"] = signatureError.ProblemType()
		if encoded, err := json.Marshal(problem); err == nil {
			body = encoded
		}
	}
	writeProblemBody(response, http.StatusUnauthorized, body)
}

func writeOperationalResolutionFailure(response http.ResponseWriter, err error) bool {
	var resolutionError *signaturekey.ResolutionError
	if !errors.As(err, &resolutionError) ||
		(resolutionError.Code != signaturekey.ResolutionDenied &&
			resolutionError.Code != signaturekey.ResolutionUnavailable) {
		return false
	}
	writeProblem(response, http.StatusServiceUnavailable, "server_error", nil)
	return true
}

func writeAuthorizationStateFailure(response http.ResponseWriter, err error) bool {
	for _, target := range []error{
		ErrAuthorizationStateStoreConfig,
		ErrAuthorizationStateCapacity,
		ErrAuthorizationStateUnsafe,
		ErrAuthorizationStateLocked,
		ErrAuthorizationStateIntegrity,
		ErrAuthorizationStateUncertain,
		ErrAuthorizationStateClosed,
	} {
		if errors.Is(err, target) {
			writeProblem(response, http.StatusServiceUnavailable, "authorization_state_unavailable", err)
			return true
		}
	}
	return false
}

func writeTokenVerificationFailure(
	response http.ResponseWriter,
	status int,
	code string,
	err error,
) {
	if writeOperationalResolutionFailure(response, err) {
		return
	}
	var resolutionError *signaturekey.ResolutionError
	if errors.As(err, &resolutionError) {
		writeProblem(response, status, code, nil)
		return
	}
	writeProblem(response, status, code, err)
}

func writeResourceTokenVerificationFailure(response http.ResponseWriter, err error) {
	var validationError *aauth.TokenValidationError
	if errors.As(err, &validationError) && validationError.Code == aauth.TokenValidationExpired {
		writeTokenVerificationFailure(response, http.StatusBadRequest, "expired_resource_token", err)
		return
	}
	writeTokenVerificationFailure(response, http.StatusBadRequest, "invalid_resource_token", err)
}

func problemBody(
	status int,
	code string,
	err error,
	extensions map[string]any,
) []byte {
	detail := code
	if status >= http.StatusInternalServerError {
		detail = publicServerProblemDetail(code)
	} else if err != nil {
		detail = err.Error()
	}
	value := map[string]any{
		"type":   "about:blank",
		"title":  http.StatusText(status),
		"status": status,
		"error":  code,
		"detail": detail,
	}
	for name, extension := range extensions {
		value[name] = extension
	}
	body, marshalErr := json.Marshal(value)
	if marshalErr != nil {
		return []byte(`{"type":"about:blank","title":"Internal Server Error","status":500,"error":"server_error","detail":"the server could not complete the request"}`)
	}
	return body
}

func publicServerProblemDetail(code string) string {
	switch code {
	case "authorization_state_unavailable":
		return "authorization state is temporarily unavailable"
	case "proof_replay_unavailable":
		return "proof replay protection is temporarily unavailable"
	case "person_token_custody_unavailable":
		return "person-token custody is temporarily unavailable"
	case "event_ticket_unavailable":
		return "event-ticket custody is temporarily unavailable"
	case "replay_custody_failed":
		return "replay custody is temporarily unavailable"
	case "federation_failed":
		return "authorization federation failed"
	case "server_error":
		return "the server could not complete the request"
	default:
		public := strings.TrimSpace(strings.ReplaceAll(code, "_", " "))
		if public == "" {
			return "the server could not complete the request"
		}
		return public
	}
}

func writeProblemBody(response http.ResponseWriter, status int, body []byte) {
	response.Header().Set("Content-Type", "application/problem+json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_, _ = response.Write(body)
}

func writeMissionTerminated(response http.ResponseWriter) {
	writeProblemBody(
		response,
		http.StatusForbidden,
		problemBody(
			http.StatusForbidden,
			"mission_terminated",
			ErrMissionTerminated,
			map[string]any{"mission_status": string(aauth.MissionTerminated)},
		),
	)
}

func parseScopes(scope string) ([]string, error) {
	values := strings.Fields(scope)
	if len(values) == 0 {
		return nil, errors.New("scope is required")
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return nil, fmt.Errorf("duplicate scope %q", value)
		}
		seen[value] = true
	}
	return values, nil
}

func scopesContained(granted, requested []string) bool {
	allowed := make(map[string]bool, len(requested))
	for _, value := range requested {
		allowed[value] = true
	}
	for _, value := range granted {
		if !allowed[value] {
			return false
		}
	}
	return true
}

func decodeRetainedCompactToken(compact string, tokenType string, destination any) error {
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return err
	}
	header := parsed.Header()
	if header.Type != tokenType {
		return fmt.Errorf("reference: retained token typ is %q, want %q", header.Type, tokenType)
	}
	var strictHeader jose.Header
	if err := decodeJSONBytes(bytes.NewReader(parsed.Protected()), &strictHeader); err != nil {
		return fmt.Errorf("reference: decode retained token header: %w", err)
	}
	if strictHeader != header || header.Algorithm != jose.Ed25519Algorithm || header.KeyID == "" {
		return errors.New("reference: retained token header is invalid")
	}
	if err := decodeJSONBytes(bytes.NewReader(parsed.Payload()), destination); err != nil {
		return fmt.Errorf("reference: decode retained token claims: %w", err)
	}
	return nil
}

func decodeRetainedAgentToken(compact string) (aauth.AgentTokenClaims, error) {
	var claims aauth.AgentTokenClaims
	if err := decodeRetainedCompactToken(compact, aauth.AgentTokenType, &claims); err != nil {
		return claims, err
	}
	if err := validateRetainedAgentClaims(claims); err != nil {
		return claims, err
	}
	return claims, nil
}

func decodeRetainedResourceToken(compact string) (aauth.ResourceTokenClaims, error) {
	var claims aauth.ResourceTokenClaims
	if err := decodeRetainedCompactToken(compact, aauth.ResourceTokenType, &claims); err != nil {
		return claims, err
	}
	if err := validateRetainedResourceClaims(claims); err != nil {
		return claims, err
	}
	return claims, nil
}

func decodeRetainedAuthToken(compact string) (aauth.AuthTokenClaims, error) {
	var claims aauth.AuthTokenClaims
	if err := decodeRetainedCompactToken(compact, aauth.AuthTokenType, &claims); err != nil {
		return claims, err
	}
	if err := validateRetainedAuthClaims(claims); err != nil {
		return claims, err
	}
	return claims, nil
}

func validateRetainedAgentClaims(claims aauth.AgentTokenClaims) error {
	if aauth.ValidateServerIdentifier(claims.Issuer) != nil || claims.DWK != aauth.AgentDiscoveryDocument ||
		aauth.ValidateAgentIdentifier(claims.Subject) != nil || claims.JTI == "" ||
		claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt > int64((24*time.Hour)/time.Second) ||
		aauth.ValidateAgentRelationship(claims.Subject, claims.ParentAgent) != nil {
		return errors.New("reference: retained agent-token claims are invalid")
	}
	_, agentDomain, ok := strings.Cut(strings.TrimPrefix(claims.Subject, "aauth:"), "@")
	if !ok || claims.Issuer != "https://"+agentDomain {
		return errors.New("reference: retained agent-token issuer does not match its subject")
	}
	if claims.PersonServer != "" && aauth.ValidateServerIdentifier(claims.PersonServer) != nil {
		return errors.New("reference: retained agent-token person server is invalid")
	}
	if _, err := claims.Confirmation.JWK.PublicKey(); err != nil {
		return errors.New("reference: retained agent-token confirmation key is invalid")
	}
	return nil
}

func validateRetainedResourceClaims(claims aauth.ResourceTokenClaims) error {
	if aauth.ValidateServerIdentifier(claims.Issuer) != nil || claims.DWK != aauth.ResourceDiscoveryDocument ||
		aauth.ValidateServerIdentifier(claims.Audience) != nil || claims.JTI == "" ||
		aauth.ValidateServerIdentifier(claims.PersonServer) != nil || claims.Subject == "" ||
		claims.PresentedJTI == "" || claims.Agent != "" || claims.Mission != nil ||
		claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt ||
		!validRetainedThumbprint(claims.AgentJKT) {
		return errors.New("reference: retained resource-token claims are invalid")
	}
	if _, err := parseScopes(claims.Scope); err != nil {
		return errors.New("reference: retained resource-token scope is invalid")
	}
	if claims.MissionS256 != "" && !validRetainedThumbprint(claims.MissionS256) {
		return errors.New("reference: retained resource-token mission digest is invalid")
	}
	return nil
}

func validateRetainedAuthClaims(claims aauth.AuthTokenClaims) error {
	if aauth.ValidateServerIdentifier(claims.Issuer) != nil ||
		(claims.DWK != aauth.PersonDiscoveryDocument && claims.DWK != aauth.AccessDiscoveryDocument) ||
		aauth.ValidateServerIdentifier(claims.Audience) != nil || claims.JTI == "" ||
		aauth.ValidateServerIdentifier(claims.PersonServer) != nil || claims.Subject == "" ||
		claims.Agent != "" || claims.Actor != nil || claims.Mission != nil ||
		claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt > int64(time.Hour/time.Second) {
		return errors.New("reference: retained auth-token claims are invalid")
	}
	if claims.DWK == aauth.PersonDiscoveryDocument && claims.PersonServer != claims.Issuer {
		return errors.New("reference: retained person-server auth-token identity is invalid")
	}
	if _, err := claims.Confirmation.JWK.PublicKey(); err != nil {
		return errors.New("reference: retained auth-token confirmation key is invalid")
	}
	if claims.MissionS256 != "" && !validRetainedThumbprint(claims.MissionS256) {
		return errors.New("reference: retained auth-token mission digest is invalid")
	}
	return nil
}

func retainedResourceTokenMatches(compact string, expected aauth.ResourceTokenClaims) bool {
	claims, err := decodeRetainedResourceToken(compact)
	return err == nil && reflect.DeepEqual(claims, expected)
}

func latestRetainedAuthorizationInputIssuedAt(
	resourceTokenCompact string,
	agentTokenCompact string,
	subagentTokenCompact string,
	upstreamTokenCompact string,
) (int64, error) {
	resource, err := decodeRetainedResourceToken(resourceTokenCompact)
	if err != nil {
		return 0, err
	}
	agent, err := decodeRetainedAgentToken(agentTokenCompact)
	if err != nil {
		return 0, err
	}
	latest := resource.IssuedAt
	if agent.IssuedAt > latest {
		latest = agent.IssuedAt
	}
	if subagentTokenCompact != "" {
		subagent, err := decodeRetainedAgentToken(subagentTokenCompact)
		if err != nil {
			return 0, err
		}
		if subagent.IssuedAt > latest {
			latest = subagent.IssuedAt
		}
	}
	if upstreamTokenCompact != "" {
		upstream, err := decodeRetainedAuthToken(upstreamTokenCompact)
		if err != nil {
			return 0, err
		}
		if upstream.IssuedAt > latest {
			latest = upstream.IssuedAt
		}
	}
	return latest, nil
}

// verifyRetainedAuthToken verifies a terminal token from retained key material
// at its own issuance instant. Recovery therefore rechecks structure,
// signature, and lifetime construction without consulting discovery, current
// policy, or the wall clock.
func verifyRetainedAuthToken(compact string, key jose.JWK) (aauth.AuthTokenClaims, error) {
	claims, err := decodeRetainedAuthToken(compact)
	if err != nil {
		return claims, err
	}
	return verifyRetainedAuthTokenClaimsAt(
		compact,
		key,
		claims,
		time.Unix(claims.IssuedAt, 0).UTC(),
	)
}

func verifyRetainedAuthTokenAt(
	compact string,
	key jose.JWK,
	verifiedAt time.Time,
) (aauth.AuthTokenClaims, error) {
	claims, err := decodeRetainedAuthToken(compact)
	if err != nil {
		return claims, err
	}
	return verifyRetainedAuthTokenClaimsAt(compact, key, claims, verifiedAt.UTC())
}

func verifyRetainedAuthTokenClaimsAt(
	compact string,
	key jose.JWK,
	claims aauth.AuthTokenClaims,
	verifiedAt time.Time,
) (aauth.AuthTokenClaims, error) {
	header, err := jose.PeekHeader(compact)
	if err != nil {
		return claims, err
	}
	verified, err := aauth.VerifyAuthToken(
		context.Background(),
		compact,
		signaturekey.StaticKeyResolver{claims.Issuer: {header.KeyID: key}},
		aauth.ClockFunc(func() time.Time { return verifiedAt }),
	)
	if err != nil {
		return claims, err
	}
	verifiedClaims, err := claimsWithoutAuthorization(verified)
	if err != nil {
		return claims, err
	}
	if !reflect.DeepEqual(verifiedClaims, claims) {
		return claims, errors.New("reference: retained auth-token claims changed during verification")
	}
	return claims, nil
}

func verifyRetainedAgentToken(compact string, key jose.JWK) (aauth.AgentTokenClaims, error) {
	claims, err := decodeRetainedAgentToken(compact)
	if err != nil {
		return claims, err
	}
	return verifyRetainedAgentTokenClaimsAt(
		compact,
		key,
		claims,
		time.Unix(claims.IssuedAt, 0).UTC(),
	)
}

func verifyRetainedAgentTokenAt(
	compact string,
	key jose.JWK,
	verifiedAt time.Time,
) (aauth.AgentTokenClaims, error) {
	claims, err := decodeRetainedAgentToken(compact)
	if err != nil {
		return claims, err
	}
	return verifyRetainedAgentTokenClaimsAt(compact, key, claims, verifiedAt.UTC())
}

func verifyRetainedAgentTokenClaimsAt(
	compact string,
	key jose.JWK,
	claims aauth.AgentTokenClaims,
	verifiedAt time.Time,
) (aauth.AgentTokenClaims, error) {
	header, err := jose.PeekHeader(compact)
	if err != nil {
		return claims, err
	}
	verified, err := aauth.VerifyAgentToken(
		context.Background(),
		compact,
		signaturekey.StaticKeyResolver{claims.Issuer: {header.KeyID: key}},
		aauth.ClockFunc(func() time.Time { return verifiedAt }),
	)
	if err != nil {
		return claims, err
	}
	verifiedClaims, err := claimsWithoutAuthorization(verified)
	if err != nil {
		return claims, err
	}
	if !reflect.DeepEqual(verifiedClaims, claims) {
		return claims, errors.New("reference: retained agent-token claims changed during verification")
	}
	return claims, nil
}

func verifyRetainedResourceToken(compact string, key jose.JWK) (aauth.ResourceTokenClaims, error) {
	claims, err := decodeRetainedResourceToken(compact)
	if err != nil {
		return claims, err
	}
	return verifyRetainedResourceTokenClaimsAt(
		compact,
		key,
		claims,
		time.Unix(claims.IssuedAt, 0).UTC(),
	)
}

func verifyRetainedResourceTokenAt(
	compact string,
	key jose.JWK,
	verifiedAt time.Time,
) (aauth.ResourceTokenClaims, error) {
	claims, err := decodeRetainedResourceToken(compact)
	if err != nil {
		return claims, err
	}
	return verifyRetainedResourceTokenClaimsAt(compact, key, claims, verifiedAt.UTC())
}

func verifyRetainedResourceTokenClaimsAt(
	compact string,
	key jose.JWK,
	claims aauth.ResourceTokenClaims,
	verifiedAt time.Time,
) (aauth.ResourceTokenClaims, error) {
	header, err := jose.PeekHeader(compact)
	if err != nil {
		return claims, err
	}
	verified, err := aauth.VerifyResourceToken(
		context.Background(),
		compact,
		signaturekey.StaticKeyResolver{claims.Issuer: {header.KeyID: key}},
		aauth.ClockFunc(func() time.Time { return verifiedAt }),
	)
	if err != nil {
		return claims, err
	}
	verifiedClaims, err := claimsWithoutAuthorization(verified)
	if err != nil {
		return claims, err
	}
	if !reflect.DeepEqual(verifiedClaims, claims) {
		return claims, errors.New("reference: retained resource-token claims changed during verification")
	}
	return claims, nil
}

func validRetainedThumbprint(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func endpointIdentifier(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse endpoint: %w", err)
	}
	identifier := parsed.Scheme + "://" + parsed.Host
	if err := aauth.ValidateServerIdentifier(identifier); err != nil {
		return "", err
	}
	return identifier, nil
}
