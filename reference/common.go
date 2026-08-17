// Package reference provides small, deployable AAuth role handlers and an
// agent client built exclusively on the public aauth package.
package reference

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

const maxJSONBody = 1 << 20

func decodeJSON(response http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(response, request.Body, maxJSONBody)
	return decodeJSONBytes(request.Body, destination)
}

func decodeJSONBytes(reader io.Reader, destination any) error {
	encoded, err := io.ReadAll(io.LimitReader(reader, maxJSONBody+1))
	if err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	if len(encoded) > maxJSONBody {
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

// writeSignatureFailure emits the AAuth HTTP-signature profile's 401 response.
// Authentication failure is distinct from policy denial: callers use this only
// before an endpoint has successfully authenticated the request.
func writeSignatureFailure(response http.ResponseWriter, err error) {
	if writeOperationalResolutionFailure(response, err) {
		return
	}
	var signatureError *aauth.SignatureError
	if !errors.As(err, &signatureError) {
		signatureError = &aauth.SignatureError{
			Code:  aauth.SignatureErrorInvalidSignature,
			Cause: err,
		}
	}
	header, formatErr := aauth.FormatSignatureError(*signatureError)
	if formatErr != nil {
		signatureError = &aauth.SignatureError{
			Code:  aauth.SignatureErrorInvalidSignature,
			Cause: formatErr,
		}
		header, _ = aauth.FormatSignatureError(*signatureError)
	}
	response.Header().Set("Signature-Error", header)
	if len(signatureError.AcceptedAlgorithms) > 0 {
		if value, err := aauth.FormatAcceptSignatureAlgorithms(signatureError.AcceptedAlgorithms); err == nil {
			response.Header().Set("Accept-Signature-Alg", value)
		}
	}
	if len(signatureError.AcceptedSchemes) > 0 {
		if value, err := aauth.FormatAcceptSignatureSchemes(signatureError.AcceptedSchemes); err == nil {
			response.Header().Set("Accept-Signature-Scheme", value)
		}
	}
	extensions := make(map[string]any)
	if len(signatureError.RequiredInput) > 0 {
		extensions["required_input"] = signatureError.RequiredInput
	}
	// Causes can contain admitted endpoints, trust configuration, and
	// transport diagnostics. They remain available to the local caller but
	// are never copied into a remote Problem Details response.
	body := problemBody(http.StatusUnauthorized, string(signatureError.Code), nil, extensions)
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
	var resolutionError *aauth.KeyResolutionError
	if !errors.As(err, &resolutionError) ||
		(resolutionError.Code != aauth.KeyResolutionDenied &&
			resolutionError.Code != aauth.KeyResolutionUnavailable) {
		return false
	}
	writeProblem(response, http.StatusServiceUnavailable, "server_error", nil)
	return true
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
	var resolutionError *aauth.KeyResolutionError
	if errors.As(err, &resolutionError) {
		writeProblem(response, status, code, nil)
		return
	}
	writeProblem(response, status, code, err)
}

func problemBody(
	status int,
	code string,
	err error,
	extensions map[string]any,
) []byte {
	detail := code
	if err != nil {
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
		return []byte(`{"type":"about:blank","title":"Internal Server Error","status":500,"error":"server_error","detail":"reference: encode problem response"}`)
	}
	return body
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
