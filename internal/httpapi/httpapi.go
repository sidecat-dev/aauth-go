// Package httpapi contains the small HTTP/JSON conventions shared by the AAuth
// role packages.
package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// DefaultMaxBodyBytes is the fallback bound for decoded JSON requests.
const DefaultMaxBodyBytes int64 = 1 << 20

// DecodeJSON reads one bounded JSON value, rejects ambiguous or non-exact
// spellings of known fields, permits additive extension members, and leaves no
// trailing value unread.
func DecodeJSON(reader io.Reader, maxBytes int64, destination any) error {
	_, err := DecodeExactJSON(reader, maxBytes, destination)
	return err
}

// DecodeExactJSON applies DecodeJSON's validation and returns an independent
// copy of the exact input bytes.
func DecodeExactJSON(reader io.Reader, maxBytes int64, destination any) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("request body is required")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBodyBytes
	}
	body, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, errors.New("request body is too large")
	}
	if err := jsonstrict.RejectAmbiguousNames(body); err != nil {
		return nil, err
	}
	if err := jsonstrict.RejectCaseVariants(body, destination); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(destination); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("request body must contain exactly one JSON value")
	}
	return append([]byte(nil), body...), nil
}

// WriteJSON writes one JSON response.
func WriteJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

// ProblemFields carries explicitly public extensions supplied by the deciding
// role. Diagnostic causes are never serialized into these fields.
type ProblemFields struct {
	// Detail is an explicitly public explanation; never copy a diagnostic cause.
	Detail            string `json:"-"`
	MissionStatus     string `json:"mission_status,omitempty"`
	TerminationReason string `json:"termination_reason,omitempty"`
}

// WriteProblem writes an AAuth problem response with optional public fields.
// Diagnostic causes stay local; only explicitly supplied public detail crosses
// the wire.
func WriteProblem(response http.ResponseWriter, status int, code string, cause error, fields ...ProblemFields) {
	defer ReportProblem(response, status, code, cause)
	detail := http.StatusText(status)
	var signatureFailure *signaturekey.Error
	if status == http.StatusUnauthorized {
		failureCode := signaturekey.ErrorInvalidSignature
		if strings.Contains(code, "token") {
			failureCode = signaturekey.ErrorInvalidJWT
		}
		signatureFailure = signaturekey.NormalizeError(cause, failureCode)
	}
	if signatureFailure != nil {
		if header, err := signaturekey.FormatError(*signatureFailure); err == nil {
			response.Header().Set("Signature-Error", header)
		}
		if len(signatureFailure.AcceptedAlgorithms) > 0 {
			if header, err := signaturekey.FormatAcceptAlgorithms(signatureFailure.AcceptedAlgorithms); err == nil {
				response.Header().Set("Accept-Signature-Alg", header)
			}
		}
		if len(signatureFailure.AcceptedSchemes) > 0 {
			if header, err := signaturekey.FormatAcceptSchemes(signatureFailure.AcceptedSchemes); err == nil {
				response.Header().Set("Accept-Signature-Scheme", header)
			}
		}
		if public := strings.TrimSpace(signatureFailure.PublicDetail()); public != "" {
			detail = public
		}
	}
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(status)
	var extensions ProblemFields
	if len(fields) > 0 {
		extensions = fields[0]
	}
	if extensions.Detail != "" {
		detail = extensions.Detail
	}
	_ = json.NewEncoder(response).Encode(struct {
		Type   string `json:"type,omitempty"`
		Status int    `json:"status"`
		Code   string `json:"error"`
		Detail string `json:"detail,omitempty"`
		ProblemFields
	}{
		Type: func() string {
			if signatureFailure == nil {
				return ""
			}
			return signatureFailure.ProblemType()
		}(),
		Status: status, Code: code, Detail: detail,
		ProblemFields: extensions,
	})
}

// ReportProblem forwards a local diagnostic without changing the response.
// Internal response wrappers forward this hook without exposing their underlying
// transport or adding optional HTTP capabilities.
func ReportProblem(response http.ResponseWriter, status int, code string, cause error) {
	if reporter, ok := response.(interface {
		ReportAAuthProblem(int, string, error)
	}); ok {
		reporter.ReportAAuthProblem(status, code, cause)
	}
}
