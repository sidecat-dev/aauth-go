package aauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

const maxProblemResponseBytes = 1 << 20

// ErrorCode is an AAuth problem-details error member.
type ErrorCode string

// ProblemError is an AAuth RFC 9457 error response. Code is the required
// AAuth "error" extension member.
type ProblemError struct {
	Type              string
	Title             string
	Status            int
	Code              ErrorCode
	Detail            string
	Instance          string
	MissionStatus     string
	TerminationReason string
}

func (problem *ProblemError) Error() string {
	if problem == nil {
		return "aauth: unknown problem response"
	}
	termination := ""
	if problem.TerminationReason != "" {
		termination = " termination_reason=" + problem.TerminationReason
	}
	if problem.Detail != "" {
		return fmt.Sprintf("aauth: server returned %d %s%s: %s", problem.Status, problem.Code, termination, problem.Detail)
	}
	return fmt.Sprintf("aauth: server returned %d %s%s", problem.Status, problem.Code, termination)
}

// DecodeProblemResponse validates and consumes an AAuth problem-details body.
func DecodeProblemResponse(response *http.Response) (*ProblemError, error) {
	if response == nil || response.Body == nil {
		return nil, errors.New("aauth: problem response body is required")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/problem+json" {
		return nil, errors.New("aauth: problem response must use application/problem+json")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProblemResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("aauth: read problem response: %w", err)
	}
	if len(body) > maxProblemResponseBytes {
		return nil, errors.New("aauth: problem response is too large")
	}
	if err := jsonstrict.RejectAmbiguousNames(body); err != nil {
		return nil, fmt.Errorf("aauth: decode problem response: %w", err)
	}
	var wire struct {
		Type              string    `json:"type"`
		Title             string    `json:"title"`
		Status            int       `json:"status"`
		Code              ErrorCode `json:"error"`
		Detail            string    `json:"detail"`
		Instance          string    `json:"instance"`
		MissionStatus     string    `json:"mission_status"`
		TerminationReason string    `json:"termination_reason"`
	}
	if err := jsonstrict.RejectCaseVariants(body, &wire); err != nil {
		return nil, fmt.Errorf("aauth: decode problem response: %w", err)
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("aauth: decode problem response: %w", err)
	}
	if !validErrorCode(string(wire.Code)) {
		return nil, errors.New("aauth: problem response error code is invalid")
	}
	if wire.Status != 0 && wire.Status != response.StatusCode {
		return nil, errors.New("aauth: problem response status does not match HTTP status")
	}
	if wire.Status == 0 {
		wire.Status = response.StatusCode
	}
	return &ProblemError{
		Type: wire.Type, Title: wire.Title, Status: wire.Status,
		Code: wire.Code, Detail: wire.Detail, Instance: wire.Instance,
		MissionStatus: wire.MissionStatus, TerminationReason: wire.TerminationReason,
	}, nil
}

func validErrorCode(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' {
			continue
		}
		if index > 0 && (character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.') {
			continue
		}
		return false
	}
	return true
}
