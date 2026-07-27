package aauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
)

const maxProblemResponseBytes = 1 << 20

// ProblemError is an AAuth RFC 9457 error response. Code is the required
// AAuth "error" extension member.
type ProblemError struct {
	Type     string
	Title    string
	Status   int
	Code     PollingErrorCode
	Detail   string
	Instance string
	// MissionStatus is present on mission_terminated responses.
	MissionStatus string
}

func (problem *ProblemError) Error() string {
	if problem == nil {
		return "aauth: unknown problem response"
	}
	if problem.Detail != "" {
		return fmt.Sprintf("aauth: server returned %d %s: %s", problem.Status, problem.Code, problem.Detail)
	}
	return fmt.Sprintf("aauth: server returned %d %s", problem.Status, problem.Code)
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
	var wire struct {
		Type          string           `json:"type"`
		Title         string           `json:"title"`
		Status        int              `json:"status"`
		Code          PollingErrorCode `json:"error"`
		Detail        string           `json:"detail"`
		Instance      string           `json:"instance"`
		MissionStatus string           `json:"mission_status"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("aauth: decode problem response: %w", err)
	}
	if wire.Code == "" || !isStructuredToken(string(wire.Code)) {
		return nil, errors.New("aauth: problem response error code is invalid")
	}
	if wire.Status != 0 && wire.Status != response.StatusCode {
		return nil, errors.New("aauth: problem response status does not match HTTP status")
	}
	if wire.Status == 0 {
		wire.Status = response.StatusCode
	}
	if wire.Code == "mission_terminated" && wire.MissionStatus != "terminated" {
		return nil, errors.New("aauth: mission_terminated problem must report terminated mission_status")
	}
	return &ProblemError{
		Type:          wire.Type,
		Title:         wire.Title,
		Status:        wire.Status,
		Code:          wire.Code,
		Detail:        wire.Detail,
		Instance:      wire.Instance,
		MissionStatus: wire.MissionStatus,
	}, nil
}
