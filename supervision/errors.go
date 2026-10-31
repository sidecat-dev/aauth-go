package supervision

import (
	"errors"
	"net/http"
)

// ErrorCode is a supervision error member (Errors).
type ErrorCode string

const (
	// ErrorInvalidRequest is a malformed body, a missing member, or an
	// unrecognized action, act or event. A Person Server treats the SS as
	// unavailable for the act; retrying will not help.
	ErrorInvalidRequest ErrorCode = "invalid_request"
	// ErrorUnsupportedIss means the SS does not accept requests from this
	// Person Server.
	ErrorUnsupportedIss ErrorCode = "unsupported_iss"
	// ErrorUnknownSub means the SS accepts the Person Server but has no
	// connection for the sub. The Person Server connects and resends.
	ErrorUnknownSub ErrorCode = "unknown_sub"
	// ErrorUnknownMission means the SS has no record of mission_s256. The
	// Person Server replays the mission and resends.
	ErrorUnknownMission ErrorCode = "unknown_mission"
	// ErrorUnknownPending names a pending URL the SS does not hold, or a
	// poller that is not the requester.
	ErrorUnknownPending ErrorCode = "unknown_pending"
	// ErrorRateLimited carries a required Retry-After.
	ErrorRateLimited ErrorCode = "rate_limited"
	// ErrorServerError is an internal failure.
	ErrorServerError ErrorCode = "server_error"
)

// Status returns the HTTP status the draft assigns to code.
func (code ErrorCode) Status() int {
	switch code {
	case ErrorInvalidRequest:
		return http.StatusBadRequest
	case ErrorUnsupportedIss:
		return http.StatusForbidden
	case ErrorUnknownSub, ErrorUnknownMission, ErrorUnknownPending:
		return http.StatusNotFound
	case ErrorRateLimited:
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}

// RequestError reports a request body an SS rejects with invalid_request.
type RequestError struct{ cause error }

func (failure *RequestError) Error() string {
	if failure == nil || failure.cause == nil {
		return "supervision: invalid request"
	}
	return failure.cause.Error()
}

func (failure *RequestError) Unwrap() error { return failure.cause }

func invalidRequest(cause error) error {
	var existing *RequestError
	if errors.As(cause, &existing) {
		return cause
	}
	return &RequestError{cause: cause}
}
