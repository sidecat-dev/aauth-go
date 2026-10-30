package aauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

// RevocationError names how a revocation sent to one recipient ended when the
// recipient did not record it. It is the error member of a downstream entry in
// a revocation response.
type RevocationError string

const (
	// RevocationUnsupported means the recipient publishes no
	// revocation_endpoint or answered unsupported_iss. It honors the token
	// until its exp.
	RevocationUnsupported RevocationError = "revocation_unsupported"
	// RevocationUnavailable means the recipient did not respond, timed out, or
	// answered with a 5xx or a malformed response. The caller may revoke again
	// later.
	RevocationUnavailable RevocationError = "revocation_unavailable"
)

// DownstreamRevocation is one entry of the downstream report in a revocation
// response: an Access Server reports to a Person Server each Resource it
// revoked at. Error is empty when the revocation there succeeded.
type DownstreamRevocation struct {
	Recipient string          `json:"recipient"`
	Error     RevocationError `json:"error,omitempty"`
}

// RevocationAttempt reports how one revocation a server sent to one recipient
// ended. Exactly one of three outcomes holds: Error is empty and Pending is
// false when the recipient recorded the revocation; Pending is true when the
// recipient answered 202 or 429 rate_limited, or had not answered when the
// sender stopped waiting, so the revocation there is not yet terminal;
// otherwise Error names why it did not record. Revoking again after
// RetryAfter continues a pending attempt and re-attempts a failed one.
type RevocationAttempt struct {
	Recipient string
	Error     RevocationError
	Pending   bool
	// RetryAfter is the delay before a pending attempt can progress: the one
	// the recipient asked for, or the default polling interval.
	RetryAfter time.Duration
	// Downstream is the recipient's own report of the revocations it made.
	Downstream []DownstreamRevocation
	// Cause is a local diagnostic for an attempt that did not record. It is
	// never sent on the wire.
	Cause error
}

// Recorded reports whether the recipient recorded the revocation.
func (attempt RevocationAttempt) Recorded() bool {
	return attempt.Error == "" && !attempt.Pending
}

// RevocationLimits bounds what a revocation endpoint accepts from one verified
// caller. A recipient that accepts revocations from any verified issuer
// answers rate_limited beyond either bound.
type RevocationLimits struct {
	// Requests is how many revocation requests one caller may send in each
	// Window. Polls of a pending revocation are not counted. Zero selects 600.
	Requests int
	// Window is the length of the rate window. Zero selects one minute.
	Window time.Duration
	// MaxLifetime bounds how far past the current time a revocation's exp may
	// lie. It is the longest lifetime the recipient accepts for any token; a
	// later exp is invalid_request. Zero selects 24 hours.
	MaxLifetime time.Duration
}

// ErrRevocationLimitReached is returned by a revocation store that already
// holds as many entries for the request's issuer as it allows. The endpoint
// answers 429 rate_limited and records nothing.
var ErrRevocationLimitReached = errors.New("aauth: revocation entry limit reached")

// EncodeRevocationReport returns the body of a revocation 200 that reports
// downstream outcomes, {"downstream":[...]}. An empty report returns nil: the
// recipient then answers 200 with no body and no Content-Type.
func EncodeRevocationReport(downstream []DownstreamRevocation) ([]byte, error) {
	if len(downstream) == 0 {
		return nil, nil
	}
	for _, entry := range downstream {
		if err := ValidateServerIdentifier(entry.Recipient); err != nil {
			return nil, fmt.Errorf("aauth: downstream revocation recipient: %w", err)
		}
		if entry.Error != "" && entry.Error != RevocationUnsupported && entry.Error != RevocationUnavailable {
			return nil, fmt.Errorf("aauth: downstream revocation error %q is not defined", entry.Error)
		}
	}
	return json.Marshal(struct {
		Downstream []DownstreamRevocation `json:"downstream"`
	}{Downstream: downstream})
}

// ReadRevocationReport reads the body of a revocation 200 of at most maxBytes
// and returns its downstream report. An absent body means the revocation was
// recorded with nothing reported. A present body MUST be application/json and
// one JSON object whose optional downstream member is an array of objects;
// members are matched by exact name and unknown members are ignored. Anything
// else, including JSON null, is ErrRevocationUnavailable.
func ReadRevocationReport(response *http.Response, maxBytes int64) ([]DownstreamRevocation, error) {
	if response == nil || response.Body == nil {
		return nil, nil
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %v", ErrRevocationUnavailable, err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	unavailable := func(reason string) error { return fmt.Errorf("%w: %s", ErrRevocationUnavailable, reason) }
	if int64(len(raw)) > maxBytes {
		return nil, unavailable("response is too large")
	}
	if mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type")); parseErr != nil || mediaType != "application/json" {
		return nil, unavailable("response is not application/json")
	}
	if err := jsonstrict.RejectAmbiguousNames(raw); err != nil {
		return nil, unavailable(err.Error())
	}
	// Members are matched by exact name; any other member, including a
	// case-distinct one, is an extension this reader ignores.
	var members map[string]json.RawMessage
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' || json.Unmarshal(trimmed, &members) != nil {
		return nil, unavailable("response is not a JSON object")
	}
	var entries []map[string]json.RawMessage
	if value, present := members["downstream"]; present {
		if trimmed := bytes.TrimSpace(value); len(trimmed) == 0 || trimmed[0] != '[' || json.Unmarshal(trimmed, &entries) != nil {
			return nil, unavailable("downstream is not an array of objects")
		}
	}
	downstream := make([]DownstreamRevocation, 0, len(entries))
	for _, entry := range entries {
		if entry == nil {
			return nil, unavailable("downstream entry is not an object")
		}
		var recipient string
		if json.Unmarshal(entry["recipient"], &recipient) != nil || recipient == "" {
			return nil, unavailable("downstream entry has no recipient")
		}
		report := DownstreamRevocation{Recipient: recipient}
		if value, present := entry["error"]; present {
			var code string
			if json.Unmarshal(value, &code) != nil ||
				(RevocationError(code) != RevocationUnsupported && RevocationError(code) != RevocationUnavailable) {
				return nil, unavailable("downstream entry has an unknown error")
			}
			report.Error = RevocationError(code)
		}
		downstream = append(downstream, report)
	}
	if len(downstream) == 0 {
		return nil, nil
	}
	return downstream, nil
}
