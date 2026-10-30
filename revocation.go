package aauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

// TokenReference identifies one token in its issuer's JTI namespace.
type TokenReference struct {
	Issuer string `json:"iss"`
	JTI    string `json:"jti"`
}

// ValidateTokenReference validates a token's issuer and JTI identity; the wire request is RevocationRequest.
func ValidateTokenReference(reference TokenReference) error {
	if err := ValidateServerIdentifier(reference.Issuer); err != nil {
		return fmt.Errorf("aauth: token reference issuer: %w", err)
	}
	if reference.JTI == "" {
		return errors.New("aauth: token reference jti is required")
	}
	return nil
}

// RevocationRequest is one token-revocation request: the token's identity and
// its expiration. The wire body carries only jti and exp; the issuer is the
// verified signer of the request, never a body member.
type RevocationRequest struct {
	Reference TokenReference
	// ExpiresAt is the token's exp claim. A recipient may discard its
	// revocation state once the token can no longer be valid.
	ExpiresAt time.Time
}

// ValidateRevocationRequest validates a revocation request.
func ValidateRevocationRequest(request RevocationRequest) error {
	if err := ValidateTokenReference(request.Reference); err != nil {
		return err
	}
	if request.ExpiresAt.Unix() <= 0 {
		return errors.New("aauth: revocation request exp is required")
	}
	return nil
}

type revocationWire struct {
	JTI string `json:"jti"`
	Exp *int64 `json:"exp"`
}

// EncodeRevocationRequest returns the Protocol 11 request body {jti, exp}.
func EncodeRevocationRequest(request RevocationRequest) ([]byte, error) {
	if err := ValidateRevocationRequest(request); err != nil {
		return nil, err
	}
	exp := request.ExpiresAt.Unix()
	return json.Marshal(revocationWire{JTI: request.Reference.JTI, Exp: &exp})
}

// DecodeRevocationRequest reads a revocation request body of at most maxBytes.
// The issuer is the verified signer of the request; a body member named iss is
// ignored like any other extension member.
func DecodeRevocationRequest(body io.Reader, maxBytes int64, issuer string) (RevocationRequest, error) {
	if body == nil {
		return RevocationRequest{}, errors.New("aauth: revocation request body is required")
	}
	raw, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return RevocationRequest{}, fmt.Errorf("aauth: read revocation request: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		return RevocationRequest{}, errors.New("aauth: revocation request body is too large")
	}
	var wire revocationWire
	if err := jsonstrict.RejectAmbiguousNames(raw); err != nil {
		return RevocationRequest{}, fmt.Errorf("aauth: decode revocation request: %w", err)
	}
	if err := jsonstrict.RejectCaseVariants(raw, &wire); err != nil {
		return RevocationRequest{}, fmt.Errorf("aauth: decode revocation request: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&wire); err != nil {
		return RevocationRequest{}, fmt.Errorf("aauth: decode revocation request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return RevocationRequest{}, errors.New("aauth: revocation request must contain exactly one JSON value")
	}
	if wire.Exp == nil {
		return RevocationRequest{}, errors.New("aauth: revocation request exp is required")
	}
	request := RevocationRequest{
		Reference: TokenReference{Issuer: issuer, JTI: wire.JTI},
		ExpiresAt: time.Unix(*wire.Exp, 0).UTC(),
	}
	if err := ValidateRevocationRequest(request); err != nil {
		return RevocationRequest{}, err
	}
	return request, nil
}

// ErrRevocationUnavailable is the caller's reading of a revocation 200 whose
// body is present but is not the Protocol -11 response object. The caller MAY
// revoke again later.
var ErrRevocationUnavailable = errors.New("aauth: revocation_unavailable")

// ReadRevocationResponse reads the body of a revocation 200 of at most maxBytes
// and validates it as ReadRevocationReport does, discarding the report. A PS
// answering an AP reports nothing, and callers that need the downstream
// report use ReadRevocationReport.
func ReadRevocationResponse(response *http.Response, maxBytes int64) error {
	_, err := ReadRevocationReport(response, maxBytes)
	return err
}
