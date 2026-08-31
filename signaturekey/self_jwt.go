package signaturekey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// SelfJWTAssertion is one self-issued JWT verified with the same discovered
// public key as its accompanying HTTP request. Its accessors return immutable
// values or independent copies.
type SelfJWTAssertion struct {
	issuer            string
	discoveryDocument string
	expiresAt         time.Time
	compact           string
	payload           []byte
}

// Issuer returns the verified HTTPS issuer.
func (assertion SelfJWTAssertion) Issuer() string { return assertion.issuer }

// DiscoveryDocument returns the verified dot-well-known document name.
func (assertion SelfJWTAssertion) DiscoveryDocument() string { return assertion.discoveryDocument }

// ExpiresAt returns the assertion's required NumericDate expiry.
func (assertion SelfJWTAssertion) ExpiresAt() time.Time { return assertion.expiresAt }

// Compact returns the exact verified compact serialization.
func (assertion SelfJWTAssertion) Compact() string { return assertion.compact }

// Payload returns an independent copy of the exact verified JWT payload.
func (assertion SelfJWTAssertion) Payload() []byte {
	return append([]byte(nil), assertion.payload...)
}

type selfJWTClaims struct {
	Issuer            string          `json:"iss"`
	DiscoveryDocument string          `json:"dwk"`
	ExpiresAt         *int64          `json:"exp"`
	Confirmation      json.RawMessage `json:"cnf"`
}

// VerifySelfJWT verifies the selected self-jwt assertion and then verifies the
// HTTP Message Signature with the same discovered key. expectedType is the
// deployment-selected explicit JWT type.
func (prepared PreparedRequest) VerifySelfJWT(
	ctx context.Context,
	resolver KeyResolver,
	expectedType string,
) (VerifiedRequest, SelfJWTAssertion, error) {
	var assertion SelfJWTAssertion
	if ctx == nil {
		return VerifiedRequest{}, assertion, errors.New("aauth: verification context is required")
	}
	if resolver == nil {
		return VerifiedRequest{}, assertion, errors.New("aauth: key resolver is required")
	}
	if expectedType == "" {
		return VerifiedRequest{}, assertion, errors.New("aauth: expected self-jwt type is required")
	}
	compact, ok := prepared.credential.SelfJWT()
	if !ok {
		return VerifiedRequest{}, assertion, errors.New("aauth: prepared request does not use self-jwt")
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return VerifiedRequest{}, assertion, newError(ErrorInvalidJWT, err)
	}
	header := parsed.Header()
	if header.Type != expectedType {
		return VerifiedRequest{}, assertion, newError(
			ErrorInvalidJWT,
			fmt.Errorf("aauth: self-jwt type is %q, want %q", header.Type, expectedType),
		)
	}
	if header.Algorithm != jose.Ed25519Algorithm {
		return VerifiedRequest{}, assertion, &Error{
			Code:               ErrorUnsupportedAlgorithm,
			AcceptedAlgorithms: []string{jose.Ed25519Algorithm},
			Cause:              fmt.Errorf("aauth: unsupported self-jwt algorithm %q", header.Algorithm),
		}
	}
	if header.KeyID == "" {
		return VerifiedRequest{}, assertion, newError(ErrorInvalidJWT, errors.New("aauth: self-jwt requires kid"))
	}
	payload := parsed.Payload()
	var claims selfJWTClaims
	if err := jsonstrict.RejectCaseVariants(payload, &claims); err != nil {
		return VerifiedRequest{}, assertion, newError(ErrorInvalidJWT, err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return VerifiedRequest{}, assertion, newError(ErrorInvalidJWT, err)
	}
	if _, present := members["cnf"]; present {
		return VerifiedRequest{}, assertion, newError(ErrorInvalidJWT, errors.New("aauth: self-jwt must not contain cnf"))
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return VerifiedRequest{}, assertion, newError(ErrorInvalidJWT, err)
	}
	if err := validateHTTPSIdentifier(claims.Issuer); err != nil {
		return VerifiedRequest{}, assertion, newError(ErrorInvalidJWT, fmt.Errorf("aauth: self-jwt issuer: %w", err))
	}
	if err := ValidateDiscoveryName(claims.DiscoveryDocument); err != nil {
		return VerifiedRequest{}, assertion, newError(ErrorInvalidJWT, errors.New("aauth: self-jwt discovery document is invalid"))
	}
	if claims.ExpiresAt == nil {
		return VerifiedRequest{}, assertion, newError(ErrorInvalidJWT, errors.New("aauth: self-jwt requires exp"))
	}
	expiresAt := time.Unix(*claims.ExpiresAt, 0).UTC()
	if !expiresAt.After(prepared.verifiedAt) {
		return VerifiedRequest{}, assertion, newError(ErrorExpiredJWT, errors.New("aauth: self-jwt has expired"))
	}

	key, err := resolver.ResolveKey(ctx, claims.Issuer, claims.DiscoveryDocument, header.KeyID)
	if err != nil {
		return VerifiedRequest{}, assertion, NormalizeError(NormalizeResolutionError(err), ErrorInvalidKey)
	}
	verifiedCompact, err := parsed.Verify(key)
	if err != nil {
		refresher, refreshable := resolver.(KeyRefresher)
		if !refreshable {
			return VerifiedRequest{}, assertion, newError(ErrorInvalidJWT, err)
		}
		key, err = refresher.RefreshKey(ctx, claims.Issuer, claims.DiscoveryDocument, header.KeyID)
		if err != nil {
			return VerifiedRequest{}, assertion, NormalizeError(NormalizeResolutionError(err), ErrorInvalidKey)
		}
		verifiedCompact, err = parsed.Verify(key)
		if err != nil {
			return VerifiedRequest{}, assertion, newError(ErrorInvalidJWT, err)
		}
	}
	verifiedPayload, err := verifiedCompact.Payload()
	if err != nil {
		return VerifiedRequest{}, assertion, newError(ErrorInvalidJWT, err)
	}
	proof, err := prepared.Verify(key)
	if err != nil {
		return VerifiedRequest{}, assertion, err
	}
	proof.signer = claims.Issuer
	assertion = SelfJWTAssertion{
		issuer:            claims.Issuer,
		discoveryDocument: claims.DiscoveryDocument,
		expiresAt:         expiresAt,
		compact:           compact,
		payload:           append([]byte(nil), verifiedPayload...),
	}
	return proof, assertion, nil
}
