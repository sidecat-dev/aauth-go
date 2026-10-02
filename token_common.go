package aauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const (
	AgentTokenType    = "aa-agent+jwt"
	PersonTokenType   = "aa-person+jwt"
	ResourceTokenType = "aa-resource+jwt"
	AuthTokenType     = "aa-auth+jwt"

	AgentDiscoveryDocument    = "aauth-agent.json"
	ResourceDiscoveryDocument = "aauth-resource.json"
	PersonDiscoveryDocument   = "aauth-person.json"
	AccessDiscoveryDocument   = "aauth-access.json"
)

// TokenValidationCode identifies a stable compact-token failure class.
type TokenValidationCode string

const (
	TokenValidationExpired              TokenValidationCode = "expired"
	TokenValidationInvalidKey           TokenValidationCode = "invalid_key"
	TokenValidationUnsupportedAlgorithm TokenValidationCode = "unsupported_algorithm"
	TokenValidationNotYetValid          TokenValidationCode = "not_yet_valid"
)

// TokenValidationError preserves a validation cause for protocol adapters.
type TokenValidationError struct {
	Code  TokenValidationCode
	Cause error
}

func (failure *TokenValidationError) Error() string {
	if failure == nil || failure.Cause == nil {
		return "aauth: token validation failed"
	}
	return "aauth: token validation " + string(failure.Code) + ": " + failure.Cause.Error()
}

func (failure *TokenValidationError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

// SignatureKeyError maps token validation to the Signature-Key error registry.
func (failure *TokenValidationError) SignatureKeyError() *signaturekey.Error {
	code := signaturekey.ErrorInvalidJWT
	if failure != nil {
		switch failure.Code {
		case TokenValidationExpired:
			code = signaturekey.ErrorExpiredJWT
		case TokenValidationInvalidKey:
			code = signaturekey.ErrorInvalidKey
		case TokenValidationUnsupportedAlgorithm:
			return &signaturekey.Error{
				Code:               signaturekey.ErrorUnsupportedAlgorithm,
				AcceptedAlgorithms: []string{jose.Ed25519Algorithm},
				Cause:              failure,
			}
		}
	}
	return signaturekey.NewError(code, failure)
}

func tokenKeyValidationError(label string, err error) error {
	code := TokenValidationInvalidKey
	var unsupported interface{ UnsupportedAlgorithm() string }
	if errors.As(err, &unsupported) {
		code = TokenValidationUnsupportedAlgorithm
	}
	return &TokenValidationError{Code: code, Cause: fmt.Errorf("aauth: %s: %w", label, err)}
}

type unsupportedTokenAlgorithmError struct{ algorithm string }

func (failure *unsupportedTokenAlgorithmError) Error() string {
	return fmt.Sprintf("aauth: unsupported token algorithm %q", failure.algorithm)
}

func (failure *unsupportedTokenAlgorithmError) SignatureKeyError() *signaturekey.Error {
	return &signaturekey.Error{
		Code:               signaturekey.ErrorUnsupportedAlgorithm,
		AcceptedAlgorithms: []string{jose.Ed25519Algorithm},
		Cause:              failure,
	}
}

// UnsupportedTokenClaimError identifies a token member that this API cannot
// safely interpret. A companion-aware API may accept the same token only
// after validating that companion's complete claim set.
type UnsupportedTokenClaimError struct {
	TokenType string
	Claim     string
	Reason    string
}

func (failure *UnsupportedTokenClaimError) Error() string {
	if failure == nil {
		return "aauth: token contains an unsupported claim"
	}
	detail := fmt.Sprintf("aauth: %s contains unsupported %s claim", failure.TokenType, failure.Claim)
	if failure.Reason != "" {
		detail += ": " + failure.Reason
	}
	return detail
}

// Confirmation is the RFC 7800 confirmation claim used by AAuth.
type Confirmation struct {
	JWK jose.JWK `json:"jwk"`
}

func verifyCoreToken[T any](
	ctx context.Context,
	compact string,
	expectedType string,
	allowedDiscoveryDocuments []string,
	resolver signaturekey.KeyResolver,
	clock Clock,
	claims *T,
	locate func(T) (string, string),
	preflight func(map[string]json.RawMessage) error,
	validate func(T, time.Time) error,
) (T, error) {
	var zero T
	if resolver == nil {
		return zero, errors.New("aauth: key resolver is required")
	}
	if clock == nil {
		return zero, errors.New("aauth: clock is required")
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return zero, err
	}
	header := parsed.Header()
	if header.Type != expectedType {
		return zero, fmt.Errorf("aauth: token typ is %q, want %q", header.Type, expectedType)
	}
	payload := parsed.Payload()
	if err := jsonstrict.RejectCaseVariants(payload, claims); err != nil {
		return zero, fmt.Errorf("aauth: decode %s claims: %w", expectedType, err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return zero, fmt.Errorf("aauth: decode %s claims: %w", expectedType, err)
	}
	if preflight != nil {
		if err := preflight(members); err != nil {
			return zero, err
		}
	}
	if err := json.Unmarshal(payload, claims); err != nil {
		return zero, fmt.Errorf("aauth: decode %s claims: %w", expectedType, err)
	}
	if receiver, ok := any(claims).(interface {
		setTokenMembers(map[string]json.RawMessage)
	}); ok {
		receiver.setTokenMembers(members)
	}
	issuer, discoveryDocument := locate(*claims)
	if !slices.Contains(allowedDiscoveryDocuments, discoveryDocument) {
		return zero, fmt.Errorf("aauth: token dwk is %q", discoveryDocument)
	}
	if _, err := verifyResolvedTokenKey(ctx, parsed, issuer, discoveryDocument, resolver); err != nil {
		return zero, err
	}
	now := clock.Now().UTC()
	if err := validate(*claims, now); err != nil {
		return zero, err
	}
	return *claims, nil
}

func rejectClaims(tokenType string, members map[string]json.RawMessage, reason string, names ...string) error {
	for _, name := range names {
		if _, present := members[name]; present {
			return &UnsupportedTokenClaimError{TokenType: tokenType, Claim: name, Reason: reason}
		}
	}
	return nil
}

func validateOptionalStringClaim(tokenType string, members map[string]json.RawMessage, name string, allowEmpty bool) error {
	raw, present := members[name]
	if !present {
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("aauth: %s %s claim must be a string, not null", tokenType, name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("aauth: %s %s claim must be a string: %w", tokenType, name, err)
	}
	if !allowEmpty && value == "" {
		return fmt.Errorf("aauth: %s contains an empty %s claim; omit it when unused", tokenType, name)
	}
	return nil
}

func rejectUnsupportedAuthorizationClaims(tokenType string, members map[string]json.RawMessage) error {
	return rejectClaims(
		tokenType,
		members,
		"this Core build does not validate that companion specification",
		"r3_uri", "r3_s256", "r3_granted", "r3_per_call", "budget", "budget_consumed",
	)
}

func mintToken(key jose.SigningKey, tokenType string, claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("aauth: marshal token claims: %w", err)
	}
	return mintTokenPayload(key, tokenType, payload)
}

func mintTokenPayload(key jose.SigningKey, tokenType string, payload []byte) (string, error) {
	return jose.SignCompact(key, jose.Header{
		Algorithm: jose.Ed25519Algorithm,
		Type:      tokenType,
		KeyID:     key.ID(),
	}, payload)
}

func marshalTokenClaims(
	label string,
	claims any,
	additional map[string]json.RawMessage,
	known map[string]struct{},
) ([]byte, map[string]json.RawMessage, error) {
	base, err := json.Marshal(claims)
	if err != nil {
		return nil, nil, fmt.Errorf("aauth: marshal %s claims: %w", label, err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(base, &members); err != nil {
		return nil, nil, fmt.Errorf("aauth: decode %s claims: %w", label, err)
	}
	if len(additional) == 0 {
		return base, members, nil
	}
	for name, value := range additional {
		if name == "" {
			return nil, nil, fmt.Errorf("aauth: additional %s claim name is required", label)
		}
		for reserved := range known {
			if strings.EqualFold(name, reserved) {
				return nil, nil, fmt.Errorf("aauth: additional %s claim %q conflicts with %q", label, name, reserved)
			}
		}
		if !json.Valid(value) {
			return nil, nil, fmt.Errorf("aauth: additional %s claim %q is invalid JSON", label, name)
		}
		if err := jsonstrict.RejectAmbiguousNames(value); err != nil {
			return nil, nil, fmt.Errorf("aauth: additional %s claim %q is ambiguous JSON: %w", label, name, err)
		}
		members[name] = append(json.RawMessage(nil), value...)
	}
	payload, err := json.Marshal(members)
	if err != nil {
		return nil, nil, fmt.Errorf("aauth: marshal %s claims: %w", label, err)
	}
	return payload, members, nil
}

func additionalTokenClaims(
	members map[string]json.RawMessage,
	known map[string]struct{},
) map[string]json.RawMessage {
	additional := make(map[string]json.RawMessage)
	for name, value := range members {
		if _, reserved := known[name]; reserved {
			continue
		}
		additional[name] = append(json.RawMessage(nil), value...)
	}
	if len(additional) == 0 {
		return nil
	}
	return additional
}

func verifyResolvedTokenKey(
	ctx context.Context,
	parsed jose.ParsedCompact,
	issuer string,
	discoveryDocument string,
	resolver signaturekey.KeyResolver,
) (jose.VerifiedCompact, error) {
	header := parsed.Header()
	if header.Algorithm == "none" {
		return jose.VerifiedCompact{}, errors.New("aauth: alg none is forbidden")
	}
	if header.Algorithm != jose.Ed25519Algorithm {
		return jose.VerifiedCompact{}, &TokenValidationError{
			Code:  TokenValidationUnsupportedAlgorithm,
			Cause: &unsupportedTokenAlgorithmError{algorithm: header.Algorithm},
		}
	}
	if header.KeyID == "" {
		return jose.VerifiedCompact{}, errors.New("aauth: token kid is required")
	}
	if err := ValidateServerIdentifier(issuer); err != nil {
		return jose.VerifiedCompact{}, fmt.Errorf("aauth: token issuer: %w", err)
	}
	key, err := resolver.ResolveKey(ctx, issuer, discoveryDocument, header.KeyID)
	if err != nil {
		return jose.VerifiedCompact{}, signaturekey.NormalizeResolutionError(err)
	}
	if err := validateResolvedTokenKey(key, header.KeyID); err != nil {
		return jose.VerifiedCompact{}, err
	}
	verified, err := parsed.Verify(key)
	if err == nil {
		return verified, nil
	}
	if refresher, ok := resolver.(signaturekey.KeyRefresher); ok {
		refreshed, refreshErr := refresher.RefreshKey(ctx, issuer, discoveryDocument, header.KeyID)
		if refreshErr == nil {
			if err := validateResolvedTokenKey(refreshed, header.KeyID); err != nil {
				return jose.VerifiedCompact{}, err
			}
			if refreshedVerified, verifyErr := parsed.Verify(refreshed); verifyErr == nil {
				return refreshedVerified, nil
			}
		} else {
			normalized := signaturekey.NormalizeResolutionError(refreshErr)
			var resolutionError *signaturekey.ResolutionError
			if errors.As(normalized, &resolutionError) {
				return jose.VerifiedCompact{}, normalized
			}
		}
	}
	return jose.VerifiedCompact{}, errors.New("aauth: token signature is invalid")
}

func validateResolvedTokenKey(key jose.JWK, expectedKeyID string) error {
	if key.Kid != "" && key.Kid != expectedKeyID {
		return &TokenValidationError{
			Code:  TokenValidationInvalidKey,
			Cause: fmt.Errorf("aauth: resolved token key id %q does not match %q", key.Kid, expectedKeyID),
		}
	}
	if _, err := key.PublicKey(); err != nil {
		return tokenKeyValidationError("resolved token key", err)
	}
	return nil
}

func validateTimes(issuedAt, expiresAt, notBefore int64, now time.Time) error {
	if issuedAt <= 0 || expiresAt <= 0 || expiresAt <= issuedAt {
		return errors.New("iat and exp must define a positive lifetime")
	}
	if notBefore < 0 || notBefore >= expiresAt {
		return errors.New("nbf must be earlier than exp")
	}
	if now.IsZero() {
		return nil
	}
	if expiresAt <= now.Unix() {
		return &TokenValidationError{Code: TokenValidationExpired, Cause: errors.New("token is expired")}
	}
	if notBefore > now.Unix() {
		return &TokenValidationError{Code: TokenValidationNotYetValid, Cause: errors.New("token is not yet valid")}
	}
	return nil
}

func validateS256(name, value string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return fmt.Errorf("aauth: %s must be an unpadded base64url SHA-256 digest", name)
	}
	return nil
}
