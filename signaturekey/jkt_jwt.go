package signaturekey

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
	"gitlab.com/sidecat-dev/aauth-go/jose"
)

// JKTJWTTypeSHA256 is the mandatory SHA-256 self-issued key-delegation type.
const JKTJWTTypeSHA256 = "jkt-s256+jwt"

// JKTJWTDelegation is one verified durable-to-ephemeral key delegation.
// Compact preserves the exact signed assertion presented on the request.
type JKTJWTDelegation struct {
	issuer          string
	issuedAt        time.Time
	expiresAt       time.Time
	jti             string
	identityKey     jose.JWK
	confirmationKey jose.JWK
	compact         string
}

// Issuer returns the durable key's JWK Thumbprint URI.
func (delegation JKTJWTDelegation) Issuer() string { return delegation.issuer }

// IssuedAt returns the assertion's NumericDate issue time.
func (delegation JKTJWTDelegation) IssuedAt() time.Time { return delegation.issuedAt }

// ExpiresAt returns the assertion's NumericDate expiry.
func (delegation JKTJWTDelegation) ExpiresAt() time.Time { return delegation.expiresAt }

// JTI returns the assertion's optional replay identifier.
func (delegation JKTJWTDelegation) JTI() string { return delegation.jti }

// IdentityKey returns the durable public key that signed the assertion.
func (delegation JKTJWTDelegation) IdentityKey() jose.JWK { return delegation.identityKey }

// ConfirmationKey returns the delegated public HTTP proof key.
func (delegation JKTJWTDelegation) ConfirmationKey() jose.JWK { return delegation.confirmationKey }

// Compact returns the exact verified compact assertion.
func (delegation JKTJWTDelegation) Compact() string { return delegation.compact }

// MintJKTJWT creates the Ed25519 and SHA-256 profile of a self-issued
// Signature-Key delegation. The identity key signs only this assertion; the
// delegated confirmation key signs the accompanying HTTP request.
func MintJKTJWT(
	identityKey jose.SigningKey,
	confirmationKey jose.JWK,
	issuedAt time.Time,
	expiresAt time.Time,
	jti string,
) (string, error) {
	if identityKey.ID() == "" {
		return "", errors.New("aauth: jkt-jwt identity key is required")
	}
	identity := identityKey.PublicJWK()
	if _, err := identity.PublicKey(); err != nil {
		return "", fmt.Errorf("aauth: jkt-jwt identity key: %w", err)
	}
	if _, err := confirmationKey.PublicKey(); err != nil {
		return "", fmt.Errorf("aauth: jkt-jwt confirmation key: %w", err)
	}
	issuedAt = issuedAt.UTC().Truncate(time.Second)
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	if issuedAt.IsZero() {
		return "", errors.New("aauth: jkt-jwt issued time is required")
	}
	if !expiresAt.After(issuedAt) {
		return "", errors.New("aauth: jkt-jwt expiry must be after its issued time")
	}
	issuer, err := identity.ThumbprintURI()
	if err != nil {
		return "", err
	}
	protected, err := json.Marshal(struct {
		Algorithm string   `json:"alg"`
		Type      string   `json:"typ"`
		JWK       jose.JWK `json:"jwk"`
	}{
		Algorithm: jose.Ed25519Algorithm,
		Type:      JKTJWTTypeSHA256,
		JWK:       identity,
	})
	if err != nil {
		return "", fmt.Errorf("aauth: marshal jkt-jwt header: %w", err)
	}
	confirmationCopy := confirmationKey
	payload, err := json.Marshal(struct {
		Issuer       string            `json:"iss"`
		IssuedAt     int64             `json:"iat"`
		ExpiresAt    int64             `json:"exp"`
		Confirmation aauthConfirmation `json:"cnf"`
		JTI          string            `json:"jti,omitempty"`
	}{
		Issuer:       issuer,
		IssuedAt:     issuedAt.Unix(),
		ExpiresAt:    expiresAt.Unix(),
		Confirmation: aauthConfirmation{JWK: &confirmationCopy},
		JTI:          jti,
	})
	if err != nil {
		return "", fmt.Errorf("aauth: marshal jkt-jwt payload: %w", err)
	}
	return jose.SignCompactProtected(identityKey, protected, payload)
}

type aauthConfirmation struct {
	JWK *jose.JWK `json:"jwk"`
}

type jktJWTClaims struct {
	Issuer       string             `json:"iss"`
	IssuedAt     *int64             `json:"iat"`
	ExpiresAt    *int64             `json:"exp"`
	Confirmation *aauthConfirmation `json:"cnf"`
	JTI          string             `json:"jti,omitempty"`
}

// VerifyJKTJWT verifies the self-issued delegation and then the HTTP Message
// Signature with its exact delegated confirmation key.
func (prepared PreparedRequest) VerifyJKTJWT() (VerifiedRequest, JKTJWTDelegation, error) {
	var delegation JKTJWTDelegation
	compact, ok := prepared.credential.JKTJWT()
	if !ok {
		return VerifiedRequest{}, delegation, errors.New("aauth: prepared request does not use jkt-jwt")
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return VerifiedRequest{}, delegation, newError(ErrorInvalidJWT, err)
	}
	var protected struct {
		Algorithm string    `json:"alg"`
		Type      string    `json:"typ"`
		JWK       *jose.JWK `json:"jwk"`
	}
	if err := json.Unmarshal(parsed.Protected(), &protected); err != nil {
		return VerifiedRequest{}, delegation, newError(ErrorInvalidJWT, err)
	}
	if protected.Type != JKTJWTTypeSHA256 {
		return VerifiedRequest{}, delegation, newError(
			ErrorInvalidJWT,
			fmt.Errorf("aauth: unsupported jkt-jwt type %q", protected.Type),
		)
	}
	if protected.Algorithm != jose.Ed25519Algorithm {
		return VerifiedRequest{}, delegation, &Error{
			Code:               ErrorUnsupportedAlgorithm,
			AcceptedAlgorithms: []string{jose.Ed25519Algorithm},
			Cause:              fmt.Errorf("aauth: unsupported jkt-jwt algorithm %q", protected.Algorithm),
		}
	}
	if protected.JWK == nil {
		return VerifiedRequest{}, delegation, newError(ErrorInvalidJWT, errors.New("aauth: jkt-jwt requires protected jwk"))
	}
	identityKey := *protected.JWK
	if _, err := identityKey.PublicKey(); err != nil {
		return VerifiedRequest{}, delegation, NormalizeError(classifyResolvedJWKError(err), ErrorInvalidKey)
	}
	payload := parsed.Payload()
	var claims jktJWTClaims
	if err := jsonstrict.RejectCaseVariants(payload, &claims); err != nil {
		return VerifiedRequest{}, delegation, newError(ErrorInvalidJWT, err)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return VerifiedRequest{}, delegation, newError(ErrorInvalidJWT, err)
	}
	expectedIssuer, err := identityKey.ThumbprintURI()
	if err != nil {
		return VerifiedRequest{}, delegation, newError(ErrorInvalidJWT, err)
	}
	if claims.Issuer != expectedIssuer {
		return VerifiedRequest{}, delegation, newError(ErrorInvalidJWT, errors.New("aauth: jkt-jwt issuer does not match its identity key"))
	}
	if _, err := parsed.Verify(identityKey); err != nil {
		return VerifiedRequest{}, delegation, newError(ErrorInvalidJWT, err)
	}
	if claims.IssuedAt == nil || claims.ExpiresAt == nil {
		return VerifiedRequest{}, delegation, newError(ErrorInvalidJWT, errors.New("aauth: jkt-jwt requires iat, exp, and cnf.jwk"))
	}
	if claims.Confirmation == nil || claims.Confirmation.JWK == nil {
		return VerifiedRequest{}, delegation, newError(ErrorInvalidJWT, errors.New("aauth: jkt-jwt requires cnf.jwk"))
	}
	confirmationKey := *claims.Confirmation.JWK
	if _, err := confirmationKey.PublicKey(); err != nil {
		return VerifiedRequest{}, delegation, NormalizeError(classifyResolvedJWKError(err), ErrorInvalidKey)
	}
	issuedAt := time.Unix(*claims.IssuedAt, 0).UTC()
	expiresAt := time.Unix(*claims.ExpiresAt, 0).UTC()
	if !expiresAt.After(issuedAt) {
		return VerifiedRequest{}, delegation, newError(ErrorInvalidJWT, errors.New("aauth: jkt-jwt expiry is not after its issued time"))
	}
	if err := prepared.CheckIssuedAt(issuedAt); err != nil {
		return VerifiedRequest{}, delegation, err
	}
	if !expiresAt.After(prepared.verifiedAt) {
		return VerifiedRequest{}, delegation, newError(ErrorExpiredJWT, errors.New("aauth: jkt-jwt has expired"))
	}
	if prepared.credential.cacheRequested && claims.JTI == "" {
		return VerifiedRequest{}, delegation, newError(ErrorInvalidJWT, errors.New("aauth: cacheable jkt-jwt requires jti"))
	}
	proof, err := prepared.Verify(confirmationKey)
	if err != nil {
		return VerifiedRequest{}, delegation, err
	}
	proof.signer = claims.Issuer
	delegation = JKTJWTDelegation{
		issuer:          claims.Issuer,
		issuedAt:        issuedAt,
		expiresAt:       expiresAt,
		jti:             claims.JTI,
		identityKey:     identityKey,
		confirmationKey: confirmationKey,
		compact:         compact,
	}
	return proof, delegation, nil
}
