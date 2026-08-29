package signaturekey

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

const JKTJWTTypeSHA256 = "jkt-s256+jwt"

// JKTJWTClaims are the mandatory claims of a SHA-256 JWK Thumbprint JWT.
type JKTJWTClaims struct {
	Issuer       string       `json:"iss"`
	IssuedAt     int64        `json:"iat"`
	ExpiresAt    int64        `json:"exp"`
	Confirmation Confirmation `json:"cnf"`
}

// Confirmation carries the delegated HTTP request key.
type Confirmation struct {
	JWK jose.JWK `json:"jwk"`
}

// VerifiedJKTJWT is the trusted durable-to-ephemeral key delegation carried
// by the jkt-jwt Signature-Key scheme.
type VerifiedJKTJWT struct {
	Issuer       string
	IdentityKey  jose.JWK
	Confirmation jose.JWK
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Compact      string
}

type jktJWTHeader struct {
	Algorithm string   `json:"alg"`
	Type      string   `json:"typ"`
	JWK       jose.JWK `json:"jwk"`
}

// MintJKTJWT creates the mandatory SHA-256/Ed25519 self-issued delegation
// from a durable identity key to an HTTP request-signing key.
func MintJKTJWT(
	identityKey jose.SigningKey,
	confirmationKey jose.JWK,
	now time.Time,
	lifetime time.Duration,
) (string, error) {
	if identityKey.ID() == "" {
		return "", errors.New("aauth: jkt-jwt identity key is required")
	}
	if _, err := confirmationKey.PublicKey(); err != nil {
		return "", fmt.Errorf("aauth: jkt-jwt cnf.jwk: %w", err)
	}
	if lifetime <= 0 || now.Add(lifetime).Unix() <= now.Unix() {
		return "", errors.New("aauth: jkt-jwt lifetime must be positive")
	}
	identityJWK := identityKey.PublicJWK()
	issuer, err := identityJWK.ThumbprintURI()
	if err != nil {
		return "", fmt.Errorf("aauth: jkt-jwt identity key: %w", err)
	}
	headerBytes, err := json.Marshal(jktJWTHeader{
		Algorithm: jose.Ed25519Algorithm,
		Type:      JKTJWTTypeSHA256,
		JWK:       identityJWK,
	})
	if err != nil {
		return "", fmt.Errorf("aauth: marshal jkt-jwt header: %w", err)
	}
	claimsBytes, err := json.Marshal(JKTJWTClaims{
		Issuer:       issuer,
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(lifetime).Unix(),
		Confirmation: Confirmation{JWK: confirmationKey},
	})
	if err != nil {
		return "", fmt.Errorf("aauth: marshal jkt-jwt claims: %w", err)
	}
	return jose.SignCompactProtected(identityKey, headerBytes, claimsBytes)
}

// VerifyJKTJWT verifies the self-issued durable identity, protected header,
// time claims, and delegated request-signing key.
func VerifyJKTJWT(compact string, clock Clock) (VerifiedJKTJWT, error) {
	var verified VerifiedJKTJWT
	if clock == nil {
		return verified, errors.New("aauth: clock is required")
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		return verified, fmt.Errorf("aauth: jkt-jwt: %w", err)
	}
	headerBytes := parsed.Protected()
	var header jktJWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return verified, fmt.Errorf("aauth: parse jkt-jwt header: %w", err)
	}
	if header.Type != JKTJWTTypeSHA256 {
		return verified, fmt.Errorf("aauth: jkt-jwt typ is %q, want %q", header.Type, JKTJWTTypeSHA256)
	}
	if header.Algorithm == "none" {
		return verified, errors.New("aauth: jkt-jwt alg none is forbidden")
	}
	if header.Algorithm != jose.Ed25519Algorithm {
		return verified, &Error{
			Code:               ErrorUnsupportedAlgorithm,
			AcceptedAlgorithms: []string{jose.Ed25519Algorithm},
			Cause:              fmt.Errorf("aauth: unsupported token algorithm %q", header.Algorithm),
		}
	}
	if _, err := header.JWK.PublicKey(); err != nil {
		return verified, &Error{Code: ErrorInvalidKey, Cause: fmt.Errorf("aauth: jkt-jwt header jwk: %w", err)}
	}
	claimsBytes := parsed.Payload()
	var claims JKTJWTClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return verified, fmt.Errorf("aauth: parse jkt-jwt claims: %w", err)
	}
	expectedIssuer, err := header.JWK.ThumbprintURI()
	if err != nil {
		return verified, fmt.Errorf("aauth: jkt-jwt identity thumbprint: %w", err)
	}
	if claims.Issuer != expectedIssuer {
		return verified, errors.New("aauth: jkt-jwt issuer does not match the header jwk")
	}
	if err := validateJKTJWTTimes(claims.IssuedAt, claims.ExpiresAt, clock.Now()); err != nil {
		return verified, fmt.Errorf("aauth: jkt-jwt: %w", err)
	}
	if _, err := claims.Confirmation.JWK.PublicKey(); err != nil {
		return verified, &Error{Code: ErrorInvalidKey, Cause: fmt.Errorf("aauth: jkt-jwt cnf.jwk: %w", err)}
	}
	if _, err := parsed.Verify(header.JWK); err != nil {
		return verified, err
	}
	return VerifiedJKTJWT{
		Issuer:       claims.Issuer,
		IdentityKey:  header.JWK,
		Confirmation: claims.Confirmation.JWK,
		IssuedAt:     time.Unix(claims.IssuedAt, 0),
		ExpiresAt:    time.Unix(claims.ExpiresAt, 0),
		Compact:      compact,
	}, nil
}

func validateJKTJWTTimes(issuedAt, expiresAt int64, now time.Time) error {
	if issuedAt <= 0 || expiresAt <= issuedAt {
		return errors.New("token iat and exp must define a positive lifetime")
	}
	if issuedAt > now.Unix() {
		return errors.New("iat is in the future")
	}
	if expiresAt <= now.Unix() {
		return &Error{Code: ErrorExpiredJWT, Cause: errors.New("token is expired")}
	}
	return nil
}
