package aauth

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const JKTJWTTypeSHA256 = "jkt-s256+jwt"

// JKTJWTClaims are the mandatory claims of a SHA-256 JWK Thumbprint JWT.
type JKTJWTClaims struct {
	Issuer       string       `json:"iss"`
	IssuedAt     int64        `json:"iat"`
	ExpiresAt    int64        `json:"exp"`
	Confirmation Confirmation `json:"cnf"`
}

// VerifiedJKTJWT is the trusted durable-to-ephemeral key delegation carried
// by the jkt-jwt Signature-Key scheme.
type VerifiedJKTJWT struct {
	Issuer       string
	IdentityKey  JWK
	Confirmation JWK
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Compact      string
}

type jktJWTHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	JWK       JWK    `json:"jwk"`
}

// MintJKTJWT creates the mandatory SHA-256/Ed25519 self-issued delegation
// from a durable identity key to an HTTP request-signing key.
func MintJKTJWT(
	identityKey SigningKey,
	confirmationKey JWK,
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
		Algorithm: "EdDSA",
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
	signingInput := rawURL.EncodeToString(headerBytes) + "." + rawURL.EncodeToString(claimsBytes)
	signature, err := identityKey.sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + rawURL.EncodeToString(signature), nil
}

// VerifyJKTJWT verifies the self-issued durable identity, protected header,
// time claims, and delegated request-signing key.
func VerifyJKTJWT(compact string, clock Clock) (VerifiedJKTJWT, error) {
	var verified VerifiedJKTJWT
	if clock == nil {
		return verified, errors.New("aauth: clock is required")
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return verified, errors.New("aauth: jkt-jwt must be a three-part compact JWS")
	}
	headerBytes, err := rawURL.DecodeString(parts[0])
	if err != nil {
		return verified, fmt.Errorf("aauth: decode jkt-jwt header: %w", err)
	}
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
	if header.Algorithm != "EdDSA" {
		return verified, fmt.Errorf("aauth: unsupported jkt-jwt algorithm %q", header.Algorithm)
	}
	identityPublic, err := header.JWK.PublicKey()
	if err != nil {
		return verified, &TokenValidationError{
			Code:  TokenValidationInvalidKey,
			Cause: fmt.Errorf("aauth: jkt-jwt header jwk: %w", err),
		}
	}
	identityEd25519, ok := identityPublic.(ed25519.PublicKey)
	if !ok {
		return verified, errors.New("aauth: jkt-jwt identity key is not Ed25519")
	}

	claimsBytes, err := rawURL.DecodeString(parts[1])
	if err != nil {
		return verified, fmt.Errorf("aauth: decode jkt-jwt claims: %w", err)
	}
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
	if err := validateTimes(claims.IssuedAt, claims.ExpiresAt, clock.Now()); err != nil {
		return verified, fmt.Errorf("aauth: jkt-jwt: %w", err)
	}
	if _, err := claims.Confirmation.JWK.PublicKey(); err != nil {
		return verified, &TokenValidationError{
			Code:  TokenValidationInvalidKey,
			Cause: fmt.Errorf("aauth: jkt-jwt cnf.jwk: %w", err),
		}
	}
	signature, err := rawURL.DecodeString(parts[2])
	if err != nil {
		return verified, fmt.Errorf("aauth: decode jkt-jwt signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return verified, fmt.Errorf("aauth: Ed25519 jkt-jwt signature has %d bytes", len(signature))
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(identityEd25519, []byte(signingInput), signature) {
		return verified, errors.New("aauth: jkt-jwt signature is invalid")
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
