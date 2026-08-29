// Package jose implements the bounded Ed25519 JOSE profile used by AAuth.
package jose

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

var rawURL = base64.RawURLEncoding.Strict()

// Ed25519Algorithm is the fully specified JOSE algorithm identifier required
// by the current AAuth and Signature-Key profiles. The polymorphic EdDSA
// identifier is deliberately not accepted.
const Ed25519Algorithm = "Ed25519"

type unsupportedJWKAlgorithmError struct{ algorithm string }

func (err *unsupportedJWKAlgorithmError) Error() string {
	return fmt.Sprintf("aauth: unsupported JWK algorithm %q", err.algorithm)
}

// UnsupportedAlgorithm exposes the rejected name for structural error
// classification without making the implementation error type public.
func (err *unsupportedJWKAlgorithmError) UnsupportedAlgorithm() string {
	if err == nil {
		return ""
	}
	return err.algorithm
}

// JWK is the public JSON Web Key representation used by AAuth confirmation
// claims and key sets. Ed25519 is the mandatory implementation profile.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
}

// PublicKey validates and decodes the JWK.
func (key JWK) PublicKey() (crypto.PublicKey, error) {
	if key.Alg != Ed25519Algorithm {
		return nil, &unsupportedJWKAlgorithmError{algorithm: key.Alg}
	}
	if key.Kty != "OKP" || key.Crv != "Ed25519" {
		return nil, fmt.Errorf("aauth: unsupported JWK key type %q/%q", key.Kty, key.Crv)
	}
	decoded, err := decodeRawURLCanonical(key.X)
	if err != nil {
		return nil, fmt.Errorf("aauth: decode JWK x: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("aauth: Ed25519 JWK x has %d bytes, want %d", len(decoded), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

func decodeRawURLCanonical(value string) ([]byte, error) {
	decoded, err := rawURL.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if rawURL.EncodeToString(decoded) != value {
		return nil, errors.New("base64url value is not canonical")
	}
	return decoded, nil
}

// Thumbprint returns the RFC 7638 SHA-256 JWK thumbprint.
func (key JWK) Thumbprint() (string, error) {
	if _, err := key.PublicKey(); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
	}{
		Crv: key.Crv,
		Kty: key.Kty,
		X:   key.X,
	})
	if err != nil {
		return "", fmt.Errorf("aauth: marshal JWK thumbprint input: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return rawURL.EncodeToString(digest[:]), nil
}

// ThumbprintURI returns the SHA-256 JWK Thumbprint URI used by the jkt-jwt
// Signature-Key scheme.
func (key JWK) ThumbprintURI() (string, error) {
	thumbprint, err := key.Thumbprint()
	if err != nil {
		return "", err
	}
	return "urn:jkt:sha-256:" + thumbprint, nil
}

// Equal reports whether two JWKs identify the same public key.
func (key JWK) Equal(other JWK) bool {
	left, leftErr := key.Thumbprint()
	right, rightErr := other.Thumbprint()
	return leftErr == nil && rightErr == nil && left == right
}
