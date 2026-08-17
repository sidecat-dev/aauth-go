package aauth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

var rawURL = base64.RawURLEncoding

// Ed25519Algorithm is the fully specified JOSE algorithm identifier required
// by the current AAuth and Signature-Key profiles. The polymorphic Ed25519
// identifier is deliberately not accepted.
const Ed25519Algorithm = "Ed25519"

type unsupportedJWKAlgorithmError struct{ algorithm string }

func (err *unsupportedJWKAlgorithmError) Error() string {
	return fmt.Sprintf("aauth: unsupported JWK algorithm %q", err.algorithm)
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
	decoded, err := rawURL.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("aauth: decode JWK x: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("aauth: Ed25519 JWK x has %d bytes, want %d", len(decoded), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
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

// SigningKey holds a private protocol signing key. Its concrete signer remains
// private so callers can later provide other crypto.Signer implementations
// without exposing private key bytes through protocol values.
type SigningKey struct {
	id     string
	signer crypto.Signer
	public JWK
}

// NewSigningKey constructs the mandatory Ed25519 profile around a
// caller-custodied crypto.Signer. The signer may keep its private material in
// an operating-system key store, HSM, encrypted host store, or another
// protected boundary; AAuth retains only the signing capability and public
// key.
func NewSigningKey(id string, signer crypto.Signer) (SigningKey, error) {
	if id == "" {
		return SigningKey{}, errors.New("aauth: signing key id is required")
	}
	if signer == nil {
		return SigningKey{}, errors.New("aauth: signing key signer is required")
	}
	publicKey, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return SigningKey{}, errors.New("aauth: signer did not expose an Ed25519 public key")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return SigningKey{}, fmt.Errorf(
			"aauth: Ed25519 public key has %d bytes, want %d",
			len(publicKey),
			ed25519.PublicKeySize,
		)
	}
	return SigningKey{
		id:     id,
		signer: signer,
		public: JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   rawURL.EncodeToString(append(ed25519.PublicKey(nil), publicKey...)),
			Alg: Ed25519Algorithm,
			Kid: id,
			Use: "sig",
		},
	}, nil
}

// NewEd25519SigningKey constructs the mandatory Ed25519 profile from an
// in-memory private key. Hosts with protected key custody should prefer
// NewSigningKey.
func NewEd25519SigningKey(id string, privateKey ed25519.PrivateKey) (SigningKey, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SigningKey{}, fmt.Errorf("aauth: Ed25519 private key has %d bytes, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	return NewSigningKey(id, privateKey)
}

// ID returns the public key identifier used in JWT headers and JWKS lookup.
func (key SigningKey) ID() string {
	return key.id
}

// PublicJWK returns a copy of the public confirmation key.
func (key SigningKey) PublicJWK() JWK {
	return key.public
}

func (key SigningKey) sign(message []byte) ([]byte, error) {
	if key.signer == nil {
		return nil, errors.New("aauth: signing key is not initialized")
	}
	signature, err := key.signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("aauth: sign: %w", err)
	}
	return signature, nil
}

// KeyResolver resolves an issuer key after the token's issuer, discovery
// document, and key id have been structurally validated. Implementations
// should return KeyResolutionError for every failed lookup. The library treats
// an untyped resolver error conservatively as KeyResolutionUnavailable rather
// than misreporting an operational failure as invalid client authentication.
type KeyResolver interface {
	ResolveKey(ctx context.Context, issuer, discoveryDocument, keyID string) (JWK, error)
}

// KeyResolutionCode distinguishes protocol-visible key failures from local
// resolution failures. Callers must not infer these classes from diagnostic
// strings returned by a resolver.
type KeyResolutionCode string

const (
	// KeyResolutionUnknown means a successfully parsed, trusted key set did
	// not contain the requested key identifier.
	KeyResolutionUnknown KeyResolutionCode = "unknown"
	// KeyResolutionInvalid means the reference, trust relationship, metadata,
	// key set, or resolved key material was invalid.
	KeyResolutionInvalid KeyResolutionCode = "invalid"
	// KeyResolutionDenied means local egress admission refused discovery.
	KeyResolutionDenied KeyResolutionCode = "denied"
	// KeyResolutionUnavailable means required discovery could not currently
	// complete because of cancellation, transport, or remote-service failure.
	KeyResolutionUnavailable KeyResolutionCode = "unavailable"
	// KeyResolutionIssuerMissing means the fetched metadata document omitted
	// the issuer member required to bind it to its discovery identity.
	KeyResolutionIssuerMissing KeyResolutionCode = "issuer_missing"
	// KeyResolutionIssuerMismatch means the fetched metadata issuer did not
	// byte-for-byte match the discovery identity.
	KeyResolutionIssuerMismatch KeyResolutionCode = "issuer_mismatch"
	// KeyResolutionUnsupportedAlgorithm means the exact requested JWK names a
	// missing, polymorphic, or otherwise unsupported signing algorithm.
	KeyResolutionUnsupportedAlgorithm KeyResolutionCode = "unsupported_algorithm"
)

// KeyResolutionError preserves resolver diagnostics while exposing a stable
// classification to protocol adapters. Diagnostics are not safe to copy into
// remote responses.
type KeyResolutionError struct {
	Code  KeyResolutionCode
	Cause error
}

func (err *KeyResolutionError) Error() string {
	if err == nil || err.Cause == nil {
		return "aauth: key resolution failed"
	}
	return "aauth: key resolution " + string(err.Code) + ": " + err.Cause.Error()
}

func (err *KeyResolutionError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

func keyResolutionError(code KeyResolutionCode, cause error) error {
	return &KeyResolutionError{Code: code, Cause: cause}
}

func normalizeKeyResolutionError(err error) error {
	if err == nil {
		return nil
	}
	var resolutionError *KeyResolutionError
	if errors.As(err, &resolutionError) {
		return err
	}
	return keyResolutionError(KeyResolutionUnavailable, err)
}

// KeyRefresher is implemented by resolvers that can deliberately re-check an
// issuer after a same-kid signature failure.
type KeyRefresher interface {
	RefreshKey(ctx context.Context, issuer, discoveryDocument, keyID string) (JWK, error)
}

// StaticKeyResolver is an explicit in-memory trust source useful for embedded
// deployments, deterministic qualification, and callers that own discovery.
type StaticKeyResolver map[string]map[string]JWK

func (resolver StaticKeyResolver) ResolveKey(_ context.Context, issuer, _ string, keyID string) (JWK, error) {
	issuerKeys, ok := resolver[issuer]
	if !ok {
		return JWK{}, keyResolutionError(
			KeyResolutionInvalid,
			fmt.Errorf("aauth: issuer %q is not trusted", issuer),
		)
	}
	key, ok := issuerKeys[keyID]
	if !ok {
		return JWK{}, keyResolutionError(
			KeyResolutionUnknown,
			fmt.Errorf("aauth: issuer %q has no key %q", issuer, keyID),
		)
	}
	if key.Kid != "" && key.Kid != keyID {
		return JWK{}, keyResolutionError(
			KeyResolutionInvalid,
			fmt.Errorf("aauth: resolved key id %q does not match requested %q", key.Kid, keyID),
		)
	}
	if _, err := key.PublicKey(); err != nil {
		return JWK{}, classifyResolvedJWKError(err)
	}
	return key, nil
}

func classifyResolvedJWKError(err error) error {
	var unsupportedAlgorithm *unsupportedJWKAlgorithmError
	if errors.As(err, &unsupportedAlgorithm) {
		return keyResolutionError(KeyResolutionUnsupportedAlgorithm, err)
	}
	return keyResolutionError(KeyResolutionInvalid, err)
}
