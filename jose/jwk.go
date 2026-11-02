// Package jose implements the bounded JOSE profile used by AAuth.
//
// Compact JWS uses the fully specified Ed25519 or ES256 algorithm, the two
// AAuth names for its tokens and keys (TokenAlgorithms). Public JWKs
// additionally cover the ES384, RS256, and PS256 keys that HTTP Signature-Key
// request proofs may use.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

var rawURL = base64.RawURLEncoding.Strict()

// Ed25519Algorithm is the fully specified JOSE algorithm identifier required
// by the current AAuth and Signature-Key profiles. The polymorphic EdDSA
// identifier is deliberately not accepted.
const Ed25519Algorithm = "Ed25519"

// Fully specified JOSE algorithm identifiers that a Signature-Key public key
// may carry in addition to Ed25519. ES256 and ES384 are ECDSA on P-256 and
// P-384. RS256 is RSASSA-PKCS1-v1_5 and PS256 is RSASSA-PSS, each with
// SHA-256.
const (
	ES256Algorithm = "ES256"
	ES384Algorithm = "ES384"
	RS256Algorithm = "RS256"
	PS256Algorithm = "PS256"
)

// SignatureAlgorithms returns, in preference order, the algorithms whose
// public keys SignaturePublicKey accepts.
func SignatureAlgorithms() []string {
	return []string{Ed25519Algorithm, ES256Algorithm, ES384Algorithm, RS256Algorithm, PS256Algorithm}
}

// TokenAlgorithms returns, in preference order, the algorithms of the AAuth
// token profile: Ed25519, which every party must support, and ES256, which
// every party should support and which suits ECDSA P-256 keys held in
// hardware (AAuth Protocol, Signature Algorithms). Compact JWS, the keys that
// sign tokens and assertions, and the confirmation keys tokens carry use
// these. PublicKey accepts exactly these.
func TokenAlgorithms() []string {
	return []string{Ed25519Algorithm, ES256Algorithm}
}

// IsTokenAlgorithm reports whether algorithm is one of TokenAlgorithms.
func IsTokenAlgorithm(algorithm string) bool {
	return algorithm == Ed25519Algorithm || algorithm == ES256Algorithm
}

// signatureKeyTypes maps each supported algorithm to the only key type that
// can carry it.
var signatureKeyTypes = map[string]string{
	Ed25519Algorithm: "OKP",
	ES256Algorithm:   "EC",
	ES384Algorithm:   "EC",
	RS256Algorithm:   "RSA",
	PS256Algorithm:   "RSA",
}

const (
	minimumRSAModulusBytes = 2048 / 8
	maximumRSAModulusBytes = 8192 / 8
)

type unsupportedJWKAlgorithmError struct {
	algorithm string
	keyType   string
}

func (err *unsupportedJWKAlgorithmError) Error() string {
	if err.keyType != "" {
		return fmt.Sprintf("aauth: unsupported JWK key type %q", err.keyType)
	}
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
// claims, key sets, and Signature-Key members. Ed25519 is the mandatory
// implementation profile and ES256 the recommended second; Y, N, and E carry
// EC and RSA public keys.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
}

// UnmarshalJSON rejects private and secret key material before decoding the
// bounded public JWK representation.
func (key *JWK) UnmarshalJSON(value []byte) error {
	if key == nil {
		return errors.New("aauth: JWK destination is required")
	}
	if err := jsonstrict.RejectAmbiguousNames(value); err != nil {
		return err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(value, &members); err != nil {
		return err
	}
	for name := range members {
		if IsPrivateJWKMember(name) {
			return fmt.Errorf("aauth: private JWK member %q is not permitted", name)
		}
	}
	type publicJWK JWK
	var decoded publicJWK
	if err := jsonstrict.RejectCaseVariants(value, &decoded); err != nil {
		return err
	}
	if err := json.Unmarshal(value, &decoded); err != nil {
		return err
	}
	*key = JWK(decoded)
	return nil
}

// IsPrivateJWKMember reports whether name, compared case-insensitively, is a
// private or secret JWK member: d, k, p, q, dp, dq, qi, or oth.
func IsPrivateJWKMember(name string) bool {
	switch strings.ToLower(name) {
	case "d", "k", "p", "q", "dp", "dq", "qi", "oth":
		return true
	}
	return false
}

// PublicKey validates and decodes the JWK under the AAuth token profile used
// by token-signing and confirmation keys: an ed25519.PublicKey for Ed25519 or
// an *ecdsa.PublicKey on P-256 for ES256 (TokenAlgorithms). Any other
// algorithm is unsupported here; SignaturePublicKey accepts the wider
// Signature-Key set.
func (key JWK) PublicKey() (crypto.PublicKey, error) {
	if !IsTokenAlgorithm(key.Alg) {
		return nil, &unsupportedJWKAlgorithmError{algorithm: key.Alg}
	}
	return key.SignaturePublicKey()
}

// SignaturePublicKey validates the JWK as a Signature-Key public key and
// decodes it for its fully specified alg: an ed25519.PublicKey for Ed25519,
// an *ecdsa.PublicKey on P-256 or P-384 for ES256 or ES384, and an
// *rsa.PublicKey for RS256 or PS256.
//
// The alg member alone selects the algorithm. An absent, polymorphic,
// symmetric, or unimplemented alg, and an unimplemented kty such as oct or
// AKP, is an unsupported algorithm. A kty or crv that disagrees with alg,
// members of another key type, and malformed or non-canonical key bytes are
// invalid keys. An RSA modulus has 2048 to 8192 bits and its odd public
// exponent lies between 3 and 2^31-1, both minimally encoded.
func (key JWK) SignaturePublicKey() (crypto.PublicKey, error) {
	switch key.Alg {
	case "", "none", "HS256", "HS384", "HS512":
		return nil, &unsupportedJWKAlgorithmError{algorithm: key.Alg}
	}
	switch key.Kty {
	case "OKP", "EC", "RSA":
	default:
		return nil, &unsupportedJWKAlgorithmError{algorithm: key.Alg, keyType: key.Kty}
	}
	keyType, supported := signatureKeyTypes[key.Alg]
	if !supported {
		return nil, &unsupportedJWKAlgorithmError{algorithm: key.Alg}
	}
	if keyType != key.Kty {
		return nil, fmt.Errorf("aauth: JWK key type %q is inconsistent with alg %q", key.Kty, key.Alg)
	}
	switch key.Alg {
	case Ed25519Algorithm:
		return key.ed25519PublicKey()
	case ES256Algorithm:
		return key.ecdsaPublicKey(elliptic.P256(), "P-256", 32)
	case ES384Algorithm:
		return key.ecdsaPublicKey(elliptic.P384(), "P-384", 48)
	default:
		return key.rsaPublicKey()
	}
}

func (key JWK) ed25519PublicKey() (ed25519.PublicKey, error) {
	if key.Crv != "Ed25519" {
		return nil, fmt.Errorf("aauth: unsupported JWK key type %q/%q", key.Kty, key.Crv)
	}
	if key.Y != "" || key.N != "" || key.E != "" {
		return nil, errors.New("aauth: OKP JWK carries members of another key type")
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

func (key JWK) ecdsaPublicKey(curve elliptic.Curve, curveName string, size int) (*ecdsa.PublicKey, error) {
	if key.Crv != curveName {
		return nil, fmt.Errorf("aauth: JWK curve %q is inconsistent with alg %q", key.Crv, key.Alg)
	}
	if key.N != "" || key.E != "" {
		return nil, errors.New("aauth: EC JWK carries members of another key type")
	}
	x, err := decodeRawURLCanonical(key.X)
	if err != nil {
		return nil, fmt.Errorf("aauth: decode JWK x: %w", err)
	}
	y, err := decodeRawURLCanonical(key.Y)
	if err != nil {
		return nil, fmt.Errorf("aauth: decode JWK y: %w", err)
	}
	if len(x) != size || len(y) != size {
		return nil, fmt.Errorf("aauth: %s JWK coordinates must each have %d bytes", curveName, size)
	}
	point := append(append([]byte{4}, x...), y...)
	publicKey, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, fmt.Errorf("aauth: %s JWK is not a point on the curve: %w", curveName, err)
	}
	return publicKey, nil
}

func (key JWK) rsaPublicKey() (*rsa.PublicKey, error) {
	if key.Crv != "" || key.X != "" || key.Y != "" {
		return nil, errors.New("aauth: RSA JWK carries members of another key type")
	}
	modulus, err := decodeUnsignedInteger(key.N)
	if err != nil {
		return nil, fmt.Errorf("aauth: decode JWK n: %w", err)
	}
	exponent, err := decodeUnsignedInteger(key.E)
	if err != nil {
		return nil, fmt.Errorf("aauth: decode JWK e: %w", err)
	}
	if len(modulus) < minimumRSAModulusBytes || len(modulus) > maximumRSAModulusBytes || modulus[len(modulus)-1]&1 == 0 {
		return nil, errors.New("aauth: RSA JWK modulus must be odd and have 2048 to 8192 bits")
	}
	if len(exponent) > 4 {
		return nil, errors.New("aauth: RSA JWK exponent is too large")
	}
	value := new(big.Int).SetBytes(exponent).Int64()
	if value < 3 || value > 1<<31-1 || value&1 == 0 {
		return nil, errors.New("aauth: RSA JWK exponent must be odd and between 3 and 2^31-1")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(value)}, nil
}

// decodeUnsignedInteger decodes an RFC 7518 Base64urlUInt, which uses the
// minimum number of octets.
func decodeUnsignedInteger(value string) ([]byte, error) {
	decoded, err := decodeRawURLCanonical(value)
	if err != nil {
		return nil, err
	}
	if len(decoded) == 0 || decoded[0] == 0 {
		return nil, errors.New("integer is not minimally encoded")
	}
	return decoded, nil
}

// SignatureSize returns the length of a JWS-form signature that this key
// verifies: 64 bytes for Ed25519 and ES256, 96 for ES384, and the modulus
// length for RS256 and PS256.
func (key JWK) SignatureSize() (int, error) {
	publicKey, err := key.SignaturePublicKey()
	if err != nil {
		return 0, err
	}
	switch publicKey := publicKey.(type) {
	case ed25519.PublicKey:
		return ed25519.SignatureSize, nil
	case *ecdsa.PublicKey:
		return 2 * ecdsaCoordinateSize(publicKey.Curve), nil
	case *rsa.PublicKey:
		return publicKey.Size(), nil
	}
	return 0, errors.New("aauth: unsupported JWK public key")
}

// VerifySignature verifies a JWS-form signature over exact message bytes
// with the operation the key's alg names. ES256 and ES384 signatures are the
// fixed-size concatenation R || S. PS256 uses a salt as long as the hash.
func (key JWK) VerifySignature(message, signature []byte) error {
	publicKey, err := key.SignaturePublicKey()
	if err != nil {
		return err
	}
	invalid := errors.New("aauth: signature is invalid")
	switch key.Alg {
	case Ed25519Algorithm:
		if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey.(ed25519.PublicKey), message, signature) {
			return invalid
		}
	case ES256Algorithm, ES384Algorithm:
		ecdsaKey := publicKey.(*ecdsa.PublicKey)
		size := ecdsaCoordinateSize(ecdsaKey.Curve)
		if len(signature) != 2*size {
			return invalid
		}
		encoded, err := asn1.Marshal(struct{ R, S *big.Int }{
			R: new(big.Int).SetBytes(signature[:size]),
			S: new(big.Int).SetBytes(signature[size:]),
		})
		if err != nil || !ecdsa.VerifyASN1(ecdsaKey, signatureDigest(key.Alg, message), encoded) {
			return invalid
		}
	case RS256Algorithm:
		if rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, signatureDigest(key.Alg, message), signature) != nil {
			return invalid
		}
	case PS256Algorithm:
		options := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
		if rsa.VerifyPSS(publicKey.(*rsa.PublicKey), crypto.SHA256, signatureDigest(key.Alg, message), signature, options) != nil {
			return invalid
		}
	default:
		return &unsupportedJWKAlgorithmError{algorithm: key.Alg}
	}
	return nil
}

func signatureDigest(algorithm string, message []byte) []byte {
	if algorithm == ES384Algorithm {
		digest := sha512.Sum384(message)
		return digest[:]
	}
	digest := sha256.Sum256(message)
	return digest[:]
}

func ecdsaCoordinateSize(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
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

// Thumbprint returns the RFC 7638 SHA-256 JWK thumbprint of any key that
// SignaturePublicKey accepts. It hashes the required members of the key
// type: crv, kty, and x for OKP; crv, kty, x, and y for EC; e, kty, and n for
// RSA.
func (key JWK) Thumbprint() (string, error) {
	if _, err := key.SignaturePublicKey(); err != nil {
		return "", err
	}
	var members any
	switch key.Kty {
	case "OKP":
		members = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}{Crv: key.Crv, Kty: key.Kty, X: key.X}
	case "EC":
		members = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{Crv: key.Crv, Kty: key.Kty, X: key.X, Y: key.Y}
	default:
		members = struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{E: key.E, Kty: key.Kty, N: key.N}
	}
	canonical, err := json.Marshal(members)
	if err != nil {
		return "", fmt.Errorf("aauth: marshal JWK thumbprint input: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return rawURL.EncodeToString(digest[:]), nil
}

// RFC7638Thumbprint returns the RFC 7638 SHA-256 thumbprint of a public key
// that may lack alg, such as the RFC 7638 and RFC 8037 example keys.
// Thumbprint validates a key as AAuth uses it, which requires alg. A key
// without alg is checked here under the algorithm its type and curve
// determine: Ed25519 for an Ed25519 OKP key, ES256 for P-256, ES384 for P-384
// and RS256 for RSA, whose padding does not change the key. For a key with
// alg the two methods agree.
func (key JWK) RFC7638Thumbprint() (string, error) {
	if key.Alg == "" {
		key.Alg = impliedSignatureAlgorithm(key.Kty, key.Crv)
	}
	return key.Thumbprint()
}

// impliedSignatureAlgorithm returns the one supported algorithm a key type and
// curve determine, or empty when they determine none.
func impliedSignatureAlgorithm(keyType, curve string) string {
	switch {
	case keyType == "OKP" && curve == "Ed25519":
		return Ed25519Algorithm
	case keyType == "EC" && curve == "P-256":
		return ES256Algorithm
	case keyType == "EC" && curve == "P-384":
		return ES384Algorithm
	case keyType == "RSA":
		return RS256Algorithm
	}
	return ""
}

// ThumbprintURI returns the SHA-256 JWK Thumbprint URI used by the jkt-jwt
// Signature-Key scheme and as the pseudonymous hwk signer identity.
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
