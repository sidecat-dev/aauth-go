package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// SigningKey holds a caller-provided protocol signer, its fully specified
// algorithm, and its public JWK. It never exposes private key material.
type SigningKey struct {
	id        string
	algorithm string
	signer    crypto.Signer
	publicKey crypto.PublicKey
	publicJWK JWK
}

// NewSigningKey constructs the mandatory Ed25519 profile around a
// caller-provided crypto.Signer.
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
	publicCopy := append(ed25519.PublicKey(nil), publicKey...)
	return SigningKey{
		id:        id,
		algorithm: Ed25519Algorithm,
		signer:    signer,
		publicKey: publicCopy,
		publicJWK: JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   rawURL.EncodeToString(publicCopy),
			Alg: Ed25519Algorithm,
			Kid: id,
			Use: "sig",
		},
	}, nil
}

// NewEd25519SigningKey constructs the mandatory Ed25519 profile from an
// in-memory private key. Hosts that keep keys behind a crypto.Signer should
// prefer NewSigningKey.
func NewEd25519SigningKey(id string, privateKey ed25519.PrivateKey) (SigningKey, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SigningKey{}, fmt.Errorf("aauth: Ed25519 private key has %d bytes, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	return NewSigningKey(id, privateKey)
}

// NewSigningKeyForAlgorithm constructs a signing key for one fully specified
// algorithm from SignatureAlgorithms around a caller-provided crypto.Signer.
// The signer's public key must match the algorithm: Ed25519 for Ed25519, an
// ECDSA key on P-256 for ES256 or on P-384 for ES384, and an RSA key of 2048
// to 8192 bits for RS256 or PS256. RSA keys need the explicit algorithm
// because the key alone names neither padding nor hash.
//
// AAuth tokens and the jkt-jwt and self-jwt assertions are signed with
// Ed25519 or ES256 (TokenAlgorithms). The other algorithms sign HTTP
// requests only, such as hwk proofs.
func NewSigningKeyForAlgorithm(id, algorithm string, signer crypto.Signer) (SigningKey, error) {
	if algorithm == Ed25519Algorithm {
		return NewSigningKey(id, signer)
	}
	if id == "" {
		return SigningKey{}, errors.New("aauth: signing key id is required")
	}
	if signer == nil {
		return SigningKey{}, errors.New("aauth: signing key signer is required")
	}
	publicJWK := JWK{Kty: signatureKeyTypes[algorithm], Alg: algorithm, Kid: id, Use: "sig"}
	switch algorithm {
	case ES256Algorithm, ES384Algorithm:
		publicKey, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok {
			return SigningKey{}, fmt.Errorf("aauth: %s signer did not expose an ECDSA public key", algorithm)
		}
		curve, curveName := elliptic.P256(), "P-256"
		if algorithm == ES384Algorithm {
			curve, curveName = elliptic.P384(), "P-384"
		}
		if publicKey.Curve != curve {
			return SigningKey{}, fmt.Errorf("aauth: %s requires a %s key", algorithm, curveName)
		}
		point, err := publicKey.Bytes()
		if err != nil {
			return SigningKey{}, fmt.Errorf("aauth: encode %s public key: %w", algorithm, err)
		}
		size := ecdsaCoordinateSize(curve)
		publicJWK.Crv = curveName
		publicJWK.X = rawURL.EncodeToString(point[1 : 1+size])
		publicJWK.Y = rawURL.EncodeToString(point[1+size:])
	case RS256Algorithm, PS256Algorithm:
		publicKey, ok := signer.Public().(*rsa.PublicKey)
		if !ok || publicKey.N == nil {
			return SigningKey{}, fmt.Errorf("aauth: %s signer did not expose an RSA public key", algorithm)
		}
		publicJWK.N = rawURL.EncodeToString(publicKey.N.Bytes())
		publicJWK.E = rawURL.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())
	default:
		return SigningKey{}, &unsupportedJWKAlgorithmError{algorithm: algorithm}
	}
	publicKey, err := publicJWK.SignaturePublicKey()
	if err != nil {
		return SigningKey{}, fmt.Errorf("aauth: %s signing key: %w", algorithm, err)
	}
	return SigningKey{
		id:        id,
		algorithm: algorithm,
		signer:    signer,
		publicKey: publicKey,
		publicJWK: publicJWK,
	}, nil
}

// ID returns the public key identifier used in protected headers and key-set
// lookup.
func (key SigningKey) ID() string {
	return key.id
}

// Algorithm returns the key's fully specified JOSE algorithm identifier.
func (key SigningKey) Algorithm() string {
	return key.algorithm
}

// PublicJWK returns an independent public-key value.
func (key SigningKey) PublicJWK() JWK {
	return key.publicJWK
}

// Public implements crypto.Signer and returns an independent public-key copy.
func (key SigningKey) Public() crypto.PublicKey {
	switch publicKey := key.publicKey.(type) {
	case ed25519.PublicKey:
		if len(publicKey) != ed25519.PublicKeySize {
			return nil
		}
		return append(ed25519.PublicKey(nil), publicKey...)
	case *ecdsa.PublicKey:
		point, err := publicKey.Bytes()
		if err != nil {
			return nil
		}
		copied, err := ecdsa.ParseUncompressedPublicKey(publicKey.Curve, point)
		if err != nil {
			return nil
		}
		return copied
	case *rsa.PublicKey:
		return &rsa.PublicKey{N: new(big.Int).Set(publicKey.N), E: publicKey.E}
	}
	return nil
}

// Sign implements crypto.Signer. For an Ed25519 key it signs un-hashed
// input. For other algorithms it passes the digest and options to the
// underlying signer unchanged, under the ordinary crypto.Signer contract;
// SignMessage produces the JWS form instead.
func (key SigningKey) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if key.signer == nil {
		return nil, errors.New("aauth: signing key is not initialized")
	}
	if key.algorithm != Ed25519Algorithm {
		return key.signer.Sign(random, message, opts)
	}
	if opts == nil || opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("aauth: Ed25519 signing requires un-hashed input")
	}
	if ed25519Options, ok := opts.(*ed25519.Options); ok && ed25519Options.Context != "" {
		return nil, errors.New("aauth: Ed25519 signing context is not supported")
	}
	signature, err := key.signer.Sign(random, message, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("aauth: sign: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("aauth: Ed25519 signature has %d bytes, want %d", len(signature), ed25519.SignatureSize)
	}
	return append([]byte(nil), signature...), nil
}

// SignMessage signs exact message bytes with the key's algorithm and returns
// the JWS form that JWK.VerifySignature accepts. Ed25519 signs the message
// itself. ES256 and ES384 hash it with SHA-256 or SHA-384 and return the
// fixed-size R || S. RS256 and PS256 hash it with SHA-256 and use PKCS #1
// v1.5 or PSS with a salt as long as the hash.
func (key SigningKey) SignMessage(random io.Reader, message []byte) ([]byte, error) {
	if key.signer == nil {
		return nil, errors.New("aauth: signing key is not initialized")
	}
	switch key.algorithm {
	case Ed25519Algorithm:
		return key.Sign(random, message, crypto.Hash(0))
	case ES256Algorithm, ES384Algorithm:
		hash := crypto.SHA256
		if key.algorithm == ES384Algorithm {
			hash = crypto.SHA384
		}
		encoded, err := key.signer.Sign(random, signatureDigest(key.algorithm, message), hash)
		if err != nil {
			return nil, fmt.Errorf("aauth: sign: %w", err)
		}
		var values struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(encoded, &values)
		if err != nil || len(rest) != 0 || values.R == nil || values.S == nil || values.R.Sign() <= 0 || values.S.Sign() <= 0 {
			return nil, fmt.Errorf("aauth: %s signer returned a malformed signature", key.algorithm)
		}
		size := ecdsaCoordinateSize(key.publicKey.(*ecdsa.PublicKey).Curve)
		if values.R.BitLen() > 8*size || values.S.BitLen() > 8*size {
			return nil, fmt.Errorf("aauth: %s signer returned an oversized signature", key.algorithm)
		}
		signature := make([]byte, 2*size)
		values.R.FillBytes(signature[:size])
		values.S.FillBytes(signature[size:])
		return signature, nil
	case RS256Algorithm, PS256Algorithm:
		var options crypto.SignerOpts = crypto.SHA256
		if key.algorithm == PS256Algorithm {
			options = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
		}
		signature, err := key.signer.Sign(random, signatureDigest(key.algorithm, message), options)
		if err != nil {
			return nil, fmt.Errorf("aauth: sign: %w", err)
		}
		if len(signature) != key.publicKey.(*rsa.PublicKey).Size() {
			return nil, fmt.Errorf("aauth: %s signature has %d bytes, want the modulus size", key.algorithm, len(signature))
		}
		return append([]byte(nil), signature...), nil
	}
	return nil, &unsupportedJWKAlgorithmError{algorithm: key.algorithm}
}

var _ crypto.Signer = SigningKey{}
