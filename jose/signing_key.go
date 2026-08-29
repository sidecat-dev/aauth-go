package jose

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
)

// SigningKey holds a caller-custodied protocol signing capability and its
// public Ed25519 identity. It never exposes private key material.
type SigningKey struct {
	id        string
	signer    crypto.Signer
	publicKey ed25519.PublicKey
	publicJWK JWK
}

// NewSigningKey constructs the mandatory Ed25519 profile around a
// caller-custodied crypto.Signer.
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
// in-memory private key. Hosts with protected key custody should prefer
// NewSigningKey.
func NewEd25519SigningKey(id string, privateKey ed25519.PrivateKey) (SigningKey, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SigningKey{}, fmt.Errorf("aauth: Ed25519 private key has %d bytes, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	return NewSigningKey(id, privateKey)
}

// ID returns the public key identifier used in protected headers and key-set
// lookup.
func (key SigningKey) ID() string {
	return key.id
}

// PublicJWK returns an independent public-key value.
func (key SigningKey) PublicJWK() JWK {
	return key.publicJWK
}

// Public implements crypto.Signer and returns an independent public-key copy.
func (key SigningKey) Public() crypto.PublicKey {
	if len(key.publicKey) != ed25519.PublicKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), key.publicKey...)
}

// Sign implements crypto.Signer for the un-hashed Ed25519 operation.
func (key SigningKey) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if key.signer == nil {
		return nil, errors.New("aauth: signing key is not initialized")
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

var _ crypto.Signer = SigningKey{}
