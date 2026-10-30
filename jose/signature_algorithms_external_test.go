package jose_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/jose"
)

func newAlgorithmSigningKey(t *testing.T, algorithm string) jose.SigningKey {
	t.Helper()
	var signer crypto.Signer
	var err error
	switch algorithm {
	case jose.Ed25519Algorithm:
		_, signer, err = ed25519.GenerateKey(rand.Reader)
	case jose.ES256Algorithm:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jose.ES384Algorithm:
		signer, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case jose.RS256Algorithm, jose.PS256Algorithm:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.NewSigningKeyForAlgorithm(algorithm+"-key", algorithm, signer)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSigningKeysSignAndVerifyUnderEachSignatureAlgorithm(t *testing.T) {
	t.Parallel()

	message := []byte("signature base")
	for _, algorithm := range jose.SignatureAlgorithms() {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			key := newAlgorithmSigningKey(t, algorithm)
			public := key.PublicJWK()
			if key.Algorithm() != algorithm || public.Alg != algorithm || public.Kid != key.ID() {
				t.Fatalf("signing key = %q with public JWK %#v", key.Algorithm(), public)
			}
			encoded, err := json.Marshal(public)
			if err != nil {
				t.Fatal(err)
			}
			var decoded jose.JWK
			if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != public {
				t.Fatalf("JWK JSON round trip = %#v, %v", decoded, err)
			}
			signature, err := key.SignMessage(rand.Reader, message)
			if err != nil {
				t.Fatal(err)
			}
			if size, err := public.SignatureSize(); err != nil || size != len(signature) {
				t.Fatalf("SignatureSize() = %d, %v for a %d-byte signature", size, err, len(signature))
			}
			if err := public.VerifySignature(message, signature); err != nil {
				t.Fatalf("VerifySignature() = %v", err)
			}
			if err := public.VerifySignature([]byte("other base"), signature); err == nil {
				t.Fatal("VerifySignature() accepted a different message")
			}
			if _, err := public.Thumbprint(); err != nil {
				t.Fatalf("Thumbprint() = %v", err)
			}
			_, err = public.PublicKey()
			if supported := err == nil; supported != (algorithm == jose.Ed25519Algorithm) {
				t.Fatalf("PublicKey() error = %v; the AAuth token profile accepts only Ed25519", err)
			}
		})
	}
}

func TestSignaturePublicKeyFollowsAlgorithmDetermination(t *testing.T) {
	t.Parallel()

	ec := newAlgorithmSigningKey(t, jose.ES256Algorithm).PublicJWK()
	rsaKey := newAlgorithmSigningKey(t, jose.PS256Algorithm).PublicJWK()
	okp := newAlgorithmSigningKey(t, jose.Ed25519Algorithm).PublicJWK()
	with := func(key jose.JWK, change func(*jose.JWK)) jose.JWK {
		change(&key)
		return key
	}
	tests := []struct {
		name        string
		key         jose.JWK
		unsupported bool
	}{
		{name: "absent alg", key: with(ec, func(key *jose.JWK) { key.Alg = "" }), unsupported: true},
		{name: "polymorphic EdDSA", key: with(okp, func(key *jose.JWK) { key.Alg = "EdDSA" }), unsupported: true},
		{name: "symmetric MAC", key: with(ec, func(key *jose.JWK) { key.Alg = "HS256" }), unsupported: true},
		{name: "oct key type", key: jose.JWK{Kty: "oct", Alg: "HS256"}, unsupported: true},
		{name: "post-quantum key type", key: jose.JWK{Kty: "AKP", Alg: "ML-DSA-44"}, unsupported: true},
		{name: "RSA without padding and hash", key: with(rsaKey, func(key *jose.JWK) { key.Alg = "RSA" }), unsupported: true},
		{name: "unimplemented RSA hash", key: with(rsaKey, func(key *jose.JWK) { key.Alg = "PS512" }), unsupported: true},
		{name: "ES256 on P-384", key: with(ec, func(key *jose.JWK) { key.Crv = "P-384" })},
		{name: "ES256 with RSA key type", key: with(ec, func(key *jose.JWK) { key.Kty = "RSA" })},
		{name: "EC without y", key: with(ec, func(key *jose.JWK) { key.Y = "" })},
		{name: "EC point off the curve", key: with(ec, func(key *jose.JWK) { key.Y = key.X })},
		{name: "OKP carrying y", key: with(okp, func(key *jose.JWK) { key.Y = okp.X })},
		{name: "RSA exponent with leading zero", key: with(rsaKey, func(key *jose.JWK) { key.E = "AAEAAQ" })},
		{name: "RSA modulus below 2048 bits", key: with(rsaKey, func(key *jose.JWK) { key.N = key.N[:200] })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.key.SignaturePublicKey()
			if err == nil {
				t.Fatalf("SignaturePublicKey(%#v) succeeded", test.key)
			}
			var unsupported interface{ UnsupportedAlgorithm() string }
			if got := errors.As(err, &unsupported); got != test.unsupported {
				t.Fatalf("SignaturePublicKey() error = %v, unsupported algorithm = %t, want %t", err, got, test.unsupported)
			}
		})
	}
}

func TestThumbprintCoversEveryKeyType(t *testing.T) {
	t.Parallel()

	// RFC 7638, Section 3.1.
	key := jose.JWK{
		Kty: "RSA", Alg: jose.RS256Algorithm, E: "AQAB",
		N: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	}
	if got, err := key.Thumbprint(); err != nil || got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("RSA Thumbprint() = %q, %v", got, err)
	}
	ec := jose.JWK{
		Kty: "EC", Crv: "P-256", Alg: jose.ES256Algorithm,
		X: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", Y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	}
	if got, err := ec.ThumbprintURI(); err != nil || got != "urn:jkt:sha-256:oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U" {
		t.Fatalf("EC ThumbprintURI() = %q, %v", got, err)
	}
	other := ec
	other.Kid, other.Use = "other-id", "sig"
	if !ec.Equal(other) || ec.Equal(key) {
		t.Fatal("Equal() does not compare EC and RSA keys by thumbprint")
	}
}

func TestCompactJWSRequiresAnEd25519SigningKey(t *testing.T) {
	t.Parallel()

	key := newAlgorithmSigningKey(t, jose.ES256Algorithm)
	protected := []byte(`{"alg":"Ed25519","typ":"example+jwt","kid":"ES256-key"}`)
	if _, err := jose.SignCompactProtected(key, protected, []byte(`{}`)); err == nil {
		t.Fatal("SignCompactProtected() signed an Ed25519 header with an ES256 key")
	}
	if _, err := jose.NewSigningKeyForAlgorithm("rsa-key", jose.ES256Algorithm, mustRSAKey(t)); err == nil {
		t.Fatal("NewSigningKeyForAlgorithm() accepted an RSA signer for ES256")
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
