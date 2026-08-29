package aauth_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type recordingSigner struct {
	mu      sync.Mutex
	private ed25519.PrivateKey
	calls   int
}

func (signer *recordingSigner) Public() crypto.PublicKey {
	return signer.private.Public()
}

func (signer *recordingSigner) Sign(
	random io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) ([]byte, error) {
	signer.mu.Lock()
	signer.calls++
	signer.mu.Unlock()
	return signer.private.Sign(random, digest, opts)
}

func (signer *recordingSigner) callCount() int {
	signer.mu.Lock()
	defer signer.mu.Unlock()
	return signer.calls
}

func TestSigningKeyUsesCallerCustodiedCryptoSigner(t *testing.T) {
	t.Parallel()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &recordingSigner{private: private}
	key, err := jose.NewSigningKey("protected-agent-key", signer)
	if err != nil {
		t.Fatal(err)
	}
	if key.ID() != "protected-agent-key" ||
		!key.PublicJWK().Equal(mustJWKForPrivateKey(t, "protected-agent-key", private)) {
		t.Fatalf("signing key public identity = %q / %#v", key.ID(), key.PublicJWK())
	}

	request, err := http.NewRequest(http.MethodPost, "https://ps.example/permission", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignJWTRequest(
		request,
		key,
		"agent-token",
		aauth.ClockFunc(func() time.Time {
			return time.Date(2026, time.July, 27, 8, 0, 0, 0, time.UTC)
		}),
	); err != nil {
		t.Fatal(err)
	}
	if signer.callCount() != 1 {
		t.Fatalf("crypto signer calls = %d, want 1", signer.callCount())
	}
}

func TestStaticKeyResolverClassifiesResolutionFailures(t *testing.T) {
	t.Parallel()

	resolver := signaturekey.StaticKeyResolver{
		"https://issuer.example": {
			"invalid": {Kty: "OKP", Crv: "Ed25519", Alg: "Ed25519", X: "invalid", Kid: "invalid"},
		},
	}
	for _, test := range []struct {
		name   string
		issuer string
		keyID  string
		want   signaturekey.ResolutionCode
	}{
		{name: "unknown key", issuer: "https://issuer.example", keyID: "missing", want: signaturekey.ResolutionUnknown},
		{name: "untrusted issuer", issuer: "https://other.example", keyID: "missing", want: signaturekey.ResolutionInvalid},
		{name: "invalid key", issuer: "https://issuer.example", keyID: "invalid", want: signaturekey.ResolutionInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := resolver.ResolveKey(context.Background(), test.issuer, aauth.ResourceDiscoveryDocument, test.keyID)
			var resolutionError *signaturekey.ResolutionError
			if !errors.As(err, &resolutionError) || resolutionError.Code != test.want {
				t.Fatalf("ResolveKey error = %v (%#v), want %q", err, resolutionError, test.want)
			}
		})
	}
}

func mustJWKForPrivateKey(
	t *testing.T,
	id string,
	private ed25519.PrivateKey,
) jose.JWK {
	t.Helper()
	key, err := jose.NewEd25519SigningKey(id, private)
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicJWK()
}
