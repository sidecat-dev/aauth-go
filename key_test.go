package aauth_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

type recordingSigner struct {
	mu      sync.Mutex
	private ed25519.PrivateKey
	calls   int
}

type unsupportedSigner struct{}

func (unsupportedSigner) Public() crypto.PublicKey { return []byte("unsupported") }

func (unsupportedSigner) Sign(
	io.Reader,
	[]byte,
	crypto.SignerOpts,
) ([]byte, error) {
	return nil, nil
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
	key, err := aauth.NewSigningKey("protected-agent-key", signer)
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
	if err := aauth.SignRequest(
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

func TestSigningKeyRejectsUnsupportedOrUninitializedSigner(t *testing.T) {
	t.Parallel()

	if _, err := aauth.NewSigningKey("key", nil); err == nil {
		t.Fatal("accepted nil crypto signer")
	}
	if _, err := aauth.NewSigningKey("", &recordingSigner{}); err == nil {
		t.Fatal("accepted empty key id")
	}
	if _, err := aauth.NewSigningKey("key", unsupportedSigner{}); err == nil {
		t.Fatal("accepted signer without an Ed25519 public key")
	}
}

func mustJWKForPrivateKey(
	t *testing.T,
	id string,
	private ed25519.PrivateKey,
) aauth.JWK {
	t.Helper()
	key, err := aauth.NewEd25519SigningKey(id, private)
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicJWK()
}
