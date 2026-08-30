package signaturekey_test

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "aauth-go"
	"aauth-go/jose"
	"aauth-go/signaturekey"
)

func TestPrepareRequestStopsAtTheConfiguredRepresentationLimit(t *testing.T) {
	t.Parallel()

	const limit = int64(32)
	body := bytes.Repeat([]byte("x"), 128)
	key, err := jose.NewEd25519SigningKey(
		"request-key",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	clock := aauth.ClockFunc(func() time.Time {
		return time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	})
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/records", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, key, credential, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
		MaxBodyBytes:         int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	reader := &countingReader{reader: bytes.NewReader(body)}
	request.Body = io.NopCloser(reader)
	request.ContentLength = -1

	_, err = signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
		RequiredComponents: []string{"content-type", "content-digest"},
		MaxBodyBytes:       limit,
	})
	if err == nil {
		t.Fatal("PrepareRequest accepted an oversized representation")
	}
	if reader.read > limit+1 {
		t.Fatalf("PrepareRequest read %d bytes, want at most %d", reader.read, limit+1)
	}
	restored, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, body) {
		t.Fatalf("request body was not restored after bounded verification failure")
	}
}

func TestSignRequestStopsAtTheConfiguredLimitWithoutMutatingTheRequest(t *testing.T) {
	t.Parallel()

	const limit = int64(32)
	body := bytes.Repeat([]byte("x"), 128)
	key, err := jose.NewEd25519SigningKey(
		"request-key",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/records", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	originalContentLength := request.ContentLength
	originalGetBody := request.GetBody
	if err := signaturekey.SignRequest(request, key, credential, aauth.ClockFunc(func() time.Time {
		return time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	}), signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
		MaxBodyBytes:         limit,
	}); err == nil {
		t.Fatal("SignRequest accepted an oversized representation")
	}
	for _, name := range []string{"Content-Digest", "Signature-Key", "Signature-Input", "Signature"} {
		if value := request.Header.Get(name); value != "" {
			t.Fatalf("failed signing emitted %s: %q", name, value)
		}
	}
	restored, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, body) {
		t.Fatal("request body was not restored after bounded signing failure")
	}
	if request.ContentLength != originalContentLength || (request.GetBody == nil) != (originalGetBody == nil) {
		t.Fatal("failed signing changed request body metadata")
	}
}

func TestBodyIsNotBufferedWhenTheEndpointDoesNotRequireContentDigest(t *testing.T) {
	t.Parallel()

	key, err := jose.NewEd25519SigningKey(
		"request-key",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	clock := aauth.ClockFunc(func() time.Time {
		return time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	})
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	body := &countingReader{reader: bytes.NewReader(bytes.Repeat([]byte("x"), 2<<20))}
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/upload", body)
	request.ContentLength = -1
	if err := signaturekey.SignRequest(request, key, credential, clock, signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	if body.read != 0 || request.Header.Get("Content-Digest") != "" {
		t.Fatalf("signer read %d bytes and emitted Content-Digest %q", body.read, request.Header.Get("Content-Digest"))
	}
	prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
		AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Verify(key.PublicJWK()); err != nil {
		t.Fatal(err)
	}
}

type countingReader struct {
	reader *bytes.Reader
	read   int64
}

func (reader *countingReader) Read(destination []byte) (int, error) {
	n, err := reader.reader.Read(destination)
	reader.read += int64(n)
	return n, err
}
