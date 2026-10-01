package signaturekey_test

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Source: HTTP Signature Keys (signature-key 69f5ba2) section clock_skew. A
// signature `created` further ahead of the verifier's clock than the validity
// window is clock_skew; a `created` older than the window is invalid_signature.
func TestSignatureCreatedAheadOfTheWindowIsClockSkew(t *testing.T) {
	t.Parallel()

	key, err := jose.NewEd25519SigningKey("skew-key", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	verifierNow := time.Date(2026, 9, 30, 18, 0, 0, 0, time.UTC)
	verifierClock := aauth.ClockFunc(func() time.Time { return verifierNow })

	for _, test := range []struct {
		name     string
		offset   time.Duration
		window   time.Duration
		wantCode signaturekey.ErrorCode
	}{
		{name: "default window edge ahead is accepted", offset: signaturekey.DefaultSignatureWindow},
		{name: "one second past the default window ahead", offset: signaturekey.DefaultSignatureWindow + time.Second, wantCode: signaturekey.ErrorClockSkew},
		{name: "default window edge behind is accepted", offset: -signaturekey.DefaultSignatureWindow},
		{name: "one second older than the default window", offset: -signaturekey.DefaultSignatureWindow - time.Second, wantCode: signaturekey.ErrorInvalidSignature},
		{name: "configured window edge ahead is accepted", offset: 5 * time.Second, window: 5 * time.Second},
		{name: "configured window exceeded ahead", offset: 6 * time.Second, window: 5 * time.Second, wantCode: signaturekey.ErrorClockSkew},
		{name: "configured window exceeded behind", offset: -6 * time.Second, window: 5 * time.Second, wantCode: signaturekey.ErrorInvalidSignature},
	} {
		t.Run(test.name, func(t *testing.T) {
			senderClock := aauth.ClockFunc(func() time.Time { return verifierNow.Add(test.offset) })
			request := httptest.NewRequest(http.MethodGet, "https://resource.example/records", nil)
			if err := signaturekey.SignRequest(request, key, credential, senderClock, signaturekey.SignOptions{}); err != nil {
				t.Fatal(err)
			}
			_, err := signaturekey.PrepareRequest(request, verifierClock, signaturekey.VerifyOptions{
				AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK},
				SignatureWindow: test.window,
			})
			if test.wantCode == "" {
				if err != nil {
					t.Fatalf("PrepareRequest rejected an in-window signature: %v", err)
				}
				return
			}
			failure := signaturekey.NormalizeError(err, "")
			if failure == nil || failure.Code != test.wantCode {
				t.Fatalf("PrepareRequest error = %v, want code %q", err, test.wantCode)
			}
			header, err := signaturekey.FormatError(*failure)
			if err != nil {
				t.Fatal(err)
			}
			if want := "error=" + string(test.wantCode); header != want {
				t.Fatalf("Signature-Error = %q, want %q", header, want)
			}
		})
	}
}
