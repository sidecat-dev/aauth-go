package signaturekey_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// A JWT carried with a verified request is judged against that request's
// captured verification time and effective signature window: an iat up to the
// window ahead is accepted, and one beyond it is clock_skew.
func TestRequestCarriedJWTIssuedAtIsJudgedByTheRequestWindow(t *testing.T) {
	t.Parallel()

	key, err := jose.NewEd25519SigningKey("issued-at-key", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })

	for _, test := range []struct {
		name       string
		window     time.Duration
		wantWindow time.Duration
	}{
		{name: "default window", wantWindow: signaturekey.DefaultSignatureWindow},
		{name: "configured window", window: 5 * time.Second, wantWindow: 5 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://resource.example/records", nil)
			if err := signaturekey.SignRequest(request, key, credential, clock, signaturekey.SignOptions{}); err != nil {
				t.Fatal(err)
			}
			prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{
				AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK},
				SignatureWindow: test.window,
			})
			if err != nil {
				t.Fatal(err)
			}
			verified, err := prepared.Verify(key.PublicJWK())
			if err != nil {
				t.Fatal(err)
			}
			if got := prepared.SignatureWindow(); got != test.wantWindow {
				t.Fatalf("prepared SignatureWindow() = %s, want %s", got, test.wantWindow)
			}
			if got := verified.SignatureWindow(); got != test.wantWindow {
				t.Fatalf("verified SignatureWindow() = %s, want %s", got, test.wantWindow)
			}
			for name, check := range map[string]func(time.Time) error{
				"prepared": prepared.CheckIssuedAt,
				"verified": verified.CheckIssuedAt,
			} {
				for _, accepted := range []time.Time{now.Add(-time.Hour), now, now.Add(test.wantWindow)} {
					if err := check(accepted); err != nil {
						t.Fatalf("%s CheckIssuedAt(%s) = %v, want accepted", name, accepted.Sub(now), err)
					}
				}
				err := check(now.Add(test.wantWindow + time.Second))
				var failure *signaturekey.Error
				if !errors.As(err, &failure) || failure.Code != signaturekey.ErrorClockSkew {
					t.Fatalf("%s CheckIssuedAt(window+1s) = %#v, want %s", name, err, signaturekey.ErrorClockSkew)
				}
			}
		})
	}
}
