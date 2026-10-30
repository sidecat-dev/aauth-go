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

func signedFreshnessRequest(t *testing.T, key jose.SigningKey, path string, created time.Time, expires time.Time) *http.Request {
	t.Helper()
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://resource.example"+path, nil)
	if err := signaturekey.SignRequest(request, key, credential, aauth.ClockFunc(func() time.Time { return created }), signaturekey.SignOptions{ExpiresAt: expires}); err != nil {
		t.Fatal(err)
	}
	return request
}

func verifyFreshness(request *http.Request, key jose.SigningKey, at time.Time, maxDelay time.Duration) (signaturekey.VerifiedRequest, error) {
	prepared, err := signaturekey.PrepareRequest(request, aauth.ClockFunc(func() time.Time { return at }), signaturekey.VerifyOptions{
		AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK},
		MaxDelay:        maxDelay,
	})
	if err != nil {
		return signaturekey.VerifiedRequest{}, err
	}
	return prepared.Verify(key.PublicJWK())
}

func requireSignatureError(t *testing.T, err error, code signaturekey.ErrorCode) {
	t.Helper()
	var failure *signaturekey.Error
	if !errors.As(err, &failure) || failure.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}

// Freshness and Replay: a verifier that first sees a signed request after a
// delay anchors on the signed created, applies its own bound on that delay,
// and a replay cache it keeps spans the delay it accepts. An online verifier
// keeps the signature window, and expires is always honored.
func TestDelayedVerifierAnchorsOnCreatedAndItsReplayCacheSpansTheDelay(t *testing.T) {
	t.Parallel()

	key, err := jose.NewEd25519SigningKey("freshness-key", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{21}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	signedAt := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	request := signedFreshnessRequest(t, key, "/batch", signedAt, time.Time{})

	if _, err := verifyFreshness(request, key, signedAt.Add(10*time.Minute), 0); err == nil {
		t.Fatal("an online verifier accepted a request older than its window")
	} else {
		requireSignatureError(t, err, signaturekey.ErrorInvalidSignature)
	}
	delayed, err := verifyFreshness(request, key, signedAt.Add(50*time.Minute), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !delayed.ValidAt().Equal(signedAt) || delayed.MaxAge() != time.Hour {
		t.Fatalf("delayed verifier ValidAt %s, MaxAge %s", delayed.ValidAt(), delayed.MaxAge())
	}
	if err := delayed.CheckIssuedAt(signedAt.Add(signaturekey.DefaultSignatureWindow + time.Second)); err == nil {
		t.Fatal("a token issued after the signature beyond the window passed")
	}
	if _, err := verifyFreshness(request, key, signedAt.Add(time.Hour+time.Second), time.Hour); err == nil {
		t.Fatal("a delayed verifier accepted more delay than it allows")
	} else {
		requireSignatureError(t, err, signaturekey.ErrorInvalidSignature)
	}
	ahead := signedFreshnessRequest(t, key, "/batch", signedAt.Add(2*time.Minute), time.Time{})
	if _, err := verifyFreshness(ahead, key, signedAt, time.Hour); err == nil {
		t.Fatal("a delayed verifier accepted a created ahead of its clock")
	} else {
		requireSignatureError(t, err, signaturekey.ErrorClockSkew)
	}
	expiring := signedFreshnessRequest(t, key, "/batch", signedAt, signedAt.Add(5*time.Minute))
	if _, err := verifyFreshness(expiring, key, signedAt.Add(10*time.Minute), time.Hour); err == nil {
		t.Fatal("a delayed verifier accepted a signature past its expires")
	} else {
		requireSignatureError(t, err, signaturekey.ErrorInvalidSignature)
	}

	cache, err := signaturekey.NewReplayCache(signaturekey.ReplayCacheConfig{MaxEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Check(delayed); err != nil {
		t.Fatal(err)
	}
	again, err := verifyFreshness(request, key, signedAt.Add(59*time.Minute), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	requireSignatureError(t, cache.Check(again), signaturekey.ErrorInvalidSignature)
	other, err := verifyFreshness(signedFreshnessRequest(t, key, "/other", signedAt, time.Time{}), key, signedAt.Add(time.Minute), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Check(other); err != nil {
		t.Fatalf("a different path was refused as a replay: %v", err)
	}
	third, err := verifyFreshness(signedFreshnessRequest(t, key, "/third", signedAt, time.Time{}), key, signedAt.Add(time.Minute), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Check(third); !errors.Is(err, signaturekey.ErrReplayCacheFull) {
		t.Fatalf("full cache = %v", err)
	}

	// An online verifier's entries last its window; once that span has ended
	// the request could no longer verify, and the entry is discarded.
	online, err := signaturekey.NewReplayCache(signaturekey.ReplayCacheConfig{})
	if err != nil {
		t.Fatal(err)
	}
	fresh := signedFreshnessRequest(t, key, "/online", signedAt, time.Time{})
	first, err := verifyFreshness(fresh, key, signedAt, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := online.Check(first); err != nil {
		t.Fatal(err)
	}
	if first.MaxAge() != signaturekey.DefaultSignatureWindow {
		t.Fatalf("online MaxAge = %s", first.MaxAge())
	}
	late, err := verifyFreshness(signedFreshnessRequest(t, key, "/later", signedAt.Add(2*time.Minute), time.Time{}), key, signedAt.Add(2*time.Minute), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := online.Check(late); err != nil || online.Len() != 1 {
		t.Fatalf("online cache after its window = %d entries, %v", online.Len(), err)
	}
}
