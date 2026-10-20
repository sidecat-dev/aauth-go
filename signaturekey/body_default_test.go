package signaturekey_test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// Core a99d353 Covered Components permits additional Resource requirements.
// Automatic digest coverage is this library's bounded request profile.
func TestDefaultSigningCoversActualBodyBytes(t *testing.T) {
	key, err := jose.NewEd25519SigningKey("body-default", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{83}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	clock := fixedClock(time.Unix(1800000000, 0))
	for _, length := range []int64{0, -1, 11} {
		t.Run(map[int64]string{0: "unspecified length", -1: "unknown length", 11: "known length"}[length], func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, "https://resource.example/items", io.NopCloser(strings.NewReader(`{"value":1}`)))
			if err != nil {
				t.Fatal(err)
			}
			request.ContentLength = length
			if err := signaturekey.SignHWKRequest(request, key, clock); err != nil {
				t.Fatal(err)
			}
			if request.Header.Get("Content-Digest") == "" || !strings.Contains(request.Header.Get("Signature-Input"), `"content-digest"`) {
				t.Fatalf("body is not covered: %v", request.Header)
			}
			prepared, err := signaturekey.PrepareRequest(request, clock, signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK}})
			if err != nil {
				t.Fatal(err)
			}
			verified, err := prepared.Verify(key.PublicJWK())
			if err != nil {
				t.Fatal(err)
			}
			if string(verified.ExactBody()) != `{"value":1}` {
				t.Fatalf("authenticated body = %q", verified.ExactBody())
			}
			body, err := io.ReadAll(request.Body)
			if err != nil || string(body) != `{"value":1}` {
				t.Fatalf("application body = %q, %v", body, err)
			}
		})
	}
}

func TestDefaultSigningBoundsBodyAndPreservesFailedInput(t *testing.T) {
	key, err := jose.NewEd25519SigningKey("body-bound", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{84}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://resource.example/items", io.NopCloser(strings.NewReader("12345")))
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = -1
	if err := signaturekey.SignRequest(request, key, credential, fixedClock(time.Unix(1800000000, 0)), signaturekey.SignOptions{MaxBodyBytes: 4}); err == nil {
		t.Fatal("signer accepted a body above its bound")
	}
	body, err := io.ReadAll(request.Body)
	if err != nil || string(body) != "12345" || request.ContentLength != -1 || request.GetBody != nil {
		t.Fatalf("failed signing changed request: body=%q err=%v length=%d", body, err, request.ContentLength)
	}
	if request.Header.Get("Signature") != "" || request.Header.Get("Content-Digest") != "" {
		t.Fatalf("failed signing emitted headers: %v", request.Header)
	}
}

func TestSigningRejectsMismatchedPositiveContentLength(t *testing.T) {
	key, err := jose.NewEd25519SigningKey("body-length", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{85}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	for _, replayable := range []bool{false, true} {
		for _, length := range []int64{1, 12} {
			t.Run(fmt.Sprintf("GetBody=%t/length=%d", replayable, length), func(t *testing.T) {
				const content = `{"value":1}`
				request, err := http.NewRequest(http.MethodPost, "https://resource.example/items", strings.NewReader(content))
				if err != nil {
					t.Fatal(err)
				}
				if !replayable {
					request.GetBody = nil
				}
				request.ContentLength = length
				if err := signaturekey.SignHWKRequest(request, key, fixedClock(time.Unix(1800000000, 0))); err == nil {
					t.Fatal("signer accepted a ContentLength that differs from the signed body")
				}
				body, err := io.ReadAll(request.Body)
				if err != nil || string(body) != content || request.ContentLength != length {
					t.Fatalf("refusal changed request: body=%q err=%v length=%d", body, err, request.ContentLength)
				}
				if (request.GetBody != nil) != replayable {
					t.Fatal("refusal changed replay capability")
				}
				for _, header := range []string{"Signature", "Signature-Input", "Signature-Key", "Content-Digest"} {
					if request.Header.Get(header) != "" {
						t.Fatalf("refused request has %s: %v", header, request.Header)
					}
				}
			})
		}
	}
}

func TestSignedBodySurvivesHTTPFraming(t *testing.T) {
	key, err := jose.NewEd25519SigningKey("body-framing", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{86}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	clock := fixedClock(time.Unix(1800000000, 0))
	const content = `{"value":1}`
	for _, length := range []int64{-1, 0, int64(len(content))} {
		t.Run(fmt.Sprintf("length=%d", length), func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, "https://resource.example/items", io.NopCloser(strings.NewReader(content)))
			if err != nil {
				t.Fatal(err)
			}
			request.ContentLength = length
			if err := signaturekey.SignHWKRequest(request, key, clock); err != nil {
				t.Fatal(err)
			}
			var wire bytes.Buffer
			if err := request.Write(&wire); err != nil {
				t.Fatal(err)
			}
			received, err := http.ReadRequest(bufio.NewReader(&wire))
			if err != nil {
				t.Fatal(err)
			}
			defer received.Body.Close()
			prepared, err := signaturekey.PrepareRequest(received, clock, signaturekey.VerifyOptions{
				AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK},
			})
			if err != nil {
				t.Fatal(err)
			}
			verified, err := prepared.Verify(key.PublicJWK())
			if err != nil || string(verified.ExactBody()) != content {
				t.Fatalf("framed proof: body=%q error=%v", verified.ExactBody(), err)
			}
		})
	}
}

func TestMaximumSignedBodyLimitDoesNotDiscardContent(t *testing.T) {
	key, err := jose.NewEd25519SigningKey("maximum-body-limit", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{87}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	const content = "exact bytes"
	request, err := http.NewRequest(http.MethodPost, "https://resource.example/items", io.NopCloser(strings.NewReader(content)))
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, key, credential, fixedClock(time.Unix(1800000000, 0)), signaturekey.SignOptions{
		MaxBodyBytes: math.MaxInt64,
	}); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil || string(body) != content || request.Header.Get("Content-Digest") == "" {
		t.Fatalf("maximum limit changed content: body=%q error=%v headers=%v", body, err, request.Header)
	}
}
