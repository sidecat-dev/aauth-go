package signaturekey_test

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestResponseProofBindsRequestAndExactRepresentation(t *testing.T) {
	now := time.Date(2026, 8, 29, 22, 0, 0, 0, time.UTC)
	key, err := jose.NewEd25519SigningKey(
		"resource-response-key",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://resource.example/usage", strings.NewReader(`{"sub":"person"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"as_of":42}`)),
	}
	response.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignResponse(response, request, key, "https://resource.example", "aauth-resource.json", fixedClock(now)); err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Content-Digest") == "" || response.Header.Get("Signature") == "" || response.Header.Get("Signature-Input") == "" || response.Header.Get("Signature-Key") == "" {
		t.Fatalf("response proof headers are incomplete: %#v", response.Header)
	}
	if !strings.Contains(response.Header.Get("Signature-Input"), `"@authority";req`) || !strings.Contains(response.Header.Get("Signature-Input"), `"@path";req`) {
		t.Fatalf("response proof does not bind request authority/path: %s", response.Header.Get("Signature-Input"))
	}
	prepared, err := signaturekey.PrepareResponse(response, request, fixedClock(now), signaturekey.ResponseVerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := prepared.Verify(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	if verified.Status() != http.StatusOK || verified.Authority() != "resource.example" || verified.Path() != "/usage" || verified.Signer() != "https://resource.example" {
		t.Fatalf("verified response = status %d authority %q path %q signer %q", verified.Status(), verified.Authority(), verified.Path(), verified.Signer())
	}
	response.Body = io.NopCloser(strings.NewReader(`{"as_of":43}`))
	if _, err := signaturekey.PrepareResponse(response, request, fixedClock(now), signaturekey.ResponseVerifyOptions{}); err == nil {
		t.Fatal("tampered body retained the original response digest")
	}
	response.Body = io.NopCloser(strings.NewReader(`{"as_of":42}`))
	request.URL.Path = "/other"
	prepared, err = signaturekey.PrepareResponse(response, request, fixedClock(now), signaturekey.ResponseVerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Verify(key.PublicJWK()); err == nil {
		t.Fatal("changed request path verified under the original response proof")
	}
	request.URL.Path = "/usage"
	prepared, err = signaturekey.PrepareResponse(response, request, fixedClock(now), signaturekey.ResponseVerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := jose.NewEd25519SigningKey(
		"other-response-key",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x67}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Verify(other.PublicJWK()); err == nil {
		t.Fatal("response proof verified under a different key")
	}
}

func TestResponseProofRejectsNonExactComponentProfiles(t *testing.T) {
	now := time.Date(2026, 8, 29, 22, 10, 0, 0, time.UTC)
	key, err := jose.NewEd25519SigningKey(
		"response-profile-key",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x68}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, "https://resource.example/usage", nil)
	response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}
	response.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignResponse(response, request, key, "https://resource.example", "aauth-resource.json", fixedClock(now)); err != nil {
		t.Fatal(err)
	}
	response.Header.Set("Signature-Input", strings.Replace(response.Header.Get("Signature-Input"), `"content-digest"`, `"x-extra" "content-digest"`, 1))
	if _, err := signaturekey.PrepareResponse(response, request, fixedClock(now), signaturekey.ResponseVerifyOptions{}); err == nil {
		t.Fatal("response with an extra covered component was accepted")
	}
}
