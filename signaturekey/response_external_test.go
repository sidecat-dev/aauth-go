package signaturekey_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

// TestResponseSignatureBindsStatusFieldsAndRequest checks the RFC 9421
// Section 2.4 signature base: @status, then response fields, then request
// components under req, then @signature-params, in exactly that form, so a
// verifier rebuilding the base from those lines verifies it.
func TestResponseSignatureBindsStatusFieldsAndRequest(t *testing.T) {
	t.Parallel()

	key, err := jose.NewEd25519SigningKey("r1", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1754620001, 0)
	clock := aauth.ClockFunc(func() time.Time { return now })
	credential, err := signaturekey.NewJWKSURICredential("https://inference.example", "aauth-resource.json", "r1")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://Inference.example:443/usage", nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"aud":"https://ps.example"}`)
	header := http.Header{"Content-Type": []string{"application/json"}}
	options := signaturekey.ResponseSignOptions{
		Components:        []string{"content-type", "content-digest"},
		RequestComponents: []string{"@authority", "@path"},
	}
	if err := signaturekey.SignResponse(header, http.StatusOK, body, request, key, credential, clock, options); err != nil {
		t.Fatal(err)
	}
	params := `("@status" "content-type" "content-digest" "@authority";req "@path";req);created=1754620001`
	if got := header.Get("Signature-Input"); got != "sig="+params {
		t.Fatalf("Signature-Input = %q", got)
	}
	if got := header.Get("Signature-Key"); got != `sig=jwks_uri;id="https://inference.example";dwk="aauth-resource.json";kid="r1"` {
		t.Fatalf("Signature-Key = %q", got)
	}
	base := strings.Join([]string{
		`"@status": 200`,
		`"content-type": application/json`,
		`"content-digest": ` + header.Get("Content-Digest"),
		`"@authority";req: inference.example`,
		`"@path";req: /usage`,
		`"@signature-params": ` + params,
	}, "\n")
	encoded := strings.TrimSuffix(strings.TrimPrefix(header.Get("Signature"), "sig=:"), ":")
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.PublicJWK().VerifySignature([]byte(base), signature); err != nil {
		t.Fatalf("signature does not verify over the RFC 9421 response base: %v", err)
	}

	resolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://inference.example", DiscoveryDocument: "aauth-resource.json", KeyID: "r1"}: key.PublicJWK(),
	}
	verify := func(status int, header http.Header, body []byte, request *http.Request, at time.Time) error {
		_, err := signaturekey.VerifyResponse(
			context.Background(), status, header, body, request, resolver,
			aauth.ClockFunc(func() time.Time { return at }),
			signaturekey.ResponseVerifyOptions{
				RequiredComponents: options.Components, RequiredRequestComponents: options.RequestComponents,
			},
		)
		return err
	}
	if err := verify(http.StatusOK, header, body, request, now); err != nil {
		t.Fatalf("VerifyResponse = %v", err)
	}
	other, _ := http.NewRequest(http.MethodPost, "https://inference.example/other", nil)
	for name, failure := range map[string]error{
		"another status":       verify(http.StatusAccepted, header, body, request, now),
		"another body":         verify(http.StatusOK, header, []byte(`{}`), request, now),
		"another request path": verify(http.StatusOK, header, body, other, now),
		"stale signature":      verify(http.StatusOK, header, body, request, now.Add(2*time.Minute)),
	} {
		if failure == nil {
			t.Errorf("%s verified", name)
		}
	}
	uncovered := header.Clone()
	uncovered.Set("Signature-Input", `sig=("@status" "content-type" "content-digest");created=1754620001`)
	if err := verify(http.StatusOK, uncovered, body, request, now); err == nil {
		t.Error("a response signature that does not bind the request verified")
	}
}
