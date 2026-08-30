package signaturekey_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aauth-dev/auth-go/jose"
	"github.com/aauth-dev/auth-go/signaturekey"
)

type fixedClock time.Time

func (clock fixedClock) Now() time.Time { return time.Time(clock) }

func TestHWKRequestProofIsPortableAndCopySafe(t *testing.T) {
	now := time.Date(2026, 8, 28, 22, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	signingKey, err := jose.NewEd25519SigningKey("request-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(signingKey.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(
		http.MethodPost,
		"https://resource.example:443/items/1",
		strings.NewReader(`{"answer":42}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignRequest(
		request,
		signingKey,
		credential,
		fixedClock(now),
		signaturekey.SignOptions{Nonce: "attempt-1", AdditionalComponents: []string{"content-type"}},
	); err != nil {
		t.Fatal(err)
	}

	prepared, err := signaturekey.PrepareRequest(
		request,
		fixedClock(now.Add(10*time.Second)),
		signaturekey.VerifyOptions{
			AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeHWK},
			RequiredComponents:     []string{"content-type"},
			RequireExactComponents: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	parsedCredential := prepared.Credential()
	if parsedCredential.Scheme() != signaturekey.SchemeHWK {
		t.Fatalf("scheme = %q, want %q", parsedCredential.Scheme(), signaturekey.SchemeHWK)
	}
	proofKey, ok := parsedCredential.InlineJWK()
	if !ok || !proofKey.Equal(signingKey.PublicJWK()) {
		t.Fatalf("inline proof key = %#v, %t", proofKey, ok)
	}

	verified, err := prepared.Verify(proofKey)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Scheme() != signaturekey.SchemeHWK ||
		verified.Signer() == "" ||
		verified.ReplayKey() == "" ||
		!verified.PublicKey().Equal(signingKey.PublicJWK()) {
		t.Fatalf("invalid verified proof: scheme=%q signer=%q replay=%q key=%#v",
			verified.Scheme(), verified.Signer(), verified.ReplayKey(), verified.PublicKey())
	}
	if got, want := verified.Method(), http.MethodPost; got != want {
		t.Fatalf("method = %q, want %q", got, want)
	}
	if got, want := verified.Authority(), "resource.example"; got != want {
		t.Fatalf("authority = %q, want %q", got, want)
	}
	if got, want := verified.Path(), "/items/1"; got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	if got, want := verified.Created(), now; !got.Equal(want) {
		t.Fatalf("created = %s, want %s", got, want)
	}
	if got, want := verified.VerifiedAt(), now.Add(10*time.Second); !got.Equal(want) {
		t.Fatalf("verified at = %s, want %s", got, want)
	}
	components := verified.CoveredComponents()
	components[0] = "mutated"
	if verified.CoveredComponents()[0] == "mutated" {
		t.Fatal("covered components alias internal proof state")
	}
	if _, err := (signaturekey.PreparedRequest{}).Verify(proofKey); err == nil {
		t.Fatal("zero prepared request verified")
	}
}

func TestRequestProofCanCoverAnEmptyContentDigest(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 23, 50, 0, 0, time.UTC)
	key, err := jose.NewEd25519SigningKey(
		"empty-content-key",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4f}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/pending/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignRequest(request, key, credential, fixedClock(now), signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type", "content-digest"},
	}); err != nil {
		t.Fatal(err)
	}
	const emptySHA256 = "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
	if request.Header.Get("Content-Digest") != emptySHA256 {
		t.Fatalf("Content-Digest = %q, want empty-content digest", request.Header.Get("Content-Digest"))
	}
	if request.Body != nil && request.Body != http.NoBody {
		t.Fatalf("bodyless request gained a body: %#v", request.Body)
	}
	prepared, err := signaturekey.PrepareRequest(request, fixedClock(now), signaturekey.VerifyOptions{
		AcceptedSchemes:        []signaturekey.Scheme{signaturekey.SchemeHWK},
		RequiredComponents:     []string{"content-type", "content-digest"},
		RequireExactComponents: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Verify(key.PublicJWK()); err != nil {
		t.Fatal(err)
	}
}

func TestRequestProofCoversAnExactQueryWhenPresent(t *testing.T) {
	now := time.Date(2026, 8, 29, 17, 30, 0, 0, time.UTC)
	key, err := jose.NewEd25519SigningKey(
		"query-key",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x45}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := signaturekey.NewHWKCredential(key.PublicJWK())
	request, _ := http.NewRequest(http.MethodGet, "https://resource.example/records?mode=current&limit=1", nil)
	if err := signaturekey.SignRequest(request, key, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(request.Header.Get("Signature-Input"), `"@query"`) {
		t.Fatalf("query is not covered: %s", request.Header.Get("Signature-Input"))
	}
	prepared, err := signaturekey.PrepareRequest(
		request, fixedClock(now),
		signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK}, RequireExactComponents: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Verify(key.PublicJWK()); err != nil {
		t.Fatal(err)
	}
	request.URL.RawQuery = "mode=other&limit=1"
	changed, err := signaturekey.PrepareRequest(
		request, fixedClock(now),
		signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK}, RequireExactComponents: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changed.Verify(key.PublicJWK()); err == nil {
		t.Fatal("changed query verified under the original proof")
	}
}

func TestRequestProofCoversAnExplicitEmptyQuery(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 17, 30, 0, 0, time.UTC)
	key, err := jose.NewEd25519SigningKey(
		"query-key",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x46}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := signaturekey.NewHWKCredential(key.PublicJWK())
	request, _ := http.NewRequest(http.MethodGet, "https://resource.example/records?", nil)
	if !request.URL.ForceQuery {
		t.Fatal("test request did not preserve the explicit empty query")
	}
	if err := signaturekey.SignRequest(request, key, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(request.Header.Get("Signature-Input"), `"@query"`) {
		t.Fatalf("empty query is not covered: %s", request.Header.Get("Signature-Input"))
	}
	prepared, err := signaturekey.PrepareRequest(
		request, fixedClock(now),
		signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK}, RequireExactComponents: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Verify(key.PublicJWK()); err != nil {
		t.Fatal(err)
	}
	request.URL.ForceQuery = false
	_, err = signaturekey.PrepareRequest(
		request, fixedClock(now),
		signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK}, RequireExactComponents: true},
	)
	if err == nil {
		t.Fatal("removing the explicit empty query preserved the original proof")
	}
}

func TestJWKSURICredentialResolvesThroughTheGenericKeyContract(t *testing.T) {
	now := time.Date(2026, 8, 28, 22, 45, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	signingKey, err := jose.NewEd25519SigningKey("server-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewJWKSURICredential(
		"https://server.example",
		"service-configuration",
		signingKey.ID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://peer.example/federate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, signingKey, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(
		request,
		fixedClock(now),
		signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWKSURI}},
	)
	if err != nil {
		t.Fatal(err)
	}
	issuer, document, keyID, ok := prepared.Credential().JWKSURI()
	if !ok || issuer != "https://server.example" || document != "service-configuration" || keyID != signingKey.ID() {
		t.Fatalf("JWKS URI reference = %q %q %q %t", issuer, document, keyID, ok)
	}
	resolver := signaturekey.StaticKeyResolver{
		{Issuer: issuer, DiscoveryDocument: document, KeyID: keyID}: signingKey.PublicJWK(),
	}
	proofKey, err := resolver.ResolveKey(context.Background(), issuer, document, keyID)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := prepared.Verify(proofKey)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Scheme() != signaturekey.SchemeJWKSURI {
		t.Fatalf("scheme = %q", verified.Scheme())
	}
}

func TestJWKSURICredentialRejectsAnExplicitEmptyFragment(t *testing.T) {
	t.Parallel()

	if _, err := signaturekey.NewJWKSURICredential(
		"https://server.example#", "service-configuration", "server-key",
	); err == nil {
		t.Fatal("NewJWKSURICredential accepted an explicit empty fragment")
	}
}

func TestStructuredFieldStringsRoundTripOrFailBeforeEmission(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 22, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x49}, ed25519.SeedSize))
	for _, keyID := range []string{"key\tcontrol", "key-☃"} {
		if _, err := signaturekey.NewJWKSURICredential("https://server.example", "service-configuration", keyID); err == nil {
			t.Fatalf("NewJWKSURICredential accepted key ID %q", keyID)
		}
	}

	key, err := jose.NewEd25519SigningKey(`key"slash\`, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewJWKSURICredential(
		"https://server.example", "service-configuration", key.ID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://peer.example/federate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(
		request, key, credential, fixedClock(now),
		signaturekey.SignOptions{Nonce: `attempt"slash\`},
	); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(
		request, fixedClock(now),
		signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWKSURI}},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, _, keyID, ok := prepared.Credential().JWKSURI()
	if !ok || keyID != key.ID() {
		t.Fatalf("parsed key ID = %q, %t", keyID, ok)
	}

	badNonceRequest, _ := http.NewRequest(http.MethodGet, "https://peer.example/federate", nil)
	if err := signaturekey.SignRequest(
		badNonceRequest, key, credential, fixedClock(now),
		signaturekey.SignOptions{Nonce: "attempt\tcontrol"},
	); err == nil {
		t.Fatal("SignRequest accepted an unrepresentable nonce")
	}
	if badNonceRequest.Header.Get("Signature") != "" || badNonceRequest.Header.Get("Signature-Input") != "" ||
		badNonceRequest.Header.Get("Signature-Key") != "" {
		t.Fatal("failed signing emitted signature headers")
	}
}

func TestSigningRejectsUnsupportedAdditionalComponentsBeforeEmission(t *testing.T) {
	t.Parallel()

	key, err := jose.NewEd25519SigningKey(
		"request-key",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4a}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range []string{
		"", "Content-Type", "x-☃", "x header", "@query-param",
		"signature", "signature-input", "signature-key",
	} {
		request, _ := http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
		err := signaturekey.SignRequest(
			request, key, credential,
			fixedClock(time.Date(2026, 8, 29, 22, 0, 0, 0, time.UTC)),
			signaturekey.SignOptions{AdditionalComponents: []string{component}},
		)
		if err == nil {
			t.Fatalf("SignRequest accepted component %q", component)
		}
		if request.Header.Get("Signature") != "" || request.Header.Get("Signature-Input") != "" ||
			request.Header.Get("Signature-Key") != "" {
			t.Fatalf("failed signing with %q emitted signature headers", component)
		}
	}
}

func TestSigningFailureLeavesTheCallerRequestUnchanged(t *testing.T) {
	t.Parallel()

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4c}, ed25519.SeedSize))
	key, err := jose.NewEd25519SigningKey("request-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, "https://resource.example/records", strings.NewReader(`{"value":1}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Existing", "retained")
	request.GetBody = nil
	request.ContentLength = -1
	originalHeaders := request.Header.Clone()
	err = signaturekey.SignRequest(
		request, key, credential, fixedClock(time.Date(2026, 8, 29, 22, 0, 0, 0, time.UTC)),
		signaturekey.SignOptions{AdditionalComponents: []string{"content-digest", "x-required"}},
	)
	if err == nil {
		t.Fatal("SignRequest accepted an absent covered header")
	}
	if !reflect.DeepEqual(request.Header, originalHeaders) {
		t.Fatalf("headers after failure = %#v, want %#v", request.Header, originalHeaders)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"value":1}` {
		t.Fatalf("body after failure = %q", body)
	}
	if request.GetBody != nil || request.ContentLength != -1 {
		t.Fatal("failed signing changed request body metadata")
	}

	failing, err := jose.NewSigningKey("request-key", failingRequestSigner{public: privateKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	request, _ = http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	request.Header.Set("X-Existing", "retained")
	originalHeaders = request.Header.Clone()
	if err := signaturekey.SignRequest(
		request, failing, credential, fixedClock(time.Date(2026, 8, 29, 22, 0, 0, 0, time.UTC)), signaturekey.SignOptions{},
	); err == nil {
		t.Fatal("SignRequest unexpectedly succeeded with a failing signer")
	}
	if !reflect.DeepEqual(request.Header, originalHeaders) {
		t.Fatalf("headers after signer failure = %#v, want %#v", request.Header, originalHeaders)
	}
}

func TestSigningInitializesANilHeaderMap(t *testing.T) {
	t.Parallel()

	key, err := jose.NewEd25519SigningKey(
		"request-key", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4d}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	request.Header = nil
	if err := signaturekey.SignRequest(
		request, key, credential, fixedClock(time.Date(2026, 8, 29, 22, 0, 0, 0, time.UTC)), signaturekey.SignOptions{},
	); err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("Signature") == "" || request.Header.Get("Signature-Key") == "" {
		t.Fatalf("signed headers = %#v", request.Header)
	}
}

type failingRequestSigner struct {
	public ed25519.PublicKey
}

func (signer failingRequestSigner) Public() crypto.PublicKey { return signer.public }

func (failingRequestSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("test signer failed")
}

var _ crypto.Signer = failingRequestSigner{}

func TestJWTCredentialRemainsOpaqueUntilTheCallerSelectsItsProofKey(t *testing.T) {
	now := time.Date(2026, 8, 28, 22, 15, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	signingKey, err := jose.NewEd25519SigningKey("confirmation-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewJWTCredential("opaque.current.token")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, signingKey, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(
		request,
		fixedClock(now),
		signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWT}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := prepared.Credential().JWT(); !ok || got != "opaque.current.token" {
		t.Fatalf("JWT credential = %q, %t", got, ok)
	}
	verified, err := prepared.Verify(signingKey.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	if verified.Scheme() != signaturekey.SchemeJWT || verified.Signer() != "" {
		t.Fatalf("generic proof inferred credential semantics: scheme=%q signer=%q", verified.Scheme(), verified.Signer())
	}
}

func TestUnsupportedSchemeReturnsNegotiableTypedError(t *testing.T) {
	now := time.Date(2026, 8, 28, 22, 30, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	signingKey, err := jose.NewEd25519SigningKey("request-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(signingKey.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, signingKey, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Signature-Key", "sig=future")
	_, err = signaturekey.PrepareRequest(
		request,
		fixedClock(now),
		signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK, signaturekey.SchemeJWT}},
	)
	var failure *signaturekey.Error
	if !errors.As(err, &failure) {
		t.Fatalf("error = %T %v, want *signaturekey.Error", err, err)
	}
	if failure.Code != signaturekey.ErrorUnsupportedScheme {
		t.Fatalf("code = %q, want %q", failure.Code, signaturekey.ErrorUnsupportedScheme)
	}
	if got, want := failure.AcceptedSchemes, []signaturekey.Scheme{signaturekey.SchemeHWK, signaturekey.SchemeJWT}; !equalSchemes(got, want) {
		t.Fatalf("accepted schemes = %#v, want %#v", got, want)
	}
}

func TestRequestProofAcceptsOneArbitraryMatchingLabel(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 15, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x47}, ed25519.SeedSize))
	key, err := jose.NewEd25519SigningKey(
		"request-key",
		privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, key, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Signature-Key", "Signature-Input"} {
		request.Header.Set(name, strings.Replace(request.Header.Get(name), "sig=", "sig1=", 1))
	}
	params := strings.TrimPrefix(request.Header.Get("Signature-Input"), "sig1=")
	base := `"@method": GET` + "\n" +
		`"@authority": resource.example` + "\n" +
		`"@path": /items` + "\n" +
		`"signature-key": ` + request.Header.Get("Signature-Key") + "\n" +
		`"@signature-params": ` + params
	signature := ed25519.Sign(privateKey, []byte(base))
	request.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(signature)+":")

	prepared, err := signaturekey.PrepareRequest(
		request,
		fixedClock(now),
		signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Verify(key.PublicJWK()); err != nil {
		t.Fatal(err)
	}
}

func TestRequestProofSelectsOneApplicationLabelFromMultipleSignatures(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 20, 0, 0, time.UTC)
	key, err := jose.NewEd25519SigningKey(
		"request-key",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x49}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequest(request, key, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	request.Header.Set(
		"Signature-Input",
		request.Header.Get("Signature-Input")+", alt="+strings.TrimPrefix(request.Header.Get("Signature-Input"), "sig="),
	)
	request.Header.Set(
		"Signature",
		request.Header.Get("Signature")+", alt="+strings.TrimPrefix(request.Header.Get("Signature"), "sig="),
	)

	prepared, err := signaturekey.PrepareRequest(
		request,
		fixedClock(now),
		signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK},
			SignatureLabel:  "sig",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Verify(key.PublicJWK()); err != nil {
		t.Fatal(err)
	}
}

func TestRequestProofRejectsMismatchedOrAmbiguousLabels(t *testing.T) {
	now := time.Date(2026, 8, 29, 20, 30, 0, 0, time.UTC)
	key, err := jose.NewEd25519SigningKey(
		"request-key",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x48}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}

	newSignedRequest := func(t *testing.T) *http.Request {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := signaturekey.SignRequest(request, key, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
			t.Fatal(err)
		}
		return request
	}

	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{
			name: "Signature-Key label differs",
			mutate: func(request *http.Request) {
				request.Header.Set("Signature-Key", strings.Replace(request.Header.Get("Signature-Key"), "sig=", "sig1=", 1))
			},
		},
		{
			name: "Signature label differs",
			mutate: func(request *http.Request) {
				request.Header.Set("Signature", strings.Replace(request.Header.Get("Signature"), "sig=", "sig1=", 1))
			},
		},
		{
			name: "multiple Signature-Input members",
			mutate: func(request *http.Request) {
				request.Header.Set("Signature-Input", request.Header.Get("Signature-Input")+", sig1="+strings.TrimPrefix(request.Header.Get("Signature-Input"), "sig="))
			},
		},
		{
			name: "duplicate matching Signature-Key member",
			mutate: func(request *http.Request) {
				request.Header.Set("Signature-Key", request.Header.Get("Signature-Key")+", "+request.Header.Get("Signature-Key"))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newSignedRequest(t)
			test.mutate(request)
			if _, err := signaturekey.PrepareRequest(
				request,
				fixedClock(now),
				signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK}},
			); err == nil {
				t.Fatal("invalid label correlation was accepted")
			}
		})
	}
}

func TestJWTCredentialAcceptsStrictCacheRequest(t *testing.T) {
	credential, err := signaturekey.ParseCredential([]string{`sig1=jwt;jwt="opaque.current.token";cache`})
	if err != nil {
		t.Fatal(err)
	}
	if credential.Scheme() != signaturekey.SchemeJWT {
		t.Fatalf("scheme = %q, want %q", credential.Scheme(), signaturekey.SchemeJWT)
	}
	if !credential.CacheRequested() {
		t.Fatal("cache request was not retained")
	}
	if token, ok := credential.JWT(); !ok || token != "opaque.current.token" {
		t.Fatalf("JWT = %q, %t", token, ok)
	}
}

func TestJWTCredentialRejectsInvalidCacheAndOtherParameters(t *testing.T) {
	for _, value := range []string{
		`sig=jwt;jwt="opaque.current.token";cache="true"`,
		`sig=jwt;jwt="opaque.current.token";cache=?0`,
		`sig=jwt;jwt="opaque.current.token";unknown="value"`,
		`sig=jwt;jwt="opaque.current.token";cache;cache`,
		`sig=jwt;jwt="first";jwt="second"`,
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := signaturekey.ParseCredential([]string{value}); err == nil {
				t.Fatal("invalid Signature-Key parameters were accepted")
			}
		})
	}
}

func TestPrepareRequestClassifiesMissingProofFieldsAsInvalidRequest(t *testing.T) {
	now := time.Date(2026, 8, 29, 21, 0, 0, 0, time.UTC)
	key, err := jose.NewEd25519SigningKey(
		"request-key",
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4a}, ed25519.SeedSize)),
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{"Signature", "Signature-Input", "Signature-Key"} {
		t.Run(missing, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := signaturekey.SignRequest(request, key, credential, fixedClock(now), signaturekey.SignOptions{}); err != nil {
				t.Fatal(err)
			}
			request.Header.Del(missing)
			_, err = signaturekey.PrepareRequest(
				request,
				fixedClock(now),
				signaturekey.VerifyOptions{AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK}},
			)
			var failure *signaturekey.Error
			if !errors.As(err, &failure) || failure.Code != signaturekey.ErrorInvalidRequest {
				t.Fatalf("error = %T %v, want invalid_request Signature-Key error", err, err)
			}
		})
	}
}

func equalSchemes(left, right []signaturekey.Scheme) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
