package signaturekey_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

const testKeySetURL = "https://client.example/keys.jwks"

func TestJWKSRequestUsesTheExactURLAsSignerIdentity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 13, 0, 0, 0, time.UTC)
	key := testDiscoverySigningKey(t, "key-1", 0x52)
	credential, err := signaturekey.NewJWKSCredential(testKeySetURL, key.ID())
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
	if got, want := request.Header.Get("Signature-Key"), `sig=jwks;url="`+testKeySetURL+`";kid="key-1"`; got != want {
		t.Fatalf("Signature-Key = %q, want %q", got, want)
	}
	prepared, err := signaturekey.PrepareRequest(request, fixedClock(now), signaturekey.VerifyOptions{
		AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWKS},
	})
	if err != nil {
		t.Fatal(err)
	}
	trusted := signaturekey.StaticJWKSResolver{{URL: testKeySetURL, KeyID: key.ID()}: key.PublicJWK()}
	proof, err := prepared.VerifyJWKS(context.Background(), trusted)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Scheme() != signaturekey.SchemeJWKS || proof.Signer() != testKeySetURL {
		t.Fatalf("verified scheme = %q signer = %q", proof.Scheme(), proof.Signer())
	}

	// A URL that differs in any byte names a different signer, even where a
	// URL normalizer would treat the two as equivalent.
	for _, variant := range []string{
		"https://CLIENT.example/keys.jwks",
		"https://client.example:443/keys.jwks",
		"https://client.example/./keys.jwks",
	} {
		other := signaturekey.StaticJWKSResolver{{URL: variant, KeyID: key.ID()}: key.PublicJWK()}
		_, err := prepared.VerifyJWKS(context.Background(), other)
		assertSignatureErrorCode(t, err, signaturekey.ErrorUnknownKey)
	}
}

func TestJWKSMemberRequiresHTTPSURLAndKeyID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 13, 0, 0, 0, time.UTC)
	key := testDiscoverySigningKey(t, "key-1", 0x53)
	for _, member := range []string{
		`jwks;url="` + testKeySetURL + `"`,
		`jwks;kid="key-1"`,
		`jwks;url="http://client.example/keys.jwks";kid="key-1"`,
		`jwks;url="` + testKeySetURL + `";kid="key-1";id="https://client.example"`,
	} {
		request, err := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := signaturekey.SignHWKRequest(request, key, fixedClock(now)); err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Signature-Key", "sig="+member)
		_, err = signaturekey.PrepareRequest(request, fixedClock(now), signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWKS},
		})
		assertSignatureErrorCode(t, err, signaturekey.ErrorInvalidKey)
	}
	if _, err := signaturekey.NewJWKSCredential("http://client.example/keys.jwks", "key-1"); err == nil {
		t.Fatal("NewJWKSCredential accepted a non-HTTPS URL")
	}
}

func TestHTTPKeyResolverFetchesADirectJWKSOnce(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 13, 0, 0, 0, time.UTC)
	key := testDiscoverySigningKey(t, "key-1", 0x54).PublicJWK()
	var fetches atomic.Int32
	var admitted []string
	client := &http.Client{Transport: discoveryRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		fetches.Add(1)
		if request.URL.String() != testKeySetURL {
			t.Errorf("fetched %q, want only the jwks url", request.URL)
		}
		body, _ := json.Marshal(map[string]any{"keys": []any{
			map[string]any{"kty": "AKP", "alg": "ML-DSA-44", "kid": "future", "pub": "AAAA"},
			key,
		}})
		return discoveryResponse(request, body, "max-age=300"), nil
	})}
	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: client, TransportEnforcesEgress: true, Clock: fixedClock(now),
		Admit: func(_ context.Context, endpoint string) error {
			admitted = append(admitted, endpoint)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		resolved, err := resolver.ResolveJWKSKey(context.Background(), testKeySetURL, "key-1")
		if err != nil || !resolved.Equal(key) {
			t.Fatalf("ResolveJWKSKey() = %#v, %v", resolved, err)
		}
	}
	_, err = resolver.ResolveJWKSKey(context.Background(), testKeySetURL, "absent")
	assertSignatureErrorCode(t, signaturekey.NormalizeError(err, signaturekey.ErrorInvalidKey), signaturekey.ErrorUnknownKey)
	if got := fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want one within the refresh floor", got)
	}
	if strings.Join(admitted, ",") != testKeySetURL {
		t.Fatalf("admitted endpoints = %v", admitted)
	}
}

func TestSignRequestsWritesEveryKeyBeforeAnySignature(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 13, 0, 0, 0, time.UTC)
	pseudonym := testDiscoverySigningKey(t, "pseudonym", 0x55)
	service := testDiscoverySigningKey(t, "key-1", 0x56)
	hwk, err := signaturekey.NewHWKCredential(pseudonym.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := signaturekey.NewJWKSCredential(testKeySetURL, service.ID())
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signaturekey.SignRequests(request, []signaturekey.RequestSignature{
		{Label: "sig1", Key: pseudonym, Credential: hwk},
		{Label: "sig2", Key: service, Credential: jwks},
	}, fixedClock(now), signaturekey.SignOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"sig1=", "sig2="} {
		if !strings.Contains(request.Header.Get("Signature-Key"), label) ||
			!strings.Contains(request.Header.Get("Signature-Input"), label) {
			t.Fatalf("headers lack %s: %#v", label, request.Header)
		}
	}
	trusted := signaturekey.StaticJWKSResolver{{URL: testKeySetURL, KeyID: service.ID()}: service.PublicJWK()}
	verify := func(request *http.Request) error {
		first, err := signaturekey.PrepareRequest(request, fixedClock(now), signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK}, SignatureLabel: "sig1",
		})
		if err != nil {
			return err
		}
		inline, _ := first.Credential().InlineJWK()
		if _, err := first.Verify(inline); err != nil {
			return err
		}
		second, err := signaturekey.PrepareRequest(request, fixedClock(now), signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWKS}, SignatureLabel: "sig2",
		})
		if err != nil {
			return err
		}
		_, err = second.VerifyJWKS(context.Background(), trusted)
		return err
	}
	if err := verify(request); err != nil {
		t.Fatal(err)
	}

	// Each signature covers the whole Signature-Key field, so changing the
	// second member also invalidates the first signature.
	request.Header.Set("Signature-Key", strings.Replace(request.Header.Get("Signature-Key"), `kid="key-1"`, `kid="key-2"`, 1))
	assertSignatureErrorCode(t, verify(request), signaturekey.ErrorInvalidSignature)

	for _, signatures := range [][]signaturekey.RequestSignature{
		{{Label: "sig", Key: pseudonym, Credential: hwk}, {Label: "sig", Key: service, Credential: jwks}},
		{{Label: "Sig", Key: pseudonym, Credential: hwk}},
		{{Label: "sig", Key: service, Credential: hwk}},
		nil,
	} {
		unsigned, _ := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
		if err := signaturekey.SignRequests(unsigned, signatures, fixedClock(now), signaturekey.SignOptions{}); err == nil ||
			unsigned.Header.Get("Signature-Key") != "" {
			t.Fatalf("SignRequests(%#v) = %v", signatures, err)
		}
	}
}
