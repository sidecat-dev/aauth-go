package signaturekey_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func newTestAlgorithmKey(t *testing.T, id, algorithm string) jose.SigningKey {
	t.Helper()
	var signer crypto.Signer
	var err error
	switch algorithm {
	case jose.Ed25519Algorithm:
		_, signer, err = ed25519.GenerateKey(rand.Reader)
	case jose.ES256Algorithm:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jose.ES384Algorithm:
		signer, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	default:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.NewSigningKeyForAlgorithm(id, algorithm, signer)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestHWKRequestsVerifyUnderEachAcceptedAlgorithm(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	members := map[string][]string{
		jose.Ed25519Algorithm: {"kty", "crv", "x", "alg"},
		jose.ES256Algorithm:   {"kty", "crv", "x", "y", "alg"},
		jose.ES384Algorithm:   {"kty", "crv", "x", "y", "alg"},
		jose.RS256Algorithm:   {"kty", "n", "e", "alg"},
		jose.PS256Algorithm:   {"kty", "n", "e", "alg"},
	}
	for _, algorithm := range jose.SignatureAlgorithms() {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			key := newTestAlgorithmKey(t, "request-key", algorithm)
			request, err := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := signaturekey.SignHWKRequest(request, key, fixedClock(now)); err != nil {
				t.Fatal(err)
			}
			dictionary, err := httpsfv.UnmarshalDictionary(request.Header.Values("Signature-Key"))
			if err != nil {
				t.Fatal(err)
			}
			member, _ := dictionary.Get("sig")
			if got := member.(httpsfv.Item).Params.Names(); !reflect.DeepEqual(got, members[algorithm]) {
				t.Fatalf("hwk parameters = %v, want %v", got, members[algorithm])
			}
			prepared, err := signaturekey.PrepareRequest(request, fixedClock(now), signaturekey.VerifyOptions{
				AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
				AcceptedAlgorithms: jose.SignatureAlgorithms(),
			})
			if err != nil {
				t.Fatal(err)
			}
			inline, ok := prepared.Credential().InlineJWK()
			if !ok || !inline.Equal(key.PublicJWK()) {
				t.Fatalf("InlineJWK() = %#v, %t", inline, ok)
			}
			proof, err := prepared.Verify(inline)
			if err != nil {
				t.Fatal(err)
			}
			identity, _ := key.PublicJWK().ThumbprintURI()
			if proof.Signer() != identity || proof.Label() != "sig" {
				t.Fatalf("signer = %q label = %q, want %q", proof.Signer(), proof.Label(), identity)
			}

			changed := request.Clone(request.Context())
			changed.Header = request.Header.Clone()
			changed.URL.Path = "/other"
			prepared, err = signaturekey.PrepareRequest(changed, fixedClock(now), signaturekey.VerifyOptions{
				AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
				AcceptedAlgorithms: jose.SignatureAlgorithms(),
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = prepared.Verify(inline)
			assertSignatureErrorCode(t, err, signaturekey.ErrorInvalidSignature)
		})
	}
}

func TestEndpointAcceptsOnlyItsListedAlgorithms(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	signed := func(algorithm string) *http.Request {
		request, err := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := signaturekey.SignHWKRequest(request, newTestAlgorithmKey(t, "request-key", algorithm), fixedClock(now)); err != nil {
			t.Fatal(err)
		}
		return request
	}
	tests := []struct {
		name      string
		algorithm string
		accepted  []string
		want      []string
	}{
		{name: "default endpoint", algorithm: jose.ES384Algorithm, want: jose.TokenAlgorithms()},
		{name: "RSA-only endpoint", algorithm: jose.Ed25519Algorithm, accepted: []string{jose.PS256Algorithm}, want: []string{jose.PS256Algorithm}},
		{name: "PKCS #1 is not PSS", algorithm: jose.RS256Algorithm, accepted: []string{jose.PS256Algorithm, jose.ES256Algorithm}, want: []string{jose.PS256Algorithm, jose.ES256Algorithm}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := signaturekey.PrepareRequest(signed(test.algorithm), fixedClock(now), signaturekey.VerifyOptions{
				AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
				AcceptedAlgorithms: test.accepted,
			})
			assertSignatureErrorCode(t, err, signaturekey.ErrorUnsupportedAlgorithm)
			var failure *signaturekey.Error
			if errors.As(err, &failure); !reflect.DeepEqual(failure.AcceptedAlgorithms, test.want) {
				t.Fatalf("accepted algorithms = %v, want %v", failure.AcceptedAlgorithms, test.want)
			}
		})
	}
	_, err := signaturekey.PrepareRequest(signed(jose.Ed25519Algorithm), fixedClock(now), signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
		AcceptedAlgorithms: []string{"EdDSA"},
	})
	assertSignatureErrorCode(t, err, signaturekey.ErrorInvalidRequest)
}

func TestHWKMemberFollowsAlgorithmDetermination(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	ec := newTestAlgorithmKey(t, "request-key", jose.ES256Algorithm).PublicJWK()
	rsaKey := newTestAlgorithmKey(t, "request-key", jose.PS256Algorithm).PublicJWK()
	tests := []struct {
		name   string
		member string
		want   signaturekey.ErrorCode
	}{
		{name: "EC without y", member: `hwk;kty="EC";crv="P-256";x="` + ec.X + `";alg="ES256"`, want: signaturekey.ErrorInvalidKey},
		{name: "EC with kid", member: `hwk;kty="EC";crv="P-256";x="` + ec.X + `";y="` + ec.Y + `";alg="ES256";kid="k1"`, want: signaturekey.ErrorInvalidKey},
		{name: "EC on the wrong curve", member: `hwk;kty="EC";crv="P-384";x="` + ec.X + `";y="` + ec.Y + `";alg="ES256"`, want: signaturekey.ErrorInvalidKey},
		{name: "EC without alg", member: `hwk;kty="EC";crv="P-256";x="` + ec.X + `";y="` + ec.Y + `"`, want: signaturekey.ErrorUnsupportedAlgorithm},
		{name: "RSA without exponent", member: `hwk;kty="RSA";n="` + rsaKey.N + `";alg="PS256"`, want: signaturekey.ErrorInvalidKey},
		{name: "RSA naming neither padding nor hash", member: `hwk;kty="RSA";n="` + rsaKey.N + `";e="AQAB";alg="RSA"`, want: signaturekey.ErrorUnsupportedAlgorithm},
		{name: "RSA with private exponent", member: `hwk;kty="RSA";n="` + rsaKey.N + `";e="AQAB";d="AQAB";alg="PS256"`, want: signaturekey.ErrorInvalidKey},
		{name: "post-quantum key type", member: `hwk;kty="AKP";pub="AAAA";alg="ML-DSA-44"`, want: signaturekey.ErrorUnsupportedAlgorithm},
		{name: "member of another key type", member: `hwk;kty="EC";crv="P-256";x="` + ec.X + `";y="` + ec.Y + `";e="AQAB";alg="ES256"`, want: signaturekey.ErrorInvalidKey},
		{name: "member not understood", member: `hwk;kty="EC";crv="P-256";x="` + ec.X + `";y="` + ec.Y + `";alg="ES256";use="sig";ext`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "https://resource.example/items", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := signaturekey.SignHWKRequest(request, testDiscoverySigningKey(t, "request-key", 0x51), fixedClock(now)); err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Signature-Key", "sig="+test.member)
			_, err = signaturekey.PrepareRequest(request, fixedClock(now), signaturekey.VerifyOptions{
				AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
				AcceptedAlgorithms: jose.SignatureAlgorithms(),
			})
			if test.want == "" {
				if err != nil {
					t.Fatalf("PrepareRequest() = %v; an hwk member a verifier does not understand is ignored", err)
				}
				return
			}
			assertSignatureErrorCode(t, err, test.want)
		})
	}
}
