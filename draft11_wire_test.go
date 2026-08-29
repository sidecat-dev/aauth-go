package aauth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestDraft11Ed25519WireJourney(t *testing.T) {
	now := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	issuerKey := draft11SigningKey(t, "issuer-key")
	requestKey := draft11SigningKey(t, "request-key")

	for name, key := range map[string]jose.JWK{
		"missing alg": {
			Kty: "OKP", Crv: "Ed25519", X: requestKey.PublicJWK().X,
		},
		"polymorphic EdDSA": {
			Kty: "OKP", Crv: "Ed25519", X: requestKey.PublicJWK().X, Alg: "EdDSA",
		},
		"inconsistent curve": {
			Kty: "OKP", Crv: "Ed448", X: requestKey.PublicJWK().X, Alg: "Ed25519",
		},
	} {
		t.Run("reject JWK "+name, func(t *testing.T) {
			if _, err := key.PublicKey(); err == nil {
				t.Fatalf("accepted %s JWK", name)
			}
		})
	}
	if got := requestKey.PublicJWK().Alg; got != "Ed25519" {
		t.Fatalf("public JWK alg = %q, want Ed25519", got)
	}

	credential, err := aauth.MintAgentToken("https://issuer.example", issuerKey, aauth.AgentTokenRequest{
		Agent:     "aauth:agent@issuer.example",
		PublicKey: requestKey.PublicJWK(),
		Lifetime:  time.Hour,
	}, now, "draft11-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	header, err := jose.PeekHeader(credential)
	if err != nil {
		t.Fatal(err)
	}
	if header.Algorithm != "Ed25519" {
		t.Fatalf("JWT alg = %q, want Ed25519", header.Algorithm)
	}

	request, err := http.NewRequest(http.MethodPost, "https://resource.example/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithHWK(request, requestKey, clock); err != nil {
		t.Fatal(err)
	}
	if got := request.Header.Get("Signature-Key"); !strings.Contains(got, `;alg="Ed25519"`) {
		t.Fatalf("Signature-Key = %q, want fully specified hwk alg", got)
	}
	verified, err := aauth.VerifyRequest(context.Background(), request, nil, clock, aauth.VerifyRequestOptions{
		AllowedSignatureKeyTypes: []string{aauth.SignatureKeyHWK},
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified.SignatureKeyType != aauth.SignatureKeyHWK || verified.PublicKey.Alg != "Ed25519" {
		t.Fatalf("verified request = %#v", verified)
	}
}

func TestDraft08SignatureKeyFailuresAreTypedAndNegotiable(t *testing.T) {
	now := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := draft11SigningKey(t, "request-key")
	base, err := http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithHWK(base, key, clock); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		header string
		want   aauth.SignatureErrorCode
	}{
		{
			name:   "missing hwk alg",
			header: strings.Replace(base.Header.Get("Signature-Key"), `;alg="Ed25519"`, "", 1),
			want:   aauth.SignatureErrorUnsupportedAlgorithm,
		},
		{
			name:   "polymorphic hwk alg",
			header: strings.Replace(base.Header.Get("Signature-Key"), `;alg="Ed25519"`, `;alg="EdDSA"`, 1),
			want:   aauth.SignatureErrorUnsupportedAlgorithm,
		},
		{
			name:   "unknown scheme",
			header: strings.Replace(base.Header.Get("Signature-Key"), "sig=hwk;", "sig=future-key;", 1),
			want:   aauth.SignatureErrorUnsupportedScheme,
		},
		{
			name:   "parameterless unknown scheme",
			header: "sig=future-key",
			want:   aauth.SignatureErrorUnsupportedScheme,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := base.Clone(context.Background())
			request.Header.Set("Signature-Key", test.header)
			_, err := aauth.VerifyRequest(context.Background(), request, nil, clock, aauth.VerifyRequestOptions{
				AllowedSignatureKeyTypes: []string{aauth.SignatureKeyHWK},
			})
			var signatureError *aauth.SignatureError
			if !errors.As(err, &signatureError) || signatureError.Code != test.want {
				t.Fatalf("error = %v, want SignatureError %s", err, test.want)
			}
		})
	}

	response := &http.Response{Header: make(http.Header)}
	response.Header.Set("Signature-Error", "error=unsupported_algorithm")
	response.Header.Set("Accept-Signature-Alg", "Ed25519, ES256")
	response.Header.Set("Accept-Signature-Scheme", "jwt, hwk")
	decoded, err := aauth.DecodeSignatureErrorResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(decoded.AcceptedAlgorithms, ",") != "Ed25519,ES256" ||
		strings.Join(decoded.AcceptedSchemes, ",") != "jwt,hwk" {
		t.Fatalf("decoded negotiation = %#v", decoded)
	}
	if encoded, err := aauth.FormatSignatureError(*decoded); err != nil || encoded != "error=unsupported_algorithm" {
		t.Fatalf("formatted Signature-Error = %q, %v", encoded, err)
	}
}

func TestDraft08IssuerMetadataFailuresRetainTheirProtocolCodes(t *testing.T) {
	for _, test := range []struct {
		resolution aauth.KeyResolutionCode
		want       aauth.SignatureErrorCode
	}{
		{aauth.KeyResolutionIssuerMissing, aauth.SignatureErrorIssuerMissing},
		{aauth.KeyResolutionIssuerMismatch, aauth.SignatureErrorIssuerMismatch},
	} {
		for _, path := range []struct {
			name    string
			request *http.Request
			options aauth.VerifyRequestOptions
		}{
			{
				name:    "jwks_uri",
				request: draft11JWKSURIRequest(t),
				options: aauth.VerifyRequestOptions{AllowedSignatureKeyTypes: []string{aauth.SignatureKeyJWKSURI}},
			},
			{
				name:    "jwt",
				request: draft11JWTRequest(t),
				options: aauth.VerifyRequestOptions{AllowedSignatureKeyTypes: []string{aauth.SignatureKeyJWT}},
			},
		} {
			t.Run(string(test.resolution)+"/"+path.name, func(t *testing.T) {
				err := &aauth.KeyResolutionError{Code: test.resolution, Cause: errors.New("metadata rejected")}
				_, verifyErr := aauth.VerifyRequest(
					context.Background(),
					path.request,
					failingDraft11Resolver{err: err},
					aauth.ClockFunc(func() time.Time { return time.Unix(2_000_000_100, 0) }),
					path.options,
				)
				var signatureError *aauth.SignatureError
				if !errors.As(verifyErr, &signatureError) || signatureError.Code != test.want {
					t.Fatalf("resolution %s error = %v, want %s", test.resolution, verifyErr, test.want)
				}
			})
		}
	}
}

func TestDraft08HTTPDiscoveryClassifiesMissingAndMismatchedIssuer(t *testing.T) {
	for _, test := range []struct {
		name     string
		metadata string
		want     aauth.KeyResolutionCode
	}{
		{
			name:     "missing",
			metadata: `{"jwks_uri":"https://keys.example/jwks"}`,
			want:     aauth.KeyResolutionIssuerMissing,
		},
		{
			name:     "mismatch",
			metadata: `{"issuer":"https://other.example","jwks_uri":"https://keys.example/jwks"}`,
			want:     aauth.KeyResolutionIssuerMismatch,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			gateway := newLogicalGateway(t, map[string]http.Handler{
				"issuer.example": http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
					response.Header().Set("Content-Type", "application/json")
					_, _ = response.Write([]byte(test.metadata))
				}),
			})
			defer gateway.Close()

			resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
				Client: gateway.Client(),
				Clock:  aauth.ClockFunc(func() time.Time { return time.Unix(2_000_000_100, 0) }),
				Admit:  func(context.Context, string) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = resolver.ResolveKey(
				context.Background(),
				"https://issuer.example",
				aauth.AgentDiscoveryDocument,
				"issuer-key",
			)
			var resolutionError *aauth.KeyResolutionError
			if !errors.As(err, &resolutionError) || resolutionError.Code != test.want {
				t.Fatalf("resolution error = %v, want %s", err, test.want)
			}
		})
	}
}

type failingDraft11Resolver struct{ err error }

func (resolver failingDraft11Resolver) ResolveKey(context.Context, string, string, string) (jose.JWK, error) {
	return jose.JWK{}, resolver.err
}

func draft11JWKSURIRequest(t *testing.T) *http.Request {
	t.Helper()
	key := draft11SigningKey(t, "request-key")
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequestWithJWKSURI(
		request,
		key,
		"https://issuer.example",
		aauth.AgentDiscoveryDocument,
		aauth.ClockFunc(func() time.Time { return time.Unix(2_000_000_100, 0) }),
	); err != nil {
		t.Fatal(err)
	}
	return request
}

func draft11JWTRequest(t *testing.T) *http.Request {
	t.Helper()
	issuerKey := draft11SigningKey(t, "issuer-key")
	requestKey := draft11SigningKey(t, "request-key")
	now := time.Unix(2_000_000_100, 0)
	credential, err := aauth.MintAgentToken(
		"https://issuer.example",
		issuerKey,
		aauth.AgentTokenRequest{
			Agent:     "aauth:agent@issuer.example",
			PublicKey: requestKey.PublicJWK(),
			Lifetime:  time.Hour,
		},
		now,
		"issuer-classification-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequest(
		request,
		requestKey,
		credential,
		aauth.ClockFunc(func() time.Time { return now }),
	); err != nil {
		t.Fatal(err)
	}
	return request
}

func draft11SigningKey(t *testing.T, id string) jose.SigningKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.NewEd25519SigningKey(id, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
