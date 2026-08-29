package aauth_test

import (
	"context"
	"errors"
	"fmt"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"net/http"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestDraft08JWKSValidatesOnlyTheExactRequestedKid(t *testing.T) {
	now := time.Unix(2_000_000_100, 0)
	selected := draft11SigningKey(t, "selected-key")
	gateway := newLogicalGateway(t, map[string]http.Handler{
		"issuer.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/.well-known/aauth-resource.json":
				_, _ = fmt.Fprint(response, `{"issuer":"https://issuer.example","jwks_uri":"https://keys.example/jwks"}`)
			default:
				http.NotFound(response, request)
			}
		}),
		"keys.example": http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprintf(response, `{"keys":[
				{"kty":"AKP","alg":"ML-DSA-44","kid":"future-key","x":"future"},
				{"kty":"OKP","crv":"Ed25519","x":"missing","kid":"missing-alg"},
				{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":"legacy","kid":"legacy-key"},
				{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":"bad","kid":""},
				{"kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":%q,"kid":"selected-key"}
			]}`, selected.PublicJWK().X)
		}),
	})
	defer gateway.Close()

	resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
		Client: gateway.Client(),
		Clock:  aauth.ClockFunc(func() time.Time { return now }),
		Admit:  func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveKey(
		context.Background(),
		"https://issuer.example",
		aauth.ResourceDiscoveryDocument,
		selected.ID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.Equal(selected.PublicJWK()) {
		t.Fatalf("resolved key = %#v, want selected key", resolved)
	}
}

func TestDraft08SelectedUnsupportedJWKSAlgorithmUsesNegotiableEnvelope(t *testing.T) {
	for _, algorithm := range []string{"", "EdDSA", "ML-DSA-44"} {
		name := algorithm
		if name == "" {
			name = "missing"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Unix(2_000_000_100, 0)
			key := draft11SigningKey(t, "selected-key")
			gateway := newLogicalGateway(t, map[string]http.Handler{
				"issuer.example": http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
					switch request.URL.Path {
					case "/.well-known/aauth-resource.json":
						_, _ = fmt.Fprint(response, `{"issuer":"https://issuer.example","jwks_uri":"https://keys.example/jwks"}`)
					default:
						http.NotFound(response, request)
					}
				}),
				"keys.example": http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
					_, _ = fmt.Fprintf(response, `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":%q,"x":%q,"kid":"selected-key"}]}`, algorithm, key.PublicJWK().X)
				}),
			})
			defer gateway.Close()

			resolver, err := aauth.NewHTTPKeyResolver(aauth.HTTPKeyResolverConfig{
				Client: gateway.Client(),
				Clock:  aauth.ClockFunc(func() time.Time { return now }),
				Admit:  func(context.Context, string) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := aauth.SignRequestWithJWKSURI(
				request,
				key,
				"https://issuer.example",
				aauth.ResourceDiscoveryDocument,
				aauth.ClockFunc(func() time.Time { return now }),
			); err != nil {
				t.Fatal(err)
			}
			_, err = aauth.VerifyRequest(
				context.Background(),
				request,
				resolver,
				aauth.ClockFunc(func() time.Time { return now }),
				aauth.VerifyRequestOptions{AllowedSignatureKeyTypes: []string{aauth.SignatureKeyJWKSURI}},
			)
			var signatureError *aauth.SignatureError
			if !errors.As(err, &signatureError) ||
				signatureError.Code != aauth.SignatureErrorUnsupportedAlgorithm ||
				len(signatureError.AcceptedAlgorithms) != 1 ||
				signatureError.AcceptedAlgorithms[0] != jose.Ed25519Algorithm {
				t.Fatalf("selected alg %q error = %v (%#v)", algorithm, err, signatureError)
			}
		})
	}
}
