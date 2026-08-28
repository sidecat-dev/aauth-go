package aauth_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestSignatureErrorWireContract(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		error aauth.SignatureError
		want  string
	}{
		{
			name: "required input",
			error: aauth.SignatureError{
				Code:          aauth.SignatureErrorInvalidInput,
				RequiredInput: []string{"@method", "signature-key"},
			},
			want: `error=invalid_input, required_input=("@method" "signature-key")`,
		},
		{
			name:  "unsupported algorithm has no embedded capability set",
			error: aauth.SignatureError{Code: aauth.SignatureErrorUnsupportedAlgorithm},
			want:  `error=unsupported_algorithm`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			header, err := aauth.FormatSignatureError(test.error)
			if err != nil {
				t.Fatal(err)
			}
			if header != test.want {
				t.Fatalf("Signature-Error = %q, want %q", header, test.want)
			}
			parsed, err := aauth.ParseSignatureError(header + `;future=?1`)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Code != test.error.Code ||
				strings.Join(parsed.RequiredInput, " ") != strings.Join(test.error.RequiredInput, " ") {
				t.Fatalf("parsed Signature-Error = %#v", parsed)
			}
		})
	}
}

func TestSignatureErrorPublicDetailIsReadOnly(t *testing.T) {
	t.Parallel()

	valueType := reflect.TypeOf(aauth.SignatureError{})
	if _, exists := valueType.FieldByName("PublicDetail"); exists {
		t.Fatal("SignatureError exposes mutable PublicDetail state")
	}
	if _, exists := reflect.TypeOf(&aauth.SignatureError{}).MethodByName("PublicDetail"); !exists {
		t.Fatal("SignatureError is missing the read-only PublicDetail accessor")
	}
}

func TestSignatureErrorResponseHeaderOverridesProblemBody(t *testing.T) {
	t.Parallel()

	response := &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header: http.Header{
			"Signature-Error": []string{`error=invalid_input, required_input=("@method" "signature-key")`},
			"Content-Type":    []string{"application/problem+json"},
		},
		Body: ioNopCloser(`{"type":"urn:ietf:params:sig-error:invalid_signature","status":401,"detail":"body is not authoritative"}`),
	}
	got, err := aauth.DecodeSignatureErrorResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != aauth.SignatureErrorInvalidInput || strings.Join(got.RequiredInput, " ") != "@method signature-key" {
		t.Fatalf("decoded signature error = %#v", got)
	}
}

func TestSignatureErrorResponseRequiresAuthoritativeHeader(t *testing.T) {
	t.Parallel()

	response := &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header:     http.Header{"Content-Type": []string{"application/problem+json"}},
		Body:       ioNopCloser(`{"type":"urn:ietf:params:sig-error:invalid_signature","status":401}`),
	}
	if _, err := aauth.DecodeSignatureErrorResponse(response); err == nil {
		t.Fatal("Problem Details without Signature-Error was accepted")
	}
}

func TestSignatureErrorIgnoresRFC8941UnknownMembers(t *testing.T) {
	t.Parallel()

	for _, header := range []string{
		`error=invalid_signature, future=:AQ==:`,
		`error=invalid_signature, future=1.5`,
		`error=invalid_signature, future`,
		`error=invalid_signature, future=(1 "value" :AQ==: ?1)`,
		`error=invalid_signature;future=:AQ==:`,
		`error=invalid_signature, required_input=42`,
	} {
		if parsed, err := aauth.ParseSignatureError(header); err != nil {
			t.Errorf("ParseSignatureError(%q): %v", header, err)
		} else if parsed.Code != aauth.SignatureErrorInvalidSignature {
			t.Errorf("ParseSignatureError(%q) code = %q", header, parsed.Code)
		}
	}
}

func TestSignatureErrorAppliesRFC8941DictionaryAndCodeSpecificSemantics(t *testing.T) {
	t.Parallel()

	t.Run("duplicate member uses last value", func(t *testing.T) {
		parsed, err := aauth.ParseSignatureError(`error=invalid_jwt, error=expired_jwt`)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Code != aauth.SignatureErrorExpiredJWT {
			t.Fatalf("duplicate error code = %q", parsed.Code)
		}
	})

	for _, header := range []string{
		`error="invalid_signature"`,
		`error=invalid_input, required_input=42`,
		`error=invalid_input, required_input=("")`,
		`error=invalid_signature, future=:not-base64:`,
	} {
		t.Run(header, func(t *testing.T) {
			if _, err := aauth.ParseSignatureError(header); err == nil {
				t.Fatalf("ParseSignatureError(%q) succeeded", header)
			}
		})
	}
}

func TestSignatureErrorCombinesMultipleHTTPFieldLines(t *testing.T) {
	t.Parallel()

	response := &http.Response{Header: make(http.Header)}
	response.Header.Add("Signature-Error", `error=invalid_input`)
	response.Header.Add("Signature-Error", `required_input=("@method" "@path")`)
	parsed, err := aauth.DecodeSignatureErrorResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Code != aauth.SignatureErrorInvalidInput ||
		strings.Join(parsed.RequiredInput, " ") != "@method @path" {
		t.Fatalf("combined Signature-Error = %#v", parsed)
	}
}

func TestSignatureErrorUsesStrictStructuredFieldStrings(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"contains\ttab", "non-ASCII-\u00e9"} {
		if _, err := aauth.FormatSignatureError(aauth.SignatureError{
			Code:          aauth.SignatureErrorInvalidInput,
			RequiredInput: []string{value},
		}); err == nil {
			t.Errorf("FormatSignatureError accepted RFC 8941-invalid string %q", value)
		}
	}

	value := `quote-" and slash-\`
	header, err := aauth.FormatSignatureError(aauth.SignatureError{
		Code:          aauth.SignatureErrorInvalidInput,
		RequiredInput: []string{value},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := aauth.ParseSignatureError(header)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.RequiredInput) != 1 || parsed.RequiredInput[0] != value {
		t.Fatalf("escaped string round trip = %#v from %q", parsed.RequiredInput, header)
	}
}

func TestSignatureErrorPreservesFutureRegistryCodes(t *testing.T) {
	t.Parallel()

	const header = `error=future_error, future=:AQ==:`
	parsed, err := aauth.ParseSignatureError(header)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Code != aauth.SignatureErrorCode("future_error") {
		t.Fatalf("future error code = %q", parsed.Code)
	}
	formatted, err := aauth.FormatSignatureError(*parsed)
	if err != nil {
		t.Fatal(err)
	}
	if formatted != `error=future_error` {
		t.Fatalf("formatted future error = %q", formatted)
	}
}

func TestVerifyRequestClassifiesExpiresAndRequiredInputs(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := testSigningKey(t, "request-key")
	issuerKey := testSigningKey(t, "issuer-key")
	credential, err := aauth.MintAgentToken("https://ap.example", issuerKey, aauth.AgentTokenRequest{
		Agent:     "aauth:agent@ap.example",
		PublicKey: key.PublicJWK(),
		Lifetime:  time.Hour,
	}, now, "agent-token")
	if err != nil {
		t.Fatal(err)
	}
	resolver := aauth.StaticKeyResolver{
		"https://ap.example": {"issuer-key": issuerKey.PublicJWK()},
	}

	t.Run("future expires is accepted", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := aauth.SignRequestWithOptions(request, key, credential, clock, aauth.SignRequestOptions{
			ExpiresAt: now.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		_, err = aauth.VerifyRequest(context.Background(), request, resolver, clock, aauth.VerifyRequestOptions{
			AllowedCredentialTypes: []string{aauth.AgentTokenType},
		})
		if err != nil {
			t.Fatalf("future expires VerifyRequest: %v", err)
		}
		if !strings.Contains(request.Header.Get("Signature-Input"), ";expires=") {
			t.Fatalf("Signature-Input = %q, want expires parameter", request.Header.Get("Signature-Input"))
		}
	})

	t.Run("sub-second expires cannot serialize at created", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
		if err != nil {
			t.Fatal(err)
		}
		err = aauth.SignRequestWithOptions(request, key, credential, clock, aauth.SignRequestOptions{
			ExpiresAt: now.Add(500 * time.Millisecond),
		})
		if err == nil {
			t.Fatal("signer accepted expires that serializes at the created second")
		}
	})

	t.Run("past expires is invalid signature", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := aauth.SignRequestWithHWK(request, key, clock); err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Signature-Input", strings.Replace(request.Header.Get("Signature-Input"), ";created=", ";expires=1;created=", 1))
		_, err = aauth.VerifyRequest(context.Background(), request, nil, clock, aauth.VerifyRequestOptions{
			AllowedSignatureKeyTypes: []string{aauth.SignatureKeyHWK},
		})
		var signatureError *aauth.SignatureError
		if !errors.As(err, &signatureError) || signatureError.Code != aauth.SignatureErrorInvalidSignature {
			t.Fatalf("past expires error = %v (%#v)", err, signatureError)
		}
	})

	t.Run("missing covered component identifies all requirements", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := aauth.SignRequestWithHWK(request, key, clock); err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Signature-Input", strings.Replace(request.Header.Get("Signature-Input"), ` "@path"`, "", 1))
		_, err = aauth.VerifyRequest(context.Background(), request, nil, clock, aauth.VerifyRequestOptions{
			AllowedSignatureKeyTypes: []string{aauth.SignatureKeyHWK},
		})
		var signatureError *aauth.SignatureError
		if !errors.As(err, &signatureError) || signatureError.Code != aauth.SignatureErrorInvalidInput ||
			!containsString(signatureError.RequiredInput, "@path") {
			t.Fatalf("required component error = %v (%#v)", err, signatureError)
		}
	})
}

func TestVerifyRequestClassifiesKeyAndJWTFailures(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := testSigningKey(t, "request-key")
	for _, test := range []struct {
		name  string
		setup func(*http.Request) error
		want  aauth.SignatureErrorCode
	}{
		{
			name: "malformed key",
			setup: func(request *http.Request) error {
				if err := aauth.SignRequestWithHWK(request, key, clock); err != nil {
					return err
				}
				request.Header.Set("Signature-Key", "not-a-signature-key")
				return nil
			},
			want: aauth.SignatureErrorInvalidKey,
		},
		{
			name: "malformed jwt",
			setup: func(request *http.Request) error {
				if err := aauth.SignRequestWithHWK(request, key, clock); err != nil {
					return err
				}
				request.Header.Set("Signature-Key", `sig=jwt;jwt="not-a-jwt"`)
				return nil
			},
			want: aauth.SignatureErrorInvalidJWT,
		},
		{
			name: "unknown jwks key",
			setup: func(request *http.Request) error {
				return aauth.SignRequestWithJWKSURI(request, key, "https://ps.example", aauth.PersonDiscoveryDocument, clock)
			},
			want: aauth.SignatureErrorUnknownKey,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.setup(request); err != nil {
				t.Fatal(err)
			}
			_, err = aauth.VerifyRequest(context.Background(), request, aauth.StaticKeyResolver{
				"https://ps.example": {},
			}, clock, aauth.VerifyRequestOptions{
				AllowedSignatureKeyTypes: []string{aauth.SignatureKeyJWT, aauth.SignatureKeyJWKSURI},
			})
			var signatureError *aauth.SignatureError
			if !errors.As(err, &signatureError) || signatureError.Code != test.want {
				t.Fatalf("error = %v (%#v), want %s", err, signatureError, test.want)
			}
		})
	}
}

func TestVerifyRequestMapsTypedKeyResolutionFailures(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	key := testSigningKey(t, "request-key")
	for _, test := range []struct {
		name          string
		err           error
		signatureCode aauth.SignatureErrorCode
		resolution    aauth.KeyResolutionCode
	}{
		{
			name:          "unknown key",
			err:           &aauth.KeyResolutionError{Code: aauth.KeyResolutionUnknown, Cause: errors.New("missing")},
			signatureCode: aauth.SignatureErrorUnknownKey,
		},
		{
			name:          "invalid key",
			err:           &aauth.KeyResolutionError{Code: aauth.KeyResolutionInvalid, Cause: errors.New("invalid")},
			signatureCode: aauth.SignatureErrorInvalidKey,
		},
		{
			name:       "egress denied",
			err:        &aauth.KeyResolutionError{Code: aauth.KeyResolutionDenied, Cause: errors.New("private policy detail")},
			resolution: aauth.KeyResolutionDenied,
		},
		{
			name:       "resolver unavailable",
			err:        &aauth.KeyResolutionError{Code: aauth.KeyResolutionUnavailable, Cause: errors.New("private transport detail")},
			resolution: aauth.KeyResolutionUnavailable,
		},
		{
			name:       "untyped resolver error",
			err:        errors.New("unclassified resolver failure"),
			resolution: aauth.KeyResolutionUnavailable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := aauth.SignRequestWithJWKSURI(
				request,
				key,
				"https://ps.example",
				aauth.PersonDiscoveryDocument,
				clock,
			); err != nil {
				t.Fatal(err)
			}
			_, err = aauth.VerifyRequest(
				context.Background(),
				request,
				failingKeyResolver{err: test.err},
				clock,
				aauth.VerifyRequestOptions{AllowedSignatureKeyTypes: []string{aauth.SignatureKeyJWKSURI}},
			)
			if test.signatureCode != "" {
				var signatureError *aauth.SignatureError
				if !errors.As(err, &signatureError) || signatureError.Code != test.signatureCode {
					t.Fatalf("VerifyRequest error = %v (%#v), want %q", err, signatureError, test.signatureCode)
				}
				return
			}
			var resolutionError *aauth.KeyResolutionError
			var signatureError *aauth.SignatureError
			if !errors.As(err, &resolutionError) || resolutionError.Code != test.resolution ||
				errors.As(err, &signatureError) {
				t.Fatalf("VerifyRequest operational error = %v resolution=%#v signature=%#v", err, resolutionError, signatureError)
			}
		})
	}
}

func TestVerifyRequestClassifiesExpiredJWTWithoutStringInspection(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	issuer := testSigningKey(t, "issuer-key")
	requestKey := testSigningKey(t, "request-key")
	credential, err := aauth.MintAgentToken("https://ap.example", issuer, aauth.AgentTokenRequest{
		Agent:     "aauth:agent@ap.example",
		PublicKey: requestKey.PublicJWK(),
		Lifetime:  time.Minute,
	}, now.Add(-time.Hour), "expired-agent-token")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequest(request, requestKey, credential, clock); err != nil {
		t.Fatal(err)
	}
	_, err = aauth.VerifyRequest(context.Background(), request, aauth.StaticKeyResolver{
		"https://ap.example": {"issuer-key": issuer.PublicJWK()},
	}, clock, aauth.VerifyRequestOptions{AllowedCredentialTypes: []string{aauth.AgentTokenType}})
	var signatureError *aauth.SignatureError
	if !errors.As(err, &signatureError) || signatureError.Code != aauth.SignatureErrorExpiredJWT {
		t.Fatalf("expired JWT error = %v (%#v)", err, signatureError)
	}
	var validationError *aauth.TokenValidationError
	if !errors.As(err, &validationError) || validationError.Code != aauth.TokenValidationExpired {
		t.Fatalf("expired JWT cause = %v (%#v)", err, validationError)
	}
}

func TestVerifyRequestClassifiesJWTIssuerKeyAbsence(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	oldIssuer := testSigningKey(t, "issuer-key")
	currentIssuer := testSigningKey(t, "issuer-key")
	requestKey := testSigningKey(t, "request-key")
	credential, err := aauth.MintAgentToken("https://ap.example", currentIssuer, aauth.AgentTokenRequest{
		Agent:     "aauth:agent@ap.example",
		PublicKey: requestKey.PublicJWK(),
		Lifetime:  time.Hour,
	}, now, "agent-token")
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name     string
		resolver aauth.KeyResolver
	}{
		{
			name: "initial lookup",
			resolver: failingKeyResolver{err: &aauth.KeyResolutionError{
				Code:  aauth.KeyResolutionUnknown,
				Cause: errors.New("issuer kid is absent"),
			}},
		},
		{
			name: "same-kid refresh",
			resolver: refreshUnknownResolver{
				stale: oldIssuer.PublicJWK(),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := aauth.SignRequest(request, requestKey, credential, clock); err != nil {
				t.Fatal(err)
			}
			_, err = aauth.VerifyRequest(
				context.Background(),
				request,
				test.resolver,
				clock,
				aauth.VerifyRequestOptions{AllowedCredentialTypes: []string{aauth.AgentTokenType}},
			)
			var signatureError *aauth.SignatureError
			var resolutionError *aauth.KeyResolutionError
			if !errors.As(err, &signatureError) ||
				signatureError.Code != aauth.SignatureErrorUnknownKey ||
				!errors.As(err, &resolutionError) ||
				resolutionError.Code != aauth.KeyResolutionUnknown {
				t.Fatalf(
					"VerifyRequest error = %v signature=%#v resolution=%#v, want unknown_key",
					err,
					signatureError,
					resolutionError,
				)
			}
		})
	}
}

func TestVerifyRequestTreatsUntypedJWTResolverFailureAsUnavailable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	issuer := testSigningKey(t, "issuer-key")
	requestKey := testSigningKey(t, "request-key")
	credential, err := aauth.MintAgentToken("https://ap.example", issuer, aauth.AgentTokenRequest{
		Agent:     "aauth:agent@ap.example",
		PublicKey: requestKey.PublicJWK(),
		Lifetime:  time.Hour,
	}, now, "agent-token")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/data", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := aauth.SignRequest(request, requestKey, credential, clock); err != nil {
		t.Fatal(err)
	}
	_, err = aauth.VerifyRequest(
		context.Background(),
		request,
		failingKeyResolver{err: errors.New("unclassified resolver failure")},
		clock,
		aauth.VerifyRequestOptions{AllowedCredentialTypes: []string{aauth.AgentTokenType}},
	)
	var resolutionError *aauth.KeyResolutionError
	var signatureError *aauth.SignatureError
	if !errors.As(err, &resolutionError) ||
		resolutionError.Code != aauth.KeyResolutionUnavailable ||
		errors.As(err, &signatureError) {
		t.Fatalf("VerifyRequest error = %v resolution=%#v signature=%#v", err, resolutionError, signatureError)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type failingKeyResolver struct{ err error }

func (resolver failingKeyResolver) ResolveKey(context.Context, string, string, string) (aauth.JWK, error) {
	return aauth.JWK{}, resolver.err
}

type refreshUnknownResolver struct{ stale aauth.JWK }

func (resolver refreshUnknownResolver) ResolveKey(context.Context, string, string, string) (aauth.JWK, error) {
	return resolver.stale, nil
}

func (refreshUnknownResolver) RefreshKey(context.Context, string, string, string) (aauth.JWK, error) {
	return aauth.JWK{}, &aauth.KeyResolutionError{
		Code:  aauth.KeyResolutionUnknown,
		Cause: errors.New("issuer kid disappeared after refresh"),
	}
}

type stringReadCloser struct{ *strings.Reader }

func (stringReadCloser) Close() error { return nil }

func ioNopCloser(body string) *stringReadCloser {
	return &stringReadCloser{Reader: strings.NewReader(body)}
}
