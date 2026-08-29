package reference

import (
	"errors"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"net/http/httptest"
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestSignatureFailureEmitsDraft08NegotiationHeaders(t *testing.T) {
	response := httptest.NewRecorder()
	writeSignatureFailure(response, &aauth.SignatureError{
		Code:               aauth.SignatureErrorUnsupportedAlgorithm,
		AcceptedAlgorithms: []string{jose.Ed25519Algorithm},
		AcceptedSchemes:    []string{aauth.SignatureKeyJWT, aauth.SignatureKeyHWK},
	})

	if got := response.Header().Get("Signature-Error"); got != "error=unsupported_algorithm" {
		t.Fatalf("Signature-Error = %q", got)
	}
	if got := response.Header().Get("Accept-Signature-Alg"); got != "Ed25519" {
		t.Fatalf("Accept-Signature-Alg = %q", got)
	}
	if got := response.Header().Get("Accept-Signature-Scheme"); got != "jwt, hwk" {
		t.Fatalf("Accept-Signature-Scheme = %q", got)
	}
	if strings.Contains(response.Body.String(), "supported_algorithms") {
		t.Fatalf("legacy supported_algorithms leaked: %s", response.Body.String())
	}
}

func TestSignatureFailureDoesNotEmitUnclassifiedCause(t *testing.T) {
	t.Parallel()

	for _, cause := range []error{
		errors.New("private parse diagnostic"),
		&aauth.KeyResolutionError{Code: aauth.KeyResolutionUnknown, Cause: errors.New("private key identifier")},
		&aauth.TokenValidationError{Code: aauth.TokenValidationInvalidKey, Cause: errors.New("private trust configuration")},
	} {
		response := httptest.NewRecorder()
		writeSignatureFailure(response, &aauth.SignatureError{
			Code:  aauth.SignatureErrorInvalidJWT,
			Cause: cause,
		})
		if strings.Contains(response.Body.String(), "private") {
			t.Fatalf("signature response leaked cause: %s", response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"detail":"invalid_jwt"`) {
			t.Fatalf("signature response detail = %s", response.Body.String())
		}
	}
}
