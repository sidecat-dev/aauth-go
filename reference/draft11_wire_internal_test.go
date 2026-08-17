package reference

import (
	"net/http/httptest"
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestSignatureFailureEmitsDraft08NegotiationHeaders(t *testing.T) {
	response := httptest.NewRecorder()
	writeSignatureFailure(response, &aauth.SignatureError{
		Code:               aauth.SignatureErrorUnsupportedAlgorithm,
		AcceptedAlgorithms: []string{aauth.Ed25519Algorithm},
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
