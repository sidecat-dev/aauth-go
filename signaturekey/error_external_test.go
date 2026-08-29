package signaturekey_test

import (
	"reflect"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestSignatureErrorAndNegotiationHeadersRoundTrip(t *testing.T) {
	header, err := signaturekey.FormatError(signaturekey.Error{
		Code:          signaturekey.ErrorInvalidInput,
		RequiredInput: []string{"content-digest", "signature-key"},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := signaturekey.ParseError(header)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Code != signaturekey.ErrorInvalidInput ||
		!reflect.DeepEqual(parsed.RequiredInput, []string{"content-digest", "signature-key"}) {
		t.Fatalf("parsed error = %#v", parsed)
	}
	if parsed.Cause != nil {
		t.Fatalf("wire error retained a local cause: %v", parsed.Cause)
	}

	algorithms, err := signaturekey.FormatAcceptAlgorithms([]string{"Ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	if algorithms != "Ed25519" {
		t.Fatalf("Accept-Signature-Alg = %q", algorithms)
	}
	schemes, err := signaturekey.FormatAcceptSchemes([]signaturekey.Scheme{
		signaturekey.SchemeHWK,
		signaturekey.SchemeJWT,
	})
	if err != nil {
		t.Fatal(err)
	}
	if schemes != "hwk, jwt" {
		t.Fatalf("Accept-Signature-Scheme = %q", schemes)
	}
}
