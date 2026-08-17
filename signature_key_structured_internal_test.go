package aauth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSignatureKeyUsesRFC8941DictionarySelection(t *testing.T) {
	parsed, err := parseSignatureKey([]string{
		`other=future`,
		`sig=hwk;kty="OKP";crv="Ed25519";x="abc";alg="Ed25519"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.scheme != SignatureKeyHWK ||
		parsed.parameters["kty"] != "OKP" ||
		parsed.parameters["alg"] != Ed25519Algorithm {
		t.Fatalf("parsed Signature-Key = %#v", parsed)
	}

	_, err = parseSignatureKey([]string{`sig=future`})
	var unsupported *unsupportedSignatureKeySchemeError
	if !errors.As(err, &unsupported) || unsupported.scheme != "future" {
		t.Fatalf("parameterless unknown scheme error = %v", err)
	}
}

func TestSignatureKeyAcceptsOnlyRFC8941StringEscapes(t *testing.T) {
	parsed, err := parseSignatureKey([]string{`sig=jwt;jwt="a\\b\"c"`})
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.parameters["jwt"]; got != "a\\b\"c" {
		t.Fatalf("decoded RFC 8941 string = %q", got)
	}

	for _, header := range []string{
		`sig=jwt;jwt="a\nb"`,
		`sig=jwt;jwt="a\x41"`,
		`sig=jwt;jwt="a\u0041"`,
	} {
		if _, err := parseSignatureKey([]string{header}); err == nil {
			t.Errorf("accepted Go-only escape in %q", header)
		}
	}
}

func TestSignatureKeyRejectsMalformedStructuredMembers(t *testing.T) {
	for _, header := range []string{
		`sig="hwk"`,
		`sig=(hwk)`,
		`sig=hwk;kty="OKP";crv="Ed25519";x="abc";alg=Ed25519`,
		`sig=hwk;kty="OKP";crv="Ed25519";x="abc";alg="Ed25519",`,
	} {
		if _, err := parseSignatureKey([]string{header}); err == nil {
			t.Errorf("accepted malformed Signature-Key %q", header)
		}
	}
}

func TestSignatureKeySplitFieldLinesAreAllCoveredByTheSignature(t *testing.T) {
	now := time.Unix(2_000_000_100, 0)
	clock := ClockFunc(func() time.Time { return now })
	key := internalTestSigningKey(t, "request-key")
	request, err := http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
	if err != nil {
		t.Fatal(err)
	}
	public := key.PublicJWK()
	request.Header.Add("Signature-Key", `other=future`)
	request.Header.Add(
		"Signature-Key",
		`sig=hwk;kty=`+strconv.Quote(public.Kty)+
			`;crv=`+strconv.Quote(public.Crv)+
			`;x=`+strconv.Quote(public.X)+
			`;alg=`+strconv.Quote(public.Alg),
	)
	components := []string{"@method", "@authority", "@path", "signature-key"}
	params := signatureParams(components, now.Unix(), time.Time{}, "")
	base := `"@method": GET` + "\n" +
		`"@authority": resource.example` + "\n" +
		`"@path": /records` + "\n" +
		`"signature-key": ` + strings.Join(request.Header.Values("Signature-Key"), ", ") + "\n" +
		`"@signature-params": ` + params
	signature, err := key.sign([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Signature-Input", "sig="+params)
	request.Header.Set("Signature", "sig=:"+base64.StdEncoding.EncodeToString(signature)+":")

	if _, err := VerifyRequest(
		context.Background(),
		request,
		nil,
		clock,
		VerifyRequestOptions{AllowedSignatureKeyTypes: []string{SignatureKeyHWK}},
	); err != nil {
		t.Fatal(err)
	}

	mutated := request.Clone(context.Background())
	mutated.Header["Signature-Key"][0] = strings.Replace(
		mutated.Header["Signature-Key"][0],
		"future",
		"changed",
		1,
	)
	_, err = VerifyRequest(
		context.Background(),
		mutated,
		nil,
		clock,
		VerifyRequestOptions{AllowedSignatureKeyTypes: []string{SignatureKeyHWK}},
	)
	var signatureError *SignatureError
	if !errors.As(err, &signatureError) || signatureError.Code != SignatureErrorInvalidSignature {
		t.Fatalf("split-field mutation error = %v, want invalid_signature", err)
	}
}
