package aauth_test

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestTokenReferenceValidation(t *testing.T) {
	t.Parallel()

	if err := aauth.ValidateTokenReference(aauth.TokenReference{
		Issuer: "https://issuer.example", JTI: "token-123",
	}); err != nil {
		t.Fatalf("valid token reference: %v", err)
	}
	for _, reference := range []aauth.TokenReference{
		{JTI: "token-123"},
		{Issuer: "not-an-https-origin", JTI: "token-123"},
		{Issuer: "https://issuer.example"},
	} {
		if err := aauth.ValidateTokenReference(reference); err == nil {
			t.Fatalf("invalid token reference accepted: %#v", reference)
		}
	}
}

func TestRevocationRequestCodec(t *testing.T) {
	t.Parallel()

	const issuer = "https://issuer.example"
	request := aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: issuer, JTI: "token-123"},
		ExpiresAt: time.Unix(2000000000, 0),
	}
	body, err := aauth.EncodeRevocationRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"jti":"token-123","exp":2000000000}` {
		t.Fatalf("encoded body = %s", body)
	}
	decoded, err := aauth.DecodeRevocationRequest(strings.NewReader(string(body)), 1024, issuer)
	if err != nil || decoded.Reference != request.Reference || !decoded.ExpiresAt.Equal(request.ExpiresAt) {
		t.Fatalf("decoded = %#v, %v", decoded, err)
	}

	// A body iss is not authoritative: the issuer is the verified signer.
	decoded, err = aauth.DecodeRevocationRequest(
		strings.NewReader(`{"iss":"https://other.example","jti":"token-123","exp":2000000000}`), 1024, issuer)
	if err != nil || decoded.Reference.Issuer != issuer {
		t.Fatalf("body iss decoded = %#v, %v", decoded, err)
	}

	for name, input := range map[string]string{
		"missing exp":    `{"jti":"token-123"}`,
		"missing jti":    `{"exp":2000000000}`,
		"string exp":     `{"jti":"token-123","exp":"2000000000"}`,
		"zero exp":       `{"jti":"token-123","exp":0}`,
		"null exp":       `{"jti":"token-123","exp":null}`,
		"negative exp":   `{"jti":"token-123","exp":-5}`,
		"overflow exp":   `{"jti":"token-123","exp":99999999999999999999}`,
		"fractional exp": `{"jti":"token-123","exp":1.5}`,
		"duplicate name": `{"jti":"a","jti":"b","exp":2000000000}`,
		"case variant":   `{"JTI":"token-123","exp":2000000000}`,
		"trailing value": `{"jti":"token-123","exp":2000000000} {}`,
		"non-object":     `["token-123"]`,
		"empty":          ``,
	} {
		if _, err := aauth.DecodeRevocationRequest(strings.NewReader(input), 1024, issuer); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := aauth.DecodeRevocationRequest(strings.NewReader(string(body)), 8, issuer); err == nil {
		t.Fatal("oversized body accepted")
	}
	for name, invalid := range map[string]aauth.RevocationRequest{
		"no exp":       {Reference: request.Reference},
		"no reference": {ExpiresAt: request.ExpiresAt},
	} {
		if _, err := aauth.EncodeRevocationRequest(invalid); err == nil {
			t.Fatalf("%s encoded", name)
		}
	}
}

func TestReadRevocationResponseBounds(t *testing.T) {
	t.Parallel()
	response := func(contentType, body string) *http.Response {
		header := make(http.Header)
		if contentType != "" {
			header.Set("Content-Type", contentType)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body))}
	}
	if err := aauth.ReadRevocationResponse(response("application/json", `{"downstream":[{"recipient":"r","error":"revocation_unsupported"},{"recipient":"s"}]}`), 1024); err != nil {
		t.Fatalf("valid report = %v", err)
	}
	for name, bad := range map[string]*http.Response{
		"oversize":          response("application/json", `{"x":"`+strings.Repeat("a", 64)+`"}`),
		"case variant":      response("application/json", `{"downstream":[],"Downstream":[]}`),
		"entry no receiver": response("application/json", `{"downstream":[{"error":"revocation_unsupported"}]}`),
		"null entry":        response("application/json", `{"downstream":[null]}`),
		"bad media type":    response("application/json;;", `{}`),
	} {
		if err := aauth.ReadRevocationResponse(bad, 32); !errors.Is(err, aauth.ErrRevocationUnavailable) {
			t.Fatalf("%s = %v", name, err)
		}
	}
}
