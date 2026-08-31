package aauth_test

import (
	"testing"

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
