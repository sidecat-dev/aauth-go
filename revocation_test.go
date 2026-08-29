package aauth_test

import (
	"testing"

	aa "gitlab.com/sidecat-dev/aauth-go"
)

func TestTokenRevocationRequestValidation(t *testing.T) {
	valid := aa.TokenRevocationRequest{
		Issuer: "https://agent.example",
		JTI:    "agent-token-1",
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []aa.TokenRevocationRequest{
		{},
		{Issuer: "not-an-https-issuer", JTI: valid.JTI},
		{Issuer: valid.Issuer},
		{Issuer: valid.Issuer, JTI: " agent-token-1"},
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("invalid revocation request accepted: %#v", invalid)
		}
	}
}
