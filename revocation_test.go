package aauth_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	aa "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
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

func TestAgentProviderRevocationClientValidatesInputs(t *testing.T) {
	now := time.Date(2026, 8, 30, 1, 0, 0, 0, time.UTC)
	provider, err := reference.NewAgentProvider(reference.AgentProviderConfig{
		Identifier: "https://ap.example", SigningKey: testSigningKey(t, "provider-revocation-key"),
		Clock: aa.ClockFunc(func() time.Time { return now }), NewID: func() string { return "agent-token" },
	})
	if err != nil {
		t.Fatal(err)
	}
	valid := aa.TokenRevocationRequest{Issuer: "https://ap.example", JTI: "agent-token"}
	for _, test := range []struct {
		name     string
		client   *http.Client
		endpoint string
		input    aa.TokenRevocationRequest
	}{
		{name: "nil client", endpoint: "https://ps.example/revoke", input: valid},
		{name: "invalid endpoint", client: &http.Client{}, endpoint: "http://ps.example/revoke", input: valid},
		{name: "invalid input", client: &http.Client{}, endpoint: "https://ps.example/revoke", input: aa.TokenRevocationRequest{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := provider.RevokeToken(context.Background(), test.client, test.endpoint, test.input); err == nil {
				t.Fatal("invalid revocation client input succeeded")
			}
		})
	}
}
