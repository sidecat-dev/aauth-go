package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestGenerateProducesVerifiableGoAgentRequest(t *testing.T) {
	path := t.TempDir() + "/go-agent-request.json"
	if err := generate(path); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture goRequestFixture
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Schema != goAgentRequestSchema ||
		fixture.Request.Method != http.MethodGet ||
		fixture.Request.URL == "" ||
		fixture.Request.AgentToken == "" {
		t.Fatalf("generated fixture = %#v", fixture)
	}
	request, err := http.NewRequest(
		fixture.Request.Method,
		fixture.Request.URL,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range fixture.Request.Headers {
		request.Header.Set(name, value)
	}
	resolver := aauth.StaticKeyResolver{
		fixture.Issuer: {
			fixture.IssuerKey.Kid: fixture.IssuerKey,
		},
	}
	verified, err := aauth.VerifyRequest(
		context.Background(),
		request,
		resolver,
		aauth.ClockFunc(func() time.Time {
			return time.Unix(fixture.Now, 0)
		}),
		aauth.VerifyRequestOptions{
			RequiredComponents:     []string{"aauth-mission"},
			AllowedCredentialTypes: []string{aauth.AgentTokenType},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Agent != fixture.Expected.Agent ||
		!verified.PublicKey.Equal(fixture.Expected.AgentKey) {
		t.Fatalf("verified generated request = %#v", verified)
	}
}
