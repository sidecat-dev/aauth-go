package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestGenerateRejectsObsoleteAgentRequestMode(t *testing.T) {
	output := filepath.Join(t.TempDir(), "go-agent-request.json")
	command := exec.Command("go", "run", ".", output)
	combined, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(combined), "usage:") {
		t.Fatalf("obsolete generator mode error = %v output=%s", err, combined)
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("obsolete generator wrote output: %v", statErr)
	}
}

func TestGenerateProducesVerifiableGoJKTJWTRequest(t *testing.T) {
	path := t.TempDir() + "/go-jkt-jwt-request.json"
	if err := generateJKTJWTRequest(path); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture goJKTJWTRequestFixture
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Schema != goJKTJWTRequestSchema ||
		fixture.Request.Method != http.MethodPost ||
		fixture.Request.URL == "" {
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
	verified, err := aauth.VerifyRequest(
		context.Background(),
		request,
		nil,
		aauth.ClockFunc(func() time.Time {
			return time.Unix(fixture.Now, 0)
		}),
		aauth.VerifyRequestOptions{
			AllowedSignatureKeyTypes: []string{aauth.SignatureKeyJKTJWT},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Signer != fixture.Expected.Identity ||
		!verified.IdentityKey.Equal(fixture.Expected.IdentityKey) ||
		!verified.PublicKey.Equal(fixture.Expected.RequestKey) {
		t.Fatalf("verified generated request = %#v", verified)
	}
}
