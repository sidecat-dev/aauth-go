package signaturekey_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCleanExternalModuleCanSignAndVerifyARequest(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate signaturekey source")
	}
	moduleRoot := filepath.Dir(filepath.Dir(sourceFile))
	externalModule := t.TempDir()

	goMod := "module example.com/signaturekey-consumer\n\n" +
		"go 1.24.0\n\n" +
		"require aauth-go v0.0.0\n\n" +
		"replace aauth-go => " + filepath.ToSlash(moduleRoot) + "\n"
	writeExternalModuleFile(t, externalModule, "go.mod", goMod)
	writeExternalModuleFile(t, externalModule, "request_test.go", externalModuleRequestTest)

	command := exec.Command("go", "test", "-mod=mod", "./...", "-count=1")
	command.Dir = externalModule
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("clean external module failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "ok  \texample.com/signaturekey-consumer") {
		t.Fatalf("clean external module output = %q", output)
	}
}

func writeExternalModuleFile(t *testing.T, directory, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

const externalModuleRequestTest = `package consumer_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	aauth "aauth-go"
	"aauth-go/jose"
	"aauth-go/signaturekey"
)

type clock time.Time

func (value clock) Now() time.Time { return time.Time(value) }

func TestPublicPackagesCompose(t *testing.T) {
	now := time.Date(2026, 8, 28, 23, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	key, err := jose.NewEd25519SigningKey("external-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://resource.example/tasks/1", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignRequest(request, key, credential, clock(now), signaturekey.SignOptions{
		AdditionalComponents: []string{"content-type"},
	}); err != nil {
		t.Fatal(err)
	}
	prepared, err := signaturekey.PrepareRequest(request, clock(now), signaturekey.VerifyOptions{
		AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK},
		RequiredComponents: []string{"content-type"},
		RequireExactComponents: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	proofKey, ok := prepared.Credential().InlineJWK()
	if !ok {
		t.Fatal("HWK credential did not expose its proof key")
	}
	proof, err := prepared.Verify(proofKey)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Scheme() != signaturekey.SchemeHWK || proof.ReplayKey() == "" {
		t.Fatalf("proof = scheme %q, replay %q", proof.Scheme(), proof.ReplayKey())
	}
}

func TestCoreVerificationReturnsTypedClaims(t *testing.T) {
	now := time.Date(2026, 8, 29, 2, 30, 0, 0, time.UTC)
	issuerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	issuerKey, err := jose.NewEd25519SigningKey("issuer-key", issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	requestPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize))
	requestKey, err := jose.NewEd25519SigningKey("request-key", requestPrivate)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := aauth.MintAgentToken(
		"https://provider.example",
		issuerKey,
		aauth.AgentTokenRequest{
			Agent: "aauth:external@provider.example",
			PersonServer: "https://person.example",
			PublicKey: requestKey.PublicJWK(),
			Lifetime: time.Hour,
		},
		now,
		"external-evidence",
	)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := aauth.VerifyAgentToken(
		context.Background(),
		compact,
		signaturekey.StaticKeyResolver{
			{
				Issuer: "https://provider.example",
				DiscoveryDocument: aauth.AgentDiscoveryDocument,
				KeyID: issuerKey.ID(),
			}: issuerKey.PublicJWK(),
		},
		clock(now),
	)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "aauth:external@provider.example" {
		t.Fatalf("claims = %#v", claims)
	}
}
`
