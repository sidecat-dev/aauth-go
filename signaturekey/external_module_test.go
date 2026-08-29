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
		"require gitlab.com/sidecat-dev/aauth-go v0.0.0\n\n" +
		"replace gitlab.com/sidecat-dev/aauth-go => " + filepath.ToSlash(moduleRoot) + "\n"
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
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
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
	if err := signaturekey.SignRequest(request, key, credential, clock(now), signaturekey.SignOptions{}); err != nil {
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
`
