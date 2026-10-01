package signaturekey_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A clean external module that imports only public packages observes the
// clock_skew classification and the exact Signature-Error value.
func TestCleanExternalModuleObservesClockSkew(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate signaturekey source")
	}
	moduleRoot := filepath.Dir(filepath.Dir(sourceFile))
	externalModule := t.TempDir()

	goMod := "module example.com/clockskew-consumer\n\n" +
		"go 1.25\n\n" +
		"require gitlab.com/sidecat-dev/aauth-go v0.0.0\n\n" +
		"replace gitlab.com/sidecat-dev/aauth-go => " + filepath.ToSlash(moduleRoot) + "\n"
	writeExternalModuleFile(t, externalModule, "go.mod", goMod)
	writeExternalModuleFile(t, externalModule, "skew_test.go", externalModuleClockSkewTest)

	command := exec.Command("go", "test", "-mod=mod", "./...", "-count=1")
	command.Dir = externalModule
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("clean external module failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "ok  \texample.com/clockskew-consumer") {
		t.Fatalf("clean external module output = %q", output)
	}
}

const externalModuleClockSkewTest = `package consumer_test

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

func TestSenderAheadOfVerifierIsClockSkew(t *testing.T) {
	verifier := time.Date(2026, 9, 30, 18, 0, 0, 0, time.UTC)
	key, err := jose.NewEd25519SigningKey("consumer-key", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := signaturekey.NewHWKCredential(key.PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		offset time.Duration
		want   signaturekey.ErrorCode
	}{
		{offset: signaturekey.DefaultSignatureWindow},
		{offset: signaturekey.DefaultSignatureWindow + time.Second, want: signaturekey.ErrorClockSkew},
		{offset: -signaturekey.DefaultSignatureWindow - time.Second, want: signaturekey.ErrorInvalidSignature},
	} {
		request, err := http.NewRequest(http.MethodGet, "https://resource.example/records", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := signaturekey.SignRequest(request, key, credential, clock(verifier.Add(test.offset)), signaturekey.SignOptions{}); err != nil {
			t.Fatal(err)
		}
		_, err = signaturekey.PrepareRequest(request, clock(verifier), signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK},
		})
		if test.want == "" {
			if err != nil {
				t.Fatalf("offset %s rejected: %v", test.offset, err)
			}
			continue
		}
		failure := signaturekey.NormalizeError(err, "")
		if failure == nil || failure.Code != test.want {
			t.Fatalf("offset %s: error %v, want %q", test.offset, err, test.want)
		}
		header, err := signaturekey.FormatError(*failure)
		if err != nil || header != "error="+string(test.want) {
			t.Fatalf("offset %s: Signature-Error %q err %v", test.offset, header, err)
		}
	}
}
`
