package r3_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCleanExternalModuleValidatesR3DocumentsAndTokenEvidence(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate r3 source")
	}
	moduleRoot := filepath.Dir(filepath.Dir(sourceFile))
	externalModule := t.TempDir()
	goMod := "module example.com/r3-consumer\n\n" +
		"go 1.24.0\n\n" +
		"require gitlab.com/sidecat-dev/aauth-go v0.0.0\n\n" +
		"replace gitlab.com/sidecat-dev/aauth-go => " + filepath.ToSlash(moduleRoot) + "\n"
	writeR3ExternalFile(t, externalModule, "go.mod", goMod)
	writeR3ExternalFile(t, externalModule, "document_test.go", r3ExternalModuleTest)

	command := exec.Command("go", "test", "-mod=mod", "./...", "-count=1")
	command.Dir = externalModule
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("clean R3 module failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "ok  \texample.com/r3-consumer") {
		t.Fatalf("clean R3 module output = %q", output)
	}
}

func writeR3ExternalFile(t *testing.T, directory, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

const r3ExternalModuleTest = `package consumer_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestR3Document(t *testing.T) {
	exact := []byte(` + "`" + `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}` + "`" + `)
	document, err := r3.ParseDocument(exact)
	if err != nil {
		t.Fatal(err)
	}
	set := document.OperationSet()
	if !set.Contains(json.RawMessage(` + "`" + `{"tool":"read"}` + "`" + `)) || r3.S256(exact) == "" {
		t.Fatalf("document = %#v", document)
	}
}

func TestR3TokenEvidence(t *testing.T) {
	now := time.Date(2026, 8, 29, 6, 0, 0, 0, time.UTC)
	issuer, err := jose.NewEd25519SigningKey("issuer", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	requestKey, err := jose.NewEd25519SigningKey("request", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(aauth.AuthTokenClaims{
		Issuer: "https://person.example", DWK: aauth.PersonDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-r3-external",
		Confirmation: aauth.Confirmation{JWK: requestKey.PublicJWK()},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		Subject: "person", Scope: "read", PersonServer: "https://person.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(claims, &payload); err != nil {
		t.Fatal(err)
	}
	payload["r3_uri"] = json.RawMessage("\"https://resource.example/r3/current\"")
	digest := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
	payload["r3_s256"] = json.RawMessage("\"" + digest + "\"")
	payload["r3_granted"] = json.RawMessage(` + "`" + `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}` + "`" + `)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.SignCompact(issuer, jose.Header{
		Algorithm: jose.Ed25519Algorithm, Type: aauth.AuthTokenType, KeyID: issuer.ID(),
	}, payloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	core, err := aauth.VerifyAuthToken(context.Background(), compact,
		signaturekey.StaticKeyResolver{"https://person.example": {issuer.ID(): issuer.PublicJWK()}},
		aauth.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	result, err := r3.ValidateAuthToken(core)
	if err != nil || !result.Valid() || result.Digest() != digest {
		t.Fatalf("R3 result = %#v, %v", result, err)
	}
}

func TestR3AuthorizationGrant(t *testing.T) {
	now := time.Date(2026, 8, 29, 6, 30, 0, 0, time.UTC)
	resourceKey, _ := jose.NewEd25519SigningKey("resource", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x34}, ed25519.SeedSize)))
	accessKey, _ := jose.NewEd25519SigningKey("access", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x35}, ed25519.SeedSize)))
	agentKey, _ := jose.NewEd25519SigningKey("agent", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x36}, ed25519.SeedSize)))
	exact := []byte(` + "`" + `{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"read"}]}` + "`" + `)
	reference, err := r3.NewDocumentReference("https://resource.example/r3/direct", exact)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, _ := agentKey.PublicJWK().Thumbprint()
	resourceCompact, err := r3.MintResourceToken(resourceKey, aauth.ResourceTokenClaims{
		Issuer: "https://resource.example", DWK: aauth.ResourceDiscoveryDocument,
		Audience: "https://access.example", JTI: "resource-direct", AgentJKT: thumbprint,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Scope: "read",
		PersonServer: "https://person.example", Subject: "person", PresentedJTI: "person-token",
	}, reference)
	if err != nil {
		t.Fatal(err)
	}
	resourceCore, err := aauth.VerifyResourceToken(context.Background(), resourceCompact,
		signaturekey.StaticKeyResolver{"https://resource.example": {resourceKey.ID(): resourceKey.PublicJWK()}},
		aauth.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	resourceResult, _ := r3.ValidateResourceToken(resourceCore)
	verifiedDocument, err := r3.VerifyDocument(resourceResult, exact)
	if err != nil {
		t.Fatal(err)
	}
	requested := r3.OperationSet{Vocabulary: r3.VocabularyMCP, Operations: []json.RawMessage{json.RawMessage(` + "`" + `{"tool":"read"}` + "`" + `)}}
	grant, err := r3.NewAuthorizationGrant(verifiedDocument, r3.AuthorizationDecision{Granted: requested})
	if err != nil {
		t.Fatal(err)
	}
	authCompact, err := r3.MintAuthToken(accessKey, aauth.AuthTokenClaims{
		Issuer: "https://access.example", DWK: aauth.AccessDiscoveryDocument,
		Audience: "https://resource.example", JTI: "auth-direct",
		Confirmation: aauth.Confirmation{JWK: agentKey.PublicJWK()},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		Subject: "person", Scope: "read", PersonServer: "https://person.example",
	}, grant)
	if err != nil {
		t.Fatal(err)
	}
	authCore, err := aauth.VerifyAuthToken(context.Background(), authCompact,
		signaturekey.StaticKeyResolver{"https://access.example": {accessKey.ID(): accessKey.PublicJWK()}},
		aauth.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	authResult, err := r3.ValidateAuthToken(authCore)
	if err != nil || r3.ValidateAuthorizationGrant(resourceResult, authResult, requested) != nil {
		t.Fatalf("direct result = %#v, %v", authResult, err)
	}
}
`
