package r3_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCleanExternalModuleUsesOnlyTheR3Package(t *testing.T) {
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
	"encoding/json"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/r3"
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
`
