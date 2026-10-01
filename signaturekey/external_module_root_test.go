package signaturekey_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// externalModuleRoot returns the directory of the module under test. It asks
// the go command from the test's working directory (the package directory under
// go test), so it does not depend on source paths embedded in the test binary,
// which -trimpath removes. The result is checked to be this module.
func externalModuleRoot(t *testing.T) string {
	t.Helper()
	command := exec.Command("go", "env", "GOMOD")
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("locate module with go env GOMOD: %v", err)
	}
	goMod := strings.TrimSpace(string(output))
	if !filepath.IsAbs(goMod) || filepath.Base(goMod) != "go.mod" {
		t.Fatalf("go env GOMOD = %q, want an absolute go.mod path", goMod)
	}
	contents, err := os.ReadFile(goMod)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "module gitlab.com/sidecat-dev/aauth-go\n") {
		t.Fatalf("%s is not the aauth-go module", goMod)
	}
	return filepath.Dir(goMod)
}
