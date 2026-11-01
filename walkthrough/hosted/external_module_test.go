package main

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostedWalkthroughUsesPublishedPublicModule(t *testing.T) {
	command := exec.Command("go", "list", "-m", "-json", "gitlab.com/sidecat-dev/aauth-go")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var module struct {
		Path    string
		Version string
		Dir     string
		Replace *struct{ Path, Dir string }
	}
	if err := json.Unmarshal(output, &module); err != nil {
		t.Fatal(err)
	}
	if module.Path != "gitlab.com/sidecat-dev/aauth-go" || module.Version != "v0.0.0-20261101230727-1e0b03e4069f" {
		t.Fatalf("library module = %s %s", module.Path, module.Version)
	}
	if module.Replace != nil {
		t.Fatalf("library module uses a replacement: %#v", module.Replace)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.Abs(module.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if dir == root || strings.HasPrefix(dir, root+string(filepath.Separator)) {
		t.Fatalf("library resolved from checkout %s instead of the downloaded module", dir)
	}
}
