package testutil_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The examples must run when copied out of this module. An internal store
// import breaks this consumer boundary even when the example passes in-tree.
func TestPublicStoreExamplesRunInAnExternalModule(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	consumer := t.TempDir()
	module := "module example.com/aauth-examples\n\ngo 1.25\n\nrequire gitlab.com/sidecat-dev/aauth-go v0.0.0\n\nreplace gitlab.com/sidecat-dev/aauth-go => " + strconv.Quote(filepath.ToSlash(root)) + "\n"
	if err := os.WriteFile(filepath.Join(consumer, "go.mod"), []byte(module), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mission", "fourparty", "audit", "permission", "interactionquestion", "interactionrelay", "selfhosted", "bootstrap", "psconsent", "budget", "revocation"} {
		source := filepath.Join(root, "example", name)
		target := filepath.Join(consumer, name)
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(source)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			content, err := os.ReadFile(filepath.Join(source, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, entry.Name()), content, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, args := range [][]string{{"test", "-mod=mod", "./...", "-count=1"}, {"run", "-mod=mod", "./mission"}} {
		command := exec.CommandContext(ctx, "go", args...)
		command.Dir = consumer
		command.Env = append(os.Environ(), "GOWORK=off")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("external examples %v: %v\n%s", args, err, output)
		}
	}
}
