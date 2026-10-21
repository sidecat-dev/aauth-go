package testutil_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The service guide's sub-agent snippets must compile against the public API
// from an external module, so the guide cannot drift from the code it shows.
func TestServiceGuideSubagentSnippetsCompile(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	guide, err := os.ReadFile(filepath.Join(root, "USE-IN-YOUR-SERVICE.md"))
	if err != nil {
		t.Fatal(err)
	}
	section, ok := strings.CutPrefix(string(guide)[strings.Index(string(guide), "## Delegate to a sub-agent"):], "## Delegate to a sub-agent")
	if !ok {
		t.Fatal("guide has no sub-agent section")
	}
	if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}
	blocks := regexp.MustCompile("(?s)```go\n(.*?)```").FindAllStringSubmatch(section, -1)
	if len(blocks) != 5 {
		t.Fatalf("sub-agent section has %d Go snippets, want 5", len(blocks))
	}
	source := `package guide

import (
	"context"
	"errors"
	"net/http"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
)
`
	for _, block := range blocks {
		source += "\n" + block[1]
	}
	consumer := t.TempDir()
	module := "module example.com/aauth-guide\n\ngo 1.25\n\nrequire gitlab.com/sidecat-dev/aauth-go v0.0.0\n\nreplace gitlab.com/sidecat-dev/aauth-go => " + strconv.Quote(filepath.ToSlash(root)) + "\n"
	if err := os.WriteFile(filepath.Join(consumer, "go.mod"), []byte(module), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(consumer, "guide.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "vet", "-mod=mod", "./...")
	command.Dir = consumer
	command.Env = append(os.Environ(), "GOWORK=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("guide snippets do not compile: %v\n%s\n%s", err, output, source)
	}
}
