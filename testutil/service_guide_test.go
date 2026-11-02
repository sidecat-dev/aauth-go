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

// Compile the guide against the public API and exercise its hosted policy:
// Bootstrap 28e8258, Sub-Agents Under a Hosted AP, assigns discriminator
// collisions and the live-child limit to the host.
func TestServiceGuideSubagentSnippets(t *testing.T) {
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
	"fmt"
	"net/http"
	"sync"
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
	if err := os.WriteFile(filepath.Join(consumer, "guide_test.go"), []byte(serviceGuideSubagentTest), 0600); err != nil {
		t.Fatal(err)
	}
	// Include compilation in the enclosing test deadline, leaving time to
	// report cancellation before the test runner exits.
	ctx := t.Context()
	if deadline, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline.Add(-time.Second))
		defer cancel()
	}
	command := exec.CommandContext(ctx, "go", "test", "-mod=mod", "-count=1", "./...")
	command.Dir = consumer
	command.Env = append(os.Environ(), "GOWORK=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("guide snippets failed: %v (context: %v)\n%s", err, ctx.Err(), output)
	}
}

const serviceGuideSubagentTest = `package guide

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestHostedRegistryFromZeroValue(t *testing.T) {
	key := func(id string) jose.SigningKey {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil { t.Fatal(err) }
		result, err := jose.NewEd25519SigningKey(id, private)
		if err != nil { t.Fatal(err) }
		return result
	}
	clock := aauth.ClockFunc(func() time.Time { return time.Unix(1800000000, 0) })
	var ids int
	provider, err := agentprovider.New(agentprovider.Config{
		Issuer: "https://ap.example", SigningKey: key("provider"), Clock: clock,
		NewID: func() string { ids++; return fmt.Sprintf("token-%d", ids) },
	})
	if err != nil { t.Fatal(err) }
	parentKey := key("parent")
	parent, err := provider.Issue(t.Context(), aauth.AgentTokenRequest{
		Agent: "aauth:planner@ap.example", PublicKey: parentKey.PublicJWK(), Lifetime: time.Hour,
	})
	if err != nil { t.Fatal(err) }
	mux := http.NewServeMux()
	mountSubagents(mux, provider, &subagentRegistry{})
	for n := 0; n < 4; n++ {
		body, err := json.Marshal(map[string]any{
			"jwk": key(fmt.Sprintf("child-%d", n)).PublicJWK(), "discriminator": "search",
		})
		if err != nil { t.Fatal(err) }
		request := httptest.NewRequest(http.MethodPost, "https://ap.example/subagent", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if err := signaturekey.SignJWTRequestWithOptions(request, parentKey, parent, clock, signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type", "content-digest"},
		}); err != nil { t.Fatal(err) }
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		want := http.StatusOK
		if n == 3 { want = http.StatusForbidden }
		if response.Code != want { t.Fatalf("request %d: got %d %s, want %d", n, response.Code, response.Body, want) }
		if n == 3 { continue }
		var token struct { AgentToken string ` + "`json:\"agent_token\"`" + ` }
		if err := json.Unmarshal(response.Body.Bytes(), &token); err != nil { t.Fatal(err) }
		compact, err := jose.ParseCompact(token.AgentToken)
		if err != nil { t.Fatal(err) }
		var claims struct { Subject string ` + "`json:\"sub\"`" + ` }
		if err := json.Unmarshal(compact.Payload(), &claims); err != nil { t.Fatal(err) }
		discriminator := "search"
		if n > 0 { discriminator = fmt.Sprintf("worker%d", n) }
		if want := "aauth:planner+" + discriminator + "@ap.example"; claims.Subject != want {
			t.Fatalf("child %d: got %q, want %q", n, claims.Subject, want)
		}
	}
}
`
