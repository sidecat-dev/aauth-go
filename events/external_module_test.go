package events_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCleanExternalModuleUsesEventsContractsAndDiscovery(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate events source")
	}
	moduleRoot := filepath.Dir(filepath.Dir(sourceFile))
	externalModule := t.TempDir()
	goMod := "module example.com/events-consumer\n\n" +
		"go 1.24.0\n\n" +
		"require gitlab.com/sidecat-dev/aauth-go v0.0.0\n\n" +
		"replace gitlab.com/sidecat-dev/aauth-go => " + filepath.ToSlash(moduleRoot) + "\n"
	writeEventsExternalFile(t, externalModule, "go.mod", goMod)
	writeEventsExternalFile(t, externalModule, "events_test.go", eventsExternalModuleTest)

	command := exec.Command("go", "test", "-mod=mod", "./...", "-count=1")
	command.Dir = externalModule
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("clean Events module failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "ok  \texample.com/events-consumer") {
		t.Fatalf("clean Events module output = %q", output)
	}
}

func writeEventsExternalFile(t *testing.T, directory, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

const eventsExternalModuleTest = `package consumer_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"gitlab.com/sidecat-dev/aauth-go/events"
)

type clock time.Time

func (value clock) Now() time.Time { return time.Time(value) }

func TestEventsPackage(t *testing.T) {
	exact := []byte(` + "`" + `{
		"asyncapi":"3.0.0",
		"info":{"title":"Updates","version":"1"},
		"channels":{"protected":{"address":"/events/{subscriptionTicket}","description":"Protected updates","parameters":{"subscriptionTicket":{"description":"Opaque ticket"}},"messages":{"update":{"$ref":"#/components/messages/update"}}}},
		"operations":{"receiveUpdate":{"action":"receive","channel":{"$ref":"#/channels/protected"}}},
		"components":{"securitySchemes":{"aauth_subscribe":{"type":"http","scheme":"aauth-subscribe"}},"messages":{"update":{"contentType":"application/json","payload":{"type":"object"}}}}
	}` + "`" + `)
	contract, err := events.ParseEventsAsyncAPI(exact)
	if err != nil || contract.Digest() == "" {
		t.Fatalf("contract = %#v, %v", contract, err)
	}
	now := clock(time.Date(2026, 8, 29, 6, 0, 0, 0, time.UTC))
	admit := func(context.Context, string) error { return nil }
	if _, err := events.NewHTTPEventsContractResolver(events.HTTPEventsContractResolverConfig{
		Client: &http.Client{}, Clock: now, Admit: admit,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := events.NewHTTPAgentEventMetadataResolver(events.HTTPAgentEventMetadataResolverConfig{
		Client: &http.Client{}, Clock: now, Admit: admit,
	}); err != nil {
		t.Fatal(err)
	}
}
`
