package aauth_test

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestEventsContractAndDiscoveryHaveNoRootOwnerOrBackEdge(t *testing.T) {
	rootFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	production := rootFiles[:0]
	for _, path := range rootFiles {
		if !strings.HasSuffix(path, "_test.go") {
			production = append(production, path)
		}
	}
	checkFilesForForbiddenIdentifiers(t, production, map[string]struct{}{
		"AgentEventMetadata":                   {},
		"EventsAsyncAPIContract":               {},
		"EventsAsyncAPIMessage":                {},
		"HTTPAgentEventMetadataResolver":       {},
		"HTTPAgentEventMetadataResolverConfig": {},
		"HTTPAgentEventMetadataResolverLimits": {},
		"HTTPEventsContractResolver":           {},
		"HTTPEventsContractResolverConfig":     {},
		"HTTPEventsContractResolverLimits":     {},
		"NewHTTPAgentEventMetadataResolver":    {},
		"NewHTTPEventsContractResolver":        {},
		"ParseEventsAsyncAPI":                  {},
	})

	for _, path := range production {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imported := range parsed.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err == nil && (name == "gitlab.com/sidecat-dev/aauth-go/events" || name == "gitlab.com/sidecat-dev/aauth-go/r3") {
				t.Errorf("root file %s imports %s", path, name)
			}
		}
	}
}
