package aauth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestR3CallableAuthorizationSurfaceIsAbsent(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		value     any
		forbidden []string
	}{
		{aauth.AuthorizationRequest{}, []string{"R3"}},
		{aauth.AuthorizationDecision{}, []string{"R3Granted"}},
		{aauth.ResourceTokenClaims{}, []string{"R3URI", "R3S256"}},
		{aauth.AuthTokenClaims{}, []string{"R3URI", "R3S256", "R3Granted", "R3PerCall", "R3Conditional"}},
		{reference.ResourceConfig{}, []string{
			"R3Vocabularies", "R3DocumentStore", "R3DocumentForOperations",
			"R3RequiredForRequest", "R3OperationForRequest", "R3ProposalForRequest",
		}},
		{reference.AccessServerConfig{}, []string{
			"R3HTTPClient", "R3Audit", "R3Admit", "R3FetchTimeout", "R3CacheLimit",
		}},
		{reference.ResourceGrant{}, []string{"RequestedR3"}},
	} {
		typeOf := reflect.TypeOf(test.value)
		for _, field := range test.forbidden {
			if _, exists := typeOf.FieldByName(field); exists {
				t.Errorf("%s still exposes direct-R3 field %s", typeOf, field)
			}
		}
	}

	documentType := reflect.TypeOf(aauth.R3Document{})
	if _, exists := documentType.FieldByName("Version"); exists {
		t.Error("R3Document still exposes the removed version member")
	}
	for _, field := range []string{"Vocabulary", "Operations", "Account", "Parameters", "Display"} {
		if _, exists := documentType.FieldByName(field); !exists {
			t.Errorf("R3Document is missing current neutral field %s", field)
		}
	}
}

func TestR3CallableAuthorizationImplementationIsAbsent(t *testing.T) {
	t.Parallel()

	forbiddenRoot := map[string]struct{}{
		"R3VocabularyOpenAPIGateway": {},
		"R3Authorization":            {},
		"R3AuditRecord":              {},
		"R3Proposal":                 {},
		"R3CallParameter":            {},
		"BuildR3Proposal":            {},
		"MatchR3Call":                {},
		"validateR3Reference":        {},
	}
	forbiddenReference := map[string]struct{}{
		"RequestedR3":                     {},
		"R3Operations":                    {},
		"r3DocumentStore":                 {},
		"r3DocumentForOperations":         {},
		"r3RequiredForRequest":            {},
		"r3OperationForRequest":           {},
		"R3ProposalForRequest":            {},
		"r3ProposalForRequest":            {},
		"handleR3Document":                {},
		"r3HTTPClient":                    {},
		"r3Audit":                         {},
		"r3Admit":                         {},
		"r3FetchTimeout":                  {},
		"r3CacheLimit":                    {},
		"r3Cache":                         {},
		"r3CacheEntry":                    {},
		"fetchR3Authorization":            {},
		"fetchR3AuthorizationUncached":    {},
		"newR3FetchNonce":                 {},
		"validateR3AuthorizationDecision": {},
		"validateR3DecisionSet":           {},
		"cloneR3OperationSet":             {},
		"cloneR3Document":                 {},
		"validateResourceGrantR3Request":  {},
	}

	checkFilesForForbiddenIdentifiers(t, []string{"decision.go", "token.go", "r3.go"}, forbiddenRoot)
	referenceFiles, err := filepath.Glob(filepath.Join("reference", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	production := referenceFiles[:0]
	for _, path := range referenceFiles {
		if !strings.HasSuffix(path, "_test.go") && filepath.Base(path) != "r3_document_store.go" {
			production = append(production, path)
		}
	}
	checkFilesForForbiddenIdentifiers(t, production, forbiddenReference)

	for _, path := range production {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err == nil && value == "GET /r3/{s256}" {
				t.Errorf("%s still registers the direct-R3 document route", path)
			}
			return true
		})
	}
}

func checkFilesForForbiddenIdentifiers(t *testing.T, paths []string, forbidden map[string]struct{}) {
	t.Helper()
	for _, path := range paths {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			if _, exists := forbidden[identifier.Name]; exists {
				t.Errorf("%s still contains direct-R3 identifier %s", path, identifier.Name)
			}
			return true
		})
	}
}
