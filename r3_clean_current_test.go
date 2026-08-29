package aauth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/reference"
)

func TestR3CompanionOwnsAuthorizationWithoutExpandingCoreClaims(t *testing.T) {
	for _, value := range []any{
		aauth.AuthorizationRequest{},
		aauth.AuthorizationDecision{},
		aauth.ResourceTokenClaims{},
		aauth.AuthTokenClaims{},
	} {
		typeOf := reflect.TypeOf(value)
		for _, field := range []string{"R3", "R3URI", "R3S256", "R3Granted", "R3PerCall", "R3Conditional"} {
			if _, exists := typeOf.FieldByName(field); exists {
				t.Errorf("Core type %s owns companion field %s", typeOf, field)
			}
		}
	}
	for _, field := range []struct {
		value any
		name  string
	}{
		{reference.ResourceConfig{}, "R3"},
		{reference.AccessServerConfig{}, "R3GrantPolicy"},
		{reference.PersonServerConfig{}, "R3Review"},
		{reference.ResourceGrant{}, "RequestedR3"},
	} {
		if _, exists := reflect.TypeOf(field.value).FieldByName(field.name); !exists {
			t.Errorf("%T is missing current R3 seam %s", field.value, field.name)
		}
	}
}

func TestRemovedR3ConditionalFormIsAbsentFromProduction(t *testing.T) {
	for _, directory := range []string{".", "r3", "reference"} {
		paths, err := filepath.Glob(filepath.Join(directory, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(parsed, func(node ast.Node) bool {
				if value, ok := node.(*ast.Ident); ok {
					if value.Name == "R3Conditional" || value.Name == "r3Conditional" {
						t.Errorf("%s retains removed identifier %s", path, value.Name)
					}
				}
				return true
			})
		}
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
			if ok {
				if _, blocked := forbidden[identifier.Name]; blocked {
					t.Errorf("%s contains forbidden identifier %s", path, identifier.Name)
				}
			}
			return true
		})
	}
}
