package vocabtest_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var rolePackageDirectories = []string{
	"agent",
	"resource",
	"personserver",
	"accessserver",
	"internal/r3fetch",
	"internal/r3dispatch",
}

func TestRolePackagesDoNotImportVocabularyAdapters(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	var violations []string
	visitRoleSourceFiles(t, root, func(path, relative string, fileSet *token.FileSet, file *ast.File) {
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", relative, err)
			}
			if importPath == "gitlab.com/sidecat-dev/aauth-go/r3/vocab" || strings.HasPrefix(importPath, "gitlab.com/sidecat-dev/aauth-go/r3/vocab/") {
				position := fileSet.Position(spec.Pos())
				violations = append(violations, sourceViolation(relative, position.Line, "imports "+importPath))
			}
		}
	})

	requireNoArchitectureViolations(t, violations)
}

func TestRolePackagesDoNotSelectConcreteVocabularyURIs(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	var violations []string
	visitRoleSourceFiles(t, root, func(path, relative string, fileSet *token.FileSet, file *ast.File) {
		rootR3Aliases := make(map[string]struct{})
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil || importPath != "gitlab.com/sidecat-dev/aauth-go/r3" {
				continue
			}
			alias := "r3"
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			if alias != "." && alias != "_" {
				rootR3Aliases[alias] = struct{}{}
			}
		}

		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.BasicLit:
				if value.Kind != token.STRING {
					return true
				}
				literal, err := strconv.Unquote(value.Value)
				if err == nil && strings.HasPrefix(literal, "urn:aauth:vocabulary:") {
					position := fileSet.Position(value.Pos())
					violations = append(violations, sourceViolation(relative, position.Line, "contains concrete vocabulary URI "+literal))
				}
			case *ast.SelectorExpr:
				qualifier, ok := value.X.(*ast.Ident)
				if !ok {
					return true
				}
				if _, ok := rootR3Aliases[qualifier.Name]; !ok {
					return true
				}
				// Generic r3.Vocabulary and r3.VocabularyURI are allowed. A
				// selector such as r3.MCPVocabulary is concrete dispatch that
				// belongs in a vocabulary registration outside role code.
				if value.Sel.Name != "Vocabulary" && strings.HasSuffix(value.Sel.Name, "Vocabulary") {
					position := fileSet.Position(value.Pos())
					violations = append(violations, sourceViolation(relative, position.Line, "selects concrete "+qualifier.Name+"."+value.Sel.Name))
				}
			}
			return true
		})
	})

	requireNoArchitectureViolations(t, violations)
}

func TestVisitRoleSourceFilesWalksNestedPackages(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	for _, directory := range rolePackageDirectories {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(directory)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	nested := filepath.Join(root, "agent", "nested", "adapter.go")
	if err := os.MkdirAll(filepath.Dir(nested), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nested, []byte("package nested\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var visited []string
	visitRoleSourceFiles(t, root, func(_ string, relative string, _ *token.FileSet, _ *ast.File) {
		visited = append(visited, relative)
	})
	if len(visited) != 1 || visited[0] != "agent/nested/adapter.go" {
		t.Fatalf("visited role sources = %#v, want nested source", visited)
	}
}

func visitRoleSourceFiles(
	t *testing.T,
	root string,
	visit func(path, relative string, fileSet *token.FileSet, file *ast.File),
) {
	t.Helper()
	for _, directory := range rolePackageDirectories {
		absolute := filepath.Join(root, filepath.FromSlash(directory))
		err := filepath.WalkDir(absolute, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				t.Fatalf("relative source path %s: %v", path, err)
			}
			relative = filepath.ToSlash(relative)
			fileSet := token.NewFileSet()
			file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse role source %s: %v", relative, err)
			}
			visit(path, relative, fileSet, file)
			return nil
		})
		if err != nil {
			t.Fatalf("walk role package %s: %v", directory, err)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("get test working directory: %v", err)
	}
	root := filepath.Clean(filepath.Join(workingDirectory, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("locate repository root from %s: %v", workingDirectory, err)
	}
	return root
}

func sourceViolation(path string, line int, detail string) string {
	return path + ":" + strconv.Itoa(line) + ": " + detail
}

func requireNoArchitectureViolations(t *testing.T, violations []string) {
	t.Helper()
	if len(violations) == 0 {
		return
	}
	sort.Strings(violations)
	t.Fatalf("R3 vocabulary-neutral role boundary violations:\n%s", strings.Join(violations, "\n"))
}
