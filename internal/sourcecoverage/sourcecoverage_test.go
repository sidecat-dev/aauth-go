package sourcecoverage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedCoverageEvidenceAndReportAreCurrent(t *testing.T) {
	bundle, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	repoDir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyEvidence(repoDir); err != nil {
		t.Fatal(err)
	}
	report, err := bundle.RenderMarkdown()
	if err != nil {
		t.Fatal(err)
	}
	checkedIn, err := os.ReadFile(filepath.Join(repoDir, "SOURCE-COVERAGE.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(report, checkedIn) {
		t.Fatal("SOURCE-COVERAGE.md differs from embedded coverage data")
	}
}

func TestBundleVerifiesPinnedSourcesSectionsAndEvidence(t *testing.T) {
	sourceDir := t.TempDir()
	repoDir := t.TempDir()
	sourceBody := []byte(
		"# Introduction\n\nContext.\n\n" +
			"## Permission Endpoint {#permission-endpoint}\n\n" +
			"The server MUST verify the request.\n",
	)
	writeTestFile(t, filepath.Join(sourceDir, "core.md"), sourceBody)
	writeTestFile(t, filepath.Join(repoDir, "permission_test.go"), []byte(
		"package proof\n\n"+
			"import \"testing\"\n\n"+
			"func TestPermissionProof(t *testing.T) {}\n",
	))
	bundle := testBundle(sourceBody)

	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate bundle: %v", err)
	}
	if err := bundle.VerifySources(sourceDir); err != nil {
		t.Fatalf("verify sources: %v", err)
	}
	if err := bundle.VerifyEvidence(repoDir); err != nil {
		t.Fatalf("verify evidence: %v", err)
	}
	report, err := bundle.RenderMarkdown()
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"source coverage is not a full-conformance claim",
		"| Exercised | 0 |",
		"| Partial | 1 |",
		"| Unclaimed | 1 |",
		"`permission_test.go:TestPermissionProof`",
	} {
		if !strings.Contains(string(report), expected) {
			t.Fatalf("coverage report does not contain %q:\n%s", expected, report)
		}
	}
}

func TestBundleRejectsSourceDrift(t *testing.T) {
	sourceDir := t.TempDir()
	sourceBody := []byte("# Introduction\n")
	writeTestFile(t, filepath.Join(sourceDir, "core.md"), sourceBody)
	bundle := testBundle(sourceBody)

	writeTestFile(
		t,
		filepath.Join(sourceDir, "core.md"),
		[]byte("# Introduction\n\nChanged.\n"),
	)
	if err := bundle.VerifySources(sourceDir); err == nil ||
		!strings.Contains(err.Error(), "source digest") {
		t.Fatalf("source drift error = %v", err)
	}
}

func TestBundleRejectsSectionInventoryDrift(t *testing.T) {
	sourceDir := t.TempDir()
	sourceBody := []byte(
		"# Introduction\n\n" +
			"## Permission Endpoint {#permission-endpoint}\n",
	)
	writeTestFile(t, filepath.Join(sourceDir, "core.md"), sourceBody)
	bundle := testBundle(sourceBody)
	bundle.Inventory.Sources[0].Sections[1].Title = "Different endpoint"

	if err := bundle.VerifySources(sourceDir); err == nil ||
		!strings.Contains(err.Error(), "section inventory") {
		t.Fatalf("section drift error = %v", err)
	}
}

func TestBundleRejectsStaleEvidence(t *testing.T) {
	repoDir := t.TempDir()
	sourceBody := []byte(
		"# Introduction\n\n" +
			"## Permission Endpoint {#permission-endpoint}\n",
	)
	writeTestFile(t, filepath.Join(repoDir, "permission_test.go"), []byte(
		"package proof\n\n"+
			"import \"testing\"\n\n"+
			"func TestDifferentProof(t *testing.T) {}\n",
	))
	bundle := testBundle(sourceBody)

	if err := bundle.VerifyEvidence(repoDir); err == nil ||
		!strings.Contains(err.Error(), "TestPermissionProof") {
		t.Fatalf("stale evidence error = %v", err)
	}
}

func TestBundleRejectsUnsupportedClaimsAndDuplicateAnnotations(t *testing.T) {
	sourceBody := []byte(
		"# Introduction\n\n" +
			"## Permission Endpoint {#permission-endpoint}\n",
	)
	bundle := testBundle(sourceBody)
	bundle.Manifest.Annotations = append(
		bundle.Manifest.Annotations,
		bundle.Manifest.Annotations[0],
	)
	if err := bundle.Validate(); err == nil ||
		!strings.Contains(err.Error(), "duplicate annotation") {
		t.Fatalf("duplicate annotation error = %v", err)
	}

	bundle = testBundle(sourceBody)
	bundle.Manifest.Annotations[0].Status = StatusUnsupported
	if err := bundle.Validate(); err == nil ||
		!strings.Contains(err.Error(), "must not cite evidence") {
		t.Fatalf("unsupported evidence error = %v", err)
	}
}

func testBundle(sourceBody []byte) Bundle {
	digest := sha256.Sum256(sourceBody)
	return Bundle{
		Manifest: Manifest{
			Schema:  "aauth.source-coverage.v0",
			Profile: "test profile",
			Sources: []Source{{
				ID:       "core",
				Revision: "test-1",
				Filename: "core.md",
				Format:   SourceMarkdown,
				SHA256:   hex.EncodeToString(digest[:]),
			}},
			Annotations: []Annotation{{
				Source:  "core",
				Section: "permission-endpoint",
				Status:  StatusPartial,
				Claim:   "Permission validation is exercised for one profile.",
				Evidence: []Evidence{{
					File: "permission_test.go",
					Test: "TestPermissionProof",
				}},
			}},
		},
		Inventory: Inventory{
			Schema: "aauth.source-section-inventory.v0",
			Sources: []InventorySource{{
				ID: "core",
				Sections: []Section{
					{ID: "introduction", Level: 1, Title: "Introduction"},
					{
						ID:    "permission-endpoint",
						Level: 2,
						Title: "Permission Endpoint",
					},
				},
			}},
		},
	}
}

func writeTestFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
