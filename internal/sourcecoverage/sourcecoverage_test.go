package sourcecoverage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
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
	if err := bundle.VerifySources("sources"); err != nil {
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

func TestProfileNamesEveryPinnedDraftRevision(t *testing.T) {
	bundle, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	draftIdentity := regexp.MustCompile(`draft-[a-z0-9-]+-[0-9]{2}`)
	named := 0
	for _, source := range bundle.Manifest.Sources {
		identity := draftIdentity.FindString(source.Revision)
		if identity == "" {
			continue
		}
		named++
		if !strings.Contains(bundle.Manifest.Profile, identity) {
			t.Errorf(
				"profile %q does not name pinned source %s revision %q",
				bundle.Manifest.Profile,
				source.ID,
				identity,
			)
		}
	}
	if named == 0 {
		t.Fatal("no pinned source carries a draft revision identity")
	}
}

func TestEventsPublicClaimsMatchQualifiedProfile(t *testing.T) {
	bundle, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	repoDir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile(filepath.Join(repoDir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	normalizedREADME := strings.Join(strings.Fields(string(readme)), " ")
	for _, required := range []string{
		"The selected public Events profile is implemented and qualified",
		"same admitted, discovered key verifies both the compact JWT and its HTTP Message Signature",
		"`max_uses: 1`",
		"retains its local context and registers that exact token at the resource",
		"payload-free event",
		"AP can see the event token",
		"Any future token-carried payload would therefore be AP-visible",
		"retrieves current details from the resource under its current authorization",
		"Lost `202 Accepted`",
		"fresh HTTP proof",
		"`429 Too Many Requests`",
		"non-normative host-integration adapter",
		"Protected subscription tickets, AsyncAPI, token payloads, and multi-event replay remain outside this profile",
		"single-writer reference-host qualification",
	} {
		if !strings.Contains(normalizedREADME, required) {
			t.Errorf("README does not state qualified Events boundary %q", required)
		}
	}
	if strings.Contains(normalizedREADME, "Events, platform enrollment/attestation, and the self-jwt") {
		t.Fatal("README still identifies Events and self-jwt as unimplemented")
	}

	wantClaims := map[string]string{
		"signature-key\x00name-self-issued-jwt-self-jwt": "same discovered key",
		"events\x00protocol-overview":                    "public single-use",
		"events\x00subscribe-token":                      "max_uses:1",
		"events\x00subscription-registration":            "exact subscribe token",
		"events\x00event-token":                          "payload-free",
		"events\x00event-delivery":                       "exact event token",
		"events\x00ap-to-agent":                          "non-normative",
		"events\x00event-discovery":                      "AsyncAPI",
	}
	seen := make(map[string]bool, len(wantClaims))
	for _, annotation := range bundle.Manifest.Annotations {
		key := annotation.Source + "\x00" + annotation.Section
		requiredClaim, wanted := wantClaims[key]
		if !wanted {
			continue
		}
		seen[key] = true
		if annotation.Status != StatusPartial {
			t.Errorf("coverage annotation %q status = %q, want partial", key, annotation.Status)
		}
		if !strings.Contains(annotation.Claim, requiredClaim) {
			t.Errorf("coverage annotation %q claim does not contain %q: %q", key, requiredClaim, annotation.Claim)
		}
		if len(annotation.Evidence) == 0 {
			t.Errorf("coverage annotation %q has no executable evidence", key)
		}
	}
	for key := range wantClaims {
		if !seen[key] {
			t.Errorf("coverage annotation %q is absent", key)
		}
	}
}

func TestEventsM6ClaimsMatchQualifiedProfile(t *testing.T) {
	bundle, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	repoDir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile(filepath.Join(repoDir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	normalizedREADME := strings.Join(strings.Fields(string(readme)), " ")
	for _, required := range []string{
		"The selected protected Events profile is implemented and qualified",
		"opaque ticket capability",
		"only its SHA-256 digest",
		"bodyless signed registration",
		"direct `application/json` HTTP body",
		"signed `content-type` and `content-digest`",
		"exact AsyncAPI 3.0.0 JSON document",
		"one `receive` operation",
		"one locally referenced message",
		"inline JSON Schema",
		"Multi-event replay identity",
		"standardized AP-to-agent transport",
		"general AsyncAPI/YAML/external-reference support",
		"registration-body schema mapping",
		"lost-success protected-registration reconciliation",
	} {
		if !strings.Contains(normalizedREADME, required) {
			t.Errorf("README does not state qualified M6 Events boundary %q", required)
		}
	}

	wantClaims := map[string]string{
		"events\x00protocol-overview":         "protected one-use direct JSON",
		"events\x00subscription-registration": "digest-only opaque ticket",
		"events\x00event-token":               "direct HTTP body",
		"events\x00event-delivery":            "exact event token and payload",
		"events\x00ap-to-agent":               "independently validates",
		"events\x00event-discovery":           "AsyncAPI 3.0.0",
	}
	seen := make(map[string]bool, len(wantClaims))
	for _, annotation := range bundle.Manifest.Annotations {
		key := annotation.Source + "\x00" + annotation.Section
		requiredClaim, wanted := wantClaims[key]
		if !wanted {
			continue
		}
		seen[key] = true
		if annotation.Status != StatusPartial {
			t.Errorf("coverage annotation %q status = %q, want partial", key, annotation.Status)
		}
		if !strings.Contains(annotation.Claim, requiredClaim) {
			t.Errorf("coverage annotation %q claim does not contain %q: %q", key, requiredClaim, annotation.Claim)
		}
		if len(annotation.Evidence) == 0 {
			t.Errorf("coverage annotation %q has no executable evidence", key)
		}
	}
	for key := range wantClaims {
		if !seen[key] {
			t.Errorf("coverage annotation %q is absent", key)
		}
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
