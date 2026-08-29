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
	draftIdentity := regexp.MustCompile(`draft-[a-z0-9-]+-(?:[0-9]{2}|latest)`)
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

func TestCoveragePinsOneCompleteCurrentEditorFamily(t *testing.T) {
	bundle, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]Source{
		"core": {
			ID: "core", Revision: "draft-hardt-oauth-aauth-protocol-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5",
			Filename: "draft-hardt-oauth-aauth-protocol.md", Format: SourceMarkdown,
			SHA256: "c984278f21e3931f0cc272d6768b84bcc471f8ab4a1a1922dd92940a91df7e19",
		},
		"signature-key": {
			ID: "signature-key", Revision: "draft-hardt-httpbis-signature-key-latest at signature-key 0ff751b571e7fe51336bcc1e526954a202317cc0",
			Filename: "draft-hardt-httpbis-signature-key.md", Format: SourceMarkdown,
			SHA256: "335c6164569fc5b21aae7930c83c4088e4c02b857f9f3acee8335f16f23d66cb",
		},
		"r3": {
			ID: "r3", Revision: "draft-hardt-aauth-r3-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5",
			Filename: "draft-hardt-aauth-r3.md", Format: SourceMarkdown,
			SHA256: "dd768a3b7417c45c0028f2750a50173670fd84c8f432e54ba94799ca93621760",
		},
		"events": {
			ID: "events", Revision: "draft-hardt-aauth-events-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5",
			Filename: "draft-hardt-aauth-events.md", Format: SourceMarkdown,
			SHA256: "6ac4f1c649172a359a6ef32380b189a4edcd9855014bbb03fefe096b74802eb0",
		},
		"bootstrap": {
			ID: "bootstrap", Revision: "draft-hardt-aauth-bootstrap-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5",
			Filename: "draft-hardt-aauth-bootstrap.md", Format: SourceMarkdown,
			SHA256: "ebfe4858e9511020ceb498aea997953b8b79594689ce177ba228230c3ceaf872",
		},
		"budgets": {
			ID: "budgets", Revision: "draft-hardt-aauth-budgets-latest at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5",
			Filename: "draft-hardt-aauth-budgets.md", Format: SourceMarkdown,
			SHA256: "7a27351888d04a4d1059dd9a261243d0960bcc4d918705641b1d9e68c90d4a4d",
		},
		"interop-profile": {
			ID: "interop-profile", Revision: "interop-demo-profile at AAuth a99d353cf18aee81d0c5445bac070164fb3b8bc5",
			Filename: "interop-demo-profile.md", Format: SourceMarkdown,
			SHA256: "ee503da3ea6803370cffe03171f600d44bf9c81a05872b2014b01a61982fe195",
		},
	}
	if len(bundle.Manifest.Sources) != len(expected) {
		t.Fatalf("pinned source count = %d, want one complete seven-source editor family", len(bundle.Manifest.Sources))
	}
	seen := make(map[string]bool, len(expected))
	for _, source := range bundle.Manifest.Sources {
		want, ok := expected[source.ID]
		if !ok {
			t.Errorf("unexpected or historical source entry %q", source.ID)
			continue
		}
		if seen[source.ID] {
			t.Errorf("source entry %q appears more than once", source.ID)
		}
		seen[source.ID] = true
		if source != want {
			t.Errorf("source %q = %#v, want %#v", source.ID, source, want)
		}
	}
	for id := range expected {
		if !seen[id] {
			t.Errorf("current editor source %q is absent", id)
		}
	}
}

func TestCurrentClaimsUseCurrentEvidenceOnly(t *testing.T) {
	bundle, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	currentClaims := map[string]string{
		"core\x00overview-resource-managed":                                                     StatusExercised,
		"core\x00person-token-endpoint":                                                         StatusPartial,
		"core\x00person-token-structure":                                                        StatusExercised,
		"core\x00person-token-usage":                                                            StatusExercised,
		"core\x00person-token-verification":                                                     StatusExercised,
		"core\x00overview-person-identity":                                                      StatusExercised,
		"core\x00resource-tokens/authorization-endpoint-request":                                StatusExercised,
		"core\x00resource-tokens/authorization-endpoint-responses/response-with-resource-token": StatusExercised,
		"core\x00resource-tokens/resource-token/resource-token-structure":                       StatusExercised,
		"core\x00resource-tokens/resource-token/resource-token-verification":                    StatusPartial,
		"core\x00resource-tokens/resource-token/resource-challenge-verification":                StatusPartial,
		"core\x00requirement-auth-token":                                                        StatusPartial,
		"core\x00requirement-person-token":                                                      StatusExercised,
		"core\x00deferred-auth-token":                                                           StatusPartial,
		"core\x00covered-components":                                                            StatusPartial,
		"core\x00ps-token-endpoint/agent-token-request":                                         StatusPartial,
		"core\x00ps-token-endpoint/ps-response":                                                 StatusPartial,
		"core\x00mission-creation":                                                              StatusPartial,
		"core\x00mission-completion":                                                            StatusPartial,
		"core\x00mission-approval":                                                              StatusPartial,
		"core\x00token-revocation":                                                              StatusPartial,
		"core\x00access-server-federation":                                                      StatusPartial,
		"core\x00as-token-endpoint/ps-to-as-token-request":                                      StatusPartial,
		"core\x00as-token-endpoint/as-response":                                                 StatusPartial,
		"core\x00as-token-endpoint/auth-token-delivery":                                         StatusPartial,
		"core\x00auth-tokens/auth-token-structure":                                              StatusExercised,
		"core\x00auth-tokens/auth-token-usage":                                                  StatusExercised,
		"core\x00auth-tokens/auth-token-verification/jwt-trust-verification":                    StatusExercised,
		"core\x00auth-tokens/auth-token-verification/request-context-binding":                   StatusPartial,
		"core\x00auth-token-response-verification":                                              StatusExercised,
		"core\x00call-chaining":                                                                 StatusExercised,
		"core\x00sub-agents/sub-agent-identity":                                                 StatusExercised,
		"core\x00sub-agents/single-level-depth":                                                 StatusExercised,
		"core\x00sub-agents/parent-mediated-authorization":                                      StatusExercised,
		"core\x00requirement-responses/interaction-required":                                    StatusPartial,
		"core\x00deferred-responses/initial-request":                                            StatusExercised,
		"core\x00deferred-responses/deferred-response-state-machine":                            StatusPartial,
		"r3\x00vocabularies":                                                                    StatusPartial,
		"r3\x00r3-document/fields":                                                              StatusPartial,
		"r3\x00content-addressing":                                                              StatusPartial,
		"r3\x00r3-document/resource-token-extensions":                                           StatusPartial,
		"r3\x00auth-token-extensions":                                                           StatusPartial,
		"r3\x00authorization-endpoint-extensions/request":                                       StatusPartial,
		"r3\x00authorization-endpoint-extensions/response":                                      StatusPartial,
		"r3\x00r3-processing":                                                                   StatusPartial,
		"r3\x00r3-processing/as-processing":                                                     StatusPartial,
		"r3\x00resource-enforcement":                                                            StatusPartial,
		"r3\x00r3-document-access-restriction":                                                  StatusPartial,
		"r3\x00security-considerations/hash-verification":                                       StatusExercised,
		"r3\x00security-considerations/grant-enforcement":                                       StatusPartial,
		"r3\x00security-considerations/audit-log-integrity":                                     StatusExercised,
	}
	currentEvidence := map[string]bool{
		"access_client_test.go":                               true,
		"access_journey_test.go":                              true,
		"call_chaining_journey_test.go":                       true,
		"current_mission_recovery_test.go":                    true,
		"current_person_token_journey_test.go":                true,
		"deferred_access_journey_test.go":                     true,
		"deferred_four_party_journey_test.go":                 true,
		"deferred_person_server_journey_test.go":              true,
		"deferred_protected_journey_test.go":                  true,
		"person_token_internal_test.go":                       true,
		"person_token_access_journey_test.go":                 true,
		"protected_challenge_journey_test.go":                 true,
		"r3/document_internal_test.go":                        true,
		"r3/external_module_test.go":                          true,
		"r3/token_external_test.go":                           true,
		"r3_direct_journey_test.go":                           true,
		"reference/r3_direct_test.go":                         true,
		"reference/r3_document_store_test.go":                 true,
		"reference/protected_challenge_test.go":               true,
		"reference/deferred_protected_store_test.go":          true,
		"reference/resource_metadata_test.go":                 true,
		"reference/person_token_resource_limit_test.go":       true,
		"mission_update_journey_test.go":                      true,
		"mission_completion_journey_test.go":                  true,
		"mission_test.go":                                     true,
		"revocation_journey_test.go":                          true,
		"resource_revocation_journey_test.go":                 true,
		"access_server_revocation_journey_test.go":            true,
		"person_server_auth_token_revocation_journey_test.go": true,
		"revocation_test.go":                                  true,
		"reference/token_revocation_test.go":                  true,
		"signaturekey/request_external_test.go":               true,
		"subagent_journey_test.go":                            true,
	}
	seenCurrent := make(map[string]bool, len(currentClaims))
	obsoleteOnly := map[string]struct{}{
		"core\x00audit-endpoint/audit-request":             {},
		"core\x00audit-endpoint/audit-response":            {},
		"core\x00interaction-endpoint/interaction-request": {},
		"core\x00interaction-response-poll-authority":      {},
		"core\x00mission-creation-overview":                {},
		"core\x00mission-completion-overview":              {},
		"core\x00permission-endpoint/permission-request":   {},
		"core\x00permission-endpoint/permission-response":  {},
		"core\x00person-server/user-interaction":           {},
		"core\x00requirement-agent-token":                  {},
		"core\x00resource-initiated-interaction":           {},
		"core\x00mission-log":                              {},
		"core\x00upstream-token-verification":              {},
		"core\x00metadata-documents":                       {},
		"r3\x00authorization-endpoint-extensions":          {},
		"r3\x00per-call-proposals":                         {},
		"r3\x00r3-document":                                {},
		"interop-profile\x00aauth-interoperability-demo-profile/surface-1-ps-mission-approval-and-blob-response":        {},
		"interop-profile\x00aauth-interoperability-demo-profile/surface-3-resource-token-issuance-and-issuer-discovery": {},
		"interop-profile\x00aauth-interoperability-demo-profile/surface-4-auth-token-issuance-and-presentation":         {},
		"interop-profile\x00aauth-interoperability-demo-profile/surface-5-parent-mediated-sub-agent-token-handling":     {},
	}
	for _, annotation := range bundle.Manifest.Annotations {
		key := annotation.Source + "\x00" + annotation.Section
		if wantStatus, found := currentClaims[key]; found {
			seenCurrent[key] = true
			if annotation.Status != wantStatus {
				t.Errorf("current claim %s status = %s, want %s", key, annotation.Status, wantStatus)
			}
			if len(annotation.Evidence) == 0 {
				t.Errorf("current claim %s has no evidence", key)
			}
			for _, evidence := range annotation.Evidence {
				if !currentEvidence[evidence.File] {
					t.Errorf("current claim %s uses obsolete evidence %s", key, evidence.File)
				}
			}
		}
		if _, found := obsoleteOnly[key]; found {
			t.Errorf("obsolete evidence still claims current section %s/%s as %s", annotation.Source, annotation.Section, annotation.Status)
		}
	}
	for key := range currentClaims {
		if !seenCurrent[key] {
			t.Errorf("current claim %s is absent", key)
		}
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
		"Protected subscription tickets and AsyncAPI remain outside this public profile",
		"Token-carried payloads and multi-event replay remain outside both profiles",
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
		"signature-key\x00signature-key-http-request-header/self-issued-jwt-self-jwt": "same discovered key",
		"events\x00protocol-overview":         "public single-use",
		"events\x00subscribe-token":           "max_uses:1",
		"events\x00subscription-registration": "exact subscribe token",
		"events\x00event-token":               "payload-free",
		"events\x00event-delivery":            "exact event token",
		"events\x00ap-to-agent":               "non-normative",
		"events\x00event-discovery":           "AsyncAPI",
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
