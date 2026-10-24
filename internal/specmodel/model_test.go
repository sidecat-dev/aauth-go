package specmodel

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func minimalValidModel() Model {
	return Model{
		Schema: "aauth.protocol-heading-map.v1",
		Sources: []Source{{
			ID: "core", File: "core.md", Commit: "commit", SHA256: "digest",
			LineCount: 10, HeadingCount: 2, Authority: "normative",
		}},
		Headings: []Heading{
			{Source: "core", Heading: "First", Line: 3, End: 5, Classification: "normative", CapabilityID: "CORE-FIRST", ValuePackage: "aauth", StateOwnerRole: "none", BehaviorOwnerPackage: "none", ProofSeam: "unit", ProofDetail: "parse"},
			{Source: "core", Heading: "Second", Line: 6, End: 10, Classification: "normative", CapabilityID: "CORE-SECOND", ValuePackage: "aauth", StateOwnerRole: "none", BehaviorOwnerPackage: "none", ProofSeam: "unit", ProofDetail: "parse"},
		},
	}
}

func TestValidateRejectsOverlappingHeadingRanges(t *testing.T) {
	model := minimalValidModel()
	model.Headings[1].Line = model.Headings[0].End
	if err := Validate(model); err == nil {
		t.Fatal("Validate accepted overlapping heading ranges")
	}
}

func TestValidateRejectsUnknownVocabularies(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Heading)
	}{
		{name: "classification", change: func(heading *Heading) { heading.Classification = "normativish" }},
		{name: "state owner", change: func(heading *Heading) { heading.StateOwnerRole = "somewhere" }},
		{name: "proof seam", change: func(heading *Heading) { heading.ProofSeam = "probably-a-test" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			model := minimalValidModel()
			test.change(&model.Headings[0])
			if err := Validate(model); err == nil {
				t.Fatalf("Validate accepted unknown %s", test.name)
			}
		})
	}
}

func TestValidateRejectsTensionWithUnknownSource(t *testing.T) {
	model := minimalValidModel()
	model.SourceTensions = []SourceTension{{
		ID: "TENSION-1", Subject: "A tension", Status: "unresolved",
		Disposition: "Do not guess.", Grounding: "The source omits the binding.",
		References: []SourceReference{{Source: "missing", Lines: []int{1}}},
	}}
	if err := Validate(model); err == nil {
		t.Fatal("Validate accepted a tension referencing an unknown source")
	}
}

func TestEmbeddedModelIsStructurallyComplete(t *testing.T) {
	model, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(model.Sources), 8; got != want {
		t.Fatalf("source count = %d, want %d", got, want)
	}
	if got, want := len(model.Headings), 683; got != want {
		t.Fatalf("heading count = %d, want %d", got, want)
	}
	if got, want := len(model.SourceTensions), 18; got != want {
		t.Fatalf("source-tension count = %d, want %d", got, want)
	}
	if got, want := len(model.Requirements), 1313; got != want {
		t.Fatalf("requirement-occurrence count = %d, want %d", got, want)
	}
}

func TestVerifySourceDirectoryChecksExactBytesAndHeadingSequence(t *testing.T) {
	sourceText := "preamble\n.# Abstract\nInformational MAY.\n# Body\nA server MUST act, SHOULD NOT retry, and the value is REQUIRED.\n"
	digest := sha256.Sum256([]byte(sourceText))
	model := Model{
		Schema: "aauth.protocol-heading-map.v1",
		Sources: []Source{{
			ID: "core", File: "core.md", Commit: "commit",
			SHA256: hex.EncodeToString(digest[:]), LineCount: 5,
			HeadingCount: 2, Authority: "normative",
		}},
		Headings: []Heading{
			{Source: "core", Heading: "Abstract", Line: 2, End: 3, Classification: "informational", CapabilityID: "CORE-ABSTRACT", ValuePackage: "none", StateOwnerRole: "none", BehaviorOwnerPackage: "none", ProofSeam: "documentation", ProofDetail: "documentation-only"},
			{Source: "core", Heading: "Body", Line: 4, End: 5, Classification: "normative", CapabilityID: "CORE-BODY", ValuePackage: "aauth", StateOwnerRole: "none", BehaviorOwnerPackage: "none", ProofSeam: "unit", ProofDetail: "parse"},
		},
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "core.md"), []byte(sourceText), 0o600); err != nil {
		t.Fatal(err)
	}
	requirements, err := ExtractRequirements(model, directory)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(requirements), 4; got != want {
		t.Fatalf("requirement occurrence count = %d, want %d", got, want)
	}
	if requirements[0].Authority != "informational" || requirements[1].Strength != "MUST" || requirements[2].Strength != "SHOULD NOT" || requirements[3].Kind != "field_presence" {
		t.Fatalf("requirement extraction = %#v", requirements)
	}
	model.Requirements = requirements
	if err := VerifySourceDirectory(model, directory); err != nil {
		t.Fatalf("valid source directory: %v", err)
	}
	changedRequirements := model
	changedRequirements.Requirements = append([]Requirement(nil), model.Requirements...)
	changedRequirements.Requirements[0].LineSHA256 = strings.Repeat("0", 64)
	if err := VerifySourceDirectory(changedRequirements, directory); err == nil {
		t.Fatal("source verification accepted a changed requirement occurrence")
	}

	changed := model
	changed.Headings = append([]Heading(nil), model.Headings...)
	changed.Headings[1].Heading = "Different"
	if err := VerifySourceDirectory(changed, directory); err == nil {
		t.Fatal("source verification accepted the wrong heading")
	}

	if err := os.WriteFile(filepath.Join(directory, "core.md"), []byte(strings.Replace(sourceText, "A server MUST act", "A server MUST change", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifySourceDirectory(model, directory); err == nil {
		t.Fatal("source verification accepted changed source bytes")
	}
}

func TestVerifyManifestBindsEachSourceToOneRow(t *testing.T) {
	model := minimalValidModel()
	valid := []byte("| Name | Commit | Source | SHA-256 |\n| --- | --- | --- | --- |\n| Core | commit | core.md | digest |\n")
	if err := VerifyManifest(model, valid); err != nil {
		t.Fatalf("valid manifest: %v", err)
	}
	valuesScatteredAcrossRows := []byte("| Name | Commit | Source | SHA-256 |\n| --- | --- | --- | --- |\n| Other | commit | other.md | digest |\n| Core | wrong | core.md | wrong |\n")
	if err := VerifyManifest(model, valuesScatteredAcrossRows); err == nil {
		t.Fatal("manifest verification accepted source identity scattered across rows")
	}
}

func TestModelPinsMatchRecipientFacingManifest(t *testing.T) {
	manifest, err := os.ReadFile("../../SPECIFICATIONS.md")
	if err != nil {
		t.Fatal(err)
	}
	model, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(model, manifest); err != nil {
		t.Fatal(err)
	}
}
