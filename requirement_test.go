package aauth_test

import (
	"bytes"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestInteractionRequirementStructuredFieldRoundTrip(t *testing.T) {
	t.Parallel()

	requirement := aauth.Requirement{
		Type:            aauth.RequirementInteraction,
		InteractionURL:  "https://resource.example/interaction/pending-123",
		InteractionCode: "A1B2-C3D4",
	}
	header, err := aauth.FormatRequirementHeader(requirement)
	if err != nil {
		t.Fatal(err)
	}
	want := `requirement=interaction; url="https://resource.example/interaction/pending-123"; code="A1B2-C3D4"`
	if header != want {
		t.Fatalf("requirement header = %q", header)
	}
	parsed, err := aauth.ParseRequirementHeader(
		header + `; extension="ignored"; count=3; enabled; proof=:AQID:`,
	)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != requirement {
		t.Fatalf("parsed requirement = %#v", parsed)
	}
}

func TestUnknownRequirementValueRemainsParseable(t *testing.T) {
	t.Parallel()

	parsed, err := aauth.ParseRequirementHeader(`requirement=future-action; detail="ignored"`)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Type != aauth.RequirementType("future-action") {
		t.Fatalf("requirement type = %q", parsed.Type)
	}
}

func TestPersonTokenRequirementStructuredFieldRoundTrip(t *testing.T) {
	t.Parallel()

	requirement := aauth.Requirement{Type: aauth.RequirementPersonToken}
	header, err := aauth.FormatRequirementHeader(requirement)
	if err != nil {
		t.Fatal(err)
	}
	if header != "requirement=person-token" {
		t.Fatalf("requirement header = %q", header)
	}
	parsed, err := aauth.ParseRequirementHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != requirement {
		t.Fatalf("parsed requirement = %#v", parsed)
	}
}

func TestInteractionRequirementRejectsInvalidWireValues(t *testing.T) {
	t.Parallel()

	headers := []string{
		`requirement=interaction; code="A1B2-C3D4"`,
		`requirement=interaction; url="https://resource.example/interaction"`,
		`requirement=interaction; url="http://resource.example/interaction"; code="A1B2-C3D4"`,
		`requirement=interaction; url="https://resource.example/interaction?request=1"; code="A1B2-C3D4"`,
		`requirement=interaction; url="https://resource.example/interaction#review"; code="A1B2-C3D4"`,
		`requirement=interaction; url="https://resource.example/interaction"; code="A1B2-O3D4"`,
		`requirement="interaction"; url="https://resource.example/interaction"; code="A1B2-C3D4"`,
		`Requirement=interaction; url="https://resource.example/interaction"; code="A1B2-C3D4"`,
		`requirement=interaction, other=value; url="https://resource.example/interaction"; code="A1B2-C3D4"`,
	}
	for _, header := range headers {
		header := header
		t.Run(header, func(t *testing.T) {
			if _, err := aauth.ParseRequirementHeader(header); err == nil {
				t.Fatalf("ParseRequirementHeader(%q) succeeded", header)
			}
		})
	}
}

func TestInteractionCodeGenerationAndHumanNormalization(t *testing.T) {
	t.Parallel()

	pendingID, err := aauth.GeneratePendingID(bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if pendingID != "AAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("generated pending id = %q", pendingID)
	}

	code, err := aauth.GenerateInteractionCode(bytes.NewReader([]byte{0, 1, 2, 3, 4}))
	if err != nil {
		t.Fatal(err)
	}
	if code != "000G-40R4" {
		t.Fatalf("generated code = %q", code)
	}

	normalized, err := aauth.NormalizeInteractionCode("aib2-o3l4")
	if err != nil {
		t.Fatal(err)
	}
	if normalized != "A1B20314" {
		t.Fatalf("normalized code = %q", normalized)
	}
}

func TestInteractionCodeNormalizationRejectsWeakOrInvalidInput(t *testing.T) {
	t.Parallel()

	for _, code := range []string{"A1B2-C3D", "A1B2-U3D4", "A1B2 C3D4", "--------"} {
		code := code
		t.Run(code, func(t *testing.T) {
			if _, err := aauth.NormalizeInteractionCode(code); err == nil {
				t.Fatalf("NormalizeInteractionCode(%q) succeeded", code)
			}
		})
	}
}
