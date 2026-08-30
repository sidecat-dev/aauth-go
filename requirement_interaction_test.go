package aauth_test

import (
	"testing"

	auth "aauth-go"
)

func TestInteractionRequirementRoundTrip(t *testing.T) {
	t.Parallel()

	want := auth.InteractionRequirement{
		URL:  "https://person.example/interact",
		Code: "A1B2-C3D4",
	}
	formatted, err := auth.FormatInteractionRequirement(want)
	if err != nil {
		t.Fatal(err)
	}
	if formatted != `requirement=interaction;url="https://person.example/interact";code="A1B2-C3D4"` {
		t.Fatalf("FormatInteractionRequirement() = %q", formatted)
	}
	got, err := auth.ParseInteractionRequirement([]string{formatted})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("ParseInteractionRequirement() = %#v, want %#v", got, want)
	}
}

func TestInteractionRequirementParsesExtensionsAndLastValues(t *testing.T) {
	t.Parallel()

	got, err := auth.ParseInteractionRequirement([]string{
		`future=extension`,
		`requirement=approval`,
		`requirement=interaction;url="https://old.example/interact";url="https://person.example/interact";code="OLD1-CODE";code="A1B2-C3D4";future=?1`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://person.example/interact" || got.Code != "A1B2-C3D4" {
		t.Fatalf("ParseInteractionRequirement() = %#v", got)
	}
}

func TestInteractionRequirementAllowsCaseInsensitiveHostSpelling(t *testing.T) {
	t.Parallel()

	value := auth.InteractionRequirement{
		URL: "https://Person.Example/interact", Code: "A1B2-C3D4",
	}
	formatted, err := auth.FormatInteractionRequirement(value)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := auth.ParseInteractionRequirement([]string{formatted})
	if err != nil {
		t.Fatal(err)
	}
	if parsed != value {
		t.Fatalf("round trip = %#v, want %#v", parsed, value)
	}
}

func TestInteractionRequirementRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "empty"},
		{name: "malformed", value: `requirement=interaction;url="unterminated`},
		{name: "missing requirement", value: `other=interaction;url="https://person.example/interact";code="A1B2-C3D4"`},
		{name: "wrong requirement", value: `requirement=approval;url="https://person.example/interact";code="A1B2-C3D4"`},
		{name: "missing URL", value: `requirement=interaction;code="A1B2-C3D4"`},
		{name: "token URL", value: `requirement=interaction;url=https://person.example;code="A1B2-C3D4"`},
		{name: "HTTP URL", value: `requirement=interaction;url="http://person.example/interact";code="A1B2-C3D4"`},
		{name: "relative URL", value: `requirement=interaction;url="/interact";code="A1B2-C3D4"`},
		{name: "URL query", value: `requirement=interaction;url="https://person.example/interact?code=x";code="A1B2-C3D4"`},
		{name: "URL fragment", value: `requirement=interaction;url="https://person.example/interact#code";code="A1B2-C3D4"`},
		{name: "URL credentials", value: `requirement=interaction;url="https://user@person.example/interact";code="A1B2-C3D4"`},
		{name: "missing code", value: `requirement=interaction;url="https://person.example/interact"`},
		{name: "token code", value: `requirement=interaction;url="https://person.example/interact";code=A1B2-C3D4`},
		{name: "short code", value: `requirement=interaction;url="https://person.example/interact";code="A1B2-C3D"`},
		{name: "ambiguous code", value: `requirement=interaction;url="https://person.example/interact";code="A1BI-C3D4"`},
		{name: "lowercase emitted code", value: `requirement=interaction;url="https://person.example/interact";code="a1b2-c3d4"`},
		{name: "non Crockford code", value: `requirement=interaction;url="https://person.example/interact";code="A1B2-C3D!"`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got, err := auth.ParseInteractionRequirement([]string{test.value}); err == nil {
				t.Fatalf("ParseInteractionRequirement() = %#v, want error", got)
			}
		})
	}
}

func TestInteractionCodeComparisonNormalizesHumanInput(t *testing.T) {
	t.Parallel()

	for _, entered := range []string{
		"A1B2-C3D4",
		"a1b2c3d4",
		"AIB2-C3D4",
		"A1B2-C3D4-",
	} {
		if !auth.MatchInteractionCode("A1B2-C3D4", entered) {
			t.Errorf("MatchInteractionCode(%q) = false", entered)
		}
	}
	for _, entered := range []string{"A1B2-C3D5", "A1B2-C3DU", "A1B2-C3D"} {
		if auth.MatchInteractionCode("A1B2-C3D4", entered) {
			t.Errorf("MatchInteractionCode(%q) = true", entered)
		}
	}
}

func TestNormalizeInteractionCode(t *testing.T) {
	t.Parallel()

	got, err := auth.NormalizeInteractionCode("aiB2-o3d4")
	if err != nil {
		t.Fatal(err)
	}
	if got != "A1B203D4" {
		t.Fatalf("NormalizeInteractionCode() = %q", got)
	}
	for _, invalid := range []string{"short", "A1B2-C3DU", "A1B2-C3D!"} {
		if got, err := auth.NormalizeInteractionCode(invalid); err == nil {
			t.Fatalf("NormalizeInteractionCode(%q) = %q, want error", invalid, got)
		}
	}
}

func TestInteractionRequirementFormatterRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	for _, value := range []auth.InteractionRequirement{
		{},
		{URL: "https://person.example/interact", Code: "short"},
		{URL: "http://person.example/interact", Code: "A1B2-C3D4"},
		{URL: "https://person.example/interact?code=x", Code: "A1B2-C3D4"},
	} {
		if formatted, err := auth.FormatInteractionRequirement(value); err == nil {
			t.Fatalf("FormatInteractionRequirement(%#v) = %q, want error", value, formatted)
		}
	}
}
