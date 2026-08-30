package aauth_test

import (
	"testing"

	auth "github.com/aauth-dev/auth-go"
)

func TestAuthTokenRequirementRoundTrip(t *testing.T) {
	t.Parallel()

	const resourceToken = "eyJ.header.payload"

	t.Run("Parse", func(t *testing.T) {
		parsed, err := auth.ParseAuthTokenRequirement([]string{
			`requirement=auth-token;resource-token="eyJ.header.payload";future=?1;note="resource-token=ignored, requirement=ignored"`,
		})
		if err != nil {
			t.Fatal(err)
		}
		if parsed.ResourceToken != resourceToken {
			t.Fatalf("ResourceToken = %q, want %q", parsed.ResourceToken, resourceToken)
		}
	})

	t.Run("Format", func(t *testing.T) {
		formatted, err := auth.FormatAuthTokenRequirement(auth.AuthTokenRequirement{
			ResourceToken: resourceToken,
		})
		if err != nil {
			t.Fatal(err)
		}
		const want = `requirement=auth-token;resource-token="eyJ.header.payload"`
		if formatted != want {
			t.Fatalf("FormatAuthTokenRequirement() = %q, want %q", formatted, want)
		}

		parsed, err := auth.ParseAuthTokenRequirement([]string{formatted})
		if err != nil {
			t.Fatal(err)
		}
		if parsed.ResourceToken != resourceToken {
			t.Fatalf("round-trip ResourceToken = %q, want %q", parsed.ResourceToken, resourceToken)
		}
	})
}

func TestAuthTokenRequirementRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
	}{
		{name: "absent"},
		{name: "empty input", values: []string{}},
		{name: "empty field line", values: []string{""}},
		{name: "whitespace field line", values: []string{" \t"}},
		{name: "malformed structured field", values: []string{`requirement=auth-token;resource-token="unterminated`}},
		{name: "missing requirement", values: []string{`other=auth-token;resource-token="opaque"`}},
		{name: "bare boolean requirement", values: []string{`requirement;resource-token="opaque"`}},
		{name: "string requirement", values: []string{`requirement="auth-token";resource-token="opaque"`}},
		{name: "inner list requirement", values: []string{`requirement=(auth-token);resource-token="opaque"`}},
		{name: "wrong requirement token", values: []string{`requirement=interaction;resource-token="opaque"`}},
		{name: "missing resource token", values: []string{`requirement=auth-token`}},
		{name: "token resource token", values: []string{`requirement=auth-token;resource-token=opaque`}},
		{name: "integer resource token", values: []string{`requirement=auth-token;resource-token=1`}},
		{name: "empty resource token", values: []string{`requirement=auth-token;resource-token=""`}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if parsed, err := auth.ParseAuthTokenRequirement(test.values); err == nil {
				t.Fatalf("ParseAuthTokenRequirement() = %+v, want error", parsed)
			}
		})
	}
}

func TestAuthTokenRequirementUsesRFC8941LastValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{
			name: "dictionary member across field lines",
			values: []string{
				`requirement=interaction;resource-token="first"`,
				`requirement=auth-token;resource-token="last"`,
			},
			want: "last",
		},
		{
			name:   "parameter",
			values: []string{`requirement=auth-token;resource-token="first";resource-token="last"`},
			want:   "last",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			parsed, err := auth.ParseAuthTokenRequirement(test.values)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.ResourceToken != test.want {
				t.Fatalf("ResourceToken = %q, want %q", parsed.ResourceToken, test.want)
			}
		})
	}
}

func TestAuthTokenRequirementHandlesMultipleFieldLines(t *testing.T) {
	t.Parallel()

	parsed, err := auth.ParseAuthTokenRequirement([]string{
		`future=extension;value="ignored"`,
		`requirement=auth-token;resource-token="eyJ.multiline.payload";flag`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ResourceToken != "eyJ.multiline.payload" {
		t.Fatalf("ResourceToken = %q, want %q", parsed.ResourceToken, "eyJ.multiline.payload")
	}
}

func TestAuthTokenRequirementFormatterRejectsInvalidResourceToken(t *testing.T) {
	t.Parallel()

	for _, resourceToken := range []string{"", "line\nbreak", "non-ASCII-é"} {
		resourceToken := resourceToken
		t.Run(resourceToken, func(t *testing.T) {
			t.Parallel()

			if formatted, err := auth.FormatAuthTokenRequirement(auth.AuthTokenRequirement{
				ResourceToken: resourceToken,
			}); err == nil {
				t.Fatalf("FormatAuthTokenRequirement() = %q, want error", formatted)
			}
		})
	}
}
