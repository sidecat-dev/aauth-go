package aauth_test

import (
	"testing"

	aauth "github.com/aauth-dev/auth-go"
)

func TestGenericRequirementParsesCurrentAndExtensionTokens(t *testing.T) {
	for _, test := range []struct {
		wire string
		want aauth.Requirement
	}{
		{`requirement=interaction;url="https://ps.example/interact";code="A1B2-C3D4"`, aauth.RequirementInteraction},
		{`requirement=approval`, aauth.RequirementApproval},
		{`requirement=clarification;question="which?"`, aauth.RequirementClarification},
		{`requirement=future-consent;future=?1`, aauth.Requirement("future-consent")},
	} {
		got, err := aauth.ParseRequirement([]string{test.wire})
		if err != nil || got != test.want {
			t.Fatalf("ParseRequirement(%q) = %q, %v; want %q", test.wire, got, err, test.want)
		}
	}
}

func TestGenericRequirementRejectsMissingAndNonTokenValues(t *testing.T) {
	for _, wire := range []string{"", `other=approval`, `requirement="approval"`} {
		if got, err := aauth.ParseRequirement([]string{wire}); err == nil {
			t.Fatalf("ParseRequirement(%q) = %q, want error", wire, got)
		}
	}
}
