package budgets

import (
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestBudgetAuthTokenRequirementRoundTripsTypedReasons(t *testing.T) {
	t.Parallel()

	for _, reason := range []Reason{ReasonBudgetExhausted, ReasonInsufficientBudget} {
		reason := reason
		t.Run(reason.String(), func(t *testing.T) {
			t.Parallel()

			formatted, err := FormatAuthTokenRequirement(
				aauth.AuthTokenRequirement{ResourceToken: "eyJ.header.payload"}, reason,
			)
			if err != nil {
				t.Fatal(err)
			}
			want := `requirement=auth-token;resource-token="eyJ.header.payload";reason=` + reason.String()
			if formatted != want {
				t.Fatalf("FormatAuthTokenRequirement() = %q, want %q", formatted, want)
			}

			requirement, gotReason, err := ParseAuthTokenRequirement([]string{formatted})
			if err != nil {
				t.Fatal(err)
			}
			if requirement.ResourceToken != "eyJ.header.payload" || gotReason != reason {
				t.Fatalf("parsed requirement = %#v, %q", requirement, gotReason)
			}
		})
	}
}

func TestBudgetAuthTokenRequirementIgnoresUnrelatedExtensionParameters(t *testing.T) {
	t.Parallel()

	requirement, reason, err := ParseAuthTokenRequirement([]string{
		`future=?1, requirement=auth-token;resource-token="opaque";reason=budget-exhausted;other="reason=ignored"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if requirement.ResourceToken != "opaque" || reason != ReasonBudgetExhausted {
		t.Fatalf("parsed requirement = %#v, %q", requirement, reason)
	}
}

func TestOptionalBudgetReasonDistinguishesCoreStepUpFromBudgetStepUp(t *testing.T) {
	t.Parallel()

	core := `requirement=auth-token;resource-token="eyJ.header.payload"`
	requirement, reason, present, err := ParseOptionalAuthTokenRequirement([]string{core})
	if err != nil || requirement.ResourceToken != "eyJ.header.payload" || present || reason != "" {
		t.Fatalf("Core requirement = %#v, %q, %t, %v", requirement, reason, present, err)
	}
	if _, _, err := ParseAuthTokenRequirement([]string{core}); err == nil {
		t.Fatal("strict Budget parser accepted a requirement with no Budget reason")
	}
}

func TestBudgetAuthTokenRequirementRejectsInvalidCoreOrReasonShape(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "absent"},
		{name: "wrong requirement", values: []string{`requirement=person-token;resource-token="opaque";reason=budget-exhausted`}},
		{name: "missing resource token", values: []string{`requirement=auth-token;reason=budget-exhausted`}},
		{name: "empty resource token", values: []string{`requirement=auth-token;resource-token="";reason=budget-exhausted`}},
		{name: "token resource token", values: []string{`requirement=auth-token;resource-token=opaque;reason=budget-exhausted`}},
		{name: "missing reason", values: []string{`requirement=auth-token;resource-token="opaque"`}},
		{name: "string reason", values: []string{`requirement=auth-token;resource-token="opaque";reason="budget-exhausted"`}},
		{name: "boolean reason", values: []string{`requirement=auth-token;resource-token="opaque";reason`}},
		{name: "integer reason", values: []string{`requirement=auth-token;resource-token="opaque";reason=1`}},
		{name: "unknown reason", values: []string{`requirement=auth-token;resource-token="opaque";reason=expired`}},
		{name: "case variant reason value", values: []string{`requirement=auth-token;resource-token="opaque";reason=Budget-Exhausted`}},
		{name: "case variant reason name", values: []string{`requirement=auth-token;resource-token="opaque";Reason=budget-exhausted`}},
		{name: "case variant resource name", values: []string{`requirement=auth-token;Resource-Token="opaque";reason=budget-exhausted`}},
		{name: "malformed", values: []string{`requirement=auth-token;resource-token="unterminated;reason=budget-exhausted`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if requirement, reason, err := ParseAuthTokenRequirement(test.values); err == nil {
				t.Fatalf("ParseAuthTokenRequirement() = %#v, %q, want error", requirement, reason)
			}
		})
	}
}

func TestBudgetAuthTokenRequirementFormatterRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		requirement aauth.AuthTokenRequirement
		reason      Reason
	}{
		{name: "missing resource token", reason: ReasonBudgetExhausted},
		{name: "invalid resource token string", requirement: aauth.AuthTokenRequirement{ResourceToken: "line\nbreak"}, reason: ReasonBudgetExhausted},
		{name: "missing reason", requirement: aauth.AuthTokenRequirement{ResourceToken: "opaque"}},
		{name: "unknown reason", requirement: aauth.AuthTokenRequirement{ResourceToken: "opaque"}, reason: Reason("expired")},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if formatted, err := FormatAuthTokenRequirement(test.requirement, test.reason); err == nil {
				t.Fatalf("FormatAuthTokenRequirement() = %q, want error", formatted)
			}
		})
	}
}
