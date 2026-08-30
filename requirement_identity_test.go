package aauth_test

import (
	"testing"

	aauth "aauth-go"
)

func TestIdentityTokenRequirementsRoundTripCanonicalFields(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		format func() string
		parse  func([]string) error
		want   string
	}{
		{name: "agent", format: aauth.FormatAgentTokenRequirement, parse: aauth.ParseAgentTokenRequirement, want: "requirement=agent-token"},
		{name: "person", format: aauth.FormatPersonTokenRequirement, parse: aauth.ParsePersonTokenRequirement, want: "requirement=person-token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			formatted := test.format()
			if formatted != test.want {
				t.Fatalf("formatted = %q, want %q", formatted, test.want)
			}
			if err := test.parse([]string{"future=true", formatted}); err != nil {
				t.Fatalf("parse split fields: %v", err)
			}
			if err := test.parse([]string{formatted + "; future=true"}); err != nil {
				t.Fatalf("parse future parameter: %v", err)
			}
		})
	}
}

func TestIdentityTokenRequirementsRejectWrongShape(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		parse func([]string) error
	}{
		{name: "agent", parse: aauth.ParseAgentTokenRequirement},
		{name: "person", parse: aauth.ParsePersonTokenRequirement},
	} {
		for _, values := range [][]string{
			nil,
			{"requirement=\"agent-token\""},
			{"requirement=auth-token"},
			{"requirement=(agent-token)"},
		} {
			t.Run(test.name, func(t *testing.T) {
				if err := test.parse(values); err == nil {
					t.Fatalf("parse %q succeeded", values)
				}
			})
		}
	}
}
