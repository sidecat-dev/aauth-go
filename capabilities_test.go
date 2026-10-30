package aauth_test

import (
	"reflect"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestCapabilitiesRoundTripKnownAndExtensionTokens(t *testing.T) {
	t.Parallel()

	formatted, err := aauth.FormatCapabilities([]string{"interaction", "example-extension"})
	if err != nil {
		t.Fatal(err)
	}
	if formatted != "interaction, example-extension" {
		t.Fatalf("FormatCapabilities = %q", formatted)
	}
	parsed, err := aauth.ParseCapabilities([]string{formatted})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"interaction", "example-extension"}; !reflect.DeepEqual(parsed, want) {
		t.Fatalf("ParseCapabilities = %q, want %q", parsed, want)
	}
}

func TestCapabilitiesParserCombinesFieldLinesAndIgnoresExtensionParameters(t *testing.T) {
	t.Parallel()

	parsed, err := aauth.ParseCapabilities([]string{
		"interaction; future=?1",
		"clarification, vendor-capability; level=2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"interaction", "clarification", "vendor-capability"}; !reflect.DeepEqual(parsed, want) {
		t.Fatalf("ParseCapabilities = %q, want %q", parsed, want)
	}
}

func TestCapabilitiesParserTreatsAnAbsentHeaderAsNoCapabilities(t *testing.T) {
	t.Parallel()

	parsed, err := aauth.ParseCapabilities(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 0 {
		t.Fatalf("ParseCapabilities(nil) = %q", parsed)
	}
}

func TestCapabilitiesRejectMalformedOrAmbiguousLists(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "empty", values: []string{""}},
		{name: "string item", values: []string{`"interaction"`}},
		{name: "inner list", values: []string{"(interaction clarification)"}},
		{name: "invalid token", values: []string{"interaction?"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := aauth.ParseCapabilities(test.values); err == nil {
				t.Fatalf("ParseCapabilities(%q) succeeded", test.values)
			}
		})
	}
	for _, values := range [][]string{nil, {}, {"interaction", "interaction"}, {"not a token"}} {
		if _, err := aauth.FormatCapabilities(values); err == nil {
			t.Fatalf("FormatCapabilities(%q) succeeded", values)
		}
	}
}

// The field is an RFC 9651 List of Tokens. A member that is not a Token makes
// the list malformed, but a parameter the recipient does not recognize is
// ignored whatever its RFC 9651 type, rather than rejecting the header.
func TestCapabilitiesIgnoreUnrecognizedParametersOfEveryRFC9651Type(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "date", values: []string{"interaction", "clarification; future=@1659578233"}},
		{name: "display string", values: []string{"interaction", `clarification; future=%"f%c3%bcnf"`}},
		{name: "byte sequence", values: []string{"interaction", "clarification; future=:AQID:"}},
		{name: "decimal", values: []string{"interaction", "clarification; future=1.5"}},
		{name: "string", values: []string{"interaction", `clarification; future="later"`}},
		{name: "several", values: []string{`interaction; a=@1659578233; b=%"x"`, "clarification; c=?0"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			parsed, err := aauth.ParseCapabilities(test.values)
			if err != nil {
				t.Fatalf("ParseCapabilities(%q) = %v", test.values, err)
			}
			if want := []string{"interaction", "clarification"}; !reflect.DeepEqual(parsed, want) {
				t.Fatalf("ParseCapabilities(%q) = %q, want %q", test.values, parsed, want)
			}
		})
	}
	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "date list member", values: []string{"interaction", "@1659578233"}},
		{name: "display string list member", values: []string{"interaction", `%"future"`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := aauth.ParseCapabilities(test.values); err == nil {
				t.Fatalf("ParseCapabilities(%q) succeeded", test.values)
			}
		})
	}
}
