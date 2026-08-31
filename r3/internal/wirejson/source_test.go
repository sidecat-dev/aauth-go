package wirejson

import "testing"

func TestValidateSourceAcceptsNestedJSONWithoutDuplicateMembers(t *testing.T) {
	if err := ValidateSource([]byte(`{"one":{"two":[{"three":3}]},"four":true}`)); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSourceRejectsDuplicateMembersAtEveryDepth(t *testing.T) {
	for _, source := range []string{
		`{"one":1,"one":2}`,
		`{"outer":{"one":1,"one":2}}`,
		`[{"one":1,"one":2}]`,
	} {
		if err := ValidateSource([]byte(source)); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
}

func TestValidateSourceRejectsInvalidOrTrailingJSON(t *testing.T) {
	for _, source := range []string{``, `{`, `{} {}`, "\xff"} {
		if err := ValidateSource([]byte(source)); err == nil {
			t.Fatalf("accepted %q", source)
		}
	}
}
