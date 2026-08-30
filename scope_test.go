package aauth_test

import (
	"testing"

	auth "github.com/aauth-dev/auth-go"
)

func TestValidateScopeValueUsesOAuthScopeTokenGrammar(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"records.read", "urn:example:scope", "!#$%&'()*+,-./:;<=>?@[]^_`{|}~"} {
		if err := auth.ValidateScopeValue(value); err != nil {
			t.Fatalf("ValidateScopeValue(%q) = %v", value, err)
		}
	}
	for _, value := range []string{"", "records read", `records"read`, `records\read`, "records\tread", "récords"} {
		if err := auth.ValidateScopeValue(value); err == nil {
			t.Fatalf("ValidateScopeValue(%q) succeeded", value)
		}
	}
}

func TestParseScopeRequiresOneCanonicalSpaceAndUniqueValues(t *testing.T) {
	t.Parallel()

	values, err := auth.ParseScope("records.read records.write")
	if err != nil || len(values) != 2 || values[0] != "records.read" || values[1] != "records.write" {
		t.Fatalf("ParseScope() = %v, %v", values, err)
	}
	for _, value := range []string{"", " records.read", "records.read ", "records.read  records.write", "records.read\trecords.write", "records.read records.read"} {
		if _, err := auth.ParseScope(value); err == nil {
			t.Fatalf("ParseScope(%q) succeeded", value)
		}
	}
}
