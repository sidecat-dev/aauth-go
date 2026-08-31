package budgets

import (
	"encoding/json"
	"testing"
)

func TestUnitDeclarationRoundTripsTheResourceMetadataShape(t *testing.T) {
	t.Parallel()

	usd, _ := NewUnit("USD", 6)
	bounded, err := NewBoundedUnitDeclaration(usd, 10_000_000, "US dollars at micro-dollar precision")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(bounded)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"unit":"USD","decimals":6,"max":10000000,"description":"US dollars at micro-dollar precision"}`
	if string(encoded) != want {
		t.Fatalf("UnitDeclaration JSON = %s, want %s", encoded, want)
	}
	var parsed UnitDeclaration
	if err := json.Unmarshal(encoded, &parsed); err != nil {
		t.Fatal(err)
	}
	maximum, present := parsed.Maximum()
	if !parsed.Unit().Equal(usd) || !present || maximum != 10_000_000 ||
		parsed.Description() != "US dollars at micro-dollar precision" {
		t.Fatalf("parsed declaration = %#v", parsed)
	}

	tokens, _ := NewUnit("tokens", 0)
	unbounded, err := NewUnitDeclaration(tokens, "Model tokens")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(unbounded)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"unit":"tokens","decimals":0,"description":"Model tokens"}` {
		t.Fatalf("unbounded declaration JSON = %s", encoded)
	}
	if _, present := unbounded.Maximum(); present {
		t.Fatal("unbounded declaration exposed a maximum")
	}
}

func TestUnitDeclarationRejectsMalformedMetadataObjects(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		`null`, `{}`, `{"unit":"USD"}`, `{"decimals":6}`,
		`{"unit":null,"decimals":6}`, `{"unit":"USD","decimals":null}`,
		`{"unit":"","decimals":6}`, `{"unit":"USD","decimals":-1}`,
		`{"unit":"USD","decimals":6,"max":null}`,
		`{"unit":"USD","decimals":6,"max":-1}`,
		`{"unit":"USD","decimals":6,"max":1.5}`,
		`{"unit":"USD","decimals":6,"description":null}`,
		`{"unit":"USD","decimals":6,"future":true}`,
		`{"Unit":"USD","decimals":6}`,
		`{"unit":"USD","unit":"tokens","decimals":6}`,
	} {
		var declaration UnitDeclaration
		if err := json.Unmarshal([]byte(raw), &declaration); err == nil {
			t.Fatalf("accepted UnitDeclaration %s", raw)
		}
	}
	usd, _ := NewUnit("USD", 6)
	if _, err := NewBoundedUnitDeclaration(usd, -1, ""); err == nil {
		t.Fatal("accepted negative metadata maximum")
	}
}

func TestUnitDeclarationSetHasOneScalePerUnitAndValidatesOffers(t *testing.T) {
	t.Parallel()

	usd6, _ := NewUnit("USD", 6)
	usd2, _ := NewUnit("USD", 2)
	tokens, _ := NewUnit("tokens", 0)
	usd, _ := NewBoundedUnitDeclaration(usd6, 1_000_000, "")
	tokenDeclaration, _ := NewUnitDeclaration(tokens, "")
	declarations := []UnitDeclaration{usd, tokenDeclaration}
	if err := ValidateUnitDeclarations(declarations); err != nil {
		t.Fatal(err)
	}
	for _, value := range []Value{
		mustValue(t, 1_000_000, usd6),
		mustValue(t, 50, tokens),
	} {
		if err := ValidateDeclaredValue(declarations, value); err != nil {
			t.Fatalf("valid declared value refused: %v", err)
		}
	}
	for _, value := range []Value{
		mustValue(t, 1_000_001, usd6),
		mustValue(t, 100, usd2),
	} {
		if err := ValidateDeclaredValue(declarations, value); err == nil {
			t.Fatalf("invalid declared value accepted: %#v", value)
		}
	}
	wrongScale, _ := NewUnitDeclaration(usd2, "")
	for _, invalid := range [][]UnitDeclaration{
		{usd, usd},
		{usd, wrongScale},
		{{}},
	} {
		if err := ValidateUnitDeclarations(invalid); err == nil {
			t.Fatalf("invalid declaration set accepted: %#v", invalid)
		}
	}
}
