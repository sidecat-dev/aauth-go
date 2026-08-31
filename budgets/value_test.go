package budgets

import (
	"encoding/json"
	"testing"
)

func TestValueRoundTripsTheBudgetObject(t *testing.T) {
	t.Parallel()

	unit, err := NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewValue(5_000_000, unit)
	if err != nil {
		t.Fatal(err)
	}
	if value.Amount() != 5_000_000 || value.Unit().Name() != "USD" || value.Unit().Decimals() != 6 {
		t.Fatalf("value = %d %q/%d", value.Amount(), value.Unit().Name(), value.Unit().Decimals())
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"amount":5000000,"unit":"USD","decimals":6}`
	if string(encoded) != want {
		t.Fatalf("encoded value = %s, want %s", encoded, want)
	}

	parsed, err := ParseValueJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Amount() != value.Amount() || !parsed.Unit().Equal(value.Unit()) {
		t.Fatalf("parsed value = %d %q/%d", parsed.Amount(), parsed.Unit().Name(), parsed.Unit().Decimals())
	}

	var unmarshaled Value
	if err := json.Unmarshal(encoded, &unmarshaled); err != nil {
		t.Fatal(err)
	}
	if unmarshaled.Amount() != value.Amount() || !unmarshaled.Unit().Equal(value.Unit()) {
		t.Fatalf("unmarshaled value = %d %q/%d", unmarshaled.Amount(), unmarshaled.Unit().Name(), unmarshaled.Unit().Decimals())
	}
}

func TestValueRejectsInvalidNumbersAndDenominations(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		unit     string
		decimals int64
		amount   int64
	}{
		{name: "empty unit", decimals: 6, amount: 1},
		{name: "negative decimals", unit: "USD", decimals: -1, amount: 1},
		{name: "decimals outside carrier", unit: "USD", decimals: MaximumAmount + 1, amount: 1},
		{name: "negative amount", unit: "USD", decimals: 6, amount: -1},
		{name: "amount outside carrier", unit: "USD", decimals: 6, amount: MaximumAmount + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			unit, unitErr := NewUnit(test.unit, test.decimals)
			if unitErr != nil {
				return
			}
			if value, err := NewValue(test.amount, unit); err == nil {
				t.Fatalf("NewValue() = %#v, want error", value)
			}
		})
	}

	if encoded, err := json.Marshal(Value{}); err == nil {
		t.Fatalf("zero Value marshaled as %s", encoded)
	}
}

func TestParseValueJSONRejectsEveryMalformedBudgetShape(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		raw  string
	}{
		{name: "null", raw: `null`},
		{name: "array", raw: `[]`},
		{name: "missing amount", raw: `{"unit":"USD","decimals":6}`},
		{name: "missing unit", raw: `{"amount":1,"decimals":6}`},
		{name: "missing decimals", raw: `{"amount":1,"unit":"USD"}`},
		{name: "null amount", raw: `{"amount":null,"unit":"USD","decimals":6}`},
		{name: "null unit", raw: `{"amount":1,"unit":null,"decimals":6}`},
		{name: "null decimals", raw: `{"amount":1,"unit":"USD","decimals":null}`},
		{name: "floating amount", raw: `{"amount":1.5,"unit":"USD","decimals":6}`},
		{name: "string amount", raw: `{"amount":"1","unit":"USD","decimals":6}`},
		{name: "negative amount", raw: `{"amount":-1,"unit":"USD","decimals":6}`},
		{name: "amount outside carrier", raw: `{"amount":1000000000000000,"unit":"USD","decimals":6}`},
		{name: "negative decimals", raw: `{"amount":1,"unit":"USD","decimals":-1}`},
		{name: "empty unit", raw: `{"amount":1,"unit":"","decimals":6}`},
		{name: "unknown member", raw: `{"amount":1,"unit":"USD","decimals":6,"future":true}`},
		{name: "case variant", raw: `{"Amount":1,"unit":"USD","decimals":6}`},
		{name: "duplicate", raw: `{"amount":1,"amount":2,"unit":"USD","decimals":6}`},
		{name: "trailing value", raw: `{"amount":1,"unit":"USD","decimals":6} true`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if value, err := ParseValueJSON([]byte(test.raw)); err == nil {
				t.Fatalf("ParseValueJSON() = %#v, want error", value)
			}
		})
	}
	invalidUTF8 := append([]byte(`{"amount":1,"unit":"`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`","decimals":6}`)...)
	if value, err := ParseValueJSON(invalidUTF8); err == nil {
		t.Fatalf("ParseValueJSON() normalized invalid UTF-8 into %#v", value)
	}
}

func TestValidateNarrowingRequiresTheSameDenominationAndNoIncrease(t *testing.T) {
	t.Parallel()

	usd6, _ := NewUnit("USD", 6)
	usd2, _ := NewUnit("USD", 2)
	tokens, _ := NewUnit("tokens", 0)
	offered, _ := NewValue(5_000_000, usd6)
	unchanged, _ := NewValue(5_000_000, usd6)
	lower, _ := NewValue(2_000_000, usd6)
	higher, _ := NewValue(5_000_001, usd6)
	changedScale, _ := NewValue(500, usd2)
	changedUnit, _ := NewValue(5_000_000, tokens)

	for _, grant := range []Value{unchanged, lower} {
		if err := ValidateNarrowing(offered, grant); err != nil {
			t.Fatalf("valid narrowing refused: %v", err)
		}
	}
	for _, grant := range []Value{higher, changedScale, changedUnit, {}} {
		if err := ValidateNarrowing(offered, grant); err == nil {
			t.Fatalf("invalid narrowing accepted: %#v", grant)
		}
	}
}
