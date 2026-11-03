package budgets

import "testing"

func TestSuccessFeedbackUsesAnRFC9651Dictionary(t *testing.T) {
	t.Parallel()

	usd, _ := NewUnit("USD", 6)
	grant, _ := NewValue(2_000_000, usd)
	feedback, err := NewSuccessFeedback(grant, 221_200, 1_568_800)
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := FormatFeedback(feedback)
	if err != nil {
		t.Fatal(err)
	}
	const want = `cost=221200, remaining=1568800, unit="USD", decimals=6`
	if formatted != want {
		t.Fatalf("FormatFeedback() = %q, want %q", formatted, want)
	}
	if formatted == `cost=221200; remaining=1568800; unit="USD"; decimals=6` {
		t.Fatal("formatter reproduced the draft's invalid parameter syntax")
	}

	parsed, err := ParseFeedback([]string{formatted})
	if err != nil {
		t.Fatal(err)
	}
	assertFeedback(t, parsed, 1_568_800, 221_200, true, 0, false, usd)
	if err := ValidateFeedback(grant, parsed); err != nil {
		t.Fatalf("valid feedback denomination refused: %v", err)
	}
}

func TestRefusalFeedbackReportsTheRemainderAndOptionalRequiredAmount(t *testing.T) {
	t.Parallel()

	usd, _ := NewUnit("USD", 6)
	grant, _ := NewValue(2_000_000, usd)
	required := int64(400_000)
	insufficient, err := NewRefusalFeedback(grant, 150_000, &required)
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := FormatFeedback(insufficient)
	if err != nil {
		t.Fatal(err)
	}
	const want = `remaining=150000, required=400000, unit="USD", decimals=6`
	if formatted != want {
		t.Fatalf("FormatFeedback() = %q, want %q", formatted, want)
	}
	parsed, err := ParseFeedback([]string{formatted})
	if err != nil {
		t.Fatal(err)
	}
	assertFeedback(t, parsed, 150_000, 0, false, 400_000, true, usd)

	exhausted, err := NewRefusalFeedback(grant, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	formatted, err = FormatFeedback(exhausted)
	if err != nil {
		t.Fatal(err)
	}
	if formatted != `remaining=0, unit="USD", decimals=6` {
		t.Fatalf("exhausted feedback = %q", formatted)
	}
}

func TestParseFeedbackAcceptsTheFifteenDigitMaximumBeforeAnotherMember(t *testing.T) {
	t.Parallel()

	parsed, err := ParseFeedback([]string{`remaining=999999999999999, cost=0`})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Remaining() != 999999999999999 {
		t.Fatalf("remaining = %d", parsed.Remaining())
	}
	cost, ok := parsed.Cost()
	if !ok || cost != 0 {
		t.Fatalf("cost = %d present %v", cost, ok)
	}
	// A 16-digit integer is still outside the carrier, including when it is last.
	if _, err := ParseFeedback([]string{`remaining=1, cost=1000000000000000`}); err == nil {
		t.Fatal("16-digit cost accepted")
	}
}

func TestParseFeedbackIgnoresExtensionsButRequiresValidKnownMembers(t *testing.T) {
	t.Parallel()

	parsed, err := ParseFeedback([]string{
		`future=?1, remaining=10, cost=2, unit="calls", decimals=0`,
	})
	if err != nil {
		t.Fatal(err)
	}
	calls, _ := NewUnit("calls", 0)
	assertFeedback(t, parsed, 10, 2, true, 0, false, calls)

	for _, test := range []struct {
		name   string
		values []string
	}{
		{name: "absent"},
		{name: "malformed dictionary", values: []string{`remaining=10; cost=2`}},
		{name: "missing remaining", values: []string{`cost=2, unit="USD", decimals=6`}},
		{name: "negative remaining", values: []string{`remaining=-1`}},
		{name: "decimal remaining", values: []string{`remaining=1.5`}},
		{name: "string remaining", values: []string{`remaining="1"`}},
		{name: "boolean remaining", values: []string{`remaining`}},
		{name: "inner-list remaining", values: []string{`remaining=(1)`}},
		{name: "negative cost", values: []string{`remaining=1, cost=-1`}},
		{name: "negative required", values: []string{`remaining=1, required=-1`}},
		{name: "cost and required", values: []string{`remaining=1, cost=1, required=2`}},
		{name: "required fits remaining", values: []string{`remaining=2, required=2`}},
		{name: "unit without decimals", values: []string{`remaining=1, unit="USD"`}},
		{name: "decimals without unit", values: []string{`remaining=1, decimals=6`}},
		{name: "token unit", values: []string{`remaining=1, unit=USD, decimals=6`}},
		{name: "string decimals", values: []string{`remaining=1, unit="USD", decimals="6"`}},
		{name: "empty unit", values: []string{`remaining=1, unit="", decimals=6`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if feedback, err := ParseFeedback(test.values); err == nil {
				t.Fatalf("ParseFeedback() = %#v, want error", feedback)
			}
		})
	}
}

func TestValidateFeedbackUsesTheSignedBudgetDenomination(t *testing.T) {
	t.Parallel()

	usd6, _ := NewUnit("USD", 6)
	usd2, _ := NewUnit("USD", 2)
	grant, _ := NewValue(2_000_000, usd6)
	withoutUnit, err := ParseFeedback([]string{`remaining=10`})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFeedback(grant, withoutUnit); err != nil {
		t.Fatalf("feedback without informational denomination refused: %v", err)
	}
	wrong, _ := NewSuccessFeedback(mustValue(t, 200, usd2), 1, 199)
	if err := ValidateFeedback(grant, wrong); err == nil {
		t.Fatal("feedback with a conflicting scale was accepted")
	}
}

func TestBudgetReasonsAreClosedAndTyped(t *testing.T) {
	t.Parallel()

	for _, reason := range []Reason{ReasonBudgetExhausted, ReasonInsufficientBudget} {
		parsed, err := ParseReason(reason.String())
		if err != nil || parsed != reason {
			t.Fatalf("ParseReason(%q) = %q, %v", reason, parsed, err)
		}
	}
	for _, invalid := range []string{"", "expired", "Budget-Exhausted"} {
		if reason, err := ParseReason(invalid); err == nil {
			t.Fatalf("ParseReason(%q) = %q, want error", invalid, reason)
		}
	}
}

func TestFeedbackConstructorsRejectInvalidFigures(t *testing.T) {
	t.Parallel()

	usd, _ := NewUnit("USD", 6)
	grant, _ := NewValue(10, usd)
	negative := int64(-1)
	fitting := int64(1)
	tooLarge := MaximumAmount + 1
	for _, test := range []struct {
		name string
		make func() (Feedback, error)
	}{
		{name: "negative success cost", make: func() (Feedback, error) { return NewSuccessFeedback(grant, -1, 1) }},
		{name: "negative success remaining", make: func() (Feedback, error) { return NewSuccessFeedback(grant, 1, -1) }},
		{name: "cost outside grant", make: func() (Feedback, error) { return NewSuccessFeedback(grant, 11, 0) }},
		{name: "remaining outside grant", make: func() (Feedback, error) { return NewSuccessFeedback(grant, 1, 11) }},
		{name: "cost and remaining exceed grant", make: func() (Feedback, error) { return NewSuccessFeedback(grant, 6, 5) }},
		{name: "negative refusal remaining", make: func() (Feedback, error) { return NewRefusalFeedback(grant, -1, nil) }},
		{name: "negative required", make: func() (Feedback, error) { return NewRefusalFeedback(grant, 1, &negative) }},
		{name: "required fits remaining", make: func() (Feedback, error) { return NewRefusalFeedback(grant, 1, &fitting) }},
		{name: "required outside carrier", make: func() (Feedback, error) { return NewRefusalFeedback(grant, 1, &tooLarge) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if feedback, err := test.make(); err == nil {
				t.Fatalf("constructor = %#v, want error", feedback)
			}
		})
	}
	if formatted, err := FormatFeedback(Feedback{}); err == nil {
		t.Fatalf("zero Feedback formatted as %q", formatted)
	}
}

func TestFeedbackUnitMustFitTheRFC9651StringCarrier(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"€", "line\nbreak", string([]byte{0x7f})} {
		unit, err := NewUnit(name, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateFeedbackUnit(unit); err == nil {
			t.Fatalf("ValidateFeedbackUnit(%q) accepted an unrepresentable unit", name)
		}
		grant, _ := NewValue(1, unit)
		if _, err := NewSuccessFeedback(grant, 1, 0); err == nil {
			t.Fatalf("NewSuccessFeedback accepted unit %q", name)
		}
	}
	unit, _ := NewUnit(`quoted"\\unit`, 0)
	if err := ValidateFeedbackUnit(unit); err != nil {
		t.Fatalf("escaped ASCII unit refused: %v", err)
	}
}

func assertFeedback(t *testing.T, feedback Feedback, remaining, cost int64, hasCost bool, required int64, hasRequired bool, unit Unit) {
	t.Helper()
	if feedback.Remaining() != remaining {
		t.Fatalf("remaining = %d, want %d", feedback.Remaining(), remaining)
	}
	gotCost, gotCostPresent := feedback.Cost()
	if gotCost != cost || gotCostPresent != hasCost {
		t.Fatalf("cost = %d/%t, want %d/%t", gotCost, gotCostPresent, cost, hasCost)
	}
	gotRequired, gotRequiredPresent := feedback.Required()
	if gotRequired != required || gotRequiredPresent != hasRequired {
		t.Fatalf("required = %d/%t, want %d/%t", gotRequired, gotRequiredPresent, required, hasRequired)
	}
	gotUnit, gotUnitPresent := feedback.Unit()
	if !gotUnitPresent || !gotUnit.Equal(unit) {
		t.Fatalf("unit = %q/%d/%t, want %q/%d", gotUnit.Name(), gotUnit.Decimals(), gotUnitPresent, unit.Name(), unit.Decimals())
	}
}

func mustValue(t *testing.T, amount int64, unit Unit) Value {
	t.Helper()
	value, err := NewValue(amount, unit)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
