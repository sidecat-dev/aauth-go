package budgets

import (
	"strings"
	"testing"
)

func TestReservedHeaderOmitsCostAndTrailerCarriesOnlyCost(t *testing.T) {
	t.Parallel()

	usd, _ := NewUnit("USD", 6)
	grant, _ := NewValue(2_000_000, usd)
	header, err := NewReservedFeedback(grant, 1_568_800, 431_200)
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := FormatFeedback(header)
	if err != nil {
		t.Fatal(err)
	}
	const want = `remaining=1568800, reserved=431200, unit="USD", decimals=6`
	if formatted != want {
		t.Fatalf("reserved header = %q", formatted)
	}
	if strings.Contains(formatted, "cost=") {
		t.Fatalf("reserved header restated cost: %q", formatted)
	}
	parsed, err := ParseFeedback([]string{formatted})
	if err != nil {
		t.Fatal(err)
	}
	reserved, ok := parsed.Reserved()
	if !ok || reserved != 431_200 {
		t.Fatalf("reserved = %d, %t", reserved, ok)
	}
	if _, hasCost := parsed.Cost(); hasCost {
		t.Fatal("reserved header carried cost")
	}

	trailer, err := FormatTrailer(221_200)
	if err != nil || trailer != "cost=221200" {
		t.Fatalf("trailer = %q, %v", trailer, err)
	}
	settled, err := ApplyTrailer(parsed, []string{trailer})
	if err != nil {
		t.Fatal(err)
	}
	cost, hasCost := settled.Cost()
	if !hasCost || cost != 221_200 {
		t.Fatalf("settled cost = %d, %t", cost, hasCost)
	}
	balance, err := SettledRemaining(settled)
	if err != nil || balance != 1_568_800+431_200-221_200 {
		t.Fatalf("settled remaining = %d, %v", balance, err)
	}

	unchanged, err := ApplyTrailer(parsed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, hasCost := unchanged.Cost(); hasCost {
		t.Fatal("missing trailer invented a cost")
	}
	assumed, err := SettledRemaining(unchanged)
	if err != nil || assumed != 1_568_800 {
		t.Fatalf("assumed remaining = %d, %v", assumed, err)
	}

	for _, raw := range []string{
		`cost=1, remaining=1`,
		`remaining=1`,
		`future=?1, cost=1`,
		`cost=431201`,
	} {
		if _, err := ApplyTrailer(parsed, []string{raw}); err == nil {
			t.Fatalf("trailer %s was accepted", raw)
		}
	}
}

func TestParseFeedbackWithMergedCostTrailer(t *testing.T) {
	t.Parallel()

	unit, _ := NewUnit("USD", 6)
	grant, _ := NewValue(2_000_000, unit)
	const header = `remaining=1568800, reserved=431200, unit="USD", decimals=6`
	const trailer = `cost=221200`
	for _, fields := range [][]string{
		{header + ", " + trailer},
		{header, trailer},
	} {
		feedback, err := ParseFeedback(fields)
		if err != nil {
			t.Fatalf("parse merged feedback %q: %v", fields, err)
		}
		if err := ValidateFeedback(grant, feedback); err != nil {
			t.Fatal(err)
		}
		if cost, ok := feedback.Cost(); !ok || cost != 221_200 {
			t.Fatalf("cost = %d, %t", cost, ok)
		}
		if reserved, ok := feedback.Reserved(); !ok || reserved != 431_200 {
			t.Fatalf("reserved = %d, %t", reserved, ok)
		}
		if balance, err := SettledRemaining(feedback); err != nil || balance != 1_778_800 {
			t.Fatalf("settled remaining = %d, %v", balance, err)
		}
		if _, err := FormatFeedback(feedback); err == nil {
			t.Fatal("emitted cost and reserved together in an original header")
		}
		if _, err := ApplyTrailer(feedback, []string{trailer}); err == nil {
			t.Fatal("accepted trailer that restates cost")
		}
	}
	if _, err := ParseFeedback([]string{header, `cost=431201`}); err == nil {
		t.Fatal("accepted merged cost above the reservation")
	}
}
