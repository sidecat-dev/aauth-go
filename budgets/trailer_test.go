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
	if _, err := ParseFeedback([]string{`remaining=1, cost=1, reserved=1`}); err == nil {
		t.Fatal("header carrying cost and reserved was accepted")
	}
}
