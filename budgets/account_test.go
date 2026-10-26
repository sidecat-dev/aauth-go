package budgets

import (
	"strings"
	"testing"
	"time"
)

func TestFormatConsentAmountRendersDollarsAndScaledUnits(t *testing.T) {
	t.Parallel()
	usd, err := NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	credits, err := NewUnit("credits", 0)
	if err != nil {
		t.Fatal(err)
	}
	five, err := NewValue(5_000_000, usd)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := FormatConsentAmount(five)
	if err != nil || rendered != "$5.00" {
		t.Fatalf("consent amount = %q, %v", rendered, err)
	}
	fraction, err := NewValue(5_000_001, usd)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err = FormatConsentAmount(fraction)
	if err != nil || rendered != "$5.000001" {
		t.Fatalf("fractional consent amount = %q, %v", rendered, err)
	}
	count, err := NewValue(12, credits)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err = FormatConsentAmount(count)
	if err != nil || rendered != "12 credits" {
		t.Fatalf("credit consent amount = %q, %v", rendered, err)
	}
}

func TestSanitizeDescriptionRemovesActiveMarkup(t *testing.T) {
	t.Parallel()
	cleaned, err := SanitizeDescription("Price <script>alert(1)</script> **USD** [x](javascript:alert(1))")
	if err != nil {
		t.Fatal(err)
	}
	if cleaned != "Price  **USD** [x](alert(1))" {
		t.Fatalf("sanitized = %q", cleaned)
	}
	encoded, err := SanitizeDescription("see [x](&#106;avascript:alert(1))\n[1]: javascript:alert(2)\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(encoded), "javascript:") || strings.Contains(strings.ToLower(encoded), "&#106;") {
		t.Fatalf("encoded scheme survived: %q", encoded)
	}
	if !strings.Contains(encoded, "](alert(1))") || !strings.Contains(encoded, "[1]: alert(2)") {
		t.Fatalf("sanitized links = %q", encoded)
	}
	script, err := SanitizeDescription("open [x](vbscript:msg) or [z](data:text/html,hi)")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(script), "vbscript:") || strings.Contains(strings.ToLower(script), "data:") {
		t.Fatalf("scheme survived: %q", script)
	}
	kept, err := SanitizeDescription("read [docs](https://example.com/javascript:not-a-scheme)")
	if err != nil || !strings.Contains(kept, "https://example.com/javascript:not-a-scheme") {
		t.Fatalf("ordinary link = %q, %v", kept, err)
	}
	if _, err := SanitizeDescription(string([]byte{0xff})); err == nil {
		t.Fatal("invalid UTF-8 was accepted")
	}
}

func TestAccountedSpendReplacesTheFullGrantAssumption(t *testing.T) {
	t.Parallel()
	unit, _ := NewUnit("USD", 6)
	grant, err := NewValue(5_000_000, unit)
	if err != nil {
		t.Fatal(err)
	}
	assumed, err := AccountedSpend(grant, nil)
	if err != nil || assumed != 5_000_000 {
		t.Fatalf("unreported spend = %d, %v", assumed, err)
	}
	record, err := NewConsumptionRecord("auth-1", 125_000)
	if err != nil {
		t.Fatal(err)
	}
	spent, err := AccountedSpend(grant, &record)
	if err != nil || spent != 125_000 {
		t.Fatalf("reported spend = %d, %v", spent, err)
	}
}

func TestFreeReleasesSettledAllocationsOnly(t *testing.T) {
	t.Parallel()
	asOf := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	live := Allocation{Amount: 40, ExpiresAt: asOf.Add(time.Hour)}
	expired := Allocation{Amount: 70, ExpiresAt: asOf}
	revoked := Allocation{Amount: 15, ExpiresAt: asOf.Add(time.Hour), RevocationRecordedAt: asOf.Add(-time.Minute)}
	unsupported := Allocation{Amount: 9, ExpiresAt: asOf.Add(time.Hour)}
	free, err := Free(100, 30, []Allocation{live, expired, revoked, unsupported}, asOf)
	if err != nil {
		t.Fatal(err)
	}
	if free != 100-30-40-9 {
		t.Fatalf("free = %d", free)
	}
}
