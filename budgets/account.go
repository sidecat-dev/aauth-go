package budgets

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

var (
	descriptionScript = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	descriptionStyle  = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	descriptionTag    = regexp.MustCompile(`(?is)<[^>]*>`)
	descriptionScheme = regexp.MustCompile(`(?i)\]\(\s*(?:javascript|data):`)
)

// FormatConsentAmount renders a budget the way a Person Server shows it to a
// person. USD at decimals 6 becomes a dollar figure, keeping extra fraction
// digits when the amount is not an exact cent. Other units are the scaled
// number plus the unit name.
func FormatConsentAmount(value Value) (string, error) {
	if err := value.validate(); err != nil {
		return "", err
	}
	unit := value.Unit()
	if unit.Name() == "USD" && unit.Decimals() == 6 {
		return formatUSDMicros(value.Amount()), nil
	}
	return formatScaled(value.Amount(), unit.Decimals()) + " " + unit.Name(), nil
}

func formatUSDMicros(amount int64) string {
	dollars := amount / 1_000_000
	fraction := amount % 1_000_000
	if fraction%10_000 == 0 {
		return fmt.Sprintf("$%d.%02d", dollars, fraction/10_000)
	}
	return fmt.Sprintf("$%d.%06d", dollars, fraction)
}

func formatScaled(amount, decimals int64) string {
	if decimals <= 0 || decimals > 18 {
		return strconv.FormatInt(amount, 10)
	}
	scale := int64(1)
	for range decimals {
		scale *= 10
	}
	whole := amount / scale
	fraction := amount % scale
	return fmt.Sprintf("%d.%0*d", whole, int(decimals), fraction)
}

// SanitizeDescription removes active HTML and dangerous link schemes from a
// resource-supplied Markdown unit description before a consent screen renders
// it. The stored metadata value is unchanged; callers render the result.
func SanitizeDescription(description string) (string, error) {
	if !utf8.ValidString(description) {
		return "", errors.New("budgets: unit description must be valid UTF-8")
	}
	cleaned := descriptionScript.ReplaceAllString(description, "")
	cleaned = descriptionStyle.ReplaceAllString(cleaned, "")
	cleaned = descriptionTag.ReplaceAllString(cleaned, "")
	cleaned = descriptionScheme.ReplaceAllString(cleaned, "](")
	return cleaned, nil
}

// AccountedSpend is what an issuer holds against one allocation until a usage
// reading settles it. A missing consumption record is the full grant. A record
// replaces that assumption and is not added to it.
func AccountedSpend(grant Value, consumed *ConsumptionRecord) (int64, error) {
	if err := grant.validate(); err != nil {
		return 0, err
	}
	if consumed == nil {
		return grant.Amount(), nil
	}
	if err := consumed.validate(); err != nil {
		return 0, err
	}
	if consumed.Consumed() > grant.Amount() {
		return 0, errors.New("budgets: consumption record exceeds the grant")
	}
	return consumed.Consumed(), nil
}

// Allocation is one issuer-side budget that has not necessarily been settled.
// RevocationRecordedAt is set only when the resource recorded the revocation.
// revocation_unsupported and revocation_unavailable leave it zero and settle at
// ExpiresAt.
type Allocation struct {
	Amount               int64
	ExpiresAt            time.Time
	RevocationRecordedAt time.Time
}

// Settled reports whether a usage reading at asOf releases the allocation.
// A recorded revocation settles at that recording time. Every other allocation
// settles when exp is at or before asOf. A consumption record does not settle.
func (allocation Allocation) Settled(asOf time.Time) bool {
	asOf = asOf.UTC()
	if !allocation.RevocationRecordedAt.IsZero() {
		return !asOf.Before(allocation.RevocationRecordedAt.UTC())
	}
	return !asOf.Before(allocation.ExpiresAt.UTC())
}

// UnsettledAmount is the sum of allocations a reading at asOf has not settled.
func UnsettledAmount(allocations []Allocation, asOf time.Time) (int64, error) {
	var sum int64
	for _, allocation := range allocations {
		if err := validateAmount("allocation", allocation.Amount); err != nil {
			return 0, err
		}
		if allocation.Settled(asOf) {
			continue
		}
		next, ok := addBounded(sum, allocation.Amount)
		if !ok {
			return 0, errors.New("budgets: unsettled allocations exceed the 15-digit carrier limit")
		}
		sum = next
	}
	return sum, nil
}

// Free is ceiling − metered − unsettled allocations. A consumption record is
// not an input: it refines a live allocation and does not settle it. A
// negative result means the ceiling is already exceeded.
func Free(ceiling, metered int64, allocations []Allocation, asOf time.Time) (int64, error) {
	if err := validateAmount("ceiling", ceiling); err != nil {
		return 0, err
	}
	if err := validateAmount("metered", metered); err != nil {
		return 0, err
	}
	unsettled, err := UnsettledAmount(allocations, asOf)
	if err != nil {
		return 0, err
	}
	return ceiling - metered - unsettled, nil
}

func addBounded(sum, amount int64) (int64, bool) {
	if amount < 0 || sum > MaximumAmount-amount {
		return 0, false
	}
	return sum + amount, true
}
