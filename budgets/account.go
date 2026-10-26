package budgets

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	descriptionScript = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	descriptionStyle  = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	descriptionTag    = regexp.MustCompile(`(?is)<[^>]*>`)
	descriptionEntity = regexp.MustCompile(`(?i)&(?:#(\d{1,7})|#x([0-9a-f]{1,6})|lt|gt|amp|quot|colon|nbsp);`)
	inlineLinkDest    = regexp.MustCompile(`\]\(([^)\r\n]*)\)`)
	referenceLinkDest = regexp.MustCompile(`(?m)^[ ]{0,3}(\[[^\]\n]+\]:)[ \t]*<?([^>\s]+)>?`)
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
// Numeric character references and a small set of named entities are decoded
// before the check, so an encoded scheme such as &#106;avascript: is not a
// link. Reference-style definitions are checked as well as inline links.
// javascript:, vbscript:, and data: are removed from those destinations.
func SanitizeDescription(description string) (string, error) {
	if !utf8.ValidString(description) {
		return "", errors.New("budgets: unit description must be valid UTF-8")
	}
	cleaned := decodeDescriptionEntities(description)
	cleaned = descriptionScript.ReplaceAllString(cleaned, "")
	cleaned = descriptionStyle.ReplaceAllString(cleaned, "")
	cleaned = descriptionTag.ReplaceAllString(cleaned, "")
	return neutralizeDescriptionSchemes(cleaned), nil
}

func decodeDescriptionEntities(description string) string {
	current := description
	for range 3 {
		next := descriptionEntity.ReplaceAllStringFunc(current, decodeDescriptionEntity)
		if next == current {
			return current
		}
		current = next
	}
	return current
}

func decodeDescriptionEntity(entity string) string {
	switch strings.ToLower(entity) {
	case "&lt;":
		return "<"
	case "&gt;":
		return ">"
	case "&amp;":
		return "&"
	case "&quot;":
		return `"`
	case "&colon;":
		return ":"
	case "&nbsp;":
		return " "
	}
	body := entity[1 : len(entity)-1]
	base := 10
	digits := body[1:]
	if len(body) > 2 && (body[1] == 'x' || body[1] == 'X') {
		base = 16
		digits = body[2:]
	}
	value, err := strconv.ParseInt(digits, base, 32)
	if err != nil || value < 0 || value > unicodeMaxRune || (value >= 0xD800 && value <= 0xDFFF) {
		return entity
	}
	return string(rune(value))
}

const unicodeMaxRune = 0x10FFFF

func neutralizeDescriptionSchemes(description string) string {
	description = inlineLinkDest.ReplaceAllStringFunc(description, func(match string) string {
		stripped, ok := stripDangerousScheme(match[2 : len(match)-1])
		if !ok {
			return match
		}
		return "](" + stripped + ")"
	})
	return referenceLinkDest.ReplaceAllStringFunc(description, func(match string) string {
		parts := referenceLinkDest.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		stripped, ok := stripDangerousScheme(parts[2])
		if !ok {
			return match
		}
		return parts[1] + " " + stripped
	})
}

func stripDangerousScheme(destination string) (string, bool) {
	trimmed := strings.TrimSpace(destination)
	if len(trimmed) >= 2 && trimmed[0] == '<' && trimmed[len(trimmed)-1] == '>' {
		trimmed = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	}
	compact := compactDestination(trimmed)
	lower := strings.ToLower(compact)
	for _, scheme := range []string{"javascript:", "vbscript:", "data:"} {
		if strings.HasPrefix(lower, scheme) {
			return compact[len(scheme):], true
		}
	}
	return "", false
}

func compactDestination(destination string) string {
	var builder strings.Builder
	for _, r := range destination {
		if r <= 0x20 || r == 0x7f {
			continue
		}
		builder.WriteRune(r)
	}
	return builder.String()
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
