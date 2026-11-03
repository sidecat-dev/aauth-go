package budgets

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dunglas/httpsfv"
)

// Reason is one Budget-specific reason on an auth-token requirement.
type Reason string

const (
	ReasonBudgetExhausted    Reason = "budget-exhausted"
	ReasonInsufficientBudget Reason = "insufficient-budget"
)

// ParseReason validates a Budget-specific requirement reason.
func ParseReason(value string) (Reason, error) {
	reason := Reason(value)
	switch reason {
	case ReasonBudgetExhausted, ReasonInsufficientBudget:
		return reason, nil
	default:
		return "", fmt.Errorf("budgets: unsupported reason %q", value)
	}
}

// String returns the registered reason token.
func (reason Reason) String() string { return string(reason) }

// Feedback is the parsed AAuth-Budget response field. A fixed-price success
// carries cost. A refusal carries remaining and maybe required. A streamed
// response carries reserved and omits cost until a trailer, if any, arrives.
type Feedback struct {
	initialized bool
	remaining   int64
	cost        *int64
	reserved    *int64
	required    *int64
	unit        *Unit
}

// NewSuccessFeedback constructs feedback for a completed fixed-price request.
func NewSuccessFeedback(grant Value, cost, remaining int64) (Feedback, error) {
	if err := grant.validate(); err != nil {
		return Feedback{}, fmt.Errorf("budgets: success feedback grant: %w", err)
	}
	if err := ValidateFeedbackUnit(grant.unit); err != nil {
		return Feedback{}, err
	}
	if err := validateAmount("cost", cost); err != nil {
		return Feedback{}, err
	}
	if err := validateAmount("remaining", remaining); err != nil {
		return Feedback{}, err
	}
	if cost > grant.amount || remaining > grant.amount || cost+remaining > grant.amount {
		return Feedback{}, errors.New("budgets: success feedback exceeds the granted budget")
	}
	unit := grant.unit
	return Feedback{initialized: true, remaining: remaining, cost: &cost, unit: &unit}, nil
}

// NewRefusalFeedback constructs feedback for an exhausted or insufficient
// fixed-price request. Required is omitted when the Resource does not state a
// maximum cost for the refused request.
func NewRefusalFeedback(grant Value, remaining int64, required *int64) (Feedback, error) {
	if err := grant.validate(); err != nil {
		return Feedback{}, fmt.Errorf("budgets: refusal feedback grant: %w", err)
	}
	if err := ValidateFeedbackUnit(grant.unit); err != nil {
		return Feedback{}, err
	}
	if err := validateAmount("remaining", remaining); err != nil {
		return Feedback{}, err
	}
	if remaining > grant.amount {
		return Feedback{}, errors.New("budgets: refusal remainder exceeds the granted budget")
	}
	var retainedRequired *int64
	if required != nil {
		if err := validateAmount("required", *required); err != nil {
			return Feedback{}, err
		}
		if *required <= remaining {
			return Feedback{}, errors.New("budgets: refusal required amount must exceed the remaining budget")
		}
		value := *required
		retainedRequired = &value
	}
	unit := grant.unit
	return Feedback{initialized: true, remaining: remaining, required: retainedRequired, unit: &unit}, nil
}

// NewReservedFeedback constructs the header for a response whose cost is not
// known yet. Remaining is already net of the reservation. The header omits cost.
func NewReservedFeedback(grant Value, remaining, reserved int64) (Feedback, error) {
	if err := grant.validate(); err != nil {
		return Feedback{}, fmt.Errorf("budgets: reserved feedback grant: %w", err)
	}
	if err := ValidateFeedbackUnit(grant.unit); err != nil {
		return Feedback{}, err
	}
	if err := validateAmount("remaining", remaining); err != nil {
		return Feedback{}, err
	}
	if err := validateAmount("reserved", reserved); err != nil {
		return Feedback{}, err
	}
	if remaining > grant.amount || reserved > grant.amount || remaining+reserved > grant.amount {
		return Feedback{}, errors.New("budgets: reserved feedback exceeds the granted budget")
	}
	unit := grant.unit
	return Feedback{initialized: true, remaining: remaining, reserved: &reserved, unit: &unit}, nil
}

// Remaining returns the balance reported for the presented Auth token.
func (feedback Feedback) Remaining() int64 { return feedback.remaining }

// Cost returns the cost of this request when reported.
func (feedback Feedback) Cost() (int64, bool) {
	if feedback.cost == nil {
		return 0, false
	}
	return *feedback.cost, true
}

// Reserved returns the amount held for this request when the header reported it.
func (feedback Feedback) Reserved() (int64, bool) {
	if feedback.reserved == nil {
		return 0, false
	}
	return *feedback.reserved, true
}

// Required returns the computed maximum cost of a refused request when
// reported.
func (feedback Feedback) Required() (int64, bool) {
	if feedback.required == nil {
		return 0, false
	}
	return *feedback.required, true
}

// Unit returns the informational denomination pair when present.
func (feedback Feedback) Unit() (Unit, bool) {
	if feedback.unit == nil {
		return Unit{}, false
	}
	return *feedback.unit, true
}

// ParseFeedback parses one or more AAuth-Budget field lines as an RFC 9651
// Dictionary. Unknown members are ignored.
func ParseFeedback(values []string) (Feedback, error) {
	dictionary, err := unmarshalBudgetDictionary(values)
	if err != nil {
		return Feedback{}, fmt.Errorf("budgets: parse AAuth-Budget: %w", err)
	}
	remaining, present, err := feedbackInteger(dictionary, "remaining")
	if err != nil {
		return Feedback{}, err
	}
	if !present {
		return Feedback{}, errors.New("budgets: AAuth-Budget requires remaining")
	}
	feedback := Feedback{initialized: true, remaining: remaining}
	if cost, ok, err := feedbackInteger(dictionary, "cost"); err != nil {
		return Feedback{}, err
	} else if ok {
		feedback.cost = &cost
	}
	if reserved, ok, err := feedbackInteger(dictionary, "reserved"); err != nil {
		return Feedback{}, err
	} else if ok {
		feedback.reserved = &reserved
	}
	if required, ok, err := feedbackInteger(dictionary, "required"); err != nil {
		return Feedback{}, err
	} else if ok {
		feedback.required = &required
	}
	if feedback.cost != nil && feedback.reserved != nil {
		return Feedback{}, errors.New("budgets: AAuth-Budget header must not carry both cost and reserved")
	}

	unitName, unitPresent, err := feedbackString(dictionary, "unit")
	if err != nil {
		return Feedback{}, err
	}
	decimals, decimalsPresent, err := feedbackInteger(dictionary, "decimals")
	if err != nil {
		return Feedback{}, err
	}
	if unitPresent != decimalsPresent {
		return Feedback{}, errors.New("budgets: AAuth-Budget unit and decimals must appear together")
	}
	if unitPresent {
		unit, err := NewUnit(unitName, decimals)
		if err != nil {
			return Feedback{}, fmt.Errorf("budgets: AAuth-Budget denomination: %w", err)
		}
		feedback.unit = &unit
	}
	if err := feedback.validate(); err != nil {
		return Feedback{}, err
	}
	return feedback, nil
}

// FormatFeedback emits the canonical RFC 9651 Dictionary form.
func FormatFeedback(feedback Feedback) (string, error) {
	if err := feedback.validate(); err != nil {
		return "", err
	}
	if feedback.cost != nil && feedback.reserved != nil {
		return "", errors.New("budgets: AAuth-Budget header must not carry both cost and reserved")
	}
	dictionary := httpsfv.NewDictionary()
	if feedback.cost != nil {
		dictionary.Add("cost", httpsfv.NewItem(*feedback.cost))
	}
	dictionary.Add("remaining", httpsfv.NewItem(feedback.remaining))
	if feedback.reserved != nil {
		dictionary.Add("reserved", httpsfv.NewItem(*feedback.reserved))
	}
	if feedback.required != nil {
		dictionary.Add("required", httpsfv.NewItem(*feedback.required))
	}
	if feedback.unit != nil {
		dictionary.Add("unit", httpsfv.NewItem(feedback.unit.name))
		dictionary.Add("decimals", httpsfv.NewItem(feedback.unit.decimals))
	}
	formatted, err := httpsfv.Marshal(dictionary)
	if err != nil {
		return "", fmt.Errorf("budgets: format AAuth-Budget: %w", err)
	}
	return formatted, nil
}

// ValidateFeedback checks unsigned informational feedback against the signed
// Auth-token budget. An omitted unit pair remains valid because the pair is
// optional; a present pair must match exactly.
func ValidateFeedback(grant Value, feedback Feedback) error {
	if err := grant.validate(); err != nil {
		return fmt.Errorf("budgets: feedback grant: %w", err)
	}
	if err := feedback.validate(); err != nil {
		return err
	}
	if feedback.remaining > grant.amount {
		return errors.New("budgets: feedback remainder exceeds the signed grant")
	}
	if feedback.cost != nil && *feedback.cost+feedback.remaining > grant.amount {
		return errors.New("budgets: feedback cost and remainder exceed the signed grant")
	}
	if feedback.reserved != nil && *feedback.reserved+feedback.remaining > grant.amount {
		return errors.New("budgets: feedback reservation and remainder exceed the signed grant")
	}
	if feedback.cost != nil && feedback.reserved != nil && *feedback.cost > *feedback.reserved {
		return errors.New("budgets: trailer cost exceeds the reserved amount")
	}
	if feedback.unit != nil && !feedback.unit.Equal(grant.unit) {
		return errors.New("budgets: feedback denomination conflicts with the signed grant")
	}
	return nil
}

// ValidateFeedbackUnit checks that a JSON Budget unit is representable as an
// RFC 9651 String in AAuth-Budget. The token object permits arbitrary UTF-8,
// but a metering profile that emits the response field must establish this
// narrower carrier before any charge.
func ValidateFeedbackUnit(unit Unit) error {
	if err := unit.validate(); err != nil {
		return err
	}
	dictionary := httpsfv.NewDictionary()
	dictionary.Add("unit", httpsfv.NewItem(unit.name))
	if _, err := httpsfv.Marshal(dictionary); err != nil {
		return fmt.Errorf("budgets: unit is not representable in AAuth-Budget: %w", err)
	}
	return nil
}

func (feedback Feedback) validate() error {
	if !feedback.initialized {
		return errors.New("budgets: feedback is uninitialized")
	}
	if err := validateAmount("remaining", feedback.remaining); err != nil {
		return err
	}
	if feedback.cost != nil {
		if err := validateAmount("cost", *feedback.cost); err != nil {
			return err
		}
	}
	if feedback.reserved != nil {
		if err := validateAmount("reserved", *feedback.reserved); err != nil {
			return err
		}
	}
	if feedback.cost != nil && feedback.reserved != nil {
		if *feedback.cost > *feedback.reserved {
			return errors.New("budgets: trailer cost exceeds the reserved amount")
		}
	}
	if feedback.required != nil {
		if err := validateAmount("required", *feedback.required); err != nil {
			return err
		}
		if *feedback.required <= feedback.remaining {
			return errors.New("budgets: refusal required amount must exceed the remaining budget")
		}
	}
	if feedback.cost != nil && feedback.required != nil {
		return errors.New("budgets: AAuth-Budget cost and required are mutually exclusive")
	}
	if feedback.reserved != nil && feedback.required != nil {
		return errors.New("budgets: AAuth-Budget reserved and required are mutually exclusive")
	}
	if feedback.unit != nil {
		if err := feedback.unit.validate(); err != nil {
			return err
		}
	}
	return nil
}

// unmarshalBudgetDictionary parses an AAuth-Budget dictionary.
//
// github.com/dunglas/httpsfv v1.1.1 rejects a 15-digit integer when another
// character follows it, before it looks at that character. RFC 9651 allows
// 999999999999999, and the Budgets draft uses that as the carrier maximum.
// A field that fails only for that reason is parsed one member at a time.
// A 15-digit integer with nothing after it already parses, and a 16-digit
// integer still fails.
func unmarshalBudgetDictionary(values []string) (*httpsfv.Dictionary, error) {
	dictionary, err := httpsfv.UnmarshalDictionary(values)
	if err == nil || !errors.Is(err, httpsfv.ErrNumberOutOfRange) {
		return dictionary, err
	}
	members, splitErr := splitSFVMembers(strings.Join(values, ","))
	if splitErr != nil {
		return nil, err
	}
	merged := httpsfv.NewDictionary()
	for _, member := range members {
		one, parseErr := httpsfv.UnmarshalDictionary([]string{member})
		if parseErr != nil {
			return nil, parseErr
		}
		for _, name := range one.Names() {
			if _, exists := merged.Get(name); exists {
				return nil, err
			}
			value, _ := one.Get(name)
			merged.Add(name, value)
		}
	}
	return merged, nil
}

// splitSFVMembers divides a dictionary on commas that are not inside a
// string or an inner list. It is the fallback for the 15-digit parser bug,
// not a general structured-field parser.
func splitSFVMembers(field string) ([]string, error) {
	var members []string
	var b strings.Builder
	inString := false
	escaped := false
	depth := 0
	for _, r := range field {
		if inString {
			b.WriteRune(r)
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			if r == '"' {
				inString = false
			}
			continue
		}
		switch r {
		case '"':
			inString = true
			b.WriteRune(r)
		case '(':
			depth++
			b.WriteRune(r)
		case ')':
			if depth == 0 {
				return nil, errors.New("budgets: unbalanced inner list")
			}
			depth--
			b.WriteRune(r)
		case ',':
			if depth == 0 {
				member := strings.TrimSpace(b.String())
				if member == "" {
					return nil, errors.New("budgets: empty dictionary member")
				}
				members = append(members, member)
				b.Reset()
				continue
			}
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	if inString || escaped || depth != 0 {
		return nil, errors.New("budgets: unclosed structured-field member")
	}
	if member := strings.TrimSpace(b.String()); member != "" {
		members = append(members, member)
	}
	if len(members) == 0 {
		return nil, errors.New("budgets: empty dictionary")
	}
	return members, nil
}

func feedbackInteger(dictionary *httpsfv.Dictionary, name string) (int64, bool, error) {
	member, present := dictionary.Get(name)
	if !present {
		return 0, false, nil
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return 0, false, fmt.Errorf("budgets: AAuth-Budget %s must be an Integer item", name)
	}
	if len(item.Params.Names()) != 0 {
		return 0, false, fmt.Errorf("budgets: AAuth-Budget %s must not have parameters", name)
	}
	value, ok := item.Value.(int64)
	if !ok {
		return 0, false, fmt.Errorf("budgets: AAuth-Budget %s must be an Integer", name)
	}
	if err := validateAmount(name, value); err != nil {
		return 0, false, err
	}
	return value, true, nil
}

func feedbackString(dictionary *httpsfv.Dictionary, name string) (string, bool, error) {
	member, present := dictionary.Get(name)
	if !present {
		return "", false, nil
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return "", false, fmt.Errorf("budgets: AAuth-Budget %s must be a String item", name)
	}
	if len(item.Params.Names()) != 0 {
		return "", false, fmt.Errorf("budgets: AAuth-Budget %s must not have parameters", name)
	}
	value, ok := item.Value.(string)
	if !ok {
		return "", false, fmt.Errorf("budgets: AAuth-Budget %s must be a String", name)
	}
	return value, true, nil
}

// FormatTrailer emits the cost-only AAuth-Budget trailer. A trailer must not
// restate a member the header carried.
func FormatTrailer(cost int64) (string, error) {
	if err := validateAmount("cost", cost); err != nil {
		return "", err
	}
	dictionary := httpsfv.NewDictionary()
	dictionary.Add("cost", httpsfv.NewItem(cost))
	formatted, err := httpsfv.Marshal(dictionary)
	if err != nil {
		return "", fmt.Errorf("budgets: format AAuth-Budget trailer: %w", err)
	}
	return formatted, nil
}

// ApplyTrailer merges a cost-only trailer into a header. An empty trailer
// leaves the header unchanged: a recipient must not treat the trailer as
// necessary. Any member other than cost is rejected, including members the
// header already carried and members this profile does not recognize. The
// general header rule ignores unknown members; the trailer rule allows cost
// and nothing else, and this function follows the trailer rule.
func ApplyTrailer(header Feedback, trailer []string) (Feedback, error) {
	if err := header.validate(); err != nil {
		return Feedback{}, err
	}
	if len(trailer) == 0 {
		return header, nil
	}
	dictionary, err := httpsfv.UnmarshalDictionary(trailer)
	if err != nil {
		return Feedback{}, fmt.Errorf("budgets: parse AAuth-Budget trailer: %w", err)
	}
	for _, name := range dictionary.Names() {
		if name != "cost" {
			return Feedback{}, fmt.Errorf("budgets: AAuth-Budget trailer must not carry %s", name)
		}
	}
	cost, present, err := feedbackInteger(dictionary, "cost")
	if err != nil {
		return Feedback{}, err
	}
	if !present {
		return Feedback{}, errors.New("budgets: AAuth-Budget trailer requires cost")
	}
	if _, headerHasCost := header.Cost(); headerHasCost {
		return Feedback{}, errors.New("budgets: AAuth-Budget trailer restates cost")
	}
	updated := header
	updated.cost = &cost
	if err := updated.validate(); err != nil {
		return Feedback{}, err
	}
	return updated, nil
}

// SettledRemaining is remaining + reserved - cost after a streamed response.
// Remaining is already net of the reservation, so the unspent hold returns to
// the grant. A header that omitted cost uses the full reservation.
func SettledRemaining(feedback Feedback) (int64, error) {
	if err := feedback.validate(); err != nil {
		return 0, err
	}
	reserved, _ := feedback.Reserved()
	cost, hasCost := feedback.Cost()
	if !hasCost {
		cost = reserved
	}
	settled := feedback.remaining + reserved - cost
	if settled < 0 {
		return 0, errors.New("budgets: settled remainder is negative")
	}
	return settled, nil
}
