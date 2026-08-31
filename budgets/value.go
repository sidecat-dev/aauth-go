// Package budgets implements the AAuth Budgets protocol companion.
package budgets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

// MaximumAmount is the 15-digit limit shared by Budget JSON values and RFC
// 9651 Integer members.
const MaximumAmount int64 = 999_999_999_999_999

// Unit is one resource-selected Budget denomination and scale.
type Unit struct {
	name     string
	decimals int64
}

// NewUnit validates a Budget denomination and scale.
func NewUnit(name string, decimals int64) (Unit, error) {
	if name == "" {
		return Unit{}, errors.New("budgets: unit is required")
	}
	if !utf8.ValidString(name) {
		return Unit{}, errors.New("budgets: unit must be valid UTF-8")
	}
	if err := validateAmount("decimals", decimals); err != nil {
		return Unit{}, err
	}
	return Unit{name: name, decimals: decimals}, nil
}

// Name returns the resource-declared unit identifier.
func (unit Unit) Name() string { return unit.name }

// Decimals returns the resource-declared scale.
func (unit Unit) Decimals() int64 { return unit.decimals }

// Equal reports whether two units have the same identifier and scale.
func (unit Unit) Equal(other Unit) bool {
	return unit.name == other.name && unit.decimals == other.decimals
}

func (unit Unit) validate() error {
	validated, err := NewUnit(unit.name, unit.decimals)
	if err != nil {
		return err
	}
	if validated != unit {
		return errors.New("budgets: unit is invalid")
	}
	return nil
}

// Value is one non-negative Budget amount in a resource-selected unit.
type Value struct {
	amount int64
	unit   Unit
}

// NewValue validates a Budget amount and denomination.
func NewValue(amount int64, unit Unit) (Value, error) {
	if err := validateAmount("amount", amount); err != nil {
		return Value{}, err
	}
	if err := unit.validate(); err != nil {
		return Value{}, err
	}
	return Value{amount: amount, unit: unit}, nil
}

// Amount returns the integer Budget amount in Unit().Decimals() scale.
func (value Value) Amount() int64 { return value.amount }

// Unit returns the Budget denomination and scale.
func (value Value) Unit() Unit { return value.unit }

func (value Value) validate() error {
	validated, err := NewValue(value.amount, value.unit)
	if err != nil {
		return err
	}
	if validated != value {
		return errors.New("budgets: value is invalid")
	}
	return nil
}

type valueJSON struct {
	Amount   *int64  `json:"amount"`
	Unit     *string `json:"unit"`
	Decimals *int64  `json:"decimals"`
}

// ParseValueJSON parses exactly one strict Budget object.
func ParseValueJSON(data []byte) (Value, error) {
	var wire valueJSON
	if err := decodeStrictJSON(data, &wire); err != nil {
		return Value{}, fmt.Errorf("budgets: parse value: %w", err)
	}
	if wire.Amount == nil || wire.Unit == nil || wire.Decimals == nil {
		return Value{}, errors.New("budgets: budget requires amount, unit, and decimals")
	}
	unit, err := NewUnit(*wire.Unit, *wire.Decimals)
	if err != nil {
		return Value{}, err
	}
	return NewValue(*wire.Amount, unit)
}

// MarshalJSON emits the exact Budget object.
func (value Value) MarshalJSON() ([]byte, error) {
	if err := value.validate(); err != nil {
		return nil, err
	}
	amount, name, decimals := value.amount, value.unit.name, value.unit.decimals
	return json.Marshal(valueJSON{Amount: &amount, Unit: &name, Decimals: &decimals})
}

// UnmarshalJSON accepts only the exact Budget object.
func (value *Value) UnmarshalJSON(data []byte) error {
	if value == nil {
		return errors.New("budgets: nil Value receiver")
	}
	parsed, err := ParseValueJSON(data)
	if err != nil {
		return err
	}
	*value = parsed
	return nil
}

// ValidateNarrowing requires the same denomination and an amount no greater
// than the resource's offer.
func ValidateNarrowing(offered, granted Value) error {
	if err := offered.validate(); err != nil {
		return fmt.Errorf("budgets: offered value: %w", err)
	}
	if err := granted.validate(); err != nil {
		return fmt.Errorf("budgets: granted value: %w", err)
	}
	if !offered.unit.Equal(granted.unit) {
		return errors.New("budgets: narrowing must preserve unit and decimals")
	}
	if granted.amount > offered.amount {
		return errors.New("budgets: narrowed amount exceeds the offer")
	}
	return nil
}

func validateAmount(name string, amount int64) error {
	if amount < 0 {
		return fmt.Errorf("budgets: %s must be non-negative", name)
	}
	if amount > MaximumAmount {
		return fmt.Errorf("budgets: %s exceeds the 15-digit carrier limit", name)
	}
	return nil
}

func decodeStrictJSON(data []byte, destination any) error {
	if !utf8.Valid(data) {
		return errors.New("JSON input must be valid UTF-8")
	}
	if err := jsonstrict.RejectCaseVariants(data, destination); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON input must contain one value")
	}
	return nil
}
