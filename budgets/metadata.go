package budgets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// UnitDeclaration is one budget_units Resource-metadata entry. Unit and scale
// identify the denomination. Maximum is optional in the protocol; a host may
// require it for a bounded pricing profile.
type UnitDeclaration struct {
	unit        Unit
	maximum     int64
	hasMaximum  bool
	description string
}

// NewUnitDeclaration constructs a declaration without an advertised maximum.
func NewUnitDeclaration(unit Unit, description string) (UnitDeclaration, error) {
	return newUnitDeclaration(unit, 0, false, description)
}

// NewBoundedUnitDeclaration constructs a declaration with an advertised
// maximum amount for one Auth token.
func NewBoundedUnitDeclaration(unit Unit, maximum int64, description string) (UnitDeclaration, error) {
	return newUnitDeclaration(unit, maximum, true, description)
}

func newUnitDeclaration(unit Unit, maximum int64, hasMaximum bool, description string) (UnitDeclaration, error) {
	if err := unit.validate(); err != nil {
		return UnitDeclaration{}, fmt.Errorf("budgets: unit declaration: %w", err)
	}
	if hasMaximum {
		if err := validateAmount("metadata maximum", maximum); err != nil {
			return UnitDeclaration{}, err
		}
	}
	if !utf8.ValidString(description) {
		return UnitDeclaration{}, errors.New("budgets: unit description must be valid UTF-8")
	}
	return UnitDeclaration{
		unit: unit, maximum: maximum, hasMaximum: hasMaximum, description: description,
	}, nil
}

// Unit returns the declared denomination and scale.
func (declaration UnitDeclaration) Unit() Unit { return declaration.unit }

// Maximum returns the advertised maximum when present.
func (declaration UnitDeclaration) Maximum() (int64, bool) {
	return declaration.maximum, declaration.hasMaximum
}

// Description returns the optional Markdown description.
func (declaration UnitDeclaration) Description() string { return declaration.description }

func (declaration UnitDeclaration) validate() error {
	var (
		validated UnitDeclaration
		err       error
	)
	if declaration.hasMaximum {
		validated, err = NewBoundedUnitDeclaration(
			declaration.unit, declaration.maximum, declaration.description,
		)
	} else {
		validated, err = NewUnitDeclaration(declaration.unit, declaration.description)
	}
	if err != nil {
		return err
	}
	if validated != declaration {
		return errors.New("budgets: unit declaration is invalid")
	}
	return nil
}

type unitDeclarationJSON struct {
	Unit        *string         `json:"unit"`
	Decimals    *int64          `json:"decimals"`
	Maximum     json.RawMessage `json:"max"`
	Description json.RawMessage `json:"description"`
}

type marshaledUnitDeclaration struct {
	Unit        string  `json:"unit"`
	Decimals    int64   `json:"decimals"`
	Maximum     *int64  `json:"max,omitempty"`
	Description *string `json:"description,omitempty"`
}

// MarshalJSON emits the flat budget_units metadata object.
func (declaration UnitDeclaration) MarshalJSON() ([]byte, error) {
	if err := declaration.validate(); err != nil {
		return nil, err
	}
	wire := marshaledUnitDeclaration{
		Unit: declaration.unit.name, Decimals: declaration.unit.decimals,
	}
	if declaration.hasMaximum {
		maximum := declaration.maximum
		wire.Maximum = &maximum
	}
	if declaration.description != "" {
		description := declaration.description
		wire.Description = &description
	}
	return json.Marshal(wire)
}

// UnmarshalJSON accepts one strict budget_units metadata object.
func (declaration *UnitDeclaration) UnmarshalJSON(data []byte) error {
	if declaration == nil {
		return errors.New("budgets: nil UnitDeclaration receiver")
	}
	var wire unitDeclarationJSON
	if err := decodeStrictJSON(data, &wire); err != nil {
		return fmt.Errorf("budgets: parse unit declaration: %w", err)
	}
	if wire.Unit == nil || wire.Decimals == nil {
		return errors.New("budgets: unit declaration requires unit and decimals")
	}
	unit, err := NewUnit(*wire.Unit, *wire.Decimals)
	if err != nil {
		return err
	}
	description := ""
	if wire.Description != nil {
		if bytes.Equal(bytes.TrimSpace(wire.Description), []byte("null")) ||
			json.Unmarshal(wire.Description, &description) != nil {
			return errors.New("budgets: unit declaration description must be a string")
		}
	}
	var parsed UnitDeclaration
	if wire.Maximum == nil {
		parsed, err = NewUnitDeclaration(unit, description)
	} else {
		if bytes.Equal(bytes.TrimSpace(wire.Maximum), []byte("null")) {
			return errors.New("budgets: unit declaration maximum must be an integer")
		}
		var maximum int64
		if err := json.Unmarshal(wire.Maximum, &maximum); err != nil {
			return errors.New("budgets: unit declaration maximum must be an integer")
		}
		parsed, err = NewBoundedUnitDeclaration(unit, maximum, description)
	}
	if err != nil {
		return err
	}
	*declaration = parsed
	return nil
}

// ValidateUnitDeclarations requires valid entries and one scale per unit
// identifier.
func ValidateUnitDeclarations(declarations []UnitDeclaration) error {
	seen := make(map[string]struct{}, len(declarations))
	for _, declaration := range declarations {
		if err := declaration.validate(); err != nil {
			return err
		}
		name := declaration.unit.name
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("budgets: unit %q is declared more than once", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

// ValidateDeclaredValue checks that a signed offer or grant uses one declared
// denomination and does not exceed its advertised maximum when present.
func ValidateDeclaredValue(declarations []UnitDeclaration, value Value) error {
	if err := value.validate(); err != nil {
		return err
	}
	if err := ValidateUnitDeclarations(declarations); err != nil {
		return err
	}
	for _, declaration := range declarations {
		if declaration.unit.name != value.unit.name {
			continue
		}
		if !declaration.unit.Equal(value.unit) {
			return fmt.Errorf("budgets: unit %q uses a different declared scale", value.unit.name)
		}
		if declaration.hasMaximum && value.amount > declaration.maximum {
			return fmt.Errorf("budgets: value exceeds unit %q metadata maximum", value.unit.name)
		}
		return nil
	}
	return fmt.Errorf("budgets: unit %q is not declared", value.unit.name)
}

// FindUnitDeclaration returns the declaration for one exact denomination.
func FindUnitDeclaration(declarations []UnitDeclaration, unit Unit) (UnitDeclaration, bool) {
	for _, declaration := range declarations {
		if declaration.unit.Equal(unit) {
			return declaration, true
		}
	}
	return UnitDeclaration{}, false
}
