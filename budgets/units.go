package budgets

import (
	"errors"
	"fmt"
	"strings"
)

// BudgetUnit declares one denomination a resource may use for Budget offers.
// Max is optional; when present it is the largest amount accepted on one
// auth-token grant. Description is optional Markdown metadata for a consent
// surface and is not rendered by this package.
type BudgetUnit struct {
	Unit        string `json:"unit"`
	Decimals    int64  `json:"decimals"`
	Max         *int64 `json:"max,omitempty"`
	Description string `json:"description,omitempty"`
}

// Validate checks one exact resource-declared denomination.
func (unit BudgetUnit) Validate() error {
	if unit.Unit == "" || strings.TrimSpace(unit.Unit) != unit.Unit {
		return errors.New("aauth budgets: declared unit must be a non-empty trimmed string")
	}
	if unit.Decimals < 0 || unit.Decimals > MaxAmount {
		return errors.New("aauth budgets: declared decimals must be a non-negative integer of at most 15 digits")
	}
	if unit.Max != nil && (*unit.Max < 0 || *unit.Max > MaxAmount) {
		return errors.New("aauth budgets: declared maximum must be a non-negative integer of at most 15 digits")
	}
	if unit.Description != "" && strings.TrimSpace(unit.Description) != unit.Description {
		return errors.New("aauth budgets: declared description must be trimmed")
	}
	return nil
}

// ValidateBudgetUnits validates a canonical, non-empty set of declarations.
// A nil slice means the resource has not configured declarations; an explicit
// empty slice is rejected so it cannot silently advertise that no unit exists.
func ValidateBudgetUnits(units []BudgetUnit) error {
	if units == nil {
		return nil
	}
	if len(units) == 0 {
		return errors.New("aauth budgets: declared unit set must not be empty")
	}
	seen := make(map[string]struct{}, len(units))
	for _, unit := range units {
		if err := unit.Validate(); err != nil {
			return err
		}
		if _, exists := seen[unit.Unit]; exists {
			return fmt.Errorf("aauth budgets: declared unit %q appears more than once", unit.Unit)
		}
		seen[unit.Unit] = struct{}{}
	}
	return nil
}

// ValidateDeclaredBudget verifies that a resource offer matches one of its
// declared denominations. Nil declarations preserve an unconfigured resource's
// existing behavior.
func ValidateDeclaredBudget(units []BudgetUnit, budget Budget) error {
	if err := budget.Validate(); err != nil {
		return err
	}
	if err := ValidateBudgetUnits(units); err != nil {
		return err
	}
	if units == nil {
		return nil
	}
	for _, unit := range units {
		if unit.Unit != budget.Unit {
			continue
		}
		if unit.Decimals != budget.Decimals {
			return errors.New("aauth budgets: offer decimals do not match the declared unit")
		}
		if unit.Max != nil && budget.Amount > *unit.Max {
			return errors.New("aauth budgets: offer exceeds the declared unit maximum")
		}
		return nil
	}
	return errors.New("aauth budgets: offer uses an undeclared unit")
}
