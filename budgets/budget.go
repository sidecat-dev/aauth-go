// Package budgets implements the portable Budget value, token-member, and
// response-field parts of the AAuth Budgets companion specification. Core
// token verification remains in the module root and deployment custody remains
// in reference.
package budgets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"gitlab.com/sidecat-dev/aauth-go/internal/jsonstrict"
)

const MaxAmount int64 = 999_999_999_999_999

// Budget is one non-negative allocation in a resource-selected denomination.
type Budget struct {
	Amount   int64  `json:"amount"`
	Unit     string `json:"unit"`
	Decimals int64  `json:"decimals"`
}

// Consumption reports the amount metered against one prior auth token.
type Consumption struct {
	JTI      string `json:"jti"`
	Consumed int64  `json:"consumed"`
}

// ParseBudget strictly decodes one current Budget object.
func ParseBudget(exact []byte) (Budget, error) {
	var budget Budget
	if err := jsonstrict.RejectAmbiguousNames(exact); err != nil {
		return Budget{}, fmt.Errorf("aauth budgets: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(exact))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&budget); err != nil {
		return Budget{}, fmt.Errorf("aauth budgets: parse budget: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Budget{}, errors.New("aauth budgets: budget must contain one JSON value")
	}
	if err := budget.Validate(); err != nil {
		return Budget{}, err
	}
	return budget, nil
}

// Validate checks the current exact integer, unit, and scale bounds.
func (budget Budget) Validate() error {
	if budget.Amount < 0 || budget.Amount > MaxAmount {
		return errors.New("aauth budgets: amount must be a non-negative integer of at most 15 digits")
	}
	if budget.Unit == "" {
		return errors.New("aauth budgets: unit must be a non-empty string")
	}
	if budget.Decimals < 0 || budget.Decimals > MaxAmount {
		return errors.New("aauth budgets: decimals must be a non-negative integer of at most 15 digits")
	}
	return nil
}

// Narrow returns an allocation no larger than the preceding offer while
// preserving the resource-selected unit and scale.
func Narrow(offer Budget, amount int64) (Budget, error) {
	if err := offer.Validate(); err != nil {
		return Budget{}, err
	}
	if amount < 0 || amount > offer.Amount {
		return Budget{}, errors.New("aauth budgets: narrowed amount exceeds the preceding allocation")
	}
	narrowed := offer
	narrowed.Amount = amount
	return narrowed, nil
}

// ValidateNarrowing verifies that next preserves the resource-selected
// denomination and does not increase the preceding amount.
func ValidateNarrowing(previous, next Budget) error {
	if err := previous.Validate(); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if previous.Unit != next.Unit || previous.Decimals != next.Decimals {
		return errors.New("aauth budgets: narrowing changed the resource denomination")
	}
	if next.Amount > previous.Amount {
		return errors.New("aauth budgets: narrowing increased the allocation")
	}
	return nil
}

func validateConsumption(records []Consumption) error {
	for _, record := range records {
		if record.JTI == "" || record.Consumed < 0 || record.Consumed > MaxAmount {
			return errors.New("aauth budgets: consumption record is invalid")
		}
	}
	return nil
}

func cloneConsumption(records []Consumption) []Consumption {
	if records == nil {
		return nil
	}
	return append([]Consumption(nil), records...)
}
