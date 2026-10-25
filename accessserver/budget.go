package accessserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"gitlab.com/sidecat-dev/aauth-go/budgets"
)

func decodeBudgetCeiling(raw json.RawMessage) (*budgets.Value, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := budgets.ParseValueJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("Person Server Budget ceiling: %w", err)
	}
	return &value, nil
}

// BudgetConfig supplies the trusted Resource-metadata lookup needed before an
// Access Server can authorize a Budget grant. The resolver receives the
// verified Resource-token issuer.
type BudgetConfig struct {
	ResolveResourceUnits func(context.Context, string) ([]budgets.UnitDeclaration, error)
}

type budgetConfig struct {
	resolveResourceUnits func(context.Context, string) ([]budgets.UnitDeclaration, error)
}

type budgetMetadataResolutionError struct{ cause error }

func (failure *budgetMetadataResolutionError) Error() string { return failure.cause.Error() }
func (failure *budgetMetadataResolutionError) Unwrap() error { return failure.cause }

func newBudgetConfig(config *BudgetConfig) (*budgetConfig, error) {
	if config == nil {
		return nil, nil
	}
	if config.ResolveResourceUnits == nil {
		return nil, errors.New("accessserver: Budget Resource-unit resolver is required")
	}
	return &budgetConfig{resolveResourceUnits: config.ResolveResourceUnits}, nil
}

func (config *budgetConfig) validateOffer(
	ctx context.Context,
	resource string,
	offer budgets.Value,
) error {
	if config == nil {
		return errors.New("accessserver: Budget authorization is not configured")
	}
	declarations, err := config.resolveResourceUnits(ctx, resource)
	if err != nil {
		return &budgetMetadataResolutionError{cause: fmt.Errorf("resolve Resource Budget metadata: %w", err)}
	}
	if err := budgets.ValidateDeclaredValue(declarations, offer); err != nil {
		return fmt.Errorf("resource-token Budget metadata: %w", err)
	}
	return nil
}

func validateBudgetDecision(offered, granted *budgets.Value) (*budgets.Value, error) {
	if offered == nil {
		if granted != nil {
			return nil, errors.New("authorization decision cannot invent a Budget")
		}
		return nil, nil
	}
	if granted == nil {
		return nil, errors.New("authorization decision must preserve the Budget ceiling")
	}
	if err := budgets.ValidateNarrowing(*offered, *granted); err != nil {
		return nil, fmt.Errorf("authorization decision Budget: %w", err)
	}
	cloned := *granted
	return &cloned, nil
}

func selectBudgetCeiling(resourceOffer, personCeiling *budgets.Value) (*budgets.Value, error) {
	if resourceOffer == nil {
		if personCeiling != nil {
			return nil, errors.New("Person Server request cannot invent a Budget")
		}
		return nil, nil
	}
	// A missing parameter is not the Resource offer. The PS echoes that offer
	// when it grants the full figure; omission means the PS is not granting a
	// budget, and the AS must not issue a budget claim.
	if personCeiling == nil {
		return nil, nil
	}
	if err := budgets.ValidateNarrowing(*resourceOffer, *personCeiling); err != nil {
		return nil, fmt.Errorf("Person Server Budget ceiling: %w", err)
	}
	return cloneBudgetValue(personCeiling), nil
}

func cloneBudgetValue(value *budgets.Value) *budgets.Value {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneConsumptionRecord(record *budgets.ConsumptionRecord) *budgets.ConsumptionRecord {
	if record == nil {
		return nil
	}
	cloned := *record
	return &cloned
}
