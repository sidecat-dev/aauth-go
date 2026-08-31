package r3

import (
	"errors"
	"fmt"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

// AccessModePerCall is the R3 access-mode registry extension for an operation
// that requires a proposal-specific Auth token on every invocation.
const AccessModePerCall aauth.AccessMode = "per-call"

// OperationHints retains the sparse advisory annotations published beside one
// operation in its authoritative vocabulary. Hints describe expected caller
// preparation only; they are never evidence of a grant or successful access.
type OperationHints struct {
	initialized bool
	accessMode  *aauth.AccessMode
	budget      *bool
}

func (hints OperationHints) clone() OperationHints {
	cloned := OperationHints{initialized: hints.initialized}
	if hints.accessMode != nil {
		value := *hints.accessMode
		cloned.accessMode = &value
	}
	if hints.budget != nil {
		value := *hints.budget
		cloned.budget = &value
	}
	return cloned
}

func (hints OperationHints) validate() error {
	if !hints.initialized {
		return errors.New("r3: operation hints are uninitialized")
	}
	if hints.accessMode != nil && !validAnnotationAccessMode(*hints.accessMode) {
		return fmt.Errorf("r3: invalid operation access-mode annotation %q", *hints.accessMode)
	}
	return nil
}

// NewOperationHints constructs an owned sparse hint value. A session-token
// annotation is invalid because Resource-managed sessions apply to the whole
// Resource, not one operation.
func NewOperationHints(accessMode *aauth.AccessMode, budget *bool) (OperationHints, error) {
	if accessMode != nil && !validAnnotationAccessMode(*accessMode) {
		return OperationHints{}, fmt.Errorf("r3: invalid operation access-mode annotation %q", *accessMode)
	}
	hints := OperationHints{initialized: true}
	if accessMode != nil {
		value := *accessMode
		hints.accessMode = &value
	}
	if budget != nil {
		value := *budget
		hints.budget = &value
	}
	return hints, nil
}

// AccessMode returns the published replacement for the Resource-wide default,
// when one was present.
func (hints OperationHints) AccessMode() (aauth.AccessMode, bool) {
	if !hints.initialized || hints.accessMode == nil {
		return "", false
	}
	return *hints.accessMode, true
}

// Budget returns the published Budget hint and its independent presence bit.
func (hints OperationHints) Budget() (bool, bool) {
	if !hints.initialized || hints.budget == nil {
		return false, false
	}
	return *hints.budget, true
}

// ValidateForPublication rejects combinations that the R3 publisher rules
// forbid. Agents must still use Plan when consuming a conflicting remote
// publication because the receiver-side rule requires an auth-token fallback.
func (hints OperationHints) ValidateForPublication() error {
	if err := hints.validate(); err != nil {
		return err
	}
	budgetRequired := hints.budget != nil && *hints.budget
	if budgetRequired && hints.accessMode != nil &&
		(*hints.accessMode == aauth.AccessModeAgentToken || *hints.accessMode == aauth.AccessModePersonToken) {
		return fmt.Errorf("r3: budget:true must not be published with access mode %q", *hints.accessMode)
	}
	return nil
}

// ExpectedAccess is the Agent-side planning interpretation of public hints.
// It carries no credential and grants no access.
type ExpectedAccess struct {
	accessMode        aauth.AccessMode
	budgetRequired    bool
	publisherConflict bool
}

// AccessMode returns the credential mode the Agent should expect to need.
func (expected ExpectedAccess) AccessMode() aauth.AccessMode { return expected.accessMode }

// BudgetRequired reports that the operation is published as drawing a Budget.
func (expected ExpectedAccess) BudgetRequired() bool { return expected.budgetRequired }

// PublisherConflict reports a forbidden published combination of budget:true
// with an explicit agent-token or person-token operation annotation.
func (expected ExpectedAccess) PublisherConflict() bool { return expected.publisherConflict }

// Plan applies sparse fallback and the R3 Budget implication to produce an
// advisory expectation. Runtime AAuth-Requirement remains authoritative.
func (hints OperationHints) Plan(resourceDefault aauth.AccessMode) (ExpectedAccess, error) {
	if !hints.initialized {
		return ExpectedAccess{}, errors.New("r3: operation hints are uninitialized")
	}
	if !validResourceAccessMode(resourceDefault) {
		return ExpectedAccess{}, fmt.Errorf("r3: invalid Resource access mode %q", resourceDefault)
	}
	mode := resourceDefault
	explicitMode := false
	if hints.accessMode != nil {
		mode = *hints.accessMode
		explicitMode = true
	}
	budgetRequired := hints.budget != nil && *hints.budget
	publisherConflict := budgetRequired && explicitMode &&
		(mode == aauth.AccessModeAgentToken || mode == aauth.AccessModePersonToken)
	if budgetRequired && (mode == aauth.AccessModeAgentToken || mode == aauth.AccessModePersonToken || mode == aauth.AccessModeSessionToken) {
		mode = aauth.AccessModeAuthToken
	}
	return ExpectedAccess{
		accessMode: mode, budgetRequired: budgetRequired,
		publisherConflict: publisherConflict,
	}, nil
}

func validAnnotationAccessMode(mode aauth.AccessMode) bool {
	return mode == aauth.AccessModeAgentToken || mode == aauth.AccessModePersonToken ||
		mode == aauth.AccessModeAuthToken || mode == AccessModePerCall
}

func validResourceAccessMode(mode aauth.AccessMode) bool {
	return validAnnotationAccessMode(mode) || mode == aauth.AccessModeSessionToken
}
