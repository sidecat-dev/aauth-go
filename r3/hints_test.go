package r3

import (
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestOperationHintsPreserveSparsePublishedValues(t *testing.T) {
	mode := aauth.AccessModePersonToken
	budget := false
	hints, err := NewOperationHints(&mode, &budget)
	if err != nil {
		t.Fatal(err)
	}
	mode = aauth.AccessModeAuthToken
	budget = true

	gotMode, modePresent := hints.AccessMode()
	gotBudget, budgetPresent := hints.Budget()
	if !modePresent || gotMode != aauth.AccessModePersonToken || !budgetPresent || gotBudget {
		t.Fatalf("retained hints = %q/%t, %t/%t", gotMode, modePresent, gotBudget, budgetPresent)
	}
}

func TestOperationHintsRejectInvalidPublishedAccessModes(t *testing.T) {
	for _, mode := range []aauth.AccessMode{"", "unknown", aauth.AccessModeSessionToken} {
		mode := mode
		if _, err := NewOperationHints(&mode, nil); err == nil {
			t.Fatalf("accepted annotation access mode %q", mode)
		}
	}
}

func TestOperationHintsPlanExpectedCredentialWithoutGrantingIt(t *testing.T) {
	boolPointer := func(value bool) *bool { return &value }
	modePointer := func(value aauth.AccessMode) *aauth.AccessMode { return &value }

	for _, test := range []struct {
		name         string
		defaultMode  aauth.AccessMode
		mode         *aauth.AccessMode
		budget       *bool
		wantMode     aauth.AccessMode
		wantBudget   bool
		wantConflict bool
	}{
		{name: "resource default", defaultMode: aauth.AccessModePersonToken, wantMode: aauth.AccessModePersonToken},
		{name: "explicit replacement", defaultMode: aauth.AccessModeAuthToken, mode: modePointer(aauth.AccessModePersonToken), wantMode: aauth.AccessModePersonToken},
		{name: "per call", defaultMode: aauth.AccessModeAgentToken, mode: modePointer(AccessModePerCall), wantMode: AccessModePerCall},
		{name: "budget implies auth", defaultMode: aauth.AccessModeAgentToken, budget: boolPointer(true), wantMode: aauth.AccessModeAuthToken, wantBudget: true},
		{name: "budget replaces session default", defaultMode: aauth.AccessModeSessionToken, budget: boolPointer(true), wantMode: aauth.AccessModeAuthToken, wantBudget: true},
		{name: "contradictory published mode", defaultMode: aauth.AccessModeAuthToken, mode: modePointer(aauth.AccessModeAgentToken), budget: boolPointer(true), wantMode: aauth.AccessModeAuthToken, wantBudget: true, wantConflict: true},
		{name: "per-call budget", defaultMode: aauth.AccessModeAuthToken, mode: modePointer(AccessModePerCall), budget: boolPointer(true), wantMode: AccessModePerCall, wantBudget: true},
		{name: "explicit false budget", defaultMode: aauth.AccessModeAuthToken, budget: boolPointer(false), wantMode: aauth.AccessModeAuthToken},
	} {
		t.Run(test.name, func(t *testing.T) {
			hints, err := NewOperationHints(test.mode, test.budget)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := hints.Plan(test.defaultMode)
			if err != nil {
				t.Fatal(err)
			}
			if plan.AccessMode() != test.wantMode || plan.BudgetRequired() != test.wantBudget ||
				plan.PublisherConflict() != test.wantConflict {
				t.Fatalf("plan = %q budget=%t conflict=%t", plan.AccessMode(), plan.BudgetRequired(), plan.PublisherConflict())
			}
		})
	}
}

func TestOperationHintsSeparatePublisherValidationFromAgentFallback(t *testing.T) {
	mode := aauth.AccessModePersonToken
	budget := true
	hints, err := NewOperationHints(&mode, &budget)
	if err != nil {
		t.Fatal(err)
	}
	if err := hints.ValidateForPublication(); err == nil {
		t.Fatal("publisher validation accepted budget:true with person-token")
	}
	planned, err := hints.Plan(aauth.AccessModeAgentToken)
	if err != nil {
		t.Fatal(err)
	}
	if planned.AccessMode() != aauth.AccessModeAuthToken || !planned.PublisherConflict() {
		t.Fatalf("agent fallback = %q conflict=%t", planned.AccessMode(), planned.PublisherConflict())
	}

	perCall := AccessModePerCall
	valid, err := NewOperationHints(&perCall, &budget)
	if err != nil {
		t.Fatal(err)
	}
	if err := valid.ValidateForPublication(); err != nil {
		t.Fatalf("publisher validation refused per-call budget: %v", err)
	}
}

func TestOperationHintsPlanRejectsInvalidResourceDefault(t *testing.T) {
	hints, err := NewOperationHints(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hints.Plan("unknown"); err == nil {
		t.Fatal("planning accepted an invalid resource-wide access mode")
	}
}
