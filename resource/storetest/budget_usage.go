package storetest

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

// BudgetUsageContract constructs a Budget store that also answers usage queries.
type BudgetUsageContract struct {
	New func(testing.TB) resource.BudgetStore
}

// RunBudgetUsage checks caller filtering, calendar boundaries, per-key zeros,
// pruning, mixed units, and the 15-digit counter limit.
func RunBudgetUsage(t *testing.T, contract BudgetUsageContract) {
	t.Helper()
	if contract.New == nil {
		t.Fatal("storetest: BudgetUsageContract.New is required")
	}
	store := contract.New(t)
	usage, ok := store.(resource.BudgetUsageStore)
	if !ok {
		t.Fatal("storetest: Budget store does not implement usage queries")
	}
	ctx := context.Background()
	asOf := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	if asOf.Weekday() != time.Wednesday {
		t.Fatal("fixture weekday changed")
	}
	person := "https://person.example"
	otherPerson := "https://other-person.example"
	access := "https://access.example"
	key := usageThumbprint(1)
	otherKey := usageThumbprint(2)
	mustCharge := func(charge resource.BudgetCharge) {
		t.Helper()
		if _, err := store.Charge(ctx, charge); err != nil {
			t.Fatal(err)
		}
	}
	mustCharge(usageCharge(t, person, person, "person-1", "today", key, asOf, 4))
	mustCharge(usageCharge(t, person, person, "person-1", "monday", key, time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC), 7))
	mustCharge(usageCharge(t, person, person, "person-1", "sunday", key, time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC), 9))
	mustCharge(usageCharge(t, person, person, "person-2", "other-subject", key, asOf, 5))
	mustCharge(usageCharge(t, otherPerson, otherPerson, "person-1", "foreign", key, asOf, 11))
	mustCharge(usageCharge(t, access, person, "person-1", "federated", otherKey, asOf, 3))
	mustCharge(usageCharge(t, access, otherPerson, "person-1", "other-federation", otherKey, asOf, 8))
	zero := usageCharge(t, person, person, "person-1", "observed", usageThumbprint(3), asOf, 0)
	zero.Grant = usageCharge(t, person, person, "person-1", "observed", usageThumbprint(3), asOf, 1).Grant
	mustCharge(zero)

	personCaller := resource.BudgetUsageCaller{Identifier: person, Document: aauth.PersonDiscoveryDocument}
	result, err := usage.QueryUsage(ctx, resource.BudgetUsageQuery{
		Caller: personCaller, AsOf: asOf, Subject: "person-1", JKTs: []string{key, usageThumbprint(3), usageThumbprint(4)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.ScopeRecognized || !result.AllTimeOK || result.AllTime != 23 || result.Day != 7 || result.Week != 14 || result.Month != 7 || result.Year != 23 {
		t.Fatalf("person subject usage = %+v", result)
	}
	if result.JKTs[key] != 25 || result.JKTs[usageThumbprint(3)] != 0 {
		t.Fatalf("jkt figures = %#v", result.JKTs)
	}
	if _, present := result.JKTs[usageThumbprint(4)]; present {
		t.Fatal("unrecognized jkt was reported as zero")
	}

	foreign, err := usage.QueryUsage(ctx, resource.BudgetUsageQuery{
		Caller: resource.BudgetUsageCaller{Identifier: "https://stranger.example", Document: aauth.PersonDiscoveryDocument},
		AsOf:   asOf, Subject: "person-1",
	})
	if err != nil || foreign.ScopeRecognized {
		t.Fatalf("stranger usage = %+v, %v", foreign, err)
	}

	accessResult, err := usage.QueryUsage(ctx, resource.BudgetUsageQuery{
		Caller: resource.BudgetUsageCaller{Identifier: access, Document: aauth.AccessDiscoveryDocument},
		AsOf:   asOf, Subject: "person-1", PersonServer: person,
	})
	if err != nil || accessResult.AllTime != 3 {
		t.Fatalf("access usage = %+v, %v", accessResult, err)
	}
	otherFederation, err := usage.QueryUsage(ctx, resource.BudgetUsageQuery{
		Caller:       resource.BudgetUsageCaller{Identifier: access, Document: aauth.AccessDiscoveryDocument},
		AsOf:         asOf,
		Subject:      "person-1",
		PersonServer: otherPerson,
	})
	if err != nil || otherFederation.AllTime != 8 {
		t.Fatalf("other person-server usage = %+v, %v", otherFederation, err)
	}
	withoutPS, err := usage.QueryUsage(ctx, resource.BudgetUsageQuery{
		Caller:  resource.BudgetUsageCaller{Identifier: access, Document: aauth.AccessDiscoveryDocument},
		AsOf:    asOf,
		Subject: "person-1",
	})
	if err != nil || withoutPS.ScopeRecognized {
		t.Fatalf("access scope query without ps = %+v, %v", withoutPS, err)
	}

	stale := usageCharge(t, person, person, "person-9", "stale", usageThumbprint(5), asOf.Add(-25*time.Hour), 2)
	mustCharge(stale)
	pruned, err := usage.QueryUsage(ctx, resource.BudgetUsageQuery{
		Caller: personCaller, AsOf: asOf, JKTs: []string{usageThumbprint(5)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := pruned.JKTs[usageThumbprint(5)]; present {
		t.Fatal("pruned jkt was reported")
	}

	credits := usageCharge(t, person, person, "person-3", "credits", key, asOf, 1)
	dollars := credits
	unit, err := budgets.NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := budgets.NewValue(10, unit)
	if err != nil {
		t.Fatal(err)
	}
	dollars.Token.JTI = "dollars"
	dollars.Grant = grant
	dollars.Subject = "person-3"
	mustCharge(credits)
	mustCharge(dollars)
	if _, err := usage.QueryUsage(ctx, resource.BudgetUsageQuery{
		Caller: personCaller, AsOf: asOf, Subject: "person-3",
	}); !errors.Is(err, resource.ErrUsageMixedUnit) {
		t.Fatalf("mixed unit = %v", err)
	}

	overflowStore := contract.New(t).(resource.BudgetUsageStore)
	chargeStore := overflowStore.(resource.BudgetStore)
	huge := usageCharge(t, person, person, "person-8", "huge-a", key, asOf, budgets.MaximumAmount)
	huge.Grant = mustValue(t, budgets.MaximumAmount)
	if _, err := chargeStore.Charge(ctx, huge); err != nil {
		t.Fatal(err)
	}
	extra := usageCharge(t, person, person, "person-8", "huge-b", key, asOf, 1)
	if _, err := chargeStore.Charge(ctx, extra); err != nil {
		t.Fatal(err)
	}
	overflow, err := overflowStore.QueryUsage(ctx, resource.BudgetUsageQuery{
		Caller: personCaller, AsOf: asOf, Subject: "person-8",
	})
	if err != nil || overflow.AllTimeOK || !overflow.ScopeRecognized {
		t.Fatalf("overflow usage = %+v, %v", overflow, err)
	}
}

func usageCharge(t *testing.T, issuer, personServer, subject, jti, agent string, at time.Time, cost int64) resource.BudgetCharge {
	t.Helper()
	amount := cost
	if amount < 1 {
		amount = 1
	}
	return resource.BudgetCharge{
		Token:        aauth.TokenReference{Issuer: issuer, JTI: jti},
		PersonServer: personServer, Subject: subject, Audience: "https://resource.example",
		Tenant: "tenant-1", AgentJKT: agent, ChargedAt: at,
		Grant: mustValue(t, amount), Cost: cost,
	}
}

func mustValue(t *testing.T, amount int64) budgets.Value {
	t.Helper()
	unit, err := budgets.NewUnit("credits", 0)
	if err != nil {
		t.Fatal(err)
	}
	value, err := budgets.NewValue(amount, unit)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func usageThumbprint(fill byte) string {
	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = fill
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
