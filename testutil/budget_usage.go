package testutil

import (
	"context"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/resource"
)

type usagePosting struct {
	issuer       string
	personServer string
	subject      string
	audience     string
	tenant       string
	mission      string
	agentJKT     string
	unit         budgets.Unit
	cost         int64
	at           time.Time
}

func (store *budgetStore) QueryUsage(_ context.Context, query resource.BudgetUsageQuery) (resource.BudgetUsageResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	asOf := query.AsOf.UTC()
	result := resource.BudgetUsageResult{AllTimeOK: true, DayOK: true, WeekOK: true, MonthOK: true, YearOK: true}
	var scopeUnit budgets.Unit
	var haveScopeUnit bool
	jkts := map[string]*jktUsage{}
	for _, thumbprint := range query.JKTs {
		jkts[thumbprint] = &jktUsage{ok: true}
	}

	for _, posting := range store.postings {
		if !postingVisible(posting, query) {
			continue
		}
		if query.Subject != "" || query.Tenant != "" || query.MissionS256 != "" {
			if postingMatchesScope(posting, query) && postingAtOrBefore(posting.at, asOf) {
				if haveScopeUnit && !scopeUnit.Equal(posting.unit) {
					return resource.BudgetUsageResult{}, resource.ErrUsageMixedUnit
				}
				scopeUnit = posting.unit
				haveScopeUnit = true
				result.ScopeRecognized = true
				addUsageCounter(&result.AllTime, &result.AllTimeOK, posting.cost)
				if inUsagePeriod(posting.at, usageDayStart(asOf), asOf) {
					addUsageCounter(&result.Day, &result.DayOK, posting.cost)
				}
				if inUsagePeriod(posting.at, usageWeekStart(asOf), asOf) {
					addUsageCounter(&result.Week, &result.WeekOK, posting.cost)
				}
				if inUsagePeriod(posting.at, usageMonthStart(asOf), asOf) {
					addUsageCounter(&result.Month, &result.MonthOK, posting.cost)
				}
				if inUsagePeriod(posting.at, usageYearStart(asOf), asOf) {
					addUsageCounter(&result.Year, &result.YearOK, posting.cost)
				}
			}
		}
		figure := jkts[posting.agentJKT]
		if figure == nil || !postingAtOrBefore(posting.at, asOf) {
			continue
		}
		if figure.haveUnit && !figure.unit.Equal(posting.unit) {
			return resource.BudgetUsageResult{}, resource.ErrUsageMixedUnit
		}
		figure.unit = posting.unit
		figure.haveUnit = true
		figure.seen = true
		addUsageCounter(&figure.sum, &figure.ok, posting.cost)
		if posting.at.IsZero() {
			figure.untimed = true
		} else if posting.at.After(figure.last) {
			figure.last = posting.at
		}
	}

	if haveScopeUnit {
		if result.HasUnit && !result.Unit.Equal(scopeUnit) {
			return resource.BudgetUsageResult{}, resource.ErrUsageMixedUnit
		}
		result.Unit = scopeUnit
		result.HasUnit = true
	}
	if len(query.JKTs) == 0 {
		return result, nil
	}
	result.JKTs = map[string]int64{}
	for thumbprint, figure := range jkts {
		if !figure.seen || !figure.ok {
			continue
		}
		if !figure.untimed && !figure.last.IsZero() && figure.last.Before(asOf.Add(-24*time.Hour)) {
			continue
		}
		if result.HasUnit && figure.haveUnit && !result.Unit.Equal(figure.unit) {
			return resource.BudgetUsageResult{}, resource.ErrUsageMixedUnit
		}
		if !result.HasUnit && figure.haveUnit {
			result.Unit = figure.unit
			result.HasUnit = true
		}
		result.JKTs[thumbprint] = figure.sum
	}
	return result, nil
}

type jktUsage struct {
	sum      int64
	ok       bool
	seen     bool
	untimed  bool
	last     time.Time
	unit     budgets.Unit
	haveUnit bool
}

func postingVisible(posting usagePosting, query resource.BudgetUsageQuery) bool {
	switch query.Caller.Document {
	case aauth.PersonDiscoveryDocument:
		return posting.issuer == query.Caller.Identifier || posting.personServer == query.Caller.Identifier
	case aauth.AccessDiscoveryDocument:
		if posting.issuer != query.Caller.Identifier {
			return false
		}
		if query.Subject != "" || query.Tenant != "" || query.MissionS256 != "" {
			return posting.personServer == query.PersonServer
		}
		return true
	default:
		return false
	}
}

func postingMatchesScope(posting usagePosting, query resource.BudgetUsageQuery) bool {
	switch {
	case query.Subject != "":
		return posting.subject == query.Subject
	case query.Tenant != "":
		return posting.tenant == query.Tenant
	case query.MissionS256 != "":
		return posting.mission == query.MissionS256
	default:
		return false
	}
}

func postingAtOrBefore(at, asOf time.Time) bool {
	return at.IsZero() || !at.After(asOf)
}

func inUsagePeriod(at, start, asOf time.Time) bool {
	if at.IsZero() {
		return false
	}
	return !at.Before(start) && !at.After(asOf)
}

func addUsageCounter(sum *int64, ok *bool, cost int64) {
	if !*ok {
		return
	}
	if cost < 0 || *sum > budgets.MaximumAmount-cost {
		*ok = false
		*sum = 0
		return
	}
	*sum += cost
}

func usageDayStart(asOf time.Time) time.Time {
	return time.Date(asOf.Year(), asOf.Month(), asOf.Day(), 0, 0, 0, 0, time.UTC)
}

func usageWeekStart(asOf time.Time) time.Time {
	day := usageDayStart(asOf)
	weekday := int(day.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	return day.AddDate(0, 0, -(weekday - 1))
}

func usageMonthStart(asOf time.Time) time.Time {
	return time.Date(asOf.Year(), asOf.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func usageYearStart(asOf time.Time) time.Time {
	return time.Date(asOf.Year(), time.January, 1, 0, 0, 0, 0, time.UTC)
}
