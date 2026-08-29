package reference

import (
	"context"
	"errors"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

// BudgetEvaluation carries the current resource-denominated offer and a
// defensive projection of the resource's recent consumption evidence.
type BudgetEvaluation struct {
	Offer       budgets.Budget
	Consumption []budgets.Consumption
}

// BudgetPolicy narrows one resource-denominated offer at a PS or AS policy
// boundary. It cannot change the unit or scale.
type BudgetPolicy func(context.Context, aauth.AuthorizationRequest, BudgetEvaluation) (budgets.Budget, error)

func budgetEvaluation(result budgets.TokenResult, offer budgets.Budget) (BudgetEvaluation, error) {
	consumption, err := result.Consumption()
	if err != nil {
		return BudgetEvaluation{}, err
	}
	return BudgetEvaluation{Offer: offer, Consumption: consumption}, nil
}

func accessServerBudgetCeiling(offer budgets.Budget, person *budgets.Budget) (budgets.Budget, error) {
	if person == nil {
		return offer, offer.Validate()
	}
	if err := budgets.ValidateNarrowing(offer, *person); err != nil {
		return budgets.Budget{}, err
	}
	return *person, nil
}

type authorizationCompanionSet struct {
	coreID aauth.EvidenceID
	count  int
}

func (set authorizationCompanionSet) Valid() bool { return set.coreID.String() != "" && set.count > 0 }
func (set authorizationCompanionSet) CoreEvidenceID() aauth.EvidenceID {
	if !set.Valid() {
		return aauth.EvidenceID{}
	}
	return set.coreID
}

func validateAuthCompanions(
	core aauth.VerifiedToken[aauth.AuthTokenClaims],
	requireR3 bool,
	requireBudget bool,
) (authorizationCompanionSet, r3.TokenResult, budgets.TokenResult, error) {
	members, err := core.AuthorizationMembers()
	if err != nil {
		return authorizationCompanionSet{}, r3.TokenResult{}, budgets.TokenResult{}, err
	}
	_, hasR3 := members["r3_uri"]
	_, hasBudget := members["budget"]
	if hasR3 != requireR3 || hasBudget != requireBudget {
		return authorizationCompanionSet{}, r3.TokenResult{}, budgets.TokenResult{}, errors.New("reference: auth token companion set does not match the endpoint profile")
	}
	var r3Result r3.TokenResult
	var budgetResult budgets.TokenResult
	count := 0
	if requireR3 {
		r3Result, err = r3.ValidateAuthToken(core)
		count++
	}
	if err == nil && requireBudget {
		budgetResult, err = budgets.ValidateAuthToken(core)
		count++
	}
	if err != nil {
		return authorizationCompanionSet{}, r3.TokenResult{}, budgets.TokenResult{}, err
	}
	coreID, err := core.EvidenceID()
	if err != nil {
		return authorizationCompanionSet{}, r3.TokenResult{}, budgets.TokenResult{}, err
	}
	return authorizationCompanionSet{coreID: coreID, count: count}, r3Result, budgetResult, nil
}
