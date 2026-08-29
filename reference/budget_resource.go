package reference

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

func (resource *Resource) executeBudgeted(
	response http.ResponseWriter,
	request *http.Request,
	authorized aauth.AuthorizedRequest,
	budgetResult budgets.TokenResult,
	callKey string,
	recovered *BudgetRecord,
) {
	grant, err := budgetResult.Budget()
	if err != nil {
		writeProblem(response, http.StatusForbidden, "invalid_budget", err)
		return
	}
	var execution BudgetExecution
	if recovered != nil {
		execution = recovered.Execution
		if execution.Grant != grant {
			writeProblem(response, http.StatusForbidden, "invalid_budget", errors.New("pending Budget execution does not match the presented token"))
			return
		}
	} else {
		maximum, maximumErr := resource.budgetMaximumCost(request.Context(), copyAuthorizedRequest(authorized))
		if maximumErr != nil || maximum < 0 || maximum > grant.Amount {
			writeProblem(response, http.StatusBadRequest, "invalid_budget_bound", errors.New("resource could not establish a valid maximum cost"))
			return
		}
		execution, err = NewBudgetExecution(
			authorized.AuthTokenIssuer, authorized.AuthTokenID, callKey,
			grant, maximum, authorized.AuthTokenExpiresAt.Unix(),
		)
	}
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "budget_custody_failed", err)
		return
	}
	record, acquired, remaining, err := resource.budgetStore.Claim(request.Context(), execution)
	if errors.Is(err, ErrBudgetInsufficient) {
		required := execution.Maximum
		writeBudgetHeader(response, budgets.Header{
			Remaining: remaining, Required: &required,
			Unit: grant.Unit, Decimals: budgets.OptionalInteger(grant.Decimals),
		})
		reason := "insufficient-budget"
		if remaining == 0 {
			reason = "budget-exhausted"
		}
		if challengeErr := resource.writeBudgetChallenge(response, request, authorized, reason); challengeErr != nil {
			writeProblem(response, http.StatusServiceUnavailable, "budget_challenge_unavailable", challengeErr)
			return
		}
		writeProblem(response, http.StatusUnauthorized, "insufficient_budget", err)
		return
	}
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "budget_custody_failed", err)
		return
	}
	if record.State == "complete" {
		writeBudgetRecord(response, record, remaining, grant)
		return
	}
	if !acquired {
		response.Header().Set("Retry-After", "1")
		writeBudgetHeader(response, budgets.Header{
			Remaining: remaining, Unit: grant.Unit, Decimals: budgets.OptionalInteger(grant.Decimals),
		})
		writeProblem(response, http.StatusConflict, "budget_call_in_progress", errors.New("the metered call is already executing"))
		return
	}
	defer resource.budgetStore.Release(execution.Key)
	result, err := resource.budgetOperation(request.Context(), copyAuthorizedRequest(authorized), execution.Key)
	if err != nil {
		reserved := execution.Maximum
		writeBudgetHeader(response, budgets.Header{
			Remaining: remaining, Reserved: &reserved,
			Unit: grant.Unit, Decimals: budgets.OptionalInteger(grant.Decimals),
		})
		writeProblem(response, http.StatusInternalServerError, "operation_failed", err)
		return
	}
	body, err := json.Marshal(result.Value)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "operation_failed", err)
		return
	}
	record, remaining, err = resource.budgetStore.Complete(request.Context(), execution.Key, BudgetResult{
		Status: http.StatusOK, ContentType: "application/json", Body: body, Cost: result.Cost,
	})
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, "budget_custody_failed", err)
		return
	}
	writeBudgetRecord(response, record, remaining, grant)
}

func (resource *Resource) writeBudgetChallenge(
	response http.ResponseWriter,
	request *http.Request,
	authorized aauth.AuthorizedRequest,
	reason string,
) error {
	thumbprint, err := authorized.ConfirmationKey.Thumbprint()
	if err != nil {
		return err
	}
	lineageKey, err := ResourceAuthorizationLineageKey(
		resource.identifier, authorized.AuthTokenIssuer, authorized.PersonServer, authorized.Subject,
		thumbprint, authorized.MissionS256, authorized.Tenant, authorized.Account, "", "",
	)
	if err != nil {
		return err
	}
	lineage, err := resource.resourceTokenLineageStore.Resolve(request.Context(), lineageKey, authorized.AuthTokenIssuedAt.Unix())
	if err != nil || !lineage.Active(authorized.AuthTokenIssuedAt) || !scopeStringContains(lineage.Scope, strings.Join(authorized.Scope, " ")) {
		return errors.New("reference: Budget challenge cannot resolve the person token retained for this authorization")
	}
	offer, err := resource.budgetOffer(request.Context(), nil)
	if err != nil || resource.validateBudgetOffer(offer) != nil {
		return errors.New("reference: resource Budget policy cannot construct a reauthorization offer")
	}
	now := resource.clock.Now().UTC()
	expiresAt := now.Add(5 * time.Minute)
	if authorized.AuthTokenExpiresAt.Before(expiresAt) {
		expiresAt = authorized.AuthTokenExpiresAt
	}
	claims := aauth.ResourceTokenClaims{
		Issuer: resource.identifier, DWK: aauth.ResourceDiscoveryDocument,
		Audience: authorized.AuthTokenIssuer, JTI: resource.newID(), AgentJKT: thumbprint,
		IssuedAt: now.Unix(), ExpiresAt: expiresAt.Unix(), Scope: strings.Join(authorized.Scope, " "),
		PersonServer: authorized.PersonServer, Subject: authorized.Subject, PresentedJTI: lineage.PresentedJTI,
		MissionS256: authorized.MissionS256, Tenant: authorized.Tenant, Account: authorized.Account,
	}
	compact, err := resource.mintAndRetainResourceToken(request.Context(), claims, r3.DocumentReference{}, &offer, now)
	if err != nil {
		return err
	}
	requirement, err := aauth.FormatRequirementHeader(aauth.Requirement{
		Type: aauth.RequirementAuthToken, ResourceToken: compact, Reason: reason,
	})
	if err != nil {
		return err
	}
	response.Header().Set("AAuth-Requirement", requirement)
	return nil
}

func writeBudgetRecord(response http.ResponseWriter, record BudgetRecord, remaining int64, grant budgets.Budget) {
	cost := record.Result.Cost
	writeBudgetHeader(response, budgets.Header{
		Remaining: remaining, Cost: &cost,
		Unit: grant.Unit, Decimals: budgets.OptionalInteger(grant.Decimals),
	})
	response.Header().Set("Content-Type", record.Result.ContentType)
	response.WriteHeader(record.Result.Status)
	_, _ = response.Write(record.Result.Body)
}

func writeBudgetHeader(response http.ResponseWriter, header budgets.Header) {
	exact, err := budgets.FormatHeader(header)
	if err != nil && header.Unit != "" {
		header.Unit, header.Decimals = "", nil
		exact, err = budgets.FormatHeader(header)
	}
	if err == nil {
		response.Header().Set("AAuth-Budget", exact)
	}
}
