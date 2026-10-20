package resource

import (
	"context"
	"errors"
	"net/http"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
)

// budgetResponseWriter supplies feedback for Resource-generated refusals after
// the token and request proof have been verified. Application handlers receive
// the original writer with feedback already set by the completed charge.
type budgetResponseWriter struct {
	http.ResponseWriter
	ctx                context.Context
	store              BudgetStore
	charge             BudgetCharge
	remaining          *int64
	observationBlocked bool
	wroteHeader        bool
}

func newBudgetResponseWriter(response http.ResponseWriter, ctx context.Context, store BudgetStore, claims aauth.AuthTokenClaims, grant budgets.Value) *budgetResponseWriter {
	return &budgetResponseWriter{ResponseWriter: response, ctx: ctx, store: store, charge: BudgetCharge{
		Token:        aauth.TokenReference{Issuer: claims.Issuer, JTI: claims.JTI},
		PersonServer: claims.PersonServer, Subject: claims.Subject, Audience: claims.Audience,
		MissionS256: claims.MissionS256, Tenant: claims.Tenant, Account: cloneBudgetAccount(claims.Account), Grant: grant,
	}}
}

func (response *budgetResponseWriter) setUnchargedFeedback() error {
	if response.observationBlocked {
		return errors.New("Resource Budget balance is unavailable")
	}
	response.observationBlocked = true
	remaining := response.remaining
	if remaining == nil {
		result, err := response.store.Charge(response.ctx, response.charge)
		if err != nil && !errors.Is(err, ErrBudgetExhausted) {
			return err
		}
		if result.Cost != 0 || result.Remaining < 0 || result.Remaining > response.charge.Grant.Amount() ||
			(errors.Is(err, ErrBudgetExhausted) && result.Remaining != 0) {
			return errors.New("Resource Budget store returned an invalid balance")
		}
		remaining = &result.Remaining
	}
	feedback, err := budgets.NewSuccessFeedback(response.charge.Grant, 0, *remaining)
	if err != nil {
		return err
	}
	formatted, err := budgets.FormatFeedback(feedback)
	if err != nil {
		return err
	}
	response.Header().Set("AAuth-Budget", formatted)
	return nil
}

func (response *budgetResponseWriter) WriteHeader(status int) {
	if response.wroteHeader {
		return
	}
	response.wroteHeader = true
	if response.Header().Get("AAuth-Budget") == "" && !response.observationBlocked {
		// A meter failure is the draft's exception to feedback on every response.
		// Preserve the original refusal; an unavailable balance must not be guessed.
		_ = response.setUnchargedFeedback()
	}
	response.ResponseWriter.WriteHeader(status)
}

func (response *budgetResponseWriter) Write(body []byte) (int, error) {
	if !response.wroteHeader {
		response.WriteHeader(http.StatusOK)
	}
	return response.ResponseWriter.Write(body)
}
