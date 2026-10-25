package resource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

type budgetSettlementKey struct{}

type budgetSettlement struct {
	mu      sync.Mutex
	settled bool
	writer  http.ResponseWriter
	store   BudgetReserver
	id      string
	token   aauth.TokenReference
	hold    int64
}

// SettleBudget commits the actual cost of the reservation on this request.
// Cost must be between zero and the hold. The unspent remainder is released
// and the cost-only trailer is set. Calling it again is an error.
func SettleBudget(ctx context.Context, cost int64) error {
	if ctx == nil {
		return errors.New("resource: Budget settlement requires a context")
	}
	settlement, _ := ctx.Value(budgetSettlementKey{}).(*budgetSettlement)
	if settlement == nil {
		return errors.New("resource: no Budget reservation on this request")
	}
	return settlement.settle(cost)
}

func (settlement *budgetSettlement) settle(cost int64) error {
	settlement.mu.Lock()
	defer settlement.mu.Unlock()
	if settlement.settled {
		return ErrBudgetReservation
	}
	result, err := settlement.store.Commit(context.Background(), BudgetCommit{
		Token: settlement.token, ID: settlement.id, Cost: cost,
	})
	if err != nil {
		return err
	}
	formatted, err := budgets.FormatTrailer(result.Cost)
	if err != nil {
		return err
	}
	settlement.writer.Header().Set("AAuth-Budget", formatted)
	settlement.settled = true
	return nil
}

func (settlement *budgetSettlement) finish() {
	settlement.mu.Lock()
	pending := !settlement.settled
	settlement.mu.Unlock()
	if pending {
		_ = settlement.settle(settlement.hold)
	}
}

func (server *Server) beginReservedBudget(
	response *budgetResponseWriter,
	request *http.Request,
	claims aauth.AuthTokenClaims,
	principal AuthPrincipal,
	grant budgets.Value,
	r3Reference *r3.Reference,
) (*budgetSettlement, bool) {
	response.observationBlocked = true
	policyRequest, finish, err := cloneScopePolicyRequest(request)
	if err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("prepare Resource Budget reserve request: %w", err))
		return nil, false
	}
	hold, policyErr := server.budget.maximum(request.Context(), BudgetCostRequest{
		Request: policyRequest, Principal: cloneBudgetPrincipal(principal), Grant: grant,
	})
	finishErr := finish()
	if policyErr != nil || finishErr != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("Resource Budget reserve policy: %w", errors.Join(policyErr, finishErr)))
		return nil, false
	}
	if hold <= 0 {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("Resource Budget reserve must be positive"))
		return nil, false
	}
	if _, err := budgets.NewValue(hold, grant.Unit()); err != nil {
		writeProblem(response, http.StatusInternalServerError, "server_error", fmt.Errorf("Resource Budget reserve policy: %w", err))
		return nil, false
	}
	identifier := server.newID()
	if identifier == "" {
		writeProblem(response, http.StatusInternalServerError, "server_error", errors.New("Resource Budget reservation identifier is empty"))
		return nil, false
	}
	reserved, err := server.budget.reserver.Reserve(request.Context(), BudgetReserve{
		ID: identifier, Token: response.charge.Token, PersonServer: response.charge.PersonServer,
		Subject: response.charge.Subject, Audience: response.charge.Audience,
		MissionS256: response.charge.MissionS256, Tenant: response.charge.Tenant,
		Account: cloneBudgetAccount(response.charge.Account), Grant: grant, Hold: hold,
		AgentJKT: response.charge.AgentJKT, ReservedAt: response.charge.ChargedAt,
	})
	if err != nil {
		if !errors.Is(err, ErrBudgetInsufficient) && !errors.Is(err, ErrBudgetExhausted) {
			writeProblem(response, http.StatusInternalServerError, "server_error", err)
			return nil, false
		}
		server.refuseBudget(response, request, claims, principal, grant, r3Reference, hold, BudgetChargeResult{Remaining: reserved.Remaining}, err)
		return nil, false
	}
	feedback, err := budgets.NewReservedFeedback(grant, reserved.Remaining, reserved.Reserved)
	if err != nil {
		_ = server.budget.reserver.Release(request.Context(), BudgetRelease{Token: response.charge.Token, ID: identifier})
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return nil, false
	}
	formatted, err := budgets.FormatFeedback(feedback)
	if err != nil {
		_ = server.budget.reserver.Release(request.Context(), BudgetRelease{Token: response.charge.Token, ID: identifier})
		writeProblem(response, http.StatusInternalServerError, "server_error", err)
		return nil, false
	}
	response.Header().Set("Trailer", "AAuth-Budget")
	response.Header().Set("AAuth-Budget", formatted)
	return &budgetSettlement{
		writer: response.ResponseWriter, store: server.budget.reserver,
		id: identifier, token: response.charge.Token, hold: hold,
	}, true
}
