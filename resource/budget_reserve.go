package resource

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/r3"
)

type budgetSettlementKey struct{}

// budgetSettlement settles one reservation. A held invocation settles with no
// writer: it records the result, and the Resource writes the feedback on the
// retained response.
type budgetSettlement struct {
	mu      sync.Mutex
	settled bool
	result  *BudgetChargeResult
	writer  *budgetWriteState
	store   BudgetReserver
	id      string
	token   aauth.TokenReference
	hold    int64
	grant   budgets.Value
	now     func() time.Time
}

// budgetWriteState is the writer the reserved handler receives. Settlement
// has to know whether that writer has already sent the header: Go promotes a
// declared trailer from the live header map, so replacing AAuth-Budget before
// the first write would send cost alone and repeat it in the trailer.
type budgetWriteState struct {
	http.ResponseWriter
	mu    sync.Mutex
	wrote bool
}

func (state *budgetWriteState) WriteHeader(status int) {
	state.ResponseWriter.WriteHeader(status)
	state.markWritten()
}

func (state *budgetWriteState) Write(body []byte) (int, error) {
	n, err := state.ResponseWriter.Write(body)
	state.markWritten()
	return n, err
}

func (state *budgetWriteState) Flush() {
	flusher, ok := state.ResponseWriter.(http.Flusher)
	if !ok {
		return
	}
	flusher.Flush()
	state.markWritten()
}

func (state *budgetWriteState) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := state.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("resource: Budget response does not support hijacking")
	}
	return hijacker.Hijack()
}

func (state *budgetWriteState) Unwrap() http.ResponseWriter { return state.ResponseWriter }

func (state *budgetWriteState) markWritten() {
	state.mu.Lock()
	state.wrote = true
	state.mu.Unlock()
}

func (state *budgetWriteState) written() bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.wrote
}

// SettleBudget commits the actual cost of the reservation on this request.
// Cost must be between zero and the hold. The unspent remainder is released.
// After the handler has written the response header, the cost-only trailer is
// set and the reserved header is left as it was sent. Before that write,
// SettleBudget replaces the header with a fixed-price cost and remaining and
// drops the trailer declaration, so the header stays parseable and cost is
// not repeated. Calling it again is an error. Call it on the request goroutine
// through the writer this request passed to the handler.
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
	chargedAt := time.Time{}
	if settlement.now != nil {
		chargedAt = settlement.now().UTC()
	}
	result, err := settlement.store.Commit(context.Background(), BudgetCommit{
		Token: settlement.token, ID: settlement.id, Cost: cost, ChargedAt: chargedAt,
	})
	if err != nil {
		return err
	}
	if settlement.writer == nil {
		settlement.result = &result
		settlement.settled = true
		return nil
	}
	if settlement.writer.written() {
		formatted, err := budgets.FormatTrailer(result.Cost)
		if err != nil {
			return err
		}
		settlement.writer.Header().Set("AAuth-Budget", formatted)
	} else {
		feedback, err := budgets.NewSuccessFeedback(settlement.grant, result.Cost, result.Remaining)
		if err != nil {
			return err
		}
		formatted, err := budgets.FormatFeedback(feedback)
		if err != nil {
			return err
		}
		header := settlement.writer.Header()
		header.Del("Trailer")
		header.Set("AAuth-Budget", formatted)
	}
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
	requiredScopes []string,
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
		server.refuseBudget(response, request, claims, principal, grant, r3Reference, requiredScopes, hold, BudgetChargeResult{Remaining: reserved.Remaining, Consumed: reserved.Consumed}, err)
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
	now := func() time.Time { return time.Time{} }
	if server.clock != nil {
		now = server.clock.Now
	}
	return &budgetSettlement{
		writer: &budgetWriteState{ResponseWriter: response.ResponseWriter},
		store:  server.budget.reserver,
		id:     identifier, token: response.charge.Token, hold: hold, grant: grant, now: now,
	}, true
}
