package resource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/diagnostics"
)

func TestDiagnosticsReceivesBudgetCostFailureWithoutChangingRefusal(t *testing.T) {
	private := errors.New("private pricing backend unavailable")
	protocol := newBudgetResourceProtocol(t, 1, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("failed pricing dispatched application") }))
	protocol.config.Budget.Cost = func(context.Context, BudgetCostRequest) (int64, error) { return 0, fmt.Errorf("price: %w", private) }
	server := protocol.server(t)
	token := protocol.authToken(t, "diagnostic-budget", budgetValue(t, 2, protocol.unit))
	request := signedRequest(t, protocol.clock, protocol.agentKey, token, http.MethodGet, resourceIssuer+"/records", "")
	var observed []diagnostics.Problem
	handler := diagnostics.Handler(server.Handler(), func(ctx context.Context, p diagnostics.Problem) {
		if ctx != request.Context() {
			t.Error("lost request context")
		}
		observed = append(observed, p)
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 500 || strings.Contains(response.Body.String(), private.Error()) {
		t.Fatalf("response %d %s", response.Code, response.Body.String())
	}
	if len(observed) != 1 || observed[0].Status != 500 || observed[0].Code != "server_error" || !errors.Is(observed[0].Cause, private) {
		t.Fatalf("observations: %#v", observed)
	}
	if len(protocol.store.tokens) != 0 {
		t.Fatal("diagnostics caused a budget mutation")
	}
}
