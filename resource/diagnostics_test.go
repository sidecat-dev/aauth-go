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

func TestDiagnosticsDoesNotObservePlainAuthorityRefusals(t *testing.T) {
	protected := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("foreign authority reached the application")
	})
	regular := newBudgetResourceProtocol(t, 1, protected).server(t)
	sessions := newResourceSessionProtocol(t)
	managed, err := NewResourceManaged(sessions.config(newMemorySessionStore(), protected))
	if err != nil {
		t.Fatal(err)
	}
	for name, service := range map[string]http.Handler{
		"Resource": regular.Handler(), "Resource-managed sessions": managed.Handler(),
	} {
		t.Run(name, func(t *testing.T) {
			observed := 0
			handler := diagnostics.Handler(service, func(context.Context, diagnostics.Problem) {
				observed++
			})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://foreign.example/records", nil))
			if response.Code != http.StatusMisdirectedRequest || observed != 0 {
				t.Fatalf("foreign authority: status=%d observations=%d", response.Code, observed)
			}
			if response.Header().Get("Content-Type") != "text/plain; charset=utf-8" ||
				response.Body.String() != http.StatusText(http.StatusMisdirectedRequest)+"\n" {
				t.Fatalf("authority refusal changed: %v %q", response.Header(), response.Body.String())
			}
		})
	}
}
