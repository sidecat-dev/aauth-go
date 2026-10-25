package resource

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/budgets"
)

func TestReservedBudgetSettlesBelowTheHold(t *testing.T) {
	t.Parallel()

	protocol := newBudgetResourceProtocol(t, 1, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if _, err := response.Write([]byte("body")); err != nil {
			t.Error(err)
			return
		}
		if err := SettleBudget(request.Context(), 221_200); err != nil {
			t.Error(err)
		}
	}))
	protocol.config.Budget.Maximum = func(context.Context, BudgetCostRequest) (int64, error) {
		return 400_000, nil
	}
	protocol.config.Budget.Challenge = protocol.challenge(t, nil)
	app := protocol.server(t)
	httpServer := httptest.NewServer(app.Handler())
	defer httpServer.Close()

	authToken := protocol.authToken(t, "reserved-call", budgetValue(t, 1_000_000, protocol.unit))
	response := doBudgetRequest(t, httpServer, protocol, authToken)
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status = %d, body = %s", response.StatusCode, body)
	}
	header, err := budgets.ParseFeedback(response.Header.Values("AAuth-Budget"))
	if err != nil {
		t.Fatal(err)
	}
	reserved, ok := header.Reserved()
	if _, hasCost := header.Cost(); hasCost || !ok || reserved != 400_000 || header.Remaining() != 600_000 {
		t.Fatalf("header remaining=%d reserved=%d/%t", header.Remaining(), reserved, ok)
	}
	settled, err := budgets.ApplyTrailer(header, response.Trailer.Values("AAuth-Budget"))
	if err != nil {
		t.Fatal(err)
	}
	cost, ok := settled.Cost()
	if !ok || cost != 221_200 {
		t.Fatalf("trailer cost = %d, %t, raw = %q", cost, ok, response.Trailer.Get("AAuth-Budget"))
	}
	if consumed := protocol.store.personConsumed(personIssuer, "person-1", resourceIssuer); consumed != 221_200 {
		t.Fatalf("committed = %d", consumed)
	}
}

func TestUnsettledBudgetCommitsTheHold(t *testing.T) {
	t.Parallel()

	protocol := newBudgetResourceProtocol(t, 1, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("body"))
	}))
	protocol.config.Budget.Maximum = func(context.Context, BudgetCostRequest) (int64, error) {
		return 200_000, nil
	}
	protocol.config.Budget.Challenge = protocol.challenge(t, nil)
	app := protocol.server(t)
	httpServer := httptest.NewServer(app.Handler())
	defer httpServer.Close()

	authToken := protocol.authToken(t, "unsettled-call", budgetValue(t, 500_000, protocol.unit))
	response := doBudgetRequest(t, httpServer, protocol, authToken)
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	settled, err := budgets.ApplyTrailer(
		mustParseFeedback(t, response.Header.Values("AAuth-Budget")),
		response.Trailer.Values("AAuth-Budget"),
	)
	if err != nil {
		t.Fatal(err)
	}
	cost, ok := settled.Cost()
	if !ok || cost != 200_000 {
		t.Fatalf("assumed trailer cost = %d, %t", cost, ok)
	}
	if consumed := protocol.store.personConsumed(personIssuer, "person-1", resourceIssuer); consumed != 200_000 {
		t.Fatalf("committed hold = %d", consumed)
	}
}

func doBudgetRequest(t *testing.T, server *httptest.Server, protocol *budgetResourceProtocol, authToken string) *http.Response {
	t.Helper()
	request := signedRequest(
		t, protocol.clock, protocol.agentKey, authToken,
		http.MethodGet, resourceIssuer+"/records", "",
	)
	request.URL.Scheme = "http"
	request.URL.Host = strings.TrimPrefix(server.URL, "http://")
	request.Host = "resource.example"
	request.RequestURI = ""
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func mustParseFeedback(t *testing.T, values []string) budgets.Feedback {
	t.Helper()
	feedback, err := budgets.ParseFeedback(values)
	if err != nil {
		t.Fatal(err)
	}
	return feedback
}
