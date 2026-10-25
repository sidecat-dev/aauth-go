package resource

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.com/sidecat-dev/aauth-go/budgets"
)

func TestStreamingBudgetTrailerCarriesCostOnly(t *testing.T) {
	t.Parallel()

	usd, err := budgets.NewUnit("USD", 6)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := budgets.NewValue(2_000_000, usd)
	if err != nil {
		t.Fatal(err)
	}
	header, err := budgets.NewReservedFeedback(grant, 1_568_800, 431_200)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		if err := WriteStreamingBudgetHeader(response, header); err != nil {
			t.Error(err)
			return
		}
		response.WriteHeader(http.StatusOK)
		if _, err := response.Write([]byte("event")); err != nil {
			t.Error(err)
			return
		}
		if err := WriteStreamingBudgetTrailer(response, 221_200); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	httpResponse, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer httpResponse.Body.Close()
	if _, err := io.ReadAll(httpResponse.Body); err != nil {
		t.Fatal(err)
	}
	if len(httpResponse.Trailer.Values("AAuth-Budget")) == 0 {
		t.Fatalf("trailer missing; header=%v trailer=%v", httpResponse.Header, httpResponse.Trailer)
	}
	parsed, err := budgets.ParseFeedback(httpResponse.Header.Values("AAuth-Budget"))
	if err != nil {
		t.Fatal(err)
	}
	if _, hasCost := parsed.Cost(); hasCost {
		t.Fatal("streaming header carried cost")
	}
	if reserved, ok := parsed.Reserved(); !ok || reserved != 431_200 {
		t.Fatalf("header reserved = %d, %t", reserved, ok)
	}
	settled, err := budgets.ApplyTrailer(parsed, httpResponse.Trailer.Values("AAuth-Budget"))
	if err != nil {
		t.Fatal(err)
	}
	cost, ok := settled.Cost()
	if !ok || cost != 221_200 || strings.Contains(httpResponse.Trailer.Get("AAuth-Budget"), "remaining=") {
		t.Fatalf("trailer = %q, cost %d/%t", httpResponse.Trailer.Get("AAuth-Budget"), cost, ok)
	}
}

func TestBudgetHeaderIsSentWhenTheAgentOmitsTheBudgetCapability(t *testing.T) {
	t.Parallel()

	protocol := newBudgetResourceProtocol(t, 200_000, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	server := protocol.server(t)
	grant := budgetValue(t, 500_000, protocol.unit)
	authToken := protocol.authToken(t, "capability-budget-auth-token", grant)
	request := signedRequest(
		t, protocol.clock, protocol.agentKey, authToken,
		http.MethodGet, resourceIssuer+"/records", "",
	)
	request.Header.Set("AAuth-Capabilities", "interaction, not-a-real-capability")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	assertBudgetSuccess(t, response, 200_000, 300_000, protocol.unit)
}
