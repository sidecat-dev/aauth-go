package resource

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
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

func TestReservedBudgetSettledBeforeWriteIsAFixedPriceHeader(t *testing.T) {
	t.Parallel()

	instant := time.Date(2026, 8, 31, 18, 0, 0, 0, time.UTC)
	protocol := newBudgetResourceProtocol(t, 1, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		instant = instant.Add(48 * time.Hour)
		if err := SettleBudget(request.Context(), 221_200); err != nil {
			t.Error(err)
			return
		}
		if _, err := response.Write([]byte("body")); err != nil {
			t.Error(err)
		}
	}))
	protocol.clock = aauth.ClockFunc(func() time.Time { return instant })
	protocol.config.Clock = protocol.clock
	protocol.config.Budget.Maximum = func(context.Context, BudgetCostRequest) (int64, error) {
		return 400_000, nil
	}
	protocol.config.Budget.Challenge = protocol.challenge(t, nil)
	app := protocol.server(t)
	httpServer := httptest.NewServer(app.Handler())
	defer httpServer.Close()

	authToken := protocol.authToken(t, "settle-before-write", budgetValue(t, 1_000_000, protocol.unit))
	response := doBudgetRequest(t, httpServer, protocol, authToken)
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	header := mustParseFeedback(t, response.Header.Values("AAuth-Budget"))
	cost, hasCost := header.Cost()
	if _, reserved := header.Reserved(); reserved || !hasCost || cost != 221_200 || header.Remaining() != 778_800 {
		t.Fatalf("header cost=%d/%t remaining=%d reserved=%t raw=%q", cost, hasCost, header.Remaining(), reserved, response.Header.Get("AAuth-Budget"))
	}
	if response.Header.Get("Trailer") != "" || response.Trailer.Get("AAuth-Budget") != "" {
		t.Fatalf("early settle declared a trailer: header=%q trailer=%q", response.Header.Get("Trailer"), response.Trailer.Get("AAuth-Budget"))
	}
	settled, err := budgets.ApplyTrailer(header, response.Trailer.Values("AAuth-Budget"))
	if err != nil {
		t.Fatal(err)
	}
	settledCost, ok := settled.Cost()
	if !ok || settledCost != 221_200 {
		t.Fatalf("settled cost = %d/%t", settledCost, ok)
	}
	if got := protocol.store.committedAt(); !got.Equal(instant) {
		t.Fatalf("charge time = %s, want %s", got, instant)
	}
	if consumed := protocol.store.personConsumed(personIssuer, "person-1", resourceIssuer); consumed != 221_200 {
		t.Fatalf("committed = %d", consumed)
	}
}

func TestUnwrittenBudgetSettlementIsAFixedPriceHeader(t *testing.T) {
	t.Parallel()

	protocol := newBudgetResourceProtocol(t, 1, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	protocol.config.Budget.Maximum = func(context.Context, BudgetCostRequest) (int64, error) {
		return 200_000, nil
	}
	protocol.config.Budget.Challenge = protocol.challenge(t, nil)
	app := protocol.server(t)
	httpServer := httptest.NewServer(app.Handler())
	defer httpServer.Close()

	authToken := protocol.authToken(t, "settle-without-write", budgetValue(t, 500_000, protocol.unit))
	response := doBudgetRequest(t, httpServer, protocol, authToken)
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	header := mustParseFeedback(t, response.Header.Values("AAuth-Budget"))
	cost, hasCost := header.Cost()
	if _, reserved := header.Reserved(); reserved || !hasCost || cost != 200_000 || header.Remaining() != 300_000 {
		t.Fatalf("header cost=%d/%t remaining=%d", cost, hasCost, header.Remaining())
	}
	if _, err := budgets.ApplyTrailer(header, response.Trailer.Values("AAuth-Budget")); err != nil {
		t.Fatal(err)
	}
	if response.Trailer.Get("AAuth-Budget") != "" {
		t.Fatalf("unwritten settle sent trailer %q", response.Trailer.Get("AAuth-Budget"))
	}
	if consumed := protocol.store.personConsumed(personIssuer, "person-1", resourceIssuer); consumed != 200_000 {
		t.Fatalf("committed hold = %d", consumed)
	}
}

func TestReserveRefusalCountsCommittedSpendNotInFlightHolds(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	var closeOnce sync.Once
	closeRelease := func() { closeOnce.Do(func() { close(release) }) }
	t.Cleanup(closeRelease)
	var identifiers atomic.Int32
	var maxima atomic.Int32
	protocol := newBudgetResourceProtocol(t, 1, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(started) })
		<-release
		_, _ = response.Write([]byte("ok"))
	}))
	protocol.config.NewID = func() string { return fmt.Sprintf("reserve-%d", identifiers.Add(1)) }
	protocol.config.Budget.Maximum = func(context.Context, BudgetCostRequest) (int64, error) {
		if maxima.Add(1) == 1 {
			return 300_000, nil
		}
		return 800_000, nil
	}
	protocol.config.Budget.Challenge = protocol.challenge(t, nil)
	app := protocol.server(t)
	httpServer := httptest.NewServer(app.Handler())
	defer httpServer.Close()
	defer closeRelease()
	holding := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	refusing := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}

	authToken := protocol.authToken(t, "held-spend", budgetValue(t, 1_000_000, protocol.unit))
	firstDone := make(chan *http.Response, 1)
	go func() {
		firstDone <- doBudgetRequestWith(t, holding, httpServer, protocol, authToken)
	}()
	select {
	case <-started:
	case response := <-firstDone:
		t.Fatalf("holding request finished early with %d", response.StatusCode)
	}

	refused := doBudgetRequestWith(t, refusing, httpServer, protocol, authToken)
	defer refused.Body.Close()
	if _, err := io.ReadAll(refused.Body); err != nil {
		t.Fatal(err)
	}
	if refused.StatusCode != http.StatusUnauthorized {
		t.Fatalf("committed-only refusal = %d %s", refused.StatusCode, refused.Header.Get("AAuth-Budget"))
	}
	requirement, reason, err := budgets.ParseAuthTokenRequirement(refused.Header.Values("AAuth-Requirement"))
	if err != nil || reason != budgets.ReasonInsufficientBudget {
		t.Fatalf("requirement = %q %v", reason, err)
	}
	_, _, consumed, err := budgets.VerifyResourceToken(context.Background(), requirement.ResourceToken, protocol.resolver, protocol.clock)
	if err != nil || consumed == nil || consumed.Consumed() != 0 {
		t.Fatalf("consumption = %#v %v", consumed, err)
	}
	feedback := mustParseFeedback(t, refused.Header.Values("AAuth-Budget"))
	required, hasRequired := feedback.Required()
	if feedback.Remaining() != 700_000 || !hasRequired || required != 800_000 {
		t.Fatalf("refusal remaining=%d required=%d/%t", feedback.Remaining(), required, hasRequired)
	}

	closeRelease()
	first := <-firstDone
	defer first.Body.Close()
	if _, err := io.ReadAll(first.Body); err != nil {
		t.Fatal(err)
	}
	if first.StatusCode != http.StatusOK {
		t.Fatalf("holding request = %d", first.StatusCode)
	}
}

func TestReserveRefusalRejectsConsumptionThatIncludesInFlightHolds(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	var closeOnce sync.Once
	closeRelease := func() { closeOnce.Do(func() { close(release) }) }
	t.Cleanup(closeRelease)
	var identifiers atomic.Int32
	var maxima atomic.Int32
	protocol := newBudgetResourceProtocol(t, 1, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		once.Do(func() { close(started) })
		<-release
	}))
	protocol.config.NewID = func() string { return fmt.Sprintf("reserve-%d", identifiers.Add(1)) }
	protocol.config.Budget.Maximum = func(context.Context, BudgetCostRequest) (int64, error) {
		if maxima.Add(1) == 1 {
			return 300_000, nil
		}
		return 800_000, nil
	}
	protocol.config.Budget.Challenge = func(_ context.Context, request BudgetChallengeRequest) (string, error) {
		request.Consumed = request.Grant.Amount() - request.Remaining
		return protocol.challengeToken(t, request, nil)
	}
	app := protocol.server(t)
	httpServer := httptest.NewServer(app.Handler())
	defer httpServer.Close()
	defer closeRelease()
	holding := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	refusing := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}

	authToken := protocol.authToken(t, "held-as-consumed", budgetValue(t, 1_000_000, protocol.unit))
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		response := doBudgetRequestWith(t, holding, httpServer, protocol, authToken)
		response.Body.Close()
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("holding request did not start")
	}
	refused := doBudgetRequestWith(t, refusing, httpServer, protocol, authToken)
	defer refused.Body.Close()
	if _, err := io.ReadAll(refused.Body); err != nil {
		t.Fatal(err)
	}
	if refused.StatusCode != http.StatusInternalServerError || refused.Header.Get("AAuth-Requirement") != "" {
		t.Fatalf("hold-inflated record status=%d requirement=%q", refused.StatusCode, refused.Header.Get("AAuth-Requirement"))
	}
	closeRelease()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("holding request did not finish")
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
	return doBudgetRequestWith(t, server.Client(), server, protocol, authToken)
}

func doBudgetRequestWith(t *testing.T, client *http.Client, server *httptest.Server, protocol *budgetResourceProtocol, authToken string) *http.Response {
	t.Helper()
	request := signedRequest(
		t, protocol.clock, protocol.agentKey, authToken,
		http.MethodGet, resourceIssuer+"/records", "",
	)
	request.URL.Scheme = "http"
	request.URL.Host = strings.TrimPrefix(server.URL, "http://")
	request.Host = "resource.example"
	request.RequestURI = ""
	response, err := client.Do(request)
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
