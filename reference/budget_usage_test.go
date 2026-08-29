package reference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

func TestFileBudgetStoreUsageAggregatesAndRecoversWithoutDoubleCounting(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 29, 12, 30, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "budget.json")
	store, err := NewFileBudgetStore(path)
	if err != nil {
		t.Fatal(err)
	}
	grant := budgets.Budget{Amount: 5_000_000, Unit: "USD", Decimals: 6}
	execution, err := NewBudgetExecution("https://as.example", "auth-usage", "call-usage", grant, 1_000_000, now.Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Claim(ctx, execution); err != nil {
		t.Fatal(err)
	}
	agentJKT := aauth.S256([]byte("usage-agent"))
	mission := aauth.S256([]byte("usage-mission"))
	usage := BudgetUsageRecord{
		Key: execution.Key, PersonServer: "https://ps.example", Subject: "person-usage",
		Tenant: "tenant-usage", MissionS256: mission, AgentJKT: agentJKT,
		Unit: grant.Unit, Decimals: grant.Decimals, Consumed: 700_000, RecordedAt: now.Unix(),
	}
	result := BudgetResult{Status: http.StatusOK, ContentType: "application/json", Body: []byte(`{"ok":true}`), Cost: 700_000}
	if _, _, err := store.CompleteWithUsage(ctx, execution.Key, result, usage); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CompleteWithUsage(ctx, execution.Key, result, usage); err != nil {
		t.Fatalf("exact completion retry = %v", err)
	}
	for _, extra := range []struct {
		tokenID, callKey string
		cost             int64
		at               time.Time
		agentJKT         string
	}{
		{tokenID: "auth-usage-previous-day", callKey: "call-usage-previous-day", cost: 100_000, at: now.Add(-24 * time.Hour), agentJKT: aauth.S256([]byte("usage-agent-previous-day"))},
		{tokenID: "auth-usage-previous-month", callKey: "call-usage-previous-month", cost: 200_000, at: now.AddDate(0, -1, 0), agentJKT: aauth.S256([]byte("usage-agent-previous-month"))},
		{tokenID: "auth-usage-previous-year", callKey: "call-usage-previous-year", cost: 300_000, at: now.AddDate(-1, 0, 0), agentJKT: aauth.S256([]byte("usage-agent-previous-year"))},
	} {
		extraExecution, err := NewBudgetExecution("https://as.example", extra.tokenID, extra.callKey, grant, 1_000_000, now.Add(time.Hour).Unix())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := store.Claim(ctx, extraExecution); err != nil {
			t.Fatal(err)
		}
		extraUsage := BudgetUsageRecord{
			Key: extraExecution.Key, PersonServer: "https://ps.example", Subject: "person-usage",
			Tenant: "tenant-usage", MissionS256: mission, AgentJKT: extra.agentJKT,
			Unit: grant.Unit, Decimals: grant.Decimals, Consumed: extra.cost, RecordedAt: extra.at.Unix(),
		}
		extraResult := BudgetResult{Status: http.StatusOK, ContentType: "application/json", Body: []byte(`{"ok":true}`), Cost: extra.cost}
		if _, _, err := store.CompleteWithUsage(ctx, extraExecution.Key, extraResult, extraUsage); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := store.Usage(ctx, BudgetUsageQuery{PersonServer: "https://ps.example", Subject: "person-usage"}, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Unit != grant.Unit || snapshot.Decimals != grant.Decimals || snapshot.Usage == nil || snapshot.Usage.AllTime != 1_300_000 || snapshot.Usage.Day != 700_000 || snapshot.Usage.Week != 800_000 || snapshot.Usage.Month != 800_000 || snapshot.Usage.Year != 1_000_000 || snapshot.ByKey[agentJKT] != 700_000 {
		t.Fatalf("usage snapshot = %#v", snapshot)
	}
	reopened, err := NewFileBudgetStore(path)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.Usage(ctx, BudgetUsageQuery{PersonServer: "https://ps.example", Tenant: "tenant-usage"}, now.Add(time.Hour))
	if err != nil || recovered.Usage == nil || recovered.Usage.AllTime != 1_300_000 {
		t.Fatalf("reopened usage = %#v, %v", recovered, err)
	}
	missionSnapshot, err := reopened.Usage(ctx, BudgetUsageQuery{PersonServer: "https://ps.example", MissionS256: mission}, now.Add(time.Hour))
	if err != nil || missionSnapshot.Usage == nil || missionSnapshot.Usage.AllTime != 1_300_000 {
		t.Fatalf("mission usage = %#v, %v", missionSnapshot, err)
	}
	unknown, err := reopened.Usage(ctx, BudgetUsageQuery{PersonServer: "https://ps.example", Subject: "unknown"}, now.Add(time.Hour))
	if err != nil || unknown.Usage != nil {
		t.Fatalf("unknown scope usage = %#v, %v", unknown, err)
	}
	if _, err := reopened.Usage(ctx, BudgetUsageQuery{PersonServer: "https://other.example", Subject: "person-usage"}, now); !errors.Is(err, ErrBudgetUsageUnauthorized) {
		t.Fatalf("unknown signer entitlement error = %v", err)
	}
}

func TestBudgetUsageQueryRejectsAmbiguousScopeAndDuplicateKeys(t *testing.T) {
	for _, query := range []BudgetUsageQuery{
		{PersonServer: "https://ps.example"},
		{PersonServer: "https://ps.example", Subject: "person", Tenant: "tenant"},
		{PersonServer: "https://ps.example", AgentJKT: []string{aauth.S256([]byte("same")), aauth.S256([]byte("same"))}},
	} {
		if err := query.Validate(); err == nil {
			t.Fatalf("invalid usage query accepted: %#v", query)
		}
	}
}

func TestFileBudgetStoreUsageRefusesMixedDenominations(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 29, 14, 0, 0, 0, time.UTC)
	store, err := NewFileBudgetStore(filepath.Join(t.TempDir(), "budget.json"))
	if err != nil {
		t.Fatal(err)
	}
	complete := func(tokenID, callKey string, grant budgets.Budget, cost int64) {
		execution, executionErr := NewBudgetExecution("https://as.example", tokenID, callKey, grant, grant.Amount, now.Add(time.Hour).Unix())
		if executionErr != nil {
			t.Fatal(executionErr)
		}
		if _, _, _, executionErr = store.Claim(ctx, execution); executionErr != nil {
			t.Fatal(executionErr)
		}
		usage := BudgetUsageRecord{
			Key: execution.Key, PersonServer: "https://ps.example", Subject: "person-mixed",
			Unit: grant.Unit, Decimals: grant.Decimals, Consumed: cost, RecordedAt: now.Unix(),
		}
		if _, _, executionErr = store.CompleteWithUsage(ctx, execution.Key, BudgetResult{Status: http.StatusOK, ContentType: "application/json", Body: []byte(`{"ok":true}`), Cost: cost}, usage); executionErr != nil {
			t.Fatal(executionErr)
		}
	}
	complete("auth-usd", "call-usd", budgets.Budget{Amount: 1_000, Unit: "USD", Decimals: 2}, 100)
	complete("auth-tokens", "call-tokens", budgets.Budget{Amount: 1_000, Unit: "tokens", Decimals: 0}, 200)
	if _, err := store.Usage(ctx, BudgetUsageQuery{PersonServer: "https://ps.example", Subject: "person-mixed"}, now); !errors.Is(err, ErrBudgetUsageMixedUnits) {
		t.Fatalf("mixed denomination error = %v", err)
	}
}

func TestResourceServesSignedBudgetUsageAndHidesUnknownScopes(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 29, 13, 0, 0, 0, time.UTC)
	clock := aauth.ClockFunc(func() time.Time { return now })
	path := filepath.Join(t.TempDir(), "budget.json")
	store, err := NewFileBudgetStore(path)
	if err != nil {
		t.Fatal(err)
	}
	grant := budgets.Budget{Amount: 5_000_000, Unit: "USD", Decimals: 6}
	execution, err := NewBudgetExecution("https://as.example", "auth-endpoint-usage", "call-endpoint-usage", grant, 1_000_000, now.Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.Claim(ctx, execution); err != nil {
		t.Fatal(err)
	}
	agentJKT := aauth.S256([]byte("endpoint-agent"))
	usage := BudgetUsageRecord{Key: execution.Key, PersonServer: "https://ps.example", Subject: "person-endpoint", AgentJKT: agentJKT, Unit: grant.Unit, Decimals: grant.Decimals, Consumed: 400_000, RecordedAt: now.Unix()}
	if _, _, err := store.CompleteWithUsage(ctx, execution.Key, BudgetResult{Status: http.StatusOK, ContentType: "application/json", Body: []byte(`{"ok":true}`), Cost: 400_000}, usage); err != nil {
		t.Fatal(err)
	}
	psKey := referenceTestSigningKey(t, "usage-ps")
	otherKey := referenceTestSigningKey(t, "other-ps")
	resource := &Resource{
		identifier: "https://resource.example", accessMode: aauth.AccessModeAuthToken,
		keyResolver: signaturekey.StaticKeyResolver{
			"https://ps.example":    {psKey.ID(): psKey.PublicJWK()},
			"https://other.example": {otherKey.ID(): otherKey.PublicJWK()},
		},
		clock: clock, budgetUsageStore: store, budgetUsageEndpoint: "https://resource.example/usage", budgetUsagePath: "/usage",
	}
	metadata := httptest.NewRecorder()
	resource.Handler().ServeHTTP(metadata, httptest.NewRequest(http.MethodGet, "https://resource.example/.well-known/aauth-resource.json", nil))
	if metadata.Code != http.StatusOK || !bytes.Contains(metadata.Body.Bytes(), []byte(`"usage_endpoint":"https://resource.example/usage"`)) {
		t.Fatalf("usage metadata = %d %s", metadata.Code, metadata.Body.String())
	}
	body := []byte(`{"sub":"person-endpoint","jkts":["` + agentJKT + `"]}`)
	request := httptest.NewRequest(http.MethodPost, "https://resource.example/usage", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequest(request, psKey, "https://ps.example", aauth.PersonDiscoveryDocument, clock); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	resource.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("usage status = %d: %s", response.Code, response.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	usagePayload, ok := payload["usage"].(map[string]any)
	if !ok || usagePayload["all_time"] != float64(400_000) || payload["aud"] != "https://ps.example" {
		t.Fatalf("usage payload = %#v", payload)
	}
	keys, ok := payload["jkts"].(map[string]any)
	if !ok || keys[agentJKT] != float64(400_000) {
		t.Fatalf("usage key payload = %#v", payload["jkts"])
	}
	unknownScope := httptest.NewRequest(http.MethodPost, "https://resource.example/usage", bytes.NewReader([]byte(`{"sub":"nobody"}`)))
	unknownScope.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequest(unknownScope, psKey, "https://ps.example", aauth.PersonDiscoveryDocument, clock); err != nil {
		t.Fatal(err)
	}
	unknownResponse := httptest.NewRecorder()
	resource.Handler().ServeHTTP(unknownResponse, unknownScope)
	if unknownResponse.Code != http.StatusOK || bytes.Contains(unknownResponse.Body.Bytes(), []byte(`"usage"`)) {
		t.Fatalf("unknown scope response = %d %s", unknownResponse.Code, unknownResponse.Body.String())
	}
	unauthorized := httptest.NewRequest(http.MethodPost, "https://resource.example/usage", bytes.NewReader(body))
	unauthorized.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequest(unauthorized, otherKey, "https://other.example", aauth.PersonDiscoveryDocument, clock); err != nil {
		t.Fatal(err)
	}
	unauthorizedResponse := httptest.NewRecorder()
	resource.Handler().ServeHTTP(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusForbidden {
		t.Fatalf("unauthorized usage status = %d: %s", unauthorizedResponse.Code, unauthorizedResponse.Body.String())
	}
	malformed := httptest.NewRequest(http.MethodPost, "https://resource.example/usage", bytes.NewReader([]byte(`{"sub":"person-endpoint","tenant":"ambiguous"}`)))
	malformed.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequest(malformed, psKey, "https://ps.example", aauth.PersonDiscoveryDocument, clock); err != nil {
		t.Fatal(err)
	}
	malformedResponse := httptest.NewRecorder()
	resource.Handler().ServeHTTP(malformedResponse, malformed)
	if malformedResponse.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous usage status = %d: %s", malformedResponse.Code, malformedResponse.Body.String())
	}
	queryRequest := httptest.NewRequest(http.MethodPost, "https://resource.example/usage?unexpected=true", bytes.NewReader(body))
	queryRequest.Header.Set("Content-Type", "application/json")
	if err := signaturekey.SignJWKSURIRequest(queryRequest, psKey, "https://ps.example", aauth.PersonDiscoveryDocument, clock); err != nil {
		t.Fatal(err)
	}
	queryResponse := httptest.NewRecorder()
	resource.Handler().ServeHTTP(queryResponse, queryRequest)
	if queryResponse.Code != http.StatusBadRequest {
		t.Fatalf("query usage status = %d: %s", queryResponse.Code, queryResponse.Body.String())
	}
}
